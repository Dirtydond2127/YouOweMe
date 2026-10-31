import os, sqlite3, secrets, hmac, json
import random
from datetime import date, timedelta
from pathlib import Path
from functools import wraps
from flask import Flask, request, session, jsonify, redirect, send_from_directory, g, abort
from authlib.integrations.flask_client import OAuth

app = Flask(__name__, static_folder='static')
secret = os.environ.get('SECRET_KEY', '')
if len(secret) < 32:
    raise RuntimeError('Set SECRET_KEY to a random value of at least 32 characters')
BASE = os.environ.get('APP_URL', '').rstrip('/')
if not BASE.startswith('https://'):
    raise RuntimeError('APP_URL must be your public HTTPS origin')
app.config.update(SECRET_KEY=secret, SESSION_COOKIE_NAME='__Host-owe', SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_PATH='/',
    PERMANENT_SESSION_LIFETIME=timedelta(days=7), MAX_CONTENT_LENGTH=16384)
DB = os.environ.get('DATABASE_PATH', '/data/owe.sqlite3')
Path(DB).parent.mkdir(parents=True, exist_ok=True)
oauth = OAuth(app)
oauth.register('google', client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope':'openid email profile', 'code_challenge_method':'S256'})

def db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB, timeout=20)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db

@app.teardown_appcontext
def close_db(error):
    connection = g.pop('db', None)
    if connection: connection.close()

with app.app_context():
    db_file=Path(DB)
    if db_file.exists() and db_file.stat().st_size:
        existing=sqlite3.connect(DB,timeout=20)
        try:
            tables={r[0] for r in existing.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            cols={r[1] for r in existing.execute('PRAGMA table_info(entries)')} if 'entries' in tables else set()
            if 'entries' in tables and 'group_id' not in cols:
                backup_path=f"{DB}.pre-groups-{__import__('datetime').datetime.now().strftime('%Y%m%d-%H%M%S')}.bak"
                target=sqlite3.connect(backup_path)
                try: existing.backup(target)
                finally: target.close()
                app.logger.info('Created pre-migration database backup at %s',backup_path)
        finally: existing.close()
    db().executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, sub TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
        email TEXT NOT NULL, code TEXT UNIQUE NOT NULL);
    CREATE TABLE IF NOT EXISTS contacts (
        a INTEGER REFERENCES users(id), b INTEGER REFERENCES users(id),
        PRIMARY KEY(a,b), CHECK(a<b));
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, creator INTEGER NOT NULL REFERENCES users(id),
        code TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER NOT NULL REFERENCES groups(id), user_id INTEGER NOT NULL REFERENCES users(id),
        joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(group_id,user_id));
    CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY, creator INTEGER NOT NULL REFERENCES users(id),
        creditor INTEGER NOT NULL REFERENCES users(id), debtor INTEGER NOT NULL REFERENCES users(id),
        group_id INTEGER REFERENCES groups(id), deleted_at TEXT, deleted_by INTEGER REFERENCES users(id),
        amount INTEGER NOT NULL CHECK(amount>0), description TEXT NOT NULL, date TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','rejected','settled')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, settled_at TEXT,
        CHECK(creditor<>debtor));
    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY, entry_id INTEGER NOT NULL REFERENCES entries(id),
        actor INTEGER NOT NULL REFERENCES users(id), action TEXT NOT NULL,
        at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE INDEX IF NOT EXISTS entry_creditor ON entries(creditor);
    CREATE INDEX IF NOT EXISTS entry_debtor ON entries(debtor);
    """)
    connection=db()
    connection.execute('BEGIN IMMEDIATE')
    columns={row['name'] for row in connection.execute('PRAGMA table_info(entries)')}
    if 'group_id' not in columns: db().execute('ALTER TABLE entries ADD COLUMN group_id INTEGER REFERENCES groups(id)')
    if 'deleted_at' not in columns: db().execute('ALTER TABLE entries ADD COLUMN deleted_at TEXT')
    if 'deleted_by' not in columns: db().execute('ALTER TABLE entries ADD COLUMN deleted_by INTEGER REFERENCES users(id)')
    connection.execute('CREATE INDEX IF NOT EXISTS entry_group ON entries(group_id)')
    # Preserve old pairwise access: each existing connection becomes its own private group.
    for contact in db().execute('SELECT a,b FROM contacts').fetchall():
        pair=tuple(sorted((contact['a'],contact['b'])))
        group=db().execute('SELECT id FROM groups WHERE id IN (SELECT group_id FROM group_members WHERE user_id=?) GROUP BY id HAVING COUNT(*)=2 AND SUM(CASE WHEN user_id IN (?,?) THEN 1 ELSE 0 END)=2 LIMIT 1',(pair[0],*pair)).fetchone()
        if not group:
            names=db().execute('SELECT name FROM users WHERE id IN (?,?) ORDER BY id',(pair[0],pair[1])).fetchall()
            label=' & '.join(row['name'] for row in names)[:100]
            gid=db().execute('INSERT INTO groups(name,creator,code) VALUES(?,?,?)',(label,pair[0],secrets.token_urlsafe(18))).lastrowid
            db().executemany('INSERT INTO group_members(group_id,user_id) VALUES(?,?)',[(gid,pair[0]),(gid,pair[1])])
            group={'id':gid}
        db().execute('UPDATE entries SET group_id=? WHERE group_id IS NULL AND ((creditor=? AND debtor=?) OR (creditor=? AND debtor=?))',(group['id'],*pair,*pair))
    db().commit()
    db().commit()

def auth(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('uid'): return jsonify(error='Please sign in again.'), 401
        if not db().execute('SELECT id FROM users WHERE id=?',(session['uid'],)).fetchone():
            session.clear()
            return jsonify(error='Please sign in again.'), 401
        return fn(*args, **kwargs)
    return wrapped

@app.before_request
def csrf_check():
    if request.method in ('POST','PUT','PATCH','DELETE'):
        if request.headers.get('Origin') != BASE:
            return jsonify(error='Invalid request origin.'), 403
        token = request.headers.get('X-CSRF-Token','')
        if not token or not hmac.compare_digest(token, session.get('csrf','')):
            return jsonify(error='Session expired. Reload the page.'), 403

@app.after_request
def security(response):
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='same-origin'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Strict-Transport-Security']='max-age=31536000'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    if request.path.startswith(('/api/','/auth/')) or request.path=='/':
        response.headers['Cache-Control']='no-store'
    return response

@app.get('/health')
def health(): return {'status':'ok'}

@app.get('/')
def index(): return send_from_directory('static','index.html')

@app.get('/sw.js')
def worker():
    response=send_from_directory('static','sw.js')
    response.headers['Cache-Control']='no-cache'
    return response

@app.get('/auth/google')
def login():
    if not os.environ.get('GOOGLE_CLIENT_ID') or not os.environ.get('GOOGLE_CLIENT_SECRET'):
        return 'Google sign-in has not been configured by the administrator.', 503
    return oauth.google.authorize_redirect(BASE+'/auth/callback', nonce=secrets.token_urlsafe(24))

@app.get('/auth/callback')
def callback():
    try:
        token=oauth.google.authorize_access_token()
        user=token['userinfo']
        if not user.get('email_verified') or not user.get('sub'): abort(403)
        allowed={x.strip().lower() for x in os.environ.get('ALLOWED_EMAILS','').split(',') if x.strip()}
        if allowed and user.get('email','').lower() not in allowed:
            return 'This account is not on the administrator access list.',403
        connection=db()
        connection.execute('INSERT INTO users(sub,name,email,code) VALUES(?,?,?,?) ON CONFLICT(sub) DO UPDATE SET name=excluded.name,email=excluded.email',
            (user['sub'],user.get('name','Member')[:100],user['email'],secrets.token_urlsafe(18)))
        connection.commit()
        uid=connection.execute('SELECT id FROM users WHERE sub=?',(user['sub'],)).fetchone()['id']
        if not connection.execute('SELECT 1 FROM group_members WHERE user_id=?',(uid,)).fetchone():
            gid=connection.execute('INSERT INTO groups(name,creator,code) VALUES(?,?,?)',(user.get('name','My group')[:80],uid,secrets.token_urlsafe(18))).lastrowid
            connection.execute('INSERT INTO group_members(group_id,user_id) VALUES(?,?)',(gid,uid))
            session['group_id']=gid
        session.clear(); session.permanent=True
        session['uid']=uid; session['csrf']=secrets.token_urlsafe(32)
        return redirect('/')
    except Exception:
        app.logger.warning('Google sign-in failed; check OAuth configuration and callback URL.')
        return 'Sign-in failed. Return to the app and try again.',400

@app.post('/api/logout')
@auth
def logout():
    session.clear()
    return {'ok':True}

@app.get('/api/me')
@auth
def me():
    user=dict(db().execute('SELECT id,name,email,code FROM users WHERE id=?',(session['uid'],)).fetchone())
    admin_email=os.environ.get('ADMIN_EMAIL','').strip().lower()
    user['is_admin']=bool(admin_email and user['email'].lower()==admin_email)
    return {'user':user,'csrf':session['csrf']}

def active_group(uid):
    gid=session.get('group_id')
    if gid and db().execute('SELECT 1 FROM group_members WHERE group_id=? AND user_id=?',(gid,uid)).fetchone(): return gid
    row=db().execute('SELECT group_id FROM group_members WHERE user_id=? ORDER BY joined_at,group_id LIMIT 1',(uid,)).fetchone()
    session['group_id']=row['group_id'] if row else None
    return session['group_id']

@app.get('/api/groups')
@auth
def groups():
    uid=session['uid']; current=active_group(uid)
    rows=db().execute('SELECT g.id,g.name,g.code,COUNT(gm2.user_id) members FROM groups g JOIN group_members gm ON gm.group_id=g.id LEFT JOIN group_members gm2 ON gm2.group_id=g.id WHERE gm.user_id=? GROUP BY g.id ORDER BY g.created_at,g.id',(uid,)).fetchall()
    return jsonify(current=current,groups=[dict(r) for r in rows])

@app.post('/api/groups')
@auth
def create_group():
    data=request.get_json(silent=True) or {}; name=data.get('name','')
    if not isinstance(name,str) or not 1<=len(name.strip())<=80: return {'error':'Enter a group name up to 80 characters.'},400
    conn=db(); gid=conn.execute('INSERT INTO groups(name,creator,code) VALUES(?,?,?)',(name.strip(),session['uid'],secrets.token_urlsafe(18))).lastrowid
    conn.execute('INSERT INTO group_members(group_id,user_id) VALUES(?,?)',(gid,session['uid']));conn.commit();session['group_id']=gid
    return {'ok':True},201

@app.post('/api/groups/join')
@auth
def join_group():
    data=request.get_json(silent=True) or {}; code=data.get('code','')
    if not isinstance(code,str) or len(code)>100:return {'error':'Invalid invitation code.'},400
    group=db().execute('SELECT id FROM groups WHERE code=?',(code.strip(),)).fetchone()
    if not group:return {'error':'Group invitation not found.'},404
    db().execute('INSERT OR IGNORE INTO group_members(group_id,user_id) VALUES(?,?)',(group['id'],session['uid']));db().commit();session['group_id']=group['id']
    return {'ok':True}

@app.post('/api/groups/select')
@auth
def select_group():
    gid=(request.get_json(silent=True) or {}).get('group_id')
    if type(gid) is not int or not db().execute('SELECT 1 FROM group_members WHERE group_id=? AND user_id=?',(gid,session['uid'])).fetchone():return {'error':'Group not found.'},404
    session['group_id']=gid;return {'ok':True}

@app.get('/api/people')
@auth
def people():
    uid=session['uid']; gid=active_group(uid)
    rows=db().execute('SELECT u.id,u.name FROM users u JOIN group_members gm ON gm.user_id=u.id WHERE gm.group_id=? AND u.id<>? ORDER BY u.name',(gid,uid)).fetchall() if gid else []
    return jsonify([dict(r) for r in rows])

@app.post('/api/people')
@auth
def add_person():
    data=request.get_json(silent=True) or {}
    code=data.get('code','')
    if not isinstance(code,str) or len(code)>100: return {'error':'Invalid connection code.'},400
    group=db().execute('SELECT id FROM groups WHERE code=?',(code.strip(),)).fetchone()
    if not group:return {'error':'Group invitation not found.'},404
    db().execute('INSERT OR IGNORE INTO group_members(group_id,user_id) VALUES(?,?)',(group['id'],session['uid']));db().commit();session['group_id']=group['id']
    return {'ok':True}

@app.post('/api/code/rotate')
@auth
def rotate_code():
    gid=active_group(session['uid'])
    if not gid:return {'error':'Create a group first.'},400
    db().execute('UPDATE groups SET code=? WHERE id=?',(secrets.token_urlsafe(18),gid));db().commit()
    return {'ok':True}

@app.get('/api/entries')
@auth
def entries():
    uid=session['uid'];gid=active_group(uid)
    rows=db().execute('SELECT e.*,c.name creditor_name,d.name debtor_name FROM entries e JOIN users c ON c.id=e.creditor JOIN users d ON d.id=e.debtor WHERE e.group_id=? AND e.deleted_at IS NULL ORDER BY e.date DESC,e.id DESC',(gid,)).fetchall() if gid else []
    return jsonify([dict(r) for r in rows])

@app.post('/api/entries')
@auth
def add_entry():
    data=request.get_json(silent=True) or {};uid=session['uid']
    amount=data.get('amount');person=data.get('person');description=data.get('description','');direction=data.get('direction')
    if type(amount) is not int or not 1<=amount<=100000000 or type(person) is not int:
        return {'error':'Choose a person and enter an amount between £0.01 and £1,000,000.'},400
    if not isinstance(description,str) or not 1<=len(description.strip())<=200 or direction not in ('owed','owe'):
        return {'error':'Provide a description of up to 200 characters and a valid direction.'},400
    try:
        entry_date=date.fromisoformat(data.get('date','')).isoformat()
    except (ValueError,TypeError): return {'error':'Choose a valid date.'},400
    gid=active_group(uid)
    if not gid or not db().execute('SELECT 1 FROM group_members WHERE group_id=? AND user_id=?',(gid,person)).fetchone():
        return {'error':'Choose one of your connected people.'},403
    creditor,debtor=(uid,person) if direction=='owed' else (person,uid)
    cursor=db().execute('INSERT INTO entries(creator,creditor,debtor,group_id,amount,description,date) VALUES(?,?,?,?,?,?,?)',(uid,creditor,debtor,gid,amount,description.strip(),entry_date))
    db().execute('INSERT INTO audit(entry_id,actor,action) VALUES(?,?,?)',(cursor.lastrowid,uid,'created'))
    db().commit();return {'ok':True},201

@app.post('/api/entries/<int:eid>/<action>')
@auth
def action_entry(eid,action):
    uid=session['uid'];connection=db()
    # Serialise read/check/write to prevent competing state changes.
    connection.execute('BEGIN IMMEDIATE')
    gid=active_group(uid)
    entry=connection.execute('SELECT * FROM entries WHERE id=? AND group_id=? AND deleted_at IS NULL AND (creditor=? OR debtor=?)',(eid,gid,uid,uid)).fetchone()
    if not entry: return {'error':'Entry not found.'},404
    status=None
    if action in ('accept','reject') and entry['status']=='pending' and entry['creator']!=uid:
        status='accepted' if action=='accept' else 'rejected'
    elif action=='cancel' and entry['status']=='pending' and entry['creator']==uid: status='rejected'
    elif action=='settle' and entry['status']=='accepted' and entry['creditor']==uid: status='settled'
    if status is None: return {'error':'You cannot perform that action on this entry.'},403
    connection.execute("UPDATE entries SET status=?,settled_at=CASE WHEN ?='settled' THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id=?",(status,status,eid))
    connection.execute('INSERT INTO audit(entry_id,actor,action) VALUES(?,?,?)',(eid,uid,action))
    connection.commit();return {'ok':True}

@app.get('/api/export')
@auth
def export():
    uid=session['uid'];gid=active_group(uid)
    rows=db().execute('SELECT e.*,c.name creditor_name,d.name debtor_name FROM entries e JOIN users c ON c.id=e.creditor JOIN users d ON d.id=e.debtor WHERE e.group_id=? AND e.deleted_at IS NULL ORDER BY e.id',(gid,)).fetchall() if gid else []
    audit=db().execute('SELECT a.* FROM audit a JOIN entries e ON a.entry_id=e.id WHERE e.group_id=? AND e.deleted_at IS NULL ORDER BY a.id',(gid,)).fetchall() if gid else []
    response=jsonify(entries=[dict(r) for r in rows],audit=[dict(r) for r in audit],currency='GBP')
    response.headers['Content-Disposition']='attachment; filename=owetogether-export.json'
    return response

@app.get('/api/admin/entries')
@auth
def admin_entries():
    email=os.environ.get('ADMIN_EMAIL','').strip().lower()
    current=db().execute('SELECT email FROM users WHERE id=?',(session['uid'],)).fetchone()
    if not email or not current or current['email'].lower()!=email:return {'error':'Administrator access required.'},403
    rows=db().execute('SELECT e.*,c.name creditor_name,d.name debtor_name,g.name group_name FROM entries e JOIN users c ON c.id=e.creditor JOIN users d ON d.id=e.debtor JOIN groups g ON g.id=e.group_id ORDER BY e.id DESC').fetchall()
    return jsonify([dict(r) for r in rows])

@app.post('/api/admin/entries/<int:eid>/delete')
@auth
def admin_delete_entry(eid):
    email=os.environ.get('ADMIN_EMAIL','').strip().lower()
    current=db().execute('SELECT email FROM users WHERE id=?',(session['uid'],)).fetchone()
    if not email or not current or current['email'].lower()!=email:return {'error':'Administrator access required.'},403
    conn=db();entry=conn.execute('SELECT id FROM entries WHERE id=? AND deleted_at IS NULL',(eid,)).fetchone()
    if not entry:return {'error':'Entry not found.'},404
    conn.execute('UPDATE entries SET deleted_at=CURRENT_TIMESTAMP,deleted_by=? WHERE id=?',(session['uid'],eid))
    conn.execute('INSERT INTO audit(entry_id,actor,action) VALUES(?,?,?)',(eid,session['uid'],'admin_soft_delete'));conn.commit()
    return {'ok':True}
