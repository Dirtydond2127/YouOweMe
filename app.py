import os, sqlite3, secrets, hmac, json
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
    db().executescript("""
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, sub TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
        email TEXT NOT NULL, code TEXT UNIQUE NOT NULL);
    CREATE TABLE IF NOT EXISTS contacts (
        a INTEGER REFERENCES users(id), b INTEGER REFERENCES users(id),
        PRIMARY KEY(a,b), CHECK(a<b));
    CREATE TABLE IF NOT EXISTS entries (
        id INTEGER PRIMARY KEY, creator INTEGER NOT NULL REFERENCES users(id),
        creditor INTEGER NOT NULL REFERENCES users(id), debtor INTEGER NOT NULL REFERENCES users(id),
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
    return {'user':user,'csrf':session['csrf']}

@app.get('/api/people')
@auth
def people():
    uid=session['uid']
    rows=db().execute('SELECT id,name FROM users WHERE id IN (SELECT CASE WHEN a=? THEN b ELSE a END FROM contacts WHERE a=? OR b=?) ORDER BY name',(uid,uid,uid)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.post('/api/people')
@auth
def add_person():
    data=request.get_json(silent=True) or {}
    code=data.get('code','')
    if not isinstance(code,str) or len(code)>100: return {'error':'Invalid connection code.'},400
    person=db().execute('SELECT id FROM users WHERE code=?',(code.strip(),)).fetchone()
    if not person or person['id']==session['uid']: return {'error':'Connection code not found.'},400
    a,b=sorted([session['uid'],person['id']])
    db().execute('INSERT OR IGNORE INTO contacts(a,b) VALUES(?,?)',(a,b));db().commit()
    return {'ok':True}

@app.post('/api/code/rotate')
@auth
def rotate_code():
    db().execute('UPDATE users SET code=? WHERE id=?',(secrets.token_urlsafe(18),session['uid']));db().commit()
    return {'ok':True}

@app.get('/api/entries')
@auth
def entries():
    uid=session['uid']
    rows=db().execute('SELECT e.*,c.name creditor_name,d.name debtor_name FROM entries e JOIN users c ON c.id=e.creditor JOIN users d ON d.id=e.debtor WHERE e.creditor=? OR e.debtor=? ORDER BY e.date DESC,e.id DESC',(uid,uid)).fetchall()
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
    a,b=sorted([uid,person])
    if not db().execute('SELECT 1 FROM contacts WHERE a=? AND b=?',(a,b)).fetchone():
        return {'error':'Choose one of your connected people.'},403
    creditor,debtor=(uid,person) if direction=='owed' else (person,uid)
    cursor=db().execute('INSERT INTO entries(creator,creditor,debtor,amount,description,date) VALUES(?,?,?,?,?,?)',(uid,creditor,debtor,amount,description.strip(),entry_date))
    db().execute('INSERT INTO audit(entry_id,actor,action) VALUES(?,?,?)',(cursor.lastrowid,uid,'created'))
    db().commit();return {'ok':True},201

@app.post('/api/entries/<int:eid>/<action>')
@auth
def action_entry(eid,action):
    uid=session['uid'];connection=db()
    # Serialise read/check/write to prevent competing state changes.
    connection.execute('BEGIN IMMEDIATE')
    entry=connection.execute('SELECT * FROM entries WHERE id=? AND (creditor=? OR debtor=?)',(eid,uid,uid)).fetchone()
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
    uid=session['uid']
    rows=db().execute('SELECT e.*,c.name creditor_name,d.name debtor_name FROM entries e JOIN users c ON c.id=e.creditor JOIN users d ON d.id=e.debtor WHERE creditor=? OR debtor=? ORDER BY e.id',(uid,uid)).fetchall()
    audit=db().execute('SELECT a.* FROM audit a JOIN entries e ON a.entry_id=e.id WHERE e.creditor=? OR e.debtor=? ORDER BY a.id',(uid,uid)).fetchall()
    response=jsonify(entries=[dict(r) for r in rows],audit=[dict(r) for r in audit],currency='GBP')
    response.headers['Content-Disposition']='attachment; filename=owetogether-export.json'
    return response
