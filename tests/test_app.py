import os, tempfile, unittest
os.environ['SECRET_KEY']='test-only-secret-not-for-production-123456789'
os.environ['APP_URL']='https://owe.example.com'
_tmp=tempfile.TemporaryDirectory()
os.environ['DATABASE_PATH']=_tmp.name+'/test.sqlite3'
from app import app, db

class AccessTests(unittest.TestCase):
    def setUp(self):
        app.config['TESTING']=True
        self.client=app.test_client()
        with app.app_context():
            db().executescript('DELETE FROM audit;DELETE FROM entries;DELETE FROM group_members;DELETE FROM groups;DELETE FROM contacts;DELETE FROM users;')
            for i in range(1,4):
                db().execute('INSERT INTO users(id,sub,name,email,code) VALUES(?,?,?,?,?)',(i,str(i),'User '+str(i),str(i)+'@example.com','code'+str(i)))
            db().execute('INSERT INTO contacts(a,b) VALUES(1,2)')
            gid=db().execute("INSERT INTO groups(name,creator,code) VALUES('Pair',1,'groupcode')").lastrowid
            db().executemany('INSERT INTO group_members(group_id,user_id) VALUES(?,?)',[(gid,1),(gid,2)]);db().commit()
    def user(self,uid):
        with self.client.session_transaction(base_url='https://owe.example.com') as s:
            with app.app_context():
                group_id=db().execute('SELECT id FROM groups WHERE code=?',('groupcode',)).fetchone()['id']
            s['uid']=uid;s['csrf']='test-csrf';s['group_id']=group_id
    def get(self,path):return self.client.get(path,base_url='https://owe.example.com')
    def post(self,path,data=None,csrf=True):
        return self.client.post(path,json=data,base_url='https://owe.example.com',headers={'Origin':'https://owe.example.com',**({'X-CSRF-Token':'test-csrf'} if csrf else {})})
    def create(self):
        return self.post('/api/entries',{'person':2,'amount':1234,'description':'Dinner','date':'2026-10-30','direction':'owed'})
    def test_anonymous_denied(self):self.assertEqual(self.get('/api/entries').status_code,401)
    def test_csrf_denied(self):
        self.user(1);self.assertEqual(self.post('/api/logout',csrf=False).status_code,403)
    def test_origin_denied(self):
        self.user(1)
        self.assertEqual(self.client.post('/api/logout',base_url='https://owe.example.com',headers={'Origin':'https://evil.example','X-CSRF-Token':'test-csrf'}).status_code,403)
    def test_confirmation_and_settlement(self):
        self.user(1);self.assertEqual(self.create().status_code,201)
        eid=self.get('/api/entries').json[0]['id']
        self.assertEqual(self.post(f'/api/entries/{eid}/accept').status_code,403)
        self.assertEqual(self.post(f'/api/entries/{eid}/settle').status_code,403)
        self.user(2);self.assertEqual(self.post(f'/api/entries/{eid}/accept').status_code,200)
        self.assertEqual(self.post(f'/api/entries/{eid}/settle').status_code,403)
        self.user(1);self.assertEqual(self.post(f'/api/entries/{eid}/settle').status_code,200)
        self.assertEqual(self.get('/api/entries').json[0]['status'],'settled')
    def test_other_user_cannot_see_or_change(self):
        self.user(1);self.create();eid=self.get('/api/entries').json[0]['id']
        self.user(3);self.assertEqual(self.get('/api/entries').json,[])
        self.assertEqual(self.post(f'/api/entries/{eid}/accept').status_code,404)
        self.assertEqual(self.get('/api/export').json['entries'],[])
    def test_unconnected_user_denied(self):
        self.user(3);self.assertEqual(self.create().status_code,403)
    def test_invalid_amount(self):
        self.user(1)
        for value in [-1,0,1.5,True,100000001]:
            r=self.post('/api/entries',{'person':2,'amount':value,'description':'Dinner','date':'2026-10-30','direction':'owed'})
            self.assertEqual(r.status_code,400)
    def test_contacts_private(self):
        self.user(1);self.assertEqual([p['id'] for p in self.get('/api/people').json],[2])
    def test_connect_by_code(self):
        self.user(3);self.assertEqual(self.post('/api/people',{'code':'groupcode'}).status_code,200)
        self.assertEqual([p['id'] for p in self.get('/api/people').json],[1,2])
    def test_no_api_caching(self):
        self.user(1);self.assertEqual(self.get('/api/me').headers['Cache-Control'],'no-store')

if __name__=='__main__':unittest.main()
