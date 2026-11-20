"""ClaimLedger: small evidence review desk. Python 3.10+, standard library only."""
import json, sqlite3, secrets, hashlib, hmac, os, time, re
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parent
DB = os.environ.get('CLAIMLEDGER_DB', str(ROOT/'claimledger.sqlite3'))
VERDICTS = ('Unverified','Supported','Contradicted')

def connect():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c

def init():
    with connect() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, password_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY, owner INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, source TEXT NOT NULL, is_demo INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS claims(id INTEGER PRIMARY KEY, review_id INTEGER NOT NULL REFERENCES reviews(id) ON DELETE CASCADE, statement TEXT NOT NULL, verdict TEXT NOT NULL DEFAULT 'Unverified' CHECK(verdict IN ('Unverified','Supported','Contradicted')), note TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, claim_id INTEGER NOT NULL REFERENCES claims(id) ON DELETE CASCADE, excerpt TEXT NOT NULL, url TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS reviews_owner ON reviews(owner);
        CREATE INDEX IF NOT EXISTS claims_review ON claims(review_id);
        CREATE INDEX IF NOT EXISTS evidence_claim ON evidence(claim_id);
        ''')

def pw_hash(password,salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384,r=8,p=1).hex()

def text(data,key,limit=100000,required=True):
    value=data.get(key,'')
    if not isinstance(value,str) or len(value)>limit or (required and not value.strip()): raise ValueError('Invalid '+key)
    return value.strip()

def owned_review(c,uid,rid):
    row=c.execute('SELECT * FROM reviews WHERE id=? AND owner=?',(rid,uid)).fetchone()
    if not row: raise LookupError('Review not found')
    return row

def owned_claim(c,uid,cid):
    row=c.execute('SELECT claims.* FROM claims JOIN reviews ON reviews.id=claims.review_id WHERE claims.id=? AND reviews.owner=?',(cid,uid)).fetchone()
    if not row: raise LookupError('Claim not found')
    return row

def detail(c,uid,rid):
    row=dict(owned_review(c,uid,rid)); rows=[]
    for cl in c.execute('SELECT * FROM claims WHERE review_id=? ORDER BY id',(rid,)):
        item=dict(cl);item['evidence']=[dict(e) for e in c.execute('SELECT * FROM evidence WHERE claim_id=? ORDER BY id',(cl['id'],))];rows.append(item)
    row['claims']=rows;row['counts']={v:sum(cl['verdict']==v for cl in rows) for v in VERDICTS};row['needs_followup']=any(cl['verdict']!='Supported' for cl in rows);return row

class Handler(BaseHTTPRequestHandler):
    server_version='ClaimLedger/0.1'
    def log_message(self,fmt,*args):
        # Never log credentials or request bodies.
        pass
    def send(self,status,obj,cookie=None):
        body=json.dumps(obj).encode();self.send_response(status)
        self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Cache-Control','no-store');self.security()
        if cookie: self.send_header('Set-Cookie',cookie)
        self.end_headers();self.wfile.write(body)
    def security(self):
        self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY');self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    def session(self,c):
        try:
            cookies=SimpleCookie();cookies.load(self.headers.get('Cookie',''));token=cookies['session'].value
        except (KeyError,ValueError): return None
        return c.execute('SELECT sessions.*,users.username FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>?',(token,int(time.time()))).fetchone()
    def do_GET(self): self.handle_request('GET')
    def do_POST(self): self.handle_request('POST')
    def do_PATCH(self): self.handle_request('PATCH')
    def do_DELETE(self): self.handle_request('DELETE')
    def handle_request(self,method):
        path=urlparse(self.path).path
        if not path.startswith('/api/'):
            if method!='GET': return self.send(405,{'error':'Method not allowed'})
            files={'/':'index.html','/style.css':'style.css','/app.js':'app.js'}
            if path not in files: return self.send(404,{'error':'Not found'})
            data=(ROOT/'static'/files[path]).read_bytes();self.send_response(200);self.security();self.send_header('Content-Type',{'/':'text/html; charset=utf-8','/style.css':'text/css; charset=utf-8','/app.js':'text/javascript; charset=utf-8'}[path]);self.end_headers();self.wfile.write(data);return
        try:
            data={}
            if method!='GET':
                # Reject cross-origin mutations, including login CSRF.
                origin=self.headers.get('Origin')
                if origin and urlparse(origin).netloc!=self.headers.get('Host'): return self.send(403,{'error':'Origin rejected'})
                size=int(self.headers.get('Content-Length',0))
                if size<0 or size>200000: return self.send(413,{'error':'Request too large'})
                if size:
                    if not self.headers.get('Content-Type','').startswith('application/json'): return self.send(415,{'error':'JSON required'})
                    data=json.loads(self.rfile.read(size))
                    if not isinstance(data,dict): raise ValueError('JSON object required')
            with connect() as c:
                now=int(time.time());s=self.session(c)
                if path in ('/api/signup','/api/login') and method=='POST':
                    username=text(data,'username',40);password=text(data,'password',256)
                    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,40}',username) or len(password)<12: raise ValueError('Use a 3-40 character username and password of 12+ characters')
                    if path=='/api/signup':
                        salt=secrets.token_hex(16)
                        try: uid=c.execute('INSERT INTO users(username,salt,password_hash) VALUES (?,?,?)',(username,salt,pw_hash(password,salt))).lastrowid
                        except sqlite3.IntegrityError: return self.send(409,{'error':'Username unavailable'})
                    else:
                        u=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
                        # Calculate a hash even on unknown account to reduce account timing leaks.
                        candidate=pw_hash(password,u['salt'] if u else '00'*16)
                        if not u or not hmac.compare_digest(candidate,u['password_hash']): return self.send(401,{'error':'Invalid credentials'})
                        uid=u['id']
                    token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(24);c.execute('DELETE FROM sessions WHERE expires<=?',(now,));c.execute('INSERT INTO sessions VALUES(?,?,?,?)',(token,uid,csrf,now+86400))
                    secure='; Secure' if os.environ.get('COOKIE_SECURE')=='1' else ''
                    c.commit();return self.send(200,{'username':username,'csrf':csrf},'session='+token+'; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400'+secure)
                if not s:return self.send(401,{'error':'Sign in required'})
                uid=s['user_id']
                if method!='GET' and not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),s['csrf']): return self.send(403,{'error':'CSRF token required'})
                if path=='/api/me' and method=='GET': return self.send(200,{'username':s['username'],'csrf':s['csrf']})
                if path=='/api/logout' and method=='POST':
                    c.execute('DELETE FROM sessions WHERE token=?',(s['token'],));c.commit();return self.send(200,{'ok':True},'session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
                if path=='/api/reviews' and method=='GET':
                    return self.send(200,[dict(r) for r in c.execute('SELECT id,title,is_demo,created FROM reviews WHERE owner=? ORDER BY id DESC',(uid,))])
                if path=='/api/reviews' and method=='POST':
                    rid=c.execute('INSERT INTO reviews(owner,title,source,created) VALUES(?,?,?,?)',(uid,text(data,'title',200),text(data,'source'),now)).lastrowid;c.commit();return self.send(201,detail(c,uid,rid))
                if path=='/api/demo' and method=='POST':
                    rid=c.execute('INSERT INTO reviews(owner,title,source,is_demo,created) VALUES(?,?,?,?,?)',(uid,'DEMO: fictional Northstar 2.0 release','Synthetic demonstration, not real product claims. Northstar 2.0 supports CSV imports. The demo specification caps uploads at 5 MB. No security audit is supplied.',1,now)).lastrowid
                    cases=[('Northstar 2.0 imports CSV files.','Supported','Matches the fictional demo specification.','Synthetic specification: CSV import is enabled.','https://example.invalid/synthetic-spec'),('Northstar 2.0 accepts 20 MB uploads.','Contradicted','Fictional specification says 5 MB, not 20 MB.','Synthetic specification: maximum upload 5 MB.','https://example.invalid/synthetic-limits'),('Northstar 2.0 passed an independent security audit.','Unverified','No audit evidence is included.','','')]
                    for statement,verdict,note,excerpt,url in cases:
                        cid=c.execute('INSERT INTO claims(review_id,statement,verdict,note) VALUES(?,?,?,?)',(rid,statement,verdict,note)).lastrowid
                        if excerpt:c.execute('INSERT INTO evidence(claim_id,excerpt,url) VALUES(?,?,?)',(cid,excerpt,url))
                    c.commit();return self.send(201,detail(c,uid,rid))
                m=re.fullmatch(r'/api/reviews/(\d+)',path)
                if m:
                    rid=int(m[1]);owned_review(c,uid,rid)
                    if method=='GET':return self.send(200,detail(c,uid,rid))
                    if method=='PATCH':c.execute('UPDATE reviews SET title=?,source=? WHERE id=? AND owner=?',(text(data,'title',200),text(data,'source'),rid,uid));c.commit();return self.send(200,detail(c,uid,rid))
                    if method=='DELETE':c.execute('DELETE FROM reviews WHERE id=? AND owner=?',(rid,uid));c.commit();return self.send(200,{'ok':True})
                m=re.fullmatch(r'/api/reviews/(\d+)/claims',path)
                if m and method=='POST':
                    rid=int(m[1]);owned_review(c,uid,rid)
                    # Client-supplied verdict is deliberately ignored on create.
                    cid=c.execute('INSERT INTO claims(review_id,statement) VALUES(?,?)',(rid,text(data,'statement',2000))).lastrowid;c.commit();return self.send(201,dict(c.execute('SELECT * FROM claims WHERE id=?',(cid,)).fetchone()))
                m=re.fullmatch(r'/api/claims/(\d+)',path)
                if m:
                    cid=int(m[1]);cl=owned_claim(c,uid,cid)
                    if method=='PATCH':
                        verdict=data.get('verdict',cl['verdict'])
                        if verdict not in VERDICTS:raise ValueError('Invalid verdict')
                        statement=text(data,'statement',2000) if 'statement' in data else cl['statement'];note=text(data,'note',10000,False) if 'note' in data else cl['note']
                        c.execute('UPDATE claims SET statement=?,verdict=?,note=? WHERE id=?',(statement,verdict,note,cid));c.commit();return self.send(200,{'ok':True})
                    if method=='DELETE':c.execute('DELETE FROM claims WHERE id=?',(cid,));c.commit();return self.send(200,{'ok':True})
                m=re.fullmatch(r'/api/claims/(\d+)/evidence',path)
                if m and method=='POST':
                    cid=int(m[1]);owned_claim(c,uid,cid);url=text(data,'url',2000);p=urlparse(url)
                    if p.scheme not in ('https','http') or not p.netloc or p.username or p.password:raise ValueError('Evidence URL must be HTTP(S) without credentials')
                    eid=c.execute('INSERT INTO evidence(claim_id,excerpt,url) VALUES(?,?,?)',(cid,text(data,'excerpt',20000),url)).lastrowid;c.commit();return self.send(201,{'id':eid})
                m=re.fullmatch(r'/api/evidence/(\d+)',path)
                if m and method=='DELETE':
                    eid=int(m[1]);e=c.execute('SELECT claim_id FROM evidence WHERE id=?',(eid,)).fetchone()
                    if not e:raise LookupError('Evidence not found')
                    owned_claim(c,uid,e['claim_id']);c.execute('DELETE FROM evidence WHERE id=?',(eid,));c.commit();return self.send(200,{'ok':True})
                return self.send(404,{'error':'Not found'})
        except (ValueError,json.JSONDecodeError) as exc:return self.send(400,{'error':str(exc)})
        except LookupError as exc:return self.send(404,{'error':str(exc)})
        except Exception:
            return self.send(500,{'error':'Server error'})

if __name__=='__main__':
    init();ThreadingHTTPServer((os.environ.get('HOST','127.0.0.1'),int(os.environ.get('PORT','8080'))),Handler).serve_forever()
