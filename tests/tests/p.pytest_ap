import unittest,tempfile,os,sys,threading,json,urllib.request,urllib.error,http.cookiejar
sys.path.insert(0,os.path.dirname(os.path.dirname(__file__)))
import app
class Client:
 def __init__(self,base): self.base=base; self.csrf='';self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 def req(self,path,method='GET',data=None,csrf=True,origin=None):
  headers={'Content-Type':'application/json'}
  if csrf:headers['X-CSRF-Token']=self.csrf
  if origin:headers['Origin']=origin
  request=urllib.request.Request(self.base+'/api'+path,data=json.dumps(data).encode() if data is not None else None,headers=headers,method=method)
  try:r=self.opener.open(request)
  except urllib.error.HTTPError as e:r=e
  result=json.load(r)
  if 'csrf' in result:self.csrf=result['csrf']
  return r.status,result
class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();app.DB=cls.tmp.name+'/db';app.init();cls.server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler);threading.Thread(target=cls.server.serve_forever,daemon=True).start();cls.base='http://127.0.0.1:'+str(cls.server.server_port)
 @classmethod
 def tearDownClass(cls):cls.server.shutdown();cls.tmp.cleanup()
 def setUp(self):
  self.a=Client(self.base);self.b=Client(self.base)
  for cli in (self.a,self.b): self.assertEqual(cli.req('/signup','POST',{'username':'test_'+app.secrets.token_hex(5),'password':'unique test password 123'})[0],200)
  self.r=self.a.req('/reviews','POST',{'title':'<script>sample</script>','source':'Source text'})[1]['id'];self.cl=self.a.req(f'/reviews/{self.r}/claims','POST',{'statement':'Check this','verdict':'Supported'})[1]['id']
 def test_01_anonymous(self):self.assertEqual(Client(self.base).req('/reviews')[0],401)
 def test_02_list_isolation(self):self.assertEqual(self.b.req('/reviews')[1],[])
 def test_03_detail_isolation(self):self.assertEqual(self.b.req(f'/reviews/{self.r}')[0],404)
 def test_04_default_unverified(self):self.assertEqual(self.a.req(f'/reviews/{self.r}')[1]['claims'][0]['verdict'],'Unverified')
 def test_05_edit_verdict(self):
  self.assertEqual(self.a.req(f'/claims/{self.cl}','PATCH',{'verdict':'Supported','note':'Human checked'})[0],200);d=self.a.req(f'/reviews/{self.r}')[1];self.assertEqual(d['counts']['Supported'],1);self.assertFalse(d['needs_followup'])
 def test_06_note_and_wording(self):
  self.a.req(f'/claims/{self.cl}','PATCH',{'statement':'Revised','note':'Note'});d=self.a.req(f'/reviews/{self.r}')[1]['claims'][0];self.assertEqual((d['statement'],d['note']),('Revised','Note'))
 def test_07_edit_review(self):
  self.a.req(f'/reviews/{self.r}','PATCH',{'title':'New','source':'New source'});self.assertEqual(self.a.req(f'/reviews/{self.r}')[1]['title'],'New')
 def test_08_evidence(self):
  self.assertEqual(self.a.req(f'/claims/{self.cl}/evidence','POST',{'excerpt':'quoted','url':'https://example.com'})[0],201);self.assertEqual(len(self.a.req(f'/reviews/{self.r}')[1]['claims'][0]['evidence']),1)
 def test_09_unsafe_url(self):self.assertEqual(self.a.req(f'/claims/{self.cl}/evidence','POST',{'excerpt':'x','url':'javascript:alert(1)'})[0],400)
 def test_10_cross_owner_claim_mutation(self):
  for method,data in [('PATCH',{'verdict':'Contradicted'}),('DELETE',None)]:self.assertEqual(self.b.req(f'/claims/{self.cl}',method,data)[0],404)
 def test_11_cross_owner_review_delete(self):self.assertEqual(self.b.req(f'/reviews/{self.r}','DELETE')[0],404)
 def test_12_cross_owner_evidence_add(self):self.assertEqual(self.b.req(f'/claims/{self.cl}/evidence','POST',{'excerpt':'x','url':'https://example.com'})[0],404)
 def test_13_cross_owner_evidence_delete(self):
  eid=self.a.req(f'/claims/{self.cl}/evidence','POST',{'excerpt':'x','url':'https://example.com'})[1]['id'];self.assertEqual(self.b.req(f'/evidence/{eid}','DELETE')[0],404)
 def test_14_cascade_claim(self):
  eid=self.a.req(f'/claims/{self.cl}/evidence','POST',{'excerpt':'x','url':'https://example.com'})[1]['id'];self.a.req(f'/claims/{self.cl}','DELETE');self.assertEqual(self.a.req(f'/reviews/{self.r}')[1]['claims'],[])
  with app.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM evidence WHERE id=?',(eid,)).fetchone()[0],0)
 def test_15_cascade_review(self):
  self.a.req(f'/claims/{self.cl}/evidence','POST',{'excerpt':'x','url':'https://example.com'});self.a.req(f'/reviews/{self.r}','DELETE')
  with app.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM claims WHERE id=?',(self.cl,)).fetchone()[0],0)
 def test_16_csrf(self):self.assertEqual(self.a.req('/demo','POST',{},csrf=False)[0],403)
 def test_17_origin(self):self.assertEqual(self.a.req('/demo','POST',{},origin='https://evil.invalid')[0],403)
 def test_18_demo(self):
  d=self.a.req('/demo','POST',{})[1];self.assertEqual(d['counts'],{'Unverified':1,'Supported':1,'Contradicted':1});self.assertTrue(d['is_demo']);self.assertTrue(d['needs_followup']);self.assertEqual(self.b.req(f'/reviews/{d["id"]}')[0],404)
 def test_19_logout(self):self.a.req('/logout','POST',{});self.assertEqual(self.a.req('/me')[0],401)
 def test_20_bad_verdict(self):self.assertEqual(self.a.req(f'/claims/{self.cl}','PATCH',{'verdict':'Approved by AI'})[0],400)
 def test_21_empty_claim(self):self.assertEqual(self.a.req(f'/reviews/{self.r}/claims','POST',{'statement':' '})[0],400)
 def test_22_password_hash(self):
  with app.connect() as c:
   u=c.execute('SELECT * FROM users LIMIT 1').fetchone();self.assertNotEqual(u['password_hash'],'unique test password 123');self.assertEqual(len(u['salt']),32)
 def test_23_persistence_new_connection(self):
  with app.connect() as c:self.assertEqual(c.execute('SELECT statement FROM claims WHERE id=?',(self.cl,)).fetchone()[0],'Check this')
 def test_24_removed_evidence(self):
  eid=self.a.req(f'/claims/{self.cl}/evidence','POST',{'excerpt':'x','url':'https://example.com'})[1]['id'];self.assertEqual(self.a.req(f'/evidence/{eid}','DELETE')[0],200);self.assertEqual(self.a.req(f'/reviews/{self.r}')[1]['claims'][0]['evidence'],[])
 def test_25_login(self):
  a=Client(self.base);name='login_'+app.secrets.token_hex(5);password=app.secrets.token_urlsafe(24)
  self.assertEqual(a.req('/signup','POST',{'username':name,'password':password})[0],200);a.req('/logout','POST',{})
  self.assertEqual(a.req('/login','POST',{'username':name,'password':password})[0],200);self.assertEqual(a.req('/me')[1]['username'],name)
 def test_26_bad_login(self):self.assertEqual(Client(self.base).req('/login','POST',{'username':'unknown_test','password':'not a real password'})[0],401)
 def test_27_session_expiry(self):
  with app.connect() as c:c.execute('UPDATE sessions SET expires=0 WHERE csrf=?',(self.a.csrf,))
  self.assertEqual(self.a.req('/me')[0],401)
 def test_28_cross_owner_review_update(self):self.assertEqual(self.b.req(f'/reviews/{self.r}','PATCH',{'title':'Hijack','source':'x'})[0],404)
 def test_29_cross_owner_claim_create(self):self.assertEqual(self.b.req(f'/reviews/{self.r}/claims','POST',{'statement':'Hijack'})[0],404)
 def test_30_review_cascade_evidence(self):
  eid=self.a.req(f'/claims/{self.cl}/evidence','POST',{'excerpt':'cascade test','url':'https://example.invalid'})[1]['id'];self.a.req(f'/reviews/{self.r}','DELETE')
  with app.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM evidence WHERE id=?',(eid,)).fetchone()[0],0)
if __name__=='__main__':unittest.main(verbosity=2)
