import os,tempfile,json,secrets,base64,pathlib
ROOT=pathlib.Path(tempfile.mkdtemp(prefix='mailbridge-tests-'))
(ROOT/'config.json').write_text(json.dumps({'base_url':'https://mailbridge.test'}))
(ROOT/'master.key').write_bytes(base64.urlsafe_b64encode(secrets.token_bytes(32)))
os.environ.update(MAILBRIDGE_STATE=str(ROOT),MAILBRIDGE_CONFIG=str(ROOT/'config.json'),CREDENTIALS_DIRECTORY=str(ROOT))
import pytest,pyotp
from core import *
import web
from main import application

@pytest.fixture(autouse=True)
def database():
 with app.app_context():
  db.session.remove(); db.drop_all(); db.create_all()
  db.session.add(Owner(id=1,password_hash=PASSWORDS.hash('test-password-long-enough'),totp=encrypt('JBSWY3DPEHPK3PXP'),last_step=-1,epoch=0))
  db.session.commit()
 yield
 with app.app_context(): db.session.remove()

@pytest.fixture
def client(): return app.test_client()

def login_session(client):
 raw=secrets.token_urlsafe(32)
 with app.app_context():
  db.session.add(WebSession(id=digest(raw),expires=now()+1200,epoch=0)); db.session.commit()
 with client.session_transaction(base_url=BASE) as s:
  s['sid']=raw;s['csrf']='test-csrf'
 return {'Origin':BASE}

def oauth_flow(client,scope='mail:read mail:write mail:send organizer:read organizer:write'):
 import hashlib
 client.post('/oauth/register',base_url=BASE,json={'redirect_uris':['https://chatgpt.com/connector_platform_oauth_redirect']})
 with app.app_context(): cid=Client.query.first().client_id
 verifier=secrets.token_urlsafe(48)
 challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
 params={'client_id':cid,'response_type':'code','redirect_uri':'https://chatgpt.com/connector_platform_oauth_redirect',
  'scope':scope,'resource':RESOURCE,'state':'state-value','code_challenge':challenge,'code_challenge_method':'S256'}
 return cid,verifier,params

def tokens(client,scope='mail:read mail:write mail:send organizer:read organizer:write'):
 from urllib.parse import urlparse,parse_qs
 cid,verifier,params=oauth_flow(client,scope)
 headers=login_session(client)
 response=client.post('/oauth/authorize',base_url=BASE,query_string=params,headers=headers,data={'csrf':'test-csrf','decision':'allow'})
 assert response.status_code==302,response.get_data(as_text=True)
 values=parse_qs(urlparse(response.location).query)
 assert values['state']==['state-value'];assert values['iss']==[BASE]
 result=client.post('/oauth/token',base_url=BASE,data={'client_id':cid,'grant_type':'authorization_code',
  'code':values['code'][0],'redirect_uri':params['redirect_uri'],'code_verifier':verifier,'resource':RESOURCE})
 assert result.status_code==200,result.json
 return cid,result.json

@pytest.fixture(scope='session')
def remote_client():
 from starlette.testclient import TestClient
 with TestClient(application,base_url=BASE) as remote: yield remote
