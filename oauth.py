"""OAuth authorization-code + S256 PKCE via Authlib, with resource binding."""
from urllib.parse import urlsplit,parse_qsl,urlencode,urlunsplit
import re
from flask import request,jsonify,session,redirect
from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6749.errors import InvalidRequestError,InvalidGrantError
from authlib.oauth2.rfc7636 import CodeChallenge
from core import *

def query_client(client_id): return Client.query.filter_by(client_id=client_id).first()

def save_token(data,req):
 old=getattr(req,'refresh_token',None)
 row=Token(client_id=req.client.client_id,user_id=req.user.id,
  resource=RESOURCE,family=old.family if old else secrets.token_urlsafe(24),
  refresh_expires=old.refresh_expires if old else now()+30*86400,
  epoch=req.user.epoch,access_token=digest(data['access_token']),
  refresh_token=digest(data['refresh_token']),token_type=data['token_type'],
  scope=data.get('scope',''),expires_in=data['expires_in'],issued_at=now())
 db.session.add(row); db.session.commit()

class AuthorizationCode(grants.AuthorizationCodeGrant):
 TOKEN_ENDPOINT_AUTH_METHODS=['none']
 def save_authorization_code(self,code,req):
  p=req.payload.data
  row=Code(code=digest(code),client_id=req.client.client_id,user_id=req.user.id,
   redirect_uri=req.redirect_uri,scope=req.payload.scope,resource=RESOURCE,
   code_challenge=p['code_challenge'],code_challenge_method='S256')
  db.session.add(row); db.session.commit(); return row
 def query_authorization_code(self,code,client):
  row=Code.query.filter_by(code=digest(code),client_id=client.client_id).first()
  if row and not row.is_expired() and row.resource==RESOURCE: return row
 def delete_authorization_code(self,code):
  db.session.delete(code); db.session.commit()
 def authenticate_user(self,code): return db.session.get(Owner,code.user_id)

class Refresh(grants.RefreshTokenGrant):
 TOKEN_ENDPOINT_AUTH_METHODS=['none']
 INCLUDE_NEW_REFRESH_TOKEN=True
 def authenticate_refresh_token(self,raw):
  row=Token.query.filter_by(refresh_token=digest(raw)).first()
  if not row or not row.check_client(self.request.client): return None
  owner=db.session.get(Owner,row.user_id)
  if row.refresh_token_revoked_at:
   Token.query.filter_by(family=row.family).update({'access_token_revoked_at':now(),'refresh_token_revoked_at':now()})
   Action.query.filter_by(family=row.family,state='pending').update({'state':'cancelled'})
   db.session.commit(); audit('refresh_replay_blocked'); return None
  if row.refresh_expires<=now() or not owner or row.epoch!=owner.epoch or row.resource!=RESOURCE: return None
  return row
 def authenticate_user(self,credential): return db.session.get(Owner,credential.user_id)
 def revoke_old_credential(self,row):
  row.access_token_revoked_at=now(); row.refresh_token_revoked_at=now(); db.session.commit()

class S256(CodeChallenge):
 SUPPORTED_CODE_CHALLENGE_METHOD=['S256']
server=AuthorizationServer(app,query_client=query_client,save_token=save_token)
server.register_grant(AuthorizationCode,[S256(required=True)])
server.register_grant(Refresh)

def callback_allowed(uri):
 return uri=='https://chatgpt.com/connector_platform_oauth_redirect' or bool(re.fullmatch(r'https://chatgpt\.com/connector/oauth/[A-Za-z0-9_-]{1,160}',uri))

@app.get('/.well-known/oauth-authorization-server')
def metadata():
 return jsonify(issuer=BASE,authorization_endpoint=BASE+'/oauth/authorize',
  token_endpoint=BASE+'/oauth/token',registration_endpoint=BASE+'/oauth/register',
  revocation_endpoint=BASE+'/oauth/revoke',response_types_supported=['code'],
  grant_types_supported=['authorization_code','refresh_token'],
  token_endpoint_auth_methods_supported=['none'],
  code_challenge_methods_supported=['S256'],scopes_supported=SCOPES,
  authorization_response_iss_parameter_supported=True)

@app.get('/.well-known/oauth-protected-resource')
@app.get('/.well-known/oauth-protected-resource/mcp')
def protected_metadata():
 return jsonify(resource=RESOURCE,authorization_servers=[BASE],scopes_supported=SCOPES,
  bearer_methods_supported=['header'],resource_documentation=BASE+'/privacy')

@app.post('/oauth/register')
def register():
 if not db.session.get(Owner,1): return jsonify(error='temporarily_unavailable'),503
 if not rate_limit('registration',request.remote_addr or '',10,86400) or Client.query.count()>=100:
  return jsonify(error='rate_limited'),429
 data=request.get_json(silent=True) or {}
 uris=data.get('redirect_uris')
 if not isinstance(uris,list) or not 1<=len(uris)<=3 or not all(isinstance(x,str) and callback_allowed(x) for x in uris):
  return jsonify(error='invalid_redirect_uri'),400
 if data.get('token_endpoint_auth_method','none')!='none': return jsonify(error='invalid_client_metadata'),400
 if not set(data.get('grant_types',['authorization_code','refresh_token']))<= {'authorization_code','refresh_token'}:
  return jsonify(error='invalid_client_metadata'),400
 cid=secrets.token_urlsafe(24)
 client=Client(client_id=cid,client_id_issued_at=now(),client_secret='')
 meta={'client_name':'ChatGPT','redirect_uris':uris,'grant_types':['authorization_code','refresh_token'],
  'response_types':['code'],'token_endpoint_auth_method':'none','scope':' '.join(SCOPES)}
 client.set_client_metadata(meta); db.session.add(client); db.session.commit()
 return jsonify(client_id=cid,client_id_issued_at=client.client_id_issued_at,**meta),201

@app.post('/oauth/token')
def token():
 if not rate_limit('token',request.remote_addr or '',60,60): return jsonify(error='rate_limited'),429
 if request.form.getlist('resource')!=[RESOURCE]: return jsonify(error='invalid_target'),400
 with LOCK:
  response=server.create_token_response()
  response.headers['Cache-Control']='no-store'
  return response

@app.post('/oauth/revoke')
def revoke():
 if not rate_limit('revoke',request.remote_addr or '',30,60): return '',429
 with LOCK:
  client=query_client(request.form.get('client_id',''))
  if client:
   hashed=digest(request.form.get('token',''))
   row=Token.query.filter((Token.access_token==hashed)|(Token.refresh_token==hashed)).first()
   if row and row.client_id==client.client_id:
    Token.query.filter_by(family=row.family).update({'access_token_revoked_at':now(),'refresh_token_revoked_at':now()})
    Action.query.filter_by(family=row.family,state='pending').update({'state':'cancelled'})
    db.session.commit(); audit('connection_revoked')
 return '',200

def issuer_response(response):
 if response.status_code in (302,303) and response.headers.get('Location'):
  url=urlsplit(response.headers['Location'])
  query=parse_qsl(url.query,keep_blank_values=True)+[('iss',BASE)]
  response.headers['Location']=urlunsplit((url.scheme,url.netloc,url.path,urlencode(query),url.fragment))
 return response
