"""Owner-only control panel. MCP tokens cannot authorize browser actions."""
from flask import request,session,redirect,render_template,abort,jsonify
from urllib.parse import urlencode
from authlib.oauth2.rfc6749.errors import OAuth2Error
from core import *
from access_policy import parse_networks
from ipaddress import ip_address
import oauth,mail

REMEMBER_NETWORKS = parse_networks(CONFIG.get('remember_session_networks', []))

def trusted_session_peer():
 try:
  peer = ip_address(request.remote_addr)
 except (TypeError, ValueError):
  return None
 return str(peer) if any(peer in network for network in REMEMBER_NETWORKS) else None

def csrf(): return session.setdefault('csrf',secrets.token_urlsafe(32))
def current_owner():
 if session.permanent and (not session.get('peer') or trusted_session_peer() != session['peer']):
  return None
 raw=session.get('sid','')
 row=db.session.get(WebSession,digest(raw)) if raw else None
 owner=db.session.get(Owner,1)
 if not row or not owner or row.expires<=now() or row.epoch!=owner.epoch: return None
 return owner

def require_owner():
 owner=current_owner()
 if not owner: abort(401)
 return owner

@app.before_request
def guard():
 if request.path.startswith('/oauth/') or request.path.startswith('/.well-known/'):
  return
 if request.method=='POST':
  if request.headers.get('Origin')!=BASE: abort(403)
  sent=request.form.get('csrf','')
  if not sent or not hmac.compare_digest(sent,session.get('csrf','')): abort(403)

@app.after_request
def headers(response):
 response.headers['Cache-Control']='no-store'
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['Referrer-Policy']='same-origin'
 response.headers['X-Frame-Options']='DENY'
 response.headers['Content-Security-Policy']="default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
 response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
 return response

@app.errorhandler(401)
def need_login(error):
 return redirect('/login?'+urlencode({'next':request.full_path}))
@app.errorhandler(403)
@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(429)
@app.errorhandler(413)
def safe_error(error):
 return render_template('page.html',title='Request unavailable',mode='error',message='The request was rejected. Reload the page or sign in again.',csrf=csrf()),error.code
@app.errorhandler(500)
def failed(error):
 db.session.rollback()
 return render_template('page.html',title='Operation unavailable',mode='error',message='The operation could not be completed. Check its status before trying again.',csrf=csrf()),500

@app.get('/healthz')
def health(): return jsonify(status='ok')
@app.get('/privacy')
def privacy():
 return render_template('page.html',title='Privacy and security',mode='privacy',csrf=csrf())
@app.get('/style.css')
def style():
 return app.response_class('''
:root{font-family:system-ui,sans-serif;color:#172b3b;background:#f4f7f8;line-height:1.6}
body{margin:0}main{max-width:820px;margin:48px auto;padding:28px;background:white;border:1px solid #d6e0e5;border-radius:12px}
h1{font-size:1.8rem;line-height:1.2}h2{font-size:1.25rem}nav{display:flex;gap:20px;flex-wrap:wrap;border-bottom:1px solid #d6e0e5;padding-bottom:16px}
a{color:#075a78}label{display:block;margin:16px 0 5px;font-weight:600}input,textarea{box-sizing:border-box;width:100%;padding:12px;border:1px solid #8b9da8;border-radius:5px;font:inherit}input[type=checkbox]{width:auto}
button{margin:16px 8px 0 0;padding:12px 20px;background:#075a78;color:white;border:0;border-radius:5px;font:inherit;cursor:pointer}
button.danger{background:#9c3030}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:16px;background:#f4f7f8;border:1px solid #d6e0e5}
.notice{padding:14px;background:#eef5f9;border-left:4px solid #075a78}.error{color:#9c3030}li{margin:10px 0}small{color:#425b6b}
:focus-visible{outline:3px solid #d97900;outline-offset:3px}@media(max-width:600px){main{margin:12px;padding:18px}}
''',mimetype='text/css')

@app.route('/login',methods=['GET','POST'])
def login():
 if not db.session.get(Owner,1):
  return render_template('page.html',title='Owner setup required',mode='error',message='Run sudo /opt/mailbridge/bin/mailbridge setup-owner over SSH. Public registration is disabled.',csrf=csrf()),503
 message=''
 next_path=request.args.get('next','/')
 if not next_path.startswith('/') or next_path.startswith('//') or '\\' in next_path or any(ord(c)<32 for c in next_path): next_path='/'
 if request.method=='POST':
  if not rate_limit('login-ip',request.remote_addr or '',5,900) or not rate_limit('login-global','owner',30,900):
   abort(429)
  if verify_owner(request.form.get('password',''),request.form.get('otp','')):
   raw=secrets.token_urlsafe(32); owner=db.session.get(Owner,1)
   peer = trusted_session_peer() if request.form.get('remember') == 'yes' else None
   lifetime = int(app.permanent_session_lifetime.total_seconds()) if peer else 1200
   db.session.add(WebSession(id=digest(raw),expires=now()+lifetime,epoch=owner.epoch))
   db.session.commit(); session.clear(); session['sid']=raw; csrf()
   if peer:
    session.permanent = True
    session['peer'] = peer
   audit('owner_login'); return redirect(next_path)
  audit('login_failed'); message='Sign-in failed. Check your password and use a fresh authenticator code.'
 return render_template('page.html',title='Sign in',mode='login',message=message,csrf=csrf(),can_remember=bool(trusted_session_peer()),signed_in=bool(current_owner()))

@app.post('/logout')
def logout():
 raw=session.get('sid','')
 WebSession.query.filter_by(id=digest(raw)).delete(); db.session.commit(); session.clear()
 return redirect('/login')

@app.get('/')
def dashboard():
 require_owner()
 actions=Action.query.order_by(Action.created.desc()).limit(30).all()
 audits=Audit.query.order_by(Audit.created.desc()).limit(20).all()
 return render_template('page.html',title='Your private mail connection',mode='dashboard',
  configured=bool(setting('icloud')),actions=actions,audits=audits,resource=RESOURCE,csrf=csrf())

@app.route('/oauth/authorize',methods=['GET','POST'])
def authorize():
 if request.args.getlist('resource')!=[RESOURCE]: return jsonify(error='invalid_target'),400
 if request.args.get('code_challenge_method')!='S256' or not request.args.get('code_challenge'):
  return jsonify(error='invalid_request',error_description='S256 PKCE is required.'),400
 if len(request.args.get('state',''))>1024: abort(400)
 owner=current_owner()
 if not owner: return redirect('/login?'+urlencode({'next':request.full_path}))
 try:
  grant=oauth.server.get_consent_grant(end_user=owner)
 except OAuth2Error:
  return jsonify(error='invalid_request'),400
 requested=request.args.get('scope','').split()
 if not requested or not set(requested)<=set(SCOPES): return jsonify(error='invalid_scope'),400
 if request.method=='POST':
  if request.headers.get('Origin')!=BASE or not hmac.compare_digest(request.form.get('csrf',''),session.get('csrf','')) or not session.get('csrf'): abort(403)
  with LOCK:
   response=oauth.server.create_authorization_response(grant_user=owner if request.form.get('decision')=='allow' else None)
   audit('oauth_consent')
   return oauth.issuer_response(response)
 return render_template('page.html',title='Connect ChatGPT',mode='consent',scopes=requested,csrf=csrf())

@app.route('/account',methods=['GET','POST'])
def account():
 owner=require_owner(); message=''
 if request.method=='POST':
  if not rate_limit('account','owner',5,900): abort(429)
  with LOCK:
   if not consume_totp(owner,request.form.get('otp','')): message='Use a fresh authenticator code.'
   elif request.form.get('decision')=='disconnect':
    row=db.session.get(Setting,'icloud')
    if row: db.session.delete(row); db.session.commit()
    revoke_all(); session.clear(); return redirect('/login')
   else:
    try:
     address=mail.address(request.form.get('email',''))
     password=request.form.get('app_password','').strip()
     if not __import__('re').fullmatch(r'[a-z]{4}(?:-[a-z]{4}){3}',password): raise mail.MailError('Use the Apple app-specific password format xxxx-xxxx-xxxx-xxxx.')
     config={'email':address,'password':password,'imap_username':request.form.get('imap_username','').strip() or address}
     mail.header(config['imap_username'],254)
     mail.verify_connection(config)
     set_setting('icloud',config); revoke_all(); session.clear()
     audit('mailbox_connected'); return redirect('/login')
    except Exception:
     message='Connection failed. Check the email address, app-specific password and optional IMAP username. No credential details were logged.'
 return render_template('page.html',title='iCloud account',mode='account',configured=bool(setting('icloud')),message=message,csrf=csrf())

@app.post('/revoke-all')
def revoke_everything():
 require_owner()
 with LOCK: revoke_all()
 session.clear(); return redirect('/login')

@app.route('/actions/<action_id>',methods=['GET','POST'])
def action_detail(action_id):
 owner=require_owner(); row=db.session.get(Action,action_id)
 if not row: abort(404)
 message=''
 if request.method=='POST':
  # Action pages are status-only. No browser endpoint can execute mail actions.
  return render_action(row,'Mailbox actions are reviewed and executed in ChatGPT. For a legacy proposal, request a new review there.'),409
 return render_action(row,message)

def render_action(row,message):
 payload=decrypt(row.content)
 if payload.get('purged'):
  preview={'note':'Proposal content was purged after the retention period.'}
 elif row.kind in ('send','chat_send'):
  preview={k:payload[k] for k in ['to','cc','bcc','subject','body']}
 elif row.kind=='chat_mail_change':
  preview={**payload['snapshot']['preview'],'operation':payload['operation'],'destination':payload['snapshot']['destination']}
 else: preview={k:payload[k] for k in ['operation','folder','preview']}
 state='expired' if row.state=='pending' and row.expires<=now() else row.state
 return render_template('page.html',title='Review mail action',mode='action',action=row,
  preview=json.dumps(preview,ensure_ascii=False,indent=2),state=state,message=message,
  result=json.dumps(decrypt(row.result),indent=2) if row.result else '',csrf=csrf())
