"""Persistence and cryptographic boundaries."""
import os, json, time, secrets, hashlib, hmac, threading
from pathlib import Path
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
import pyotp
from authlib.integrations.sqla_oauth2 import OAuth2ClientMixin, OAuth2AuthorizationCodeMixin, OAuth2TokenMixin
STATE = Path(os.environ.get('MAILBRIDGE_STATE', '/var/lib/mailbridge'))
CONFIG = json.loads(Path(os.environ.get('MAILBRIDGE_CONFIG', '/etc/mailbridge/config.json')).read_text())
BASE = CONFIG['base_url'].rstrip('/')
RESOURCE = BASE + '/mcp'
SCOPES = ['mail:read','mail:write','mail:send','organizer:read','organizer:write']
KEY = (Path(os.environ.get('CREDENTIALS_DIRECTORY','/etc/mailbridge'))/'master.key').read_bytes().strip()
CIPHER = Fernet(KEY)
PASSWORDS = PasswordHasher(time_cost=3,memory_cost=65536,parallelism=1)
LOCK = threading.RLock()
app = Flask(__name__)
app.config.update(SECRET_KEY=hmac.new(KEY,b'web-session',hashlib.sha256).digest(),
 SQLALCHEMY_DATABASE_URI='sqlite:///'+str(STATE/'mailbridge.db'),
 SQLALCHEMY_ENGINE_OPTIONS={'connect_args':{'timeout':20}},
 PERMANENT_SESSION_LIFETIME=30*24*60*60, SESSION_REFRESH_EACH_REQUEST=False,
 SESSION_COOKIE_NAME='__Host-mailbridge',SESSION_COOKIE_SECURE=True,
 SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',
 MAX_CONTENT_LENGTH=131072,TRUSTED_HOSTS=[BASE.split('/')[2]],
 OAUTH2_ACCESS_TOKEN_GENERATOR=lambda *a,**k: secrets.token_urlsafe(48),
 OAUTH2_REFRESH_TOKEN_GENERATOR=lambda *a,**k: secrets.token_urlsafe(48),
 OAUTH2_TOKEN_EXPIRES_IN={'authorization_code':600,'refresh_token':600},
 OAUTH2_SCOPES_SUPPORTED=SCOPES)
db = SQLAlchemy(app)
def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def encrypt(value): return CIPHER.encrypt(json.dumps(value,ensure_ascii=False).encode()).decode()
def decrypt(value): return json.loads(CIPHER.decrypt(value.encode()))
def now(): return int(time.time())
class Setting(db.Model):
 key=db.Column(db.String,primary_key=True)
 value=db.Column(db.Text,nullable=False)
class Owner(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 password_hash=db.Column(db.Text,nullable=False)
 totp=db.Column(db.Text,nullable=False)
 last_step=db.Column(db.Integer,default=-1)
 epoch=db.Column(db.Integer,default=0)
class WebSession(db.Model):
 id=db.Column(db.String,primary_key=True)
 expires=db.Column(db.Integer,nullable=False)
 epoch=db.Column(db.Integer,nullable=False)
class Client(db.Model,OAuth2ClientMixin):
 id=db.Column(db.Integer,primary_key=True)
class Code(db.Model,OAuth2AuthorizationCodeMixin):
 id=db.Column(db.Integer,primary_key=True)
 user_id=db.Column(db.Integer,nullable=False)
 resource=db.Column(db.Text,nullable=False)
class Token(db.Model,OAuth2TokenMixin):
 id=db.Column(db.Integer,primary_key=True)
 user_id=db.Column(db.Integer,nullable=False)
 resource=db.Column(db.Text,nullable=False)
 family=db.Column(db.String,nullable=False)
 refresh_expires=db.Column(db.Integer,nullable=False)
 epoch=db.Column(db.Integer,nullable=False)
class Record(db.Model):
 id=db.Column(db.String,primary_key=True)
 kind=db.Column(db.String,nullable=False,index=True)
 content=db.Column(db.Text,nullable=False)
 status=db.Column(db.String,nullable=False,default='open')
 created=db.Column(db.Integer,nullable=False,default=now)
 updated=db.Column(db.Integer,nullable=False,default=now)
class Action(db.Model):
 id=db.Column(db.String,primary_key=True)
 kind=db.Column(db.String,nullable=False)
 content=db.Column(db.Text,nullable=False)
 client_id=db.Column(db.String,nullable=False)
 family=db.Column(db.String,nullable=False)
 state=db.Column(db.String,nullable=False,default='pending')
 created=db.Column(db.Integer,nullable=False,default=now)
 expires=db.Column(db.Integer,nullable=False)
 result=db.Column(db.Text)
class Audit(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 event=db.Column(db.String,nullable=False)
 reference=db.Column(db.String,nullable=False,default='')
 created=db.Column(db.Integer,nullable=False,default=now)
class Rate(db.Model):
 key=db.Column(db.String,primary_key=True)
 window=db.Column(db.Integer,nullable=False)
 count=db.Column(db.Integer,nullable=False)
def setting(key,default=None):
 row=db.session.get(Setting,key)
 return decrypt(row.value) if row else default
def set_setting(key,value):
 row=db.session.get(Setting,key)
 if row: row.value=encrypt(value)
 else: db.session.add(Setting(key=key,value=encrypt(value)))
 db.session.commit()
def audit(event,reference=''):
 db.session.add(Audit(event=event,reference=reference)); db.session.commit()
def rate_limit(bucket,subject,limit,seconds):
 key=hmac.new(KEY,(bucket+':'+subject).encode(),hashlib.sha256).hexdigest()
 with LOCK:
  row=db.session.get(Rate,key); window=now()//seconds*seconds
  if not row: row=Rate(key=key,window=window,count=0); db.session.add(row)
  if row.window!=window: row.window=window; row.count=0
  row.count+=1; db.session.commit()
  return row.count<=limit
def verify_owner(password,otp):
 with LOCK:
  owner=db.session.get(Owner,1)
  if not owner: return False
  try: PASSWORDS.verify(owner.password_hash,password)
  except VerificationError: return False
  return consume_totp(owner,otp)
def consume_totp(owner,otp):
 if not isinstance(otp,str) or len(otp)!=6 or not otp.isdigit(): return False
 t=pyotp.TOTP(decrypt(owner.totp)); step=now()//30
 for candidate in [step,step-1,step+1]:
  if candidate>owner.last_step and hmac.compare_digest(t.at(candidate*30),otp):
   owner.last_step=candidate; db.session.commit(); return True
 return False
def revoke_all():
 owner=db.session.get(Owner,1)
 if owner: owner.epoch+=1
 Token.query.update({'access_token_revoked_at':now(),'refresh_token_revoked_at':now()})
 WebSession.query.delete(); Code.query.delete()
 Action.query.filter_by(state='pending').update({'state':'cancelled'})
 db.session.commit(); audit('all_access_revoked')
def active_token(raw):
 row=Token.query.filter_by(access_token=digest(raw)).first()
 owner=db.session.get(Owner,1)
 if not row or not owner or row.epoch!=owner.epoch or row.access_token_revoked_at or row.is_expired() or row.resource!=RESOURCE: return None
 return row
def initialize():
 STATE.mkdir(mode=0o700,parents=True,exist_ok=True)
 with app.app_context():
  db.create_all()
  # Retire old website proposals rather than silently broadening their approval.
  Action.query.filter(Action.kind.in_(['send','mail_change']),Action.state=='pending').update({'state':'cancelled'})
  Action.query.filter_by(state='executing').update({'state':'uncertain'})
  Record.query.filter_by(kind='draft',status='sending').update({'status':'uncertain'})
  db.session.commit()
  db.session.execute(db.text('PRAGMA journal_mode=WAL')); db.session.commit()
