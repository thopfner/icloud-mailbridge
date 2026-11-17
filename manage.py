#!/opt/mailbridge/.venv/bin/python
"""Owner operations: run privately on the VPS over SSH, never in a chat."""
import sys,os,getpass,re,subprocess
from pathlib import Path
from core import *
import mail

def root_only():
 if os.geteuid()!=0: raise SystemExit('Run this command as root over SSH.')

def ssh_ready():
 result=subprocess.check_output(['/usr/sbin/sshd','-T'],text=True).lower()
 if 'passwordauthentication no' not in result or 'permitrootlogin yes' in result:
  raise SystemExit('Secure SSH before adding mail credentials. Install and test key-based SSH, disable password authentication and restrict SSH to your private administration network. See DEPLOYMENT.md.')

def setup_owner():
 ssh_ready(); initialize()
 password=getpass.getpass('New Mailbridge password (at least 16 characters): ')
 if len(password)<16 or len(password)>1024: raise SystemExit('Use 16–1024 characters.')
 if password!=getpass.getpass('Repeat password: '): raise SystemExit('Passwords differ.')
 secret=pyotp.random_base32()
 print('Add this secret to your authenticator (keep it private):',secret)
 print('Account label: iCloud Mailbridge')
 import qrcode
 qr=qrcode.QRCode(border=2); qr.add_data(pyotp.TOTP(secret).provisioning_uri(name='owner',issuer_name='iCloud Mailbridge')); qr.print_ascii(invert=True)
 code=getpass.getpass('Enter its current six-digit code: ')
 if not pyotp.TOTP(secret).verify(code,valid_window=1): raise SystemExit('Code verification failed. No changes made.')
 with app.app_context():
  owner=db.session.get(Owner,1)
  if owner: revoke_all()
  else: owner=Owner(id=1,epoch=0); db.session.add(owner)
  owner.password_hash=PASSWORDS.hash(password); owner.totp=encrypt(secret); owner.last_step=now()//30
  db.session.commit(); audit('owner_configured')
 subprocess.run(['chown','-R','mailbridge:mailbridge',str(STATE)],check=True)
 print('Owner configured. Keep the password and authenticator safe. Sign in at '+BASE)

def setup_mail():
 ssh_ready(); initialize()
 with app.app_context():
  if not db.session.get(Owner,1): raise SystemExit('Run setup-owner first.')
  email=mail.address(input('Full iCloud email address: ').strip())
  username=input('IMAP username (blank = full email): ').strip() or email
  mail.header(username,254)
  password=getpass.getpass('Apple app-specific password: ').strip()
  if not re.fullmatch(r'[a-z]{4}(?:-[a-z]{4}){3}',password): raise SystemExit('Invalid app-specific password format.')
  config={'email':email,'imap_username':username,'password':password}
  try: mail.verify_connection(config)
  except Exception: raise SystemExit('IMAP/SMTP authentication failed. No credentials saved; no message sent.')
  set_setting('icloud',config); revoke_all(); audit('mailbox_connected')
 print('IMAP and SMTP verified. Encrypted credentials saved; reconnect ChatGPT.')

def maintenance():
 with app.app_context():
  current=now()
  WebSession.query.filter(WebSession.expires<current).delete()
  Code.query.filter(Code.auth_time<current-600).delete()
  Token.query.filter(Token.refresh_expires<current-86400).delete()
  Action.query.filter(Action.state=='pending',Action.expires<current).update({'state':'expired'})
  for row in Action.query.filter(Action.created<current-30*86400).all():
   row.content=encrypt({'purged':True}); row.result=None
  Audit.query.filter(Audit.created<current-90*86400).delete()
  # Fixed-window counters need not outlive one day.
  Rate.query.filter(Rate.window < current-2*86400).delete()
  db.session.commit()

def main():
 command=sys.argv[1] if len(sys.argv)>1 else ''
 if command!='maintenance': root_only()
 if command=='setup-owner': setup_owner()
 elif command=='setup-mail': setup_mail()
 elif command=='revoke-all':
  with app.app_context(): revoke_all()
  print('All connections revoked.')
 elif command=='maintenance': maintenance()
 elif command=='status':
  with app.app_context(): print(json.dumps({'base_url':BASE,'owner_configured':bool(db.session.get(Owner,1)),'icloud_configured':bool(setting('icloud'))}))
 else: raise SystemExit('Commands: setup-owner | setup-mail | revoke-all | maintenance | status')
if __name__=='__main__':
 try: main()
 finally:
  if os.geteuid()==0 and STATE.exists(): subprocess.run(['chown','-R','mailbridge:mailbridge',str(STATE)],check=True)
