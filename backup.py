"""Encrypted local backups; master key is deliberately excluded."""
import sqlite3,tempfile,tarfile,io,os
from pathlib import Path
from datetime import datetime,timezone
from core import STATE,CIPHER
def backup():

 root=Path('/var/backups/mailbridge');root.mkdir(mode=0o700,parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='mailbridge-backup-') as work:
  dest=Path(work)/'mailbridge.db'
  with sqlite3.connect('file:'+str(STATE/'mailbridge.db')+'?mode=ro',uri=True) as src,sqlite3.connect(dest) as target: src.backup(target)
  buf=io.BytesIO()
  with tarfile.open(fileobj=buf,mode='w:gz') as tar:
   tar.add(dest,arcname='mailbridge.db')
   tar.add('/etc/mailbridge/config.json',arcname='config.json')
  encrypted=CIPHER.encrypt(buf.getvalue())
  out=root/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.fernet')
  out.write_bytes(encrypted);out.chmod(0o600)
  # Verify the backup can be authenticated and its database is readable.
  decoded=CIPHER.decrypt(out.read_bytes())
  with tarfile.open(fileobj=io.BytesIO(decoded),mode='r:gz') as tar:
   data=tar.extractfile('mailbridge.db').read()
  verify=Path(work)/'verify.db';verify.write_bytes(data)
  with sqlite3.connect(verify) as db:
   if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok': raise RuntimeError('Backup verification failed')
  for old in sorted(root.glob('*.fernet'))[:-7]: old.unlink()
  print('Encrypted backup verified:',out)
if __name__=='__main__': backup()
