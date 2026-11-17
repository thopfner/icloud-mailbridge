"""Isolated, encrypted, rebuildable email index. All IMAP operations are read-only."""
import datetime as dt,email,email.policy,fcntl,json,re,time,hashlib,hmac
from contextlib import contextmanager
from pathlib import Path
from email.utils import getaddresses
import sqlcipher3 as sqlite
from core import app,db,STATE,KEY,setting,set_setting,now
import mail

INDEX=STATE/'mail-index.db'
SYNC_LOCK=STATE/'mail-index-sync.lock'
BODY_LIMIT=12000
FOLDER_LIMIT=3000
MAX_FOLDERS=6
DEFAULTS={'enabled':False,'retention_days':90,'folders':[]}
SCHEMA="""
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS folders(name TEXT PRIMARY KEY,validity INTEGER,last_check INTEGER,role TEXT,eligible INTEGER,pending INTEGER,capped INTEGER,error TEXT);
CREATE TABLE IF NOT EXISTS messages(
 id TEXT PRIMARY KEY,folder TEXT NOT NULL,validity INTEGER NOT NULL,uid INTEGER NOT NULL,
 received INTEGER NOT NULL,role TEXT NOT NULL,mid TEXT NOT NULL,refs TEXT NOT NULL,
 sender TEXT NOT NULL,recipients TEXT NOT NULL,subject TEXT NOT NULL,body TEXT NOT NULL,
 flags TEXT NOT NULL,truncated INTEGER NOT NULL,parse_status TEXT NOT NULL,automated INTEGER NOT NULL,
 source_hash TEXT NOT NULL,UNIQUE(folder,validity,uid));
CREATE INDEX IF NOT EXISTS messages_received ON messages(received);
CREATE INDEX IF NOT EXISTS messages_folder ON messages(folder,uid);
CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(id UNINDEXED,subject,sender,recipients,body,tokenize='unicode61');
CREATE TRIGGER IF NOT EXISTS mi_insert AFTER INSERT ON messages BEGIN
 INSERT INTO message_fts(id,subject,sender,recipients,body) VALUES(new.id,new.subject,new.sender,new.recipients,new.body);
END;
CREATE TRIGGER IF NOT EXISTS mi_delete AFTER DELETE ON messages BEGIN DELETE FROM message_fts WHERE id=old.id; END;
CREATE TRIGGER IF NOT EXISTS mi_update AFTER UPDATE OF subject,sender,recipients,body ON messages BEGIN
 DELETE FROM message_fts WHERE id=old.id;
 INSERT INTO message_fts(id,subject,sender,recipients,body) VALUES(new.id,new.subject,new.sender,new.recipients,new.body);
END;
"""

def options():
 return {**DEFAULTS,**setting('mail_index_settings',{})}

def account_signature(config=None):
 config=setting('icloud',{}) if config is None else config
 if not config: return None
 # Credential/account changes invalidate access to the previous account's cache.
 return hmac.new(KEY,json.dumps(config,sort_keys=True).encode(),hashlib.sha256).hexdigest()

@contextmanager
def store():
 STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
 c=sqlite.connect(str(INDEX),timeout=5)
 INDEX.chmod(0o600)
 try:
  key=hmac.new(KEY,b'mailbridge-mail-index-v1',hashlib.sha256).hexdigest()
  c.execute('PRAGMA key="x\''+key+'\'"')
  if not c.execute('PRAGMA cipher_version').fetchone(): raise RuntimeError('Encrypted SQLite required')
  c.execute('PRAGMA temp_store=MEMORY')
  c.execute('PRAGMA cipher_memory_security=ON')
  c.execute('PRAGMA cache_size=-4096')
  c.execute('PRAGMA journal_mode=WAL')
  c.execute('PRAGMA secure_delete=ON')
  c.execute('PRAGMA busy_timeout=5000')
  c.row_factory=sqlite.Row
  c.executescript(SCHEMA)
  yield c
  c.commit()
 except Exception:
  c.rollback();raise
 finally:c.close()

def meta(c,key,default=None):
 row=c.execute('SELECT value FROM meta WHERE key=?',(key,)).fetchone()
 return json.loads(row[0]) if row else default

def put_meta(c,key,value):
 c.execute('INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',(key,json.dumps(value)))

def clear(c):
 c.execute('DELETE FROM messages');c.execute('DELETE FROM folders');c.execute('DELETE FROM meta')

def require_cache(c):
 expected=account_signature()
 if not expected: raise mail.MailError('iCloud is disconnected. Indexed mail is unavailable.')
 if meta(c,'account')!=expected: raise mail.MailError('Index is not ready for this account. Use live search_mail while synchronization runs.')

def status_from(c):
 cfg=options();expected=account_signature()
 if not expected or meta(c,'account')!=expected:
  return {'enabled':cfg['enabled'],'ready':False,'state':'disconnected' if not expected else 'awaiting_initial_sync',
   'retention_days':cfg['retention_days'],'note':'Live mail tools remain available when connected.'}
 folders=[dict(r) for r in c.execute('SELECT * FROM folders ORDER BY name')]
 last=meta(c,'last_success',0)
 return {'enabled':cfg['enabled'],'ready':True,'state':meta(c,'state','never_synced'),
  'last_attempt_at':meta(c,'last_attempt',None),'last_success_at':last or None,
  'stale':meta(c,'state')=='error' or not last or now()-last>1800,'age_seconds':now()-last if last else None,
  'complete':meta(c,'state')=='idle' and bool(folders) and all(not f['pending'] and not f['capped'] and not f['error'] for f in folders),
  'indexed_messages':c.execute('SELECT count(*) FROM messages').fetchone()[0],
  'body_limited_messages':c.execute("SELECT count(*) FROM messages WHERE truncated=1 OR parse_status!='ok'").fetchone()[0],
  'retention_days':cfg['retention_days'],'max_messages_per_folder':FOLDER_LIMIT,
  'max_body_characters':BODY_LIMIT,'folders':folders,'last_error':meta(c,'last_error',None),'last_full_reconcile_at':meta(c,'last_full_reconcile',None),
  'sync_interval_minutes':10,'analysis':'local_rules_and_on_demand_chatgpt','attachments_indexed':False,
  'note':'Timestamps are Unix seconds. Cached results may lag Apple Mail; read_mail verifies the live source before actions.'}

def status():
 with store() as c:return status_from(c)

def configure(enabled:bool=True,folders:list[str]|None=None,retention_days:int=90):
 if not 7<=retention_days<=90: raise mail.MailError('Retention must be 7–90 days.')
 current=options()
 if folders is not None:
  if len(folders)>MAX_FOLDERS:raise mail.MailError('Choose at most six folders.')
  for f in folders:mail.folder_name(f)
  available={f['name'] for f in mail.folder_list()}
  if not set(folders)<=available:raise mail.MailError('A selected folder does not exist.')
  current['folders']=list(dict.fromkeys(folders))
 current.update(enabled=bool(enabled),retention_days=retention_days)
 set_setting('mail_index_settings',current)
 return {'settings':current,'note':'Applied on the next sync. Empty folders means Inbox, Sent and Drafts. No mailbox messages are changed.'}

def choose_folders(listing,cfg):
 names={n for _,_,n in listing}
 sent={n for flags,_,n in listing if b'\\Sent' in flags}
 draft={n for flags,_,n in listing if b'\\Drafts' in flags}
 if not draft and 'Drafts' in names:draft={'Drafts'}
 chosen=cfg['folders'] or [n for _,_,n in listing if n.upper()=='INBOX' or n in sent or n in draft]
 return [(n,'draft' if n in draft else 'sent' if n in sent else 'inbox' if n.upper()=='INBOX' else 'other')
  for n in dict.fromkeys(chosen)][:MAX_FOLDERS]

def message_id(folder,validity,uid):
 return hashlib.sha256(json.dumps([folder,int(validity),int(uid)]).encode()).hexdigest()[:40]

def ids_in_header(value):
 return re.findall(r'<[^<>\s]{1,250}>',str(value or ''))[:50]

def parse_message(folder,role,validity,uid,data,raw):
 env=data.get(b'ENVELOPE')
 received=data.get(b'INTERNALDATE')
 timestamp=int(received.timestamp()) if received else now()
 subject=mail.text(mail.decode_subject(env.subject),500) if env else ''
 sender=','.join(mail.envelope_addresses(env.from_)).lower() if env else ''
 recipients=','.join(mail.envelope_addresses(env.to)+mail.envelope_addresses(env.cc)).lower() if env else ''
 mid=mail.decode_bytes(env.message_id) if env else ''
 refs=[];body='';truncated=True;parse_status='size_limit';automated=False
 if raw:
  try:
   parsed=email.message_from_bytes(raw,policy=email.policy.default)
   info=mail.extract_message(parsed)
   subject=info['subject'];body=info['body'][:BODY_LIMIT]
   sender=','.join(a.lower() for _,a in getaddresses(parsed.get_all('From',[])))[:2000]
   recipients=','.join(a.lower() for _,a in getaddresses(parsed.get_all('To',[])+parsed.get_all('Cc',[])))[:4000]
   mid=(ids_in_header(parsed.get('Message-ID')) or [''])[0]
   refs=ids_in_header(parsed.get('References'))+ids_in_header(parsed.get('In-Reply-To'))
   refs=list(dict.fromkeys(refs))[-50:]
   automated=bool(parsed.get('List-ID')) or str(parsed.get('Auto-Submitted','no')).lower()!='no'
   truncated=info['body_truncated'] or len(info['body'])>BODY_LIMIT
   parse_status='ok'
  except Exception:parse_status='parse_error'
 flags=[mail.decode_bytes(f) for f in data.get(b'FLAGS',[])]
 content_hash=hashlib.sha256((subject+'\n'+sender+'\n'+body).encode()).hexdigest()
 return {'id':message_id(folder,validity,uid),'folder':folder,'validity':int(validity),'uid':int(uid),
  'received':timestamp,'role':role,'mid':mid if ids_in_header(mid) else '', 'refs':json.dumps(refs),
  'sender':sender,'recipients':recipients,'subject':subject,'body':body,'flags':json.dumps(flags),
  'truncated':int(truncated),'parse_status':parse_status,'automated':int(automated),'source_hash':content_hash}

def upsert(c,message):
 cols=list(message)
 c.execute('INSERT INTO messages('+','.join(cols)+') VALUES('+','.join('?' for _ in cols)+') ON CONFLICT(id) DO UPDATE SET '+','.join(k+'=excluded.'+k for k in cols if k!='id'),tuple(message.values()))

def fetch_new(client,uids,started,budget_seconds,cutoff=0):
 # Bound both round trips and memory: metadata in groups of 20, MIME in groups
 # of four (at most 8 MB declared message data per fetch). Never mark mail read.
 for offset in range(0,len(uids),20):
  if time.monotonic()-started>budget_seconds:return
  group=uids[offset:offset+20]
  metadata=client.fetch(group,['ENVELOPE','INTERNALDATE','FLAGS','RFC822.SIZE'])
  for part in range(0,len(group),4):
   if time.monotonic()-started>budget_seconds:return
   chunk=group[part:part+4]
   # IMAP SINCE has day precision; avoid redownloading the expired part of
   # the boundary day on every pass after retention pruning.
   def in_window(uid):
    received=metadata[uid].get(b'INTERNALDATE')
    return not received or received.timestamp()>=cutoff
   safe=[uid for uid in chunk if uid in metadata and in_window(uid) and metadata[uid].get(b'RFC822.SIZE',mail.MAX_MESSAGE+1)<=mail.MAX_MESSAGE]
   bodies=client.fetch(safe,['BODY.PEEK[]']) if safe else {}
   for uid in chunk:
    data=metadata.get(uid)
    if not data:continue
    raw=bodies.get(uid,{}).get(b'BODY[]') if uid in safe else None
    if raw and len(raw)>mail.MAX_MESSAGE:raw=None
    yield uid,data,raw

def sync(max_new_per_folder=100,budget_seconds=240,full=False):
 """Only LIST, SELECT(readonly), SEARCH and FETCH(BODY.PEEK). Never import send tools."""
 started=time.monotonic()
 with open(SYNC_LOCK,'a') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return {'state':'already_running'}
  with store() as c:
   cfg=options();config=setting('icloud',{});signature=account_signature(config)
   if not signature:
    clear(c);put_meta(c,'state','disconnected');return {'state':'disconnected'}
   if meta(c,'account')!=signature:
    clear(c);put_meta(c,'account',signature)
   cutoff=now()-cfg['retention_days']*86400
   c.execute('DELETE FROM messages WHERE received<?',(cutoff,));c.commit()
   if not cfg['enabled']:
    put_meta(c,'state','paused');return status_from(c)
   put_meta(c,'last_attempt',now());put_meta(c,'state','syncing');c.commit()
   try:
    with mail.mailbox(config) as client:
     client.normalise_times=False
     listing=client.list_folders();available={n for _,_,n in listing}
     selected=choose_folders(listing,cfg)
     keep={f for f,_ in selected}
     for row in c.execute('SELECT name FROM folders').fetchall():
      if row[0] not in keep:
       c.execute('DELETE FROM messages WHERE folder=?',(row[0],));c.execute('DELETE FROM folders WHERE name=?',(row[0],))
     errors=False;remaining=False;fetched=0
     # Each folder receives its own bounded batch, preventing Inbox from starving Sent.
     for folder,role in selected:
      if time.monotonic()-started>budget_seconds:
       remaining=True;break
      if folder not in available:
       c.execute('DELETE FROM messages WHERE folder=?',(folder,))
       c.execute('INSERT OR REPLACE INTO folders VALUES(?,?,?,?,?,?,?,?)',(folder,0,now(),role,0,0,0,'folder_missing'));errors=True;c.commit();continue
      try:
       info=client.select_folder(folder,readonly=True);validity=int(info[b'UIDVALIDITY'])
       old=c.execute('SELECT validity FROM folders WHERE name=?',(folder,)).fetchone()
       if old and old[0]!=validity:c.execute('DELETE FROM messages WHERE folder=?',(folder,))
       cutoff_date=dt.datetime.fromtimestamp(cutoff,dt.timezone.utc).date()
       all_ids=sorted(set(client.search(['SINCE',cutoff_date,'NOT','DELETED'])))
       uids=all_ids[-FOLDER_LIMIT:];known={r['uid']:r['id'] for r in c.execute('SELECT id,uid FROM messages WHERE folder=?',(folder,))}
       active=set(uids)
       for uid,index_id in known.items():
        if uid not in active:c.execute('DELETE FROM messages WHERE id=?',(index_id,))
       # Reconcile flags/deletions every pass; bodies are downloaded only for unknown UIDs.
       for offset in range(0,len(uids),200):
        flag_data=client.fetch(uids[offset:offset+200],['FLAGS'])
        for uid,values in flag_data.items():
         if uid in known:c.execute('UPDATE messages SET flags=? WHERE id=?',(json.dumps([mail.decode_bytes(x) for x in values.get(b'FLAGS',[])]),known[uid]))
       missing=[uid for uid in reversed(uids) if uid not in known]
       done=0
       for uid,data,raw in fetch_new(client,missing[:max_new_per_folder],started,budget_seconds,cutoff):
        message=parse_message(folder,role,validity,uid,data,raw)
        # Recheck credentials before persisting data after a disconnect/account change.
        db.session.expire_all()
        if account_signature()!=signature:raise mail.MailError('account_changed')
        if message['received']>=cutoff:
         upsert(c,message);fetched+=1
        done+=1
        if done%10==0:c.commit()
       pending=max(0,len(missing)-done)
       c.execute('INSERT OR REPLACE INTO folders VALUES(?,?,?,?,?,?,?,?)',(folder,validity,now(),role,len(all_ids),pending,int(len(all_ids)>FOLDER_LIMIT),None))
       remaining=remaining or bool(pending)
       c.commit()
      except Exception:
       c.rollback()
       c.execute('INSERT INTO folders VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET last_check=excluded.last_check,error=excluded.error,pending=1',(folder,0,now(),role,0,1,0,'sync_failed'))
       c.commit();errors=True
     db.session.expire_all()
     if account_signature()!=signature:
      clear(c);put_meta(c,'state','account_changed');return {'state':'account_changed'}
     c.execute('DELETE FROM messages WHERE received<?',(cutoff,))
     put_meta(c,'last_error','one_or_more_folders_failed' if errors else None)
     put_meta(c,'state','error' if errors else 'backfilling' if remaining else 'idle')
     if not errors:put_meta(c,'last_success',now())
     if full:
      if c.execute('PRAGMA cipher_integrity_check').fetchall():raise RuntimeError('Index integrity check failed')
      c.execute("INSERT INTO message_fts(message_fts) VALUES('integrity-check')")
      put_meta(c,'last_full_reconcile',now())
     put_meta(c,'last_new_messages',fetched)
     return status_from(c)
   except Exception:
    c.rollback();put_meta(c,'state','error');put_meta(c,'last_error','sync_failed')
    return status_from(c)

def result_view(row,excerpt=400):
 r=dict(row)
 return {'indexed_id':r['id'],'message_ref':mail.reference(r['folder'],r['validity'],r['uid']),
  'folder':r['folder'],'received_at':r['received'],'subject':r['subject'],'from':r['sender'],
  'to_cc':r['recipients'],'excerpt':r['body'][:excerpt],'flags':json.loads(r['flags']),
  'body_truncated':bool(r['truncated']),'parse_status':r['parse_status'],'untrusted_content':True}

def search(query='',sender='',folder='',since='',before='',unread=False,limit=20):
 if len(query)>300 or len(sender)>254:raise mail.MailError('Search input too long.')
 limit=max(1,min(limit,50));clauses=[];params=[]
 tokens=re.findall(r'\w+',query,flags=re.UNICODE)[:20]
 join=''
 if tokens:
  join=' JOIN message_fts ON message_fts.id=m.id'
  clauses.append('message_fts MATCH ?');params.append(' AND '.join('"'+t+'"' for t in tokens))
 if sender:clauses.append('instr(lower(m.sender),lower(?))>0');params.append(sender)
 if folder:clauses.append('m.folder=?');params.append(folder)
 if since:clauses.append('m.received>=?');params.append(int(dt.datetime.combine(dt.date.fromisoformat(since),dt.time(),dt.timezone.utc).timestamp()))
 if before:clauses.append('m.received<?');params.append(int(dt.datetime.combine(dt.date.fromisoformat(before),dt.time(),dt.timezone.utc).timestamp()))
 if unread:clauses.append("instr(m.flags,?)=0");params.append(json.dumps('\\Seen'))
 clauses.append('m.received>=?');params.append(now()-options()['retention_days']*86400)
 where=' WHERE '+' AND '.join(clauses)
 with store() as c:
  require_cache(c)
  total=c.execute('SELECT count(*) FROM messages m'+join+where,params).fetchone()[0]
  rows=c.execute('SELECT m.* FROM messages m'+join+where+' ORDER BY m.received DESC,m.id LIMIT ?',params+[limit]).fetchall()
  return {'messages':[result_view(r) for r in rows],'total_matches':total,'sync':status_from(c),
   'untrusted_content':True,'note':'Search covers cached plain text only, not attachments. Use live read_mail for full current content.'}

def snapshot():
 with store() as c:
  require_cache(c)
  columns=[r[1] for r in c.execute('PRAGMA table_info(messages)')]
  selection=','.join("substr(body,1,4000) AS body" if col=='body' else "CASE WHEN length(body)>4000 THEN 1 ELSE truncated END AS truncated" if col=='truncated' else col for col in columns)
  cutoff=now()-options()['retention_days']*86400
  rows=[dict(r) for r in c.execute("SELECT "+selection+" FROM messages WHERE role!='draft' AND received>=? ORDER BY received DESC,id LIMIT 5000",(cutoff,))]
  sync=status_from(c)
  total=c.execute("SELECT count(*) FROM messages WHERE role!='draft' AND received>=?",(cutoff,)).fetchone()[0]
  sync.update(analysis_messages_considered=len(rows),analysis_limited=total>len(rows),analysis_body_characters=4000)
  return rows,sync

def main():
 import sys
 with app.app_context():
  outcome=sync(max_new_per_folder=500 if '--initial' in sys.argv else 100,full='--full' in sys.argv)
  # Metadata only. No addresses, subjects, bodies, folder names or credentials.
  print(json.dumps({k:outcome.get(k) for k in ('state','indexed_messages','complete','stale')}))
  if outcome.get('state')=='error':raise SystemExit(1)
if __name__=='__main__':main()
