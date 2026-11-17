import contextlib,copy,datetime as dt
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
import pytest
from core import *
import mail,mail_actions as actions
from conftest import tokens,login_session
from test_security import rpc

class Cloud:
 def __init__(self):
  env=SimpleNamespace(subject=b'Mailbridge test',from_=[SimpleNamespace(mailbox=b'alice',host=b'example.com')],
   to=[],date=dt.datetime(2026,11,15),message_id=b'<test@example.com>')
  self.messages={'INBOX':{1:{b'ENVELOPE':env,b'FLAGS':[],b'RFC822.SIZE':4_000_000},
   2:{b'ENVELOPE':env,b'FLAGS':[b'\\Deleted'],b'RFC822.SIZE':100}},
   'Archive':{},'Trash':{}}
  self.validity={'INBOX':10,'Archive':20,'Trash':30}
  self.calls=[];self.caps={'UIDPLUS'};self.omit_copyuid=False;self.copy_timeout=False;self.flag_timeout=False;self.corrupt_copy=False
 def list_folders(self):
  return [([],b'/','INBOX'),([b'\\Archive'],b'/','Archive'),([b'\\Trash'],b'/','Trash')]
 def select_folder(self,folder,readonly=True):
  self.folder=folder;self.readonly=readonly
  return {b'UIDVALIDITY':self.validity[folder]}
 def fetch(self,uids,fields):
  assert not any(f.startswith('BODY') for f in fields)
  return {u:copy.deepcopy(self.messages[self.folder][u]) for u in uids if u in self.messages[self.folder]}
 def has_capability(self,cap):return cap in self.caps
 def add_flags(self,uids,flags):
  assert not self.readonly
  self.calls.append(('add',self.folder,list(uids),list(flags)))
  for u in uids:self.messages[self.folder][u][b'FLAGS']=list(set(self.messages[self.folder][u][b'FLAGS'])|set(flags))
  if self.flag_timeout:raise TimeoutError('private diagnostic')
 def remove_flags(self,uids,flags):
  assert not self.readonly
  self.calls.append(('remove',self.folder,list(uids),list(flags)))
  for u in uids:self.messages[self.folder][u][b'FLAGS']=[f for f in self.messages[self.folder][u][b'FLAGS'] if f not in flags]
 def copy(self,uids,target):
  assert not self.readonly and len(uids)==1
  self.calls.append(('copy',self.folder,uids,target))
  new=max(self.messages[target],default=100)+1
  self.messages[target][new]=copy.deepcopy(self.messages[self.folder][uids[0]])
  if self.corrupt_copy:self.messages[target][new][b'RFC822.SIZE']+=1
  if self.copy_timeout:raise TimeoutError('private diagnostic')
  return b'OK' if self.omit_copyuid else f'[COPYUID {self.validity[target]} {uids[0]} {new}] Copied'.encode()
 def uid_expunge(self,uids):
  assert not self.readonly and len(uids)==1
  self.calls.append(('uid_expunge',self.folder,uids))
  for u in uids:
   if b'\\Deleted' in self.messages[self.folder][u][b'FLAGS']:del self.messages[self.folder][u]
 def expunge(self,*a,**k):pytest.fail('Blanket expunge forbidden')
 def move(self,uids,target):
  response=self.copy(uids,target)
  del self.messages[self.folder][uids[0]]
  self.calls.append(('move',self.folder,uids,target))
  return response

@pytest.fixture
def cloud(monkeypatch):
 c=Cloud()
 @contextlib.contextmanager
 def box(*args,**kwargs):yield c
 monkeypatch.setattr(mail,'mailbox',box)
 monkeypatch.setattr(mail,'smtp',lambda *a,**k:pytest.fail('Mailbox changes must not use SMTP'))
 with app.app_context():set_setting('icloud',{'email':'owner@icloud.com','password':'test-only'})
 return c

def actor():return SimpleNamespace(client_id='client',family='family')
def review(op='star',folder=None):return actions.review(mail.reference('INBOX',10,1),op,folder,actor())
def execute(r,revalidate=lambda:None):return actions.execute(r['action_id'],r['review_token'],actor(),revalidate)

@pytest.mark.parametrize('op,flag,start,wanted',[
 ('read',b'\\Seen',[],True),('unread',b'\\Seen',[b'\\Seen'],False),
 ('star',b'\\Flagged',[],True),('unstar',b'\\Flagged',[b'\\Flagged'],False)])
def test_flags_direct_once_without_browser(cloud,op,flag,start,wanted):
 cloud.messages['INBOX'][1][b'FLAGS']=start
 with app.app_context():
  r=review(op);again=review(op)
  assert r['action_id']==again['action_id'] and not cloud.calls and 'approval_url' not in r
  assert r['preview']['size']==4_000_000 and r['untrusted_content']
  result=execute(r)
  assert result['state']=='completed' and (flag in cloud.messages['INBOX'][1][b'FLAGS'])==wanted
  count=len(cloud.calls)
  assert execute(r)['replayed'] and len(cloud.calls)==count

@pytest.mark.parametrize('op,target',[('archive','Archive'),('trash','Trash'),('move','Archive')])
def test_uidplus_move_verified_and_only_exact_uid_removed(cloud,op,target):
 with app.app_context():
  r=review(op,target if op=='move' else None)
  assert not cloud.calls
  result=execute(r)
  assert result['state']=='completed'
  assert 1 not in cloud.messages['INBOX'] and 2 in cloud.messages['INBOX']
  assert len(cloud.messages[target])==1
  assert mail.decrypt(result['result']['message_ref'])['folder']==target
  assert [c[0] for c in cloud.calls]==['copy','add','uid_expunge']
  assert execute(r)['replayed'] and len(cloud.messages[target])==1

@pytest.mark.parametrize('failure',['omit_copyuid','copy_timeout','corrupt_copy'])
def test_ambiguous_copy_preserves_original_and_never_replays(cloud,failure):
 setattr(cloud,failure,True)
 with app.app_context():
  r=review('trash');result=execute(r)
  assert result['state']=='uncertain'
  assert 1 in cloud.messages['INBOX'] and b'\\Deleted' not in cloud.messages['INBOX'][1][b'FLAGS']
  assert len(cloud.messages['Trash'])==1 and len(cloud.calls)==1
  assert execute(r)['replayed'] and len(cloud.calls)==1
  assert 'private diagnostic' not in str(result)

def test_atomic_move_supported_without_uidplus(cloud):
 cloud.caps={'MOVE'}
 with app.app_context():
  assert execute(review('archive'))['state']=='completed'
  assert 1 not in cloud.messages['INBOX'] and 2 in cloud.messages['INBOX']
  assert not any(c[0]=='uid_expunge' for c in cloud.calls)

def test_unsupported_move_is_rejected_before_proposal(cloud):
 cloud.caps=set()
 with app.app_context(),pytest.raises(mail.MailError,match='Safe UID'):
  review('archive')
 assert not cloud.calls

@pytest.mark.parametrize('change',['flags','identity','source_validity','destination_validity','missing'])
def test_stale_preview_never_mutates(cloud,change):
 with app.app_context():
  r=review('archive')
  if change=='flags':cloud.messages['INBOX'][1][b'FLAGS']=[b'\\Seen']
  elif change=='identity':cloud.messages['INBOX'][1][b'RFC822.SIZE']+=1
  elif change=='source_validity':cloud.validity['INBOX']+=1
  elif change=='destination_validity':cloud.validity['Archive']+=1
  else:del cloud.messages['INBOX'][1]
  with pytest.raises(mail.MailError):execute(r)
 assert not cloud.calls

def test_transient_recent_flag_does_not_stale_review(cloud):
 with app.app_context():
  r=review();cloud.messages['INBOX'][1][b'FLAGS']=[b'\\Recent']
  assert execute(r)['state']=='completed'

def test_account_replacement_and_revalidation_fail_closed(cloud):
 with app.app_context():
  r=review()
  def denied():raise mail.MailError('revoked')
  with pytest.raises(mail.MailError,match='revoked'):execute(r,denied)
  set_setting('icloud',{'email':'other@icloud.com','password':'different'})
  with pytest.raises(mail.MailError,match='account changed'):execute(r)
 assert not cloud.calls

def test_tokens_expiry_cancellation_and_family_boundaries(cloud):
 with app.app_context():
  r=review()
  for who,key in [(SimpleNamespace(client_id='other',family='family'),r['review_token']),
    (SimpleNamespace(client_id='client',family='other'),r['review_token']),(actor(),'incorrect')]:
   with pytest.raises(mail.MailError):actions.execute(r['action_id'],key,who,lambda:None)
  row=db.session.get(Action,r['action_id']);row.expires=now()-1;db.session.commit()
  with pytest.raises(mail.MailError,match='expired'):execute(r)
  r=review()
  assert actions.cancel(r['action_id'],r['review_token'],actor())['state']=='cancelled'
  with pytest.raises(mail.MailError,match='cancelled'):execute(r)
 assert not cloud.calls

def test_ambiguous_flag_change_and_restart_are_not_retried(cloud):
 cloud.flag_timeout=True
 with app.app_context():
  r=review();assert execute(r)['state']=='uncertain'
  assert execute(r)['replayed'] and len(cloud.calls)==1
  row=db.session.get(Action,r['action_id']);row.state='executing';db.session.commit()
 initialize()
 with app.app_context():
  assert execute(r)['state']=='uncertain' and len(cloud.calls)==1

def test_parallel_execution_only_applies_once(cloud):
 with app.app_context():r=review()
 def run(_):
  with app.app_context():return execute(r)
 with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(run,[1,2]))
 assert all(r['state']=='completed' for r in results) and len(cloud.calls)==1

def test_noop_flag_does_not_issue_mutation(cloud):
 cloud.messages['INBOX'][1][b'FLAGS']=[b'\\Flagged']
 with app.app_context():
  result=execute(review())
  assert result['state']=='completed' and not result['result']['changed']
 assert not cloud.calls

def test_real_mcp_changes_need_scope_but_no_web_session(client,remote_client,cloud):
 _,data=tokens(client,'mail:read mail:write')
 with app.app_context():WebSession.query.delete();db.session.commit()
 def call(name,args):return rpc(remote_client,data['access_token'],'tools/call',{'name':name,'arguments':args}).json()['result']
 listing=rpc(remote_client,data['access_token'],'tools/list').json()['result']['tools']
 by_name={t['name']:t for t in listing}
 assert by_name['execute_mail_change']['annotations']['destructiveHint']
 assert not by_name['execute_mail_change']['annotations']['readOnlyHint']
 assert not by_name['request_mail_change']['annotations']['destructiveHint']
 result=call('request_mail_change',{'message_ref':mail.reference('INBOX',10,1),'operation':'star'})
 assert not result.get('isError'),result
 r=json.loads(result['content'][0]['text'])
 done=call('execute_mail_change',{'action_id':r['action_id'],'review_token':r['review_token']})
 assert not done.get('isError') and 'completed' in str(done)
 # A narrowed read-only token cannot perform any of these mutations.
 _,read=tokens(client,'mail:read')
 denied=rpc(remote_client,read['access_token'],'tools/call',{'name':'execute_mail_change','arguments':{'action_id':r['action_id'],'review_token':r['review_token']}}).json()['result']
 assert denied['isError'] and 'mail:write' in str(denied)

def test_web_page_cannot_execute_chat_review_even_with_mfa(client,monkeypatch,cloud):
 with app.app_context():r=review()
 headers=login_session(client)
 page=client.get('/actions/'+r['action_id'],base_url=BASE)
 assert page.status_code==200
 assert r['review_token'].encode() not in page.data
 assert b'Fresh authenticator code to execute' not in page.data and b'approve' not in page.data
 response=client.post('/actions/'+r['action_id'],base_url=BASE,headers=headers,
  data={'csrf':'test-csrf','decision':'approve','otp':'123456'})
 assert response.status_code==409 and not cloud.calls

def test_icloud_archive_without_special_use_is_supported(cloud):
 original=cloud.list_folders
 cloud.list_folders=lambda:[([] if name=='Archive' else flags,sep,name) for flags,sep,name in original()]
 with app.app_context():
  result=execute(review('archive'))
  assert result['state']=='completed' and result['result']['destination']=='Archive'

def test_missing_archive_is_not_guessed_or_created(cloud):
 original=cloud.list_folders
 cloud.list_folders=lambda:[row for row in original() if row[2]!='Archive']
 with app.app_context(),pytest.raises(mail.MailError,match='Special folder'):
  review('archive')
 assert not cloud.calls

def test_icloud_separate_copyuid_response_is_verified(cloud):
 buffer=[]
 cloud._imap=SimpleNamespace(response=lambda kind:('COPYUID',[buffer.pop()] if buffer else [None]))
 original=cloud.copy
 def separate(uids,target):
  response=original(uids,target)
  buffer.append(response.split(b'[COPYUID ',1)[1].split(b']',1)[0])
  return None
 cloud.copy=separate
 with app.app_context():
  result=execute(review('archive'))
  assert result['state']=='completed'
  assert 1 not in cloud.messages['INBOX'] and len(cloud.messages['Archive'])==1

def test_stale_copyuid_response_cannot_remove_original(cloud):
 buffer=[b'20 1 999']
 cloud._imap=SimpleNamespace(response=lambda kind:('COPYUID',[buffer.pop()] if buffer else [None]))
 cloud.omit_copyuid=True
 with app.app_context():
  assert execute(review('archive'))['state']=='uncertain'
 assert 1 in cloud.messages['INBOX'] and len(cloud.calls)==1
