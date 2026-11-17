import copy,contextlib,hashlib,email,email.policy
from types import SimpleNamespace
import pytest
from core import *
import mail,drafts
from conftest import tokens
from test_security import rpc

@pytest.fixture
def cloud(monkeypatch):
 state=SimpleNamespace(messages={},uploads=0,sends=[],retired=[],fail_upload=False,fail_cleanup=False,fail_send=False)
 def locate(p): return copy.deepcopy(state.messages.get(p['revision']))
 def append(p):
  state.uploads+=1
  remote={'message_ref':'ref-'+p['revision'],'sha256':digest(p['body']),'folder':'Drafts'}
  state.messages[p['revision']]=remote
  if state.fail_upload: raise TimeoutError()
  return copy.deepcopy(remote)
 def check(remote):
  if remote not in state.messages.values(): raise mail.MailError('Draft changed in Apple Mail.')
  return True
 def retire(remote):
  if state.fail_cleanup: raise TimeoutError()
  state.retired.append(copy.deepcopy(remote))
  for revision,saved in list(state.messages.items()):
   if saved==remote: del state.messages[revision]
  return 'moved_to_trash'
 def send(p):
  state.sends.append(copy.deepcopy(p))
  if state.fail_send: raise TimeoutError()
  return {'smtp_accepted':True,'refused_recipient_count':0,'sent_copy':'saved'}
 monkeypatch.setattr(mail,'append_draft',append)
 monkeypatch.setattr(mail,'locate_draft',locate)
 monkeypatch.setattr(mail,'check_draft',check)
 monkeypatch.setattr(mail,'retire_draft',retire)
 monkeypatch.setattr(mail,'send',send)
 return state

def content(body='Hello'):
 return mail.build_draft(['recipient@example.com'],'Test draft',body,['cc@example.com'],['bcc@example.com'])

def actor():
 return SimpleNamespace(client_id='client',family='family')

def create():
 return drafts.save(content(),idempotency_key='create-test')

def test_sync_create_edit_and_idempotency(cloud):
 with app.app_context():
  first=create()
  assert first['sync_status']=='synced' and first['icloud_verified']
  assert drafts.save(content(),idempotency_key='create-test')['id']==first['id']
  assert cloud.uploads==1
  with pytest.raises(mail.MailError,match='different content'):
   drafts.save(content('changed'),idempotency_key='create-test')
  with pytest.raises(mail.MailError,match='revision'):
   drafts.save(content('changed'),first['id'],'wrong')
  updated=drafts.save(content('changed'),first['id'],first['revision'])
  assert updated['revision']!=first['revision'] and updated['sync_status']=='synced'
  assert len(cloud.messages)==1 and len(cloud.retired)==1

def test_uncertain_upload_reconciles_without_duplicate(cloud):
 cloud.fail_upload=True
 with app.app_context():
  saved=create()
  assert saved['sync_status']=='uncertain'
  cloud.fail_upload=False
  recovered=drafts.sync(saved['id'])
  assert recovered['sync_status']=='synced' and cloud.uploads==1

def test_missing_uncertain_upload_never_reappended(cloud):
 cloud.fail_upload=True
 with app.app_context():
  saved=create(); cloud.messages.clear(); cloud.fail_upload=False
  assert drafts.sync(saved['id'])['sync_status']=='uncertain'
  assert cloud.uploads==1
  with pytest.raises(mail.MailError,match='synced'):
   drafts.review(saved['id'],actor())

def test_external_edit_blocks_edit_and_send(cloud):
 with app.app_context():
  saved=create(); review=drafts.review(saved['id'],actor())
  cloud.messages.clear()
  assert drafts.view(drafts.record(saved['id']),verify=True)['icloud_verified'] is False
  with pytest.raises(mail.MailError,match='changed'):
   drafts.save(content('edit'),saved['id'],saved['revision'])
  with pytest.raises(mail.MailError,match='changed'):
   drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  assert not cloud.sends

def test_review_does_not_send_and_replays_exact_version(cloud):
 with app.app_context():
  saved=create(); first=drafts.review(saved['id'],actor()); second=drafts.review(saved['id'],actor())
  assert first['action_id']==second['action_id']
  assert first['preview']['bcc']==['bcc@example.com']
  assert 'approval_url' not in first and not cloud.sends
  result=drafts.execute(first['action_id'],first['review_token'],actor(),lambda:None)
  assert result['state']=='completed'
  replay=drafts.execute(first['action_id'],first['review_token'],actor(),lambda:None)
  assert replay['replayed'] and len(cloud.sends)==1 and len(cloud.messages)==0

def test_edit_cancels_old_review(cloud):
 with app.app_context():
  saved=create(); first=drafts.review(saved['id'],actor())
  drafts.save(content('new'),saved['id'],saved['revision'])
  with pytest.raises(mail.MailError,match='cancelled'):
   drafts.execute(first['action_id'],first['review_token'],actor(),lambda:None)
  assert not cloud.sends

def test_review_expiry_token_and_family_boundaries(cloud):
 with app.app_context():
  saved=create(); review=drafts.review(saved['id'],actor())
  for wrong_actor,token in [(SimpleNamespace(client_id='other',family='family'),review['review_token']),
    (SimpleNamespace(client_id='client',family='other'),review['review_token']),(actor(),'wrong')]:
   with pytest.raises(mail.MailError):
    drafts.execute(review['action_id'],token,wrong_actor,lambda:None)
  action=db.session.get(Action,review['action_id']);action.expires=now()-1;db.session.commit()
  with pytest.raises(mail.MailError,match='expired'):
   drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  assert not cloud.sends

def test_uncertain_smtp_is_durable_and_not_retried(cloud):
 cloud.fail_send=True
 with app.app_context():
  saved=create(); review=drafts.review(saved['id'],actor())
  result=drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  assert result['state']=='uncertain'
  drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  with pytest.raises(mail.MailError): drafts.review(saved['id'],actor())
  with pytest.raises(mail.MailError): drafts.sync(saved['id'])
  assert len(cloud.sends)==1 and drafts.record(saved['id']).status=='uncertain'

def test_send_cleanup_retry_never_resends(cloud):
 with app.app_context():
  saved=create(); review=drafts.review(saved['id'],actor());cloud.fail_cleanup=True
  result=drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  assert result['state']=='completed' and result['result']['draft_cleanup']=='pending'
  cloud.fail_cleanup=False
  assert drafts.sync(saved['id'])['sync_status']=='removed_after_send'
  assert len(cloud.sends)==1

def test_update_cleanup_pending_blocks_send(cloud):
 with app.app_context():
  saved=create();cloud.fail_cleanup=True
  updated=drafts.save(content('new'),saved['id'],saved['revision'])
  assert updated['sync_status']=='cleanup_pending'
  with pytest.raises(mail.MailError): drafts.review(saved['id'],actor())
  cloud.fail_cleanup=False
  assert drafts.sync(saved['id'])['sync_status']=='synced' and cloud.uploads==2

def test_revalidation_failure_never_submits(cloud):
 with app.app_context():
  saved=create();review=drafts.review(saved['id'],actor())
  def revoked(): raise mail.MailError('revoked')
  with pytest.raises(mail.MailError): drafts.execute(review['action_id'],review['review_token'],actor(),revoked)
  assert not cloud.sends

def call(remote,token,name,args):
 response=rpc(remote,token,'tools/call',{'name':name,'arguments':args})
 result=response.json()['result']
 assert not result.get('isError'),result
 return json.loads(result['content'][0]['text'])

def test_real_mcp_send_without_browser_login_or_totp(client,remote_client,cloud):
 cid,data=tokens(client);token=data['access_token']
 with app.app_context():
  WebSession.query.delete();db.session.commit()
 saved=call(remote_client,token,'save_draft',{'to':['r@example.com'],'subject':'Test','body':'Hello','idempotency_key':'rpc-create'})
 review=call(remote_client,token,'request_send',{'draft_id':saved['id']})
 args={'action_id':review['action_id'],'review_token':review['review_token']}
 result=call(remote_client,token,'send_draft',args)
 assert result['state']=='completed' and len(cloud.sends)==1
 assert call(remote_client,token,'send_draft',args)['replayed']
 listed=rpc(remote_client,token,'tools/list').json()['result']['tools']
 tool=next(t for t in listed if t['name']=='send_draft')
 assert tool['annotations']['destructiveHint'] is True
 assert tool['annotations']['readOnlyHint'] is False
 assert tool['annotations']['openWorldHint'] is True

def test_send_scope_required(client,remote_client,cloud):
 _,data=tokens(client,'mail:read mail:write')
 denied=rpc(remote_client,data['access_token'],'tools/call',{'name':'send_draft','arguments':{'action_id':'x','review_token':'x'}})
 assert denied.json()['result']['isError'] and 'mail:send' in str(denied.json())
 assert not cloud.sends

def test_concurrent_retries_send_once(client,remote_client,cloud):
 from concurrent.futures import ThreadPoolExecutor
 _,data=tokens(client);token=data['access_token']
 saved=call(remote_client,token,'save_draft',{'to':['r@example.com'],'subject':'Test','body':'Hello'})
 review=call(remote_client,token,'request_send',{'draft_id':saved['id']})
 args={'action_id':review['action_id'],'review_token':review['review_token']}
 with ThreadPoolExecutor(max_workers=2) as executor:
  results=list(executor.map(lambda _:call(remote_client,token,'send_draft',args),range(2)))
 assert len(cloud.sends)==1 and all(r['state']=='completed' for r in results)

class IMAPFake:
 def __init__(self):
  self.raw=b'From: owner@icloud.com\r\nSubject: sample\r\n\r\nbody\r\n'
  self.calls=[];self.flags=[];self.copy_fails=False;self.uidplus=True
 def list_folders(self): return [([],b'/','Drafts'),([b'\\Trash'],b'/','Deleted Messages'),([],b'/','INBOX')]
 def select_folder(self,*a,**k): return {b'UIDVALIDITY':2}
 def fetch(self,ids,fields):
  assert ids==[7]
  return {7:{b'RFC822.SIZE':len(self.raw),b'FLAGS':self.flags,b'BODY[]':self.raw}}
 def has_capability(self,cap): return cap=='UIDPLUS' and self.uidplus
 def copy(self,ids,target):
  self.calls.append(('copy',ids,target))
  if self.copy_fails:raise TimeoutError()
 def add_flags(self,ids,flags): self.calls.append(('flags',ids,flags))
 def uid_expunge(self,ids): self.calls.append(('uid_expunge',ids))
 def expunge(self,*a): pytest.fail('Blanket expunge must never run')

@pytest.fixture
def imap(monkeypatch):
 fake=IMAPFake()
 @contextlib.contextmanager
 def box():yield fake
 monkeypatch.setattr(mail,'mailbox',box)
 return fake

def remote(fake):
 return {'message_ref':mail.reference('Drafts',2,7),'sha256':hashlib.sha256(fake.raw).hexdigest(),'folder':'Drafts'}

def test_icloud_folder_fallback_and_exact_uid_cleanup(imap):
 with app.app_context():
  assert mail.drafts_folder(imap)=='Drafts'
  assert mail.retire_draft(remote(imap))=='moved_to_trash'
  assert imap.calls==[('copy',[7],'Deleted Messages'),('flags',[7],[b'\\Deleted']),('uid_expunge',[7])]

def test_cleanup_copy_failure_preserves_original(imap):
 imap.copy_fails=True
 with app.app_context(),pytest.raises(TimeoutError):mail.retire_draft(remote(imap))
 assert len(imap.calls)==1 and imap.calls[0][0]=='copy'

def test_cleanup_mismatch_and_no_uidplus_fail_closed(imap):
 with app.app_context():
  wrong=remote(imap);wrong['sha256']='wrong'
  with pytest.raises(mail.MailError): mail.retire_draft(wrong)
  assert not imap.calls
  imap.uidplus=False
  with pytest.raises(mail.MailError):mail.retire_draft(remote(imap))
  assert not imap.calls

def test_bcc_saved_in_draft_but_not_outbound_headers(monkeypatch):
 monkeypatch.setattr(mail,'credentials',lambda:{'email':'owner@icloud.com','password':'fake'})
 payload={**content(),'draft_date':'Sun, 15 Nov 2026 12:00:00 +0000','draft_message_id':'<draft@icloud.com>',
  'revision':'revision1','message_id':'<send@icloud.com>'}
 draft=mail.draft_message(payload)
 assert draft['Bcc']=='bcc@example.com' and draft['X-Mailbridge-Revision']=='revision1'
 captured=[]
 class SMTP:
  def __enter__(self):return self
  def __exit__(self,*args):pass
  def send_message(self,msg,from_addr,to_addrs):
   captured.append((msg.as_bytes(),to_addrs));return {}
 @contextlib.contextmanager
 def unavailable(*a):raise TimeoutError();yield
 monkeypatch.setattr(mail,'smtp',lambda c:SMTP())
 monkeypatch.setattr(mail,'mailbox',unavailable)
 result=mail.send(payload)
 assert b'Bcc:' not in captured[0][0] and b'X-Mailbridge' not in captured[0][0]
 assert 'bcc@example.com' in captured[0][1]
 assert result['smtp_accepted'] and result['sent_copy']=='failed'

def test_partial_send_is_not_retried(cloud,monkeypatch):
 def partial(p):
  cloud.sends.append(p)
  return {'smtp_accepted':True,'refused_recipient_count':1,'refused_recipients':['cc@example.com'],'sent_copy':'saved'}
 monkeypatch.setattr(mail,'send',partial)
 with app.app_context():
  saved=create(); review=drafts.review(saved['id'],actor())
  result=drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  assert result['result']['refused_recipient_count']==1
  assert drafts.record(saved['id']).status=='partially_sent'
  drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  assert len(cloud.sends)==1

def test_process_restart_locks_interrupted_send(cloud):
 with app.app_context():
  saved=create();review=drafts.review(saved['id'],actor())
  action=db.session.get(Action,review['action_id']);action.state='executing'
  drafts.record(saved['id']).status='sending';db.session.commit()
 initialize()
 with app.app_context():
  assert db.session.get(Action,review['action_id']).state=='uncertain'
  assert drafts.record(saved['id']).status=='uncertain'
  result=drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  assert result['state']=='uncertain' and not cloud.sends

def test_uploaded_content_verified_after_server_normalization(imap,monkeypatch):
 monkeypatch.setattr(mail,'credentials',lambda:{'email':'owner@icloud.com'})
 payload={**content(),'draft_date':'Sun, 15 Nov 2026 12:00:00 +0000','draft_message_id':'<draft@icloud.com>','revision':'revision1'}
 imap.search=lambda *a,**k:[7]
 imap.raw=mail.draft_message(payload).as_bytes()+b'\r\n'
 with app.app_context():
  assert mail.locate_draft(payload)['folder']=='Drafts'
  imap.raw=imap.raw.replace(b'Hello',b'Edited externally')
  with pytest.raises(mail.MailError,match='differs'):
   mail.locate_draft(payload)
