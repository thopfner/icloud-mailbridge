import contextlib,email,email.policy,copy
from types import SimpleNamespace
import pytest
from core import *
import mail,drafts
from test_drafts import cloud,actor,call,imap,content
from conftest import tokens
from test_security import rpc

def source(**changes):
 data={'message_id':'<parent@example.com>','references':'<root@example.com> <previous@example.com>',
  'in_reply_to':'<previous@example.com>','subject':'Re: Project','from':'Alice <alice@example.com>',
  'to':'Owner <owner@icloud.com>, Bob <bob@example.com>','cc':'Carol <carol@example.com>, alias@icloud.com',
  'reply_to':'Support <support@example.com>','date':'Mon, 16 Nov 2026 09:00:00 +0000'}
 data.update(changes)
 return data

@pytest.fixture
def original(monkeypatch):
 item=source()
 monkeypatch.setattr(mail,'read',lambda ref:copy.deepcopy(item))
 monkeypatch.setattr(mail,'credentials',lambda:{'email':'owner@icloud.com','password':'fake'})
 with app.app_context():set_setting('mail_preferences',{'self_addresses':['alias@icloud.com']})
 return item

def test_reply_and_reply_all_recipient_rules(original):
 with app.app_context():
  single=mail.build_reply('source-ref','Response')
  assert single['to']==['support@example.com'] and single['cc']==[] and single['bcc']==[]
  all_=mail.build_reply('source-ref','Response',True)
  assert all_['to']==['support@example.com']
  assert all_['cc']==['bob@example.com','carol@example.com']
  assert all_['subject']=='Re: Project'
  assert all_['references']==['<root@example.com>','<previous@example.com>','<parent@example.com>']
  assert all_['reply_context']['reply_all'] is True
  original.update(reply_to='',cc='',to='owner@icloud.com')
  assert mail.build_reply('source-ref','Response',True)['to']==['alice@example.com']

def test_follow_up_to_own_sent_message(original):
 original.update(reply_to='',**{'from':'owner@icloud.com','to':'alice@example.com, owner@icloud.com','cc':'bob@example.com'})
 with app.app_context():
  reply=mail.build_reply('sent-ref','Following up')
  assert reply['to']==['alice@example.com'] and reply['cc']==[]
  assert mail.build_reply('sent-ref','Following up',True)['cc']==['bob@example.com']

@pytest.mark.parametrize('changes',[
 {'message_id':''},{'message_id':'invalid'},{'message_id':'<a@example.com> <b@example.com>'},
 {'references':'<root@example.com>\r\nBcc: attacker@example.com'},
 {'references':'<x@example.com> '*101+'bad'},
 {'reply_to':'bad address'},{'reply_to':'a@example.com\r\nBcc: b@example.com'},
 {'reply_to':'a'*2001},
])
def test_invalid_sources_fail_before_upload(original,cloud,changes):
 original.update(changes)
 with app.app_context(),pytest.raises(mail.MailError):
  drafts.save(mail.build_reply('source-ref','Response'))
 assert cloud.uploads==0 and not cloud.sends

def test_parent_fallback_and_header_parsing(original):
 original.update(references='')
 with app.app_context():
  assert mail.build_reply('source-ref','Response')['references']==['<previous@example.com>','<parent@example.com>']
  original.update(in_reply_to='')
  assert mail.build_reply('source-ref','Response')['references']==['<parent@example.com>']
  original['references']='<root@example.com>\r\n\t<previous@example.com> <root@example.com>'
  assert mail.build_reply('source-ref','Response')['references']==['<root@example.com>','<previous@example.com>','<parent@example.com>']
 for value in ['<no-at>','<@example.com>','<a@>','<a@@b>','<ü@example.com>']:
  with pytest.raises(mail.MailError):mail.message_ids(value)

def test_read_exposes_full_threading_headers():
 msg=email.message_from_bytes(b'Message-ID: <parent@example.com>\r\nReferences: <root@example.com>\r\n <previous@example.com>\r\nIn-Reply-To: <previous@example.com>\r\nReply-To: support@example.com\r\nFrom: alice@example.com\r\n\r\nHi',policy=email.policy.default)
 parsed=mail.extract_message(msg)
 assert mail.message_ids(parsed['references'])==['<root@example.com>','<previous@example.com>']
 assert parsed['reply_to']=='support@example.com'
 assert parsed['reply_addresses']['From']=='alice@example.com'

def test_reply_edit_review_and_once_only_send(original,cloud):
 with app.app_context():
  content_=mail.build_reply('source-ref','First',True)
  first=drafts.save(content_,idempotency_key='reply-key')
  assert drafts.save(content_,idempotency_key='reply-key')['id']==first['id']
  assert cloud.uploads==1
  review=drafts.review(first['id'],actor())
  assert review['message_kind']=='reply'
  assert review['preview']['reply_context']['message_ref']=='source-ref'
  edited=drafts.save(mail.build_draft(first['to'],first['subject'],'Updated',first['cc']),first['id'],first['revision'])
  assert edited['references']==first['references'] and edited['reply_context']==first['reply_context']
  with pytest.raises(mail.MailError,match='cancelled'):drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  current=drafts.review(first['id'],actor())
  drafts.execute(current['action_id'],current['review_token'],actor(),lambda:None)
  drafts.execute(current['action_id'],current['review_token'],actor(),lambda:None)
  assert len(cloud.sends)==1 and cloud.sends[0]['references']==first['references']
  assert cloud.sends[0]['reply_context']==first['reply_context']

def test_reply_cannot_be_retargeted(original,cloud):
 with app.app_context():
  first=drafts.save(mail.build_reply('source-ref','First'))
  original['message_id']='<different@example.com>'
  with pytest.raises(mail.MailError,match='retarget'):
   drafts.save(mail.build_reply('other-ref','Changed'),first['id'],first['revision'])
  assert cloud.uploads==1

def test_missing_thread_guard_and_legacy_pending_review(original,cloud):
 with app.app_context():
  with pytest.raises(mail.MailError,match='source-message link'):
   drafts.save(mail.build_draft(['a@example.com'],'Re: Something','Hello'))
  first=drafts.save(mail.build_draft(['a@example.com'],'Something','Hello'))
  review=drafts.review(first['id'],actor())
  action=db.session.get(Action,review['action_id']);p=decrypt(action.content)
  p['subject']='Re: Something';action.content=encrypt(p);db.session.commit()
  with pytest.raises(mail.MailError,match='source-message link'):
   drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  assert not cloud.sends
  row=drafts.record(first['id']);p=decrypt(row.content);p['subject']='Re: Something';drafts.persist(row,p)
  with pytest.raises(mail.MailError,match='source-message link'):drafts.review(first['id'],actor())

def test_legacy_linked_draft_works_and_missing_source_fails(original,cloud):
 with app.app_context():
  first=drafts.save(mail.build_draft(['a@example.com'],'Re: Project','Hello',reply_to_ref='source-ref'))
  row=drafts.record(first['id']);p=decrypt(row.content)
  p.pop('references');p.pop('reply_context');drafts.persist(row,p)
  review=drafts.review(first['id'],actor())
  assert mail.validate_threading(review['preview'])==['<parent@example.com>']
  edited=drafts.save(mail.build_draft(first['to'],first['subject'],'Edit'),first['id'],first['revision'])
  assert edited['in_reply_to']=='<parent@example.com>'
  upgraded=drafts.save(mail.build_draft(first['to'],first['subject'],'Upgrade',reply_to_ref='source-ref'),first['id'],edited['revision'])
  assert upgraded['references']==['<root@example.com>','<previous@example.com>','<parent@example.com>']
  assert upgraded['reply_context']['message_ref']=='source-ref'
  original['message_id']=''
  with pytest.raises(mail.MailError,match='Message-ID'):
   mail.build_draft(['a@example.com'],'Re: Project','Hello',reply_to_ref='source-ref')

def test_exact_mime_thread_headers_in_drafts_smtp_and_sent(original,monkeypatch):
 captured=[];sent=[]
 class SMTP:
  def __enter__(self):return self
  def __exit__(self,*args):pass
  def send_message(self,msg,from_addr,to_addrs):
   captured.append((msg.as_bytes(),to_addrs));return {}
 class IMAP:
  def list_folders(self):return [([b'\\Sent'],b'/','Sent')]
  def select_folder(self,*a,**kw):return {}
  def search(self,*a):return []
  def append(self,folder,raw,**kw):sent.append(raw)
 @contextlib.contextmanager
 def mailbox(*a):yield IMAP()
 monkeypatch.setattr(mail,'smtp',lambda c:SMTP())
 monkeypatch.setattr(mail,'mailbox',mailbox)
 with app.app_context():
  p=mail.build_reply('source-ref','Response',True)
  p.update(bcc=['private@example.com'],draft_date='Mon, 16 Nov 2026 09:00:00 +0000',
   draft_message_id='<draft@icloud.com>',message_id='<sent@icloud.com>',revision='v1')
  draft=mail.draft_message(p)
  result=mail.send(p)
  assert result['sent_copy']=='saved'
  for raw in [draft.as_bytes(),captured[0][0],sent[0]]:
   parsed=email.message_from_bytes(raw,policy=email.policy.default)
   assert str(parsed['In-Reply-To'])=='<parent@example.com>'
   assert mail.message_ids(str(parsed['References']))==p['references']
  assert b'Bcc:' not in captured[0][0] and b'X-Mailbridge' not in captured[0][0]
  assert b'Bcc:' in sent[0] and 'private@example.com' in captured[0][1]

def test_long_chain_icloud_roundtrip(original,imap):
 original['references']=' '.join(f'<ancestor-{i}@example.com>' for i in range(30))
 with app.app_context():
  p=mail.build_reply('source-ref','Response')
  p.update(draft_date='Mon, 16 Nov 2026 09:00:00 +0000',draft_message_id='<draft@icloud.com>',revision='v1')
  imap.search=lambda *a,**k:[7]
  imap.raw=mail.draft_message(p).as_bytes()
  assert mail.locate_draft(p)['folder']=='Drafts'

def test_mcp_reply_tool_and_legacy_compatibility(client,remote_client,original,cloud):
 _,data=tokens(client);token=data['access_token']
 tools=rpc(remote_client,token,'tools/list').json()['result']['tools']
 tool=next(t for t in tools if t['name']=='create_reply_draft')
 assert set(tool['inputSchema']['required'])=={'message_ref','body'}
 saved=call(remote_client,token,'create_reply_draft',{'message_ref':'source-ref','body':'Hello','idempotency_key':'rpc-reply'})
 assert saved['in_reply_to']=='<parent@example.com>' and saved['sync_status']=='synced'
 review=call(remote_client,token,'request_send',{'draft_id':saved['id']})
 assert review['message_kind']=='reply' and not cloud.sends
 legacy=call(remote_client,token,'save_draft',{'to':['support@example.com'],'subject':'Re: Project','body':'Legacy','reply_to_ref':'source-ref'})
 assert legacy['references']==saved['references']
 _,limited=tokens(client,'mail:write')
 denied=rpc(remote_client,limited['access_token'],'tools/call',{'name':'create_reply_draft','arguments':{'message_ref':'source-ref','body':'Denied'}})
 assert denied.json()['result']['isError'] and 'mail:read' in str(denied.json())
