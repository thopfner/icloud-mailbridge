import copy,contextlib,email,email.policy
from email.message import EmailMessage
import pytest
from core import *
import mail,drafts
from test_drafts import cloud,actor
from test_replies import original
from conftest import tokens
from test_drafts import call

@pytest.fixture
def quoted_original(original):
 original['body']='Original paragraph.\n\nSecond paragraph.\n\nOn yesterday, Bob wrote:\n> Earlier conversation.\n>> Oldest text.'
 original['body_truncated']=False
 return original

def test_new_reply_quotes_full_source_with_nested_history(quoted_original):
 with app.app_context():
  p=mail.build_reply('source-ref','My new reply.')
 assert p['reply_text']=='My new reply.'
 assert p['body']==p['reply_text']+'\n\n'+p['quoted_history']
 assert p['quoted_history'].startswith('On Mon, 16 Nov 2026 09:00:00 +0000, Alice <alice@example.com> wrote:\n')
 assert '> Original paragraph.\n>\n> Second paragraph.' in p['body']
 assert '> > Earlier conversation.' in p['body']
 assert '> >> Oldest text.' in p['body']
 assert p['body'].count(p['quoted_history'])==1

def test_legacy_reply_parameter_also_quotes(quoted_original):
 with app.app_context():
  p=mail.build_draft(['alice@example.com'],'Re: Project','Reply',reply_to_ref='source-ref')
 assert p['reply_text']=='Reply' and '> Original paragraph.' in p['body']

def test_edit_new_text_or_full_preview_does_not_duplicate_quote(quoted_original,cloud,monkeypatch):
 with app.app_context():
  p=mail.build_reply('source-ref','First')
  first=drafts.save(p,idempotency_key='quote-create')
  assert drafts.save(p,idempotency_key='quote-create')['id']==first['id']
  review=drafts.review(first['id'],actor())
  monkeypatch.setattr(mail,'read',lambda ref:pytest.fail('Edits must use the stored quote, not re-fetch/rewrite history'))
  edited=drafts.save(mail.build_draft(first['to'],first['subject'],'Second'),first['id'],first['revision'])
  assert edited['quoted_history']==first['quoted_history']
  assert edited['body']=='Second\n\n'+first['quoted_history']
  full=edited['body'].replace('Second','Third',1)
  edited2=drafts.save(mail.build_draft(first['to'],first['subject'],full),first['id'],edited['revision'])
  assert edited2['reply_text']=='Third'
  assert edited2['body'].count(first['quoted_history'])==1
  with pytest.raises(mail.MailError,match='cancelled'):
   drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  current=drafts.review(first['id'],actor())
  assert current['preview']['body']==edited2['body']
  drafts.execute(current['action_id'],current['review_token'],actor(),lambda:None)
  assert cloud.sends[0]['body']==edited2['body']

def test_modified_or_repeated_quote_fails_without_upload(quoted_original,cloud):
 with app.app_context():
  first=drafts.save(mail.build_reply('source-ref','First'))
  for body in [first['body'].replace('Original paragraph.','Altered past message.'),
               first['body']+'\n\n'+first['quoted_history']]:
   with pytest.raises(mail.MailError,match='altered or duplicated'):
    drafts.save(mail.build_draft(first['to'],first['subject'],body),first['id'],first['revision'])
  assert cloud.uploads==1

def test_quote_validation_prevents_changed_review_body(quoted_original,cloud):
 with app.app_context():
  first=drafts.save(mail.build_reply('source-ref','First'))
  review=drafts.review(first['id'],actor())
  row=db.session.get(Action,review['action_id']);p=decrypt(row.content)
  p['body']=p['reply_text'];row.content=encrypt(p);db.session.commit()
  with pytest.raises(mail.MailError,match='quoted history'):
   drafts.execute(review['action_id'],review['review_token'],actor(),lambda:None)
  assert not cloud.sends

@pytest.mark.parametrize('changes,new_text',[
 ({'body_truncated':True},'Hello'),
 ({'body':'x'*30000},'y'*25000),
 ({'body':'\n'.join(['x']*15000)},'y'*100),
])
def test_no_silent_truncation_or_oversize_upload(quoted_original,cloud,changes,new_text):
 quoted_original.update(changes)
 with app.app_context(),pytest.raises(mail.MailError):
  drafts.save(mail.build_reply('source-ref',new_text))
 assert cloud.uploads==0

def test_new_messages_unchanged_and_blank_parent_disclosed(original):
 with app.app_context():
  new=mail.build_draft(['a@example.com'],'New conversation','Just this text')
  assert new['body']=='Just this text' and 'quoted_history' not in new
  empty=mail.build_reply('source-ref','My reply')
  assert 'No readable text' in empty['quoted_history']

def test_html_only_parent_preserves_paragraphs_and_quote_depth(original,monkeypatch):
 msg=EmailMessage(policy=email.policy.default)
 msg['From']='alice@example.com';msg['To']='owner@icloud.com'
 msg['Message-ID']='<parent@example.com>';msg['Subject']='HTML test'
 msg.set_content('<html><head><style>SECRET_STYLE</style></head><body><p>Hello <b>friend</b>.</p><p>Next line<br>After break</p><blockquote><p>Previous text.</p><blockquote>Older text.</blockquote></blockquote><script>SECRET_SCRIPT</script><img src="https://tracker.invalid/pixel"></body></html>',subtype='html')
 parsed=mail.extract_message(msg)
 assert 'Hello friend.' in parsed['body'] and 'Next line\nAfter break' in parsed['body']
 assert '> Previous text.' in parsed['body'] and '> > Older text.' in parsed['body']
 assert not any(x in parsed['body'] for x in ['SECRET_SCRIPT','SECRET_STYLE','tracker.invalid','<html>'])
 monkeypatch.setattr(mail,'read',lambda ref:parsed)
 with app.app_context():p=mail.build_reply('html-ref','New reply')
 assert '> > Previous text.' in p['body'] and '> > > Older text.' in p['body']

def test_plain_alternative_preferred_over_html_no_duplicate(original):
 msg=EmailMessage(policy=email.policy.default)
 msg['Message-ID']='<p@example.com>'
 msg.set_content('Plain original.\n\nParagraph two.')
 msg.add_alternative('<p>HTML_DUPLICATE</p>',subtype='html')
 parsed=mail.extract_message(msg)
 assert 'Plain original.' in parsed['body'] and 'HTML_DUPLICATE' not in parsed['body']

def test_pre_update_review_not_silently_rewritten_and_draft_can_upgrade(quoted_original,cloud):
 with app.app_context():
  p=mail.build_reply('source-ref','Old text')
  p.pop('quoted_history');p.pop('reply_text');p['body']='Old text'
  first=drafts.save(p)
  old_review=drafts.review(first['id'],actor())
  assert old_review['preview']['body']=='Old text'
  upgraded=drafts.save(mail.build_draft(first['to'],first['subject'],'Updated',reply_to_ref='source-ref'),first['id'],first['revision'])
  assert '> Original paragraph.' in upgraded['body']
  with pytest.raises(mail.MailError,match='cancelled'):
   drafts.execute(old_review['action_id'],old_review['review_token'],actor(),lambda:None)

def test_complete_quoted_body_survives_draft_smtp_and_sent_mime(quoted_original,monkeypatch):
 sent=[];outgoing=[]
 class SMTP:
  def __enter__(self):return self
  def __exit__(self,*a):pass
  def send_message(self,msg,**kwargs):outgoing.append(msg.as_bytes());return {}
 class IMAP:
  def list_folders(self):return [([b'\\Sent'],b'/','Sent')]
  def select_folder(self,*a,**k):return {}
  def search(self,*a):return []
  def append(self,folder,raw,**kwargs):sent.append(raw)
 @contextlib.contextmanager
 def box(*a):yield IMAP()
 monkeypatch.setattr(mail,'smtp',lambda c:SMTP())
 monkeypatch.setattr(mail,'mailbox',box)
 with app.app_context():
  p=mail.build_reply('source-ref','Reply with Unicode — café.')
  p.update(draft_date='Mon, 16 Nov 2026 09:00:00 +0000',draft_message_id='<draft@example.com>',
   message_id='<sent@example.com>',revision='revision')
  draft=mail.draft_message(p).as_bytes()
  assert mail.send(p)['smtp_accepted']
 for raw in [draft,outgoing[0],sent[0]]:
  msg=email.message_from_bytes(raw,policy=email.policy.default)
  assert msg.get_content().replace('\r\n','\n').rstrip('\n')==p['body']
  assert str(msg['In-Reply-To'])=='<parent@example.com>'

def test_mcp_preview_documents_full_quote(client,remote_client,quoted_original,cloud):
 _,data=tokens(client);token=data['access_token']
 saved=call(remote_client,token,'create_reply_draft',{'message_ref':'source-ref','body':'New text','idempotency_key':'mcp-quote'})
 assert saved['reply_text']=='New text' and '> Original paragraph.' in saved['body']
 review=call(remote_client,token,'request_send',{'draft_id':saved['id']})
 assert review['preview']['body']==saved['body']
 assert 'COMPLETE outgoing text' in review['instruction']

def test_attached_email_text_is_not_automatically_quoted(original,monkeypatch):
 parent=EmailMessage(policy=email.policy.default)
 parent['From']='alice@example.com';parent['To']='owner@icloud.com';parent['Message-ID']='<parent@example.com>'
 parent['Subject']='Attachment test'
 parent.set_content('Visible parent body.')
 attached=EmailMessage(policy=email.policy.default)
 attached['From']='private@example.com';attached['Subject']='Private attachment'
 attached.set_content('PRIVATE_ATTACHED_EMAIL_CONTENT')
 parent.add_attachment(attached,filename='private.eml')
 parent.add_attachment('PRIVATE_TEXT_ATTACHMENT',filename='private.txt')
 parsed=mail.extract_message(parent)
 assert 'Visible parent body.' in parsed['body']
 assert 'PRIVATE_ATTACHED_EMAIL_CONTENT' not in parsed['body']
 assert 'PRIVATE_TEXT_ATTACHMENT' not in parsed['body']
 monkeypatch.setattr(mail,'read',lambda ref:parsed)
 with app.app_context():reply=mail.build_reply('source-ref','New reply')
 assert 'PRIVATE_' not in reply['body']

def test_multiple_plain_body_parts_use_real_line_breaks():
 msg=EmailMessage(policy=email.policy.default);msg.make_mixed()
 for text in ['First body part.','Second body part.']:
  part=EmailMessage(policy=email.policy.default);part.set_content(text);msg.attach(part)
 body=mail.extract_message(msg)['body']
 assert 'First body part.\n\nSecond body part.' in body
 assert '\\n' not in body
