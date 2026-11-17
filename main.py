import asyncio,logging
from contextlib import asynccontextmanager
from starlette.applications import Starlette
from starlette.routing import Mount
from a2wsgi import WSGIMiddleware
from starlette.responses import JSONResponse
from core import app,initialize,BASE,rate_limit,CONFIG
from access_policy import parse_networks,request_allowed
import web
from service import mcp
initialize()
for name in ('authlib','mcp','httpx','httpcore'): logging.getLogger(name).setLevel(logging.WARNING)
mcp_app=mcp.streamable_http_app()
web_app=WSGIMiddleware(app)
@asynccontextmanager
async def lifespan(server):
 async with mcp.session_manager.run(): yield
class Dispatch:
 async def __call__(self,scope,receive,send):
  target=mcp_app if scope.get('path','').rstrip('/')=='/mcp' else web_app
  await target(scope,receive,send)
server=Starlette(routes=[Mount('/',app=Dispatch())],lifespan=lifespan)
class Boundary:
 def __init__(self,inner):
  self.inner=inner; self.slots=asyncio.Semaphore(8)
  self.admin_networks=parse_networks(CONFIG.get("admin_networks",[]))
 async def __call__(self,scope,receive,send):
  if scope['type']!='http': return await self.inner(scope,receive,send)
  headers={k.lower():v for k,v in scope['headers']}
  if headers.get(b'host',b'').decode()!=BASE.split('/')[2] or scope['scheme']!='https':
   return await JSONResponse({'error':'invalid_origin'},status_code=400)(scope,receive,send)
  origin=headers.get(b'origin')
  if origin and origin.decode() not in (BASE,'https://chatgpt.com'):
   return await JSONResponse({'error':'invalid_origin'},status_code=403)(scope,receive,send)
  if len(scope['path'])>2048 or len(scope.get('query_string',b''))>4096:
   return await JSONResponse({'error':'request_too_large'},status_code=413)(scope,receive,send)
  peer=scope.get('client') or ('unknown',0)
  if not request_allowed(scope['path'],scope['method'],str(peer[0]),self.admin_networks):
   return await JSONResponse({'error':'not_found'},status_code=404,headers={'Cache-Control':'no-store'})(scope,receive,send)
  chunks=[]; size=0
  try:
   async with asyncio.timeout(10):
    while True:
     event=await receive()
     if event['type']=='http.disconnect': return
     size+=len(event.get('body',b''))
     if size>131072:
      return await JSONResponse({'error':'request_too_large'},status_code=413)(scope,receive,send)
     chunks.append(event.get('body',b''))
     if not event.get('more_body'): break
  except asyncio.TimeoutError:
   return await JSONResponse({'error':'request_timeout'},status_code=408)(scope,receive,send)
  peer=scope.get('client') or ('unknown',0)
  with app.app_context():
   allowed=rate_limit('http',str(peer[0]),240,60)
  if not allowed:
   return await JSONResponse({'error':'rate_limited'},status_code=429)(scope,receive,send)
  delivered=False
  async def buffered():
   nonlocal delivered
   if not delivered:
    delivered=True
    return {'type':'http.request','body':b''.join(chunks),'more_body':False}
   return await receive()
  async with self.slots:
   await self.inner(scope,buffered,send)
application=Boundary(server)
