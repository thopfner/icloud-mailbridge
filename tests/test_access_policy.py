"""Regression checks for public OAuth/MCP and fail-closed owner isolation."""
import pytest
from starlette.testclient import TestClient
from starlette.responses import JSONResponse
from starlette.applications import Starlette
from starlette.routing import Mount
from access_policy import parse_networks,request_allowed,PUBLIC_METHODS,OWNER_METHODS
from main import Boundary
from core import CONFIG,BASE

NETWORKS=parse_networks(['192.0.2.10/32','2001:db8::10/128'])

@pytest.mark.parametrize('path',list(OWNER_METHODS)+['/actions/known-action'])
def test_owner_routes_hidden_from_every_untrusted_peer(path):
 for peer in ['198.51.100.20','192.0.2.11','2001:db8::11','127.0.0.1','invalid']:
  for method in ['GET','POST','HEAD']:
   assert not request_allowed(path,method,peer,NETWORKS)

@pytest.mark.parametrize('path',list(PUBLIC_METHODS))
def test_public_protocol_endpoints_remain_available(path):
 for method in PUBLIC_METHODS[path]:
  assert request_allowed(path,method,'198.51.100.20',NETWORKS)
 assert not request_allowed(path,'PATCH','192.0.2.10',NETWORKS)

@pytest.mark.parametrize('path',['/debug','/login/','//login','/mcp/../account','/mcp////','/oauth/token/','/%6cogin','/actions/../account'])
def test_unknown_paths_fail_closed_for_owner_too(path):
 assert not request_allowed(path,'GET','192.0.2.10',NETWORKS)

def test_owner_requires_exact_network_and_allowed_method():
 for path,methods in OWNER_METHODS.items():
  for method in methods:
   assert request_allowed(path,method,'192.0.2.10',NETWORKS)
   assert request_allowed(path,method,'2001:db8::10',NETWORKS)
  assert not request_allowed(path,'TRACE','192.0.2.10',NETWORKS)
 assert not request_allowed('/login','GET','192.0.2.10',())
 for values in [['0.0.0.0/0'],['::/0'],['bad'],['192.0.2.10/24'],'192.0.2.10/32']:
  with pytest.raises(ValueError):parse_networks(values)

async def sentinel(scope,receive,send):
 await JSONResponse({'reached':True})(scope,receive,send)

def test_asgi_gate_ignores_forged_forwarding_headers(monkeypatch):
 monkeypatch.setitem(CONFIG,'admin_networks',['192.0.2.10/32'])
 with TestClient(Boundary(Starlette(routes=[Mount("/",app=sentinel)])),base_url=BASE,client=('198.51.100.20',1234)) as remote:
  headers={'X-Forwarded-For':'192.0.2.10','X-Real-IP':'192.0.2.10',
   'Forwarded':'for=192.0.2.10','X-Mailbridge-Admin':'1'}
  response=remote.get('/login',headers=headers)
  assert response.status_code==404
  assert response.headers['cache-control']=='no-store'
  assert remote.post('/oauth/token',data={}).status_code==200
  assert remote.post('/mcp',json={}).status_code==200
 with TestClient(Boundary(Starlette(routes=[Mount("/",app=sentinel)])),base_url=BASE,client=('192.0.2.10',1234)) as remote:
  assert remote.get('/login').status_code==200
  assert remote.get('/debug').status_code==404
