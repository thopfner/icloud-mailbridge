"""Default-deny HTTP surface. Owner access is an extra gate, never authentication."""
from ipaddress import ip_address, ip_network
import re

PUBLIC_METHODS = {
 '/mcp': {'GET', 'POST', 'DELETE'},
 '/mcp/': {'GET', 'POST', 'DELETE'},
 '/.well-known/oauth-authorization-server': {'GET', 'HEAD'},
 '/.well-known/oauth-protected-resource': {'GET', 'HEAD'},
 '/.well-known/oauth-protected-resource/mcp': {'GET', 'HEAD'},
 '/oauth/register': {'POST'},
 '/oauth/token': {'POST'},
 '/oauth/revoke': {'POST'},
 '/privacy': {'GET', 'HEAD'},
}
OWNER_METHODS = {
 '/': {'GET', 'HEAD'}, '/login': {'GET', 'HEAD', 'POST'},
 '/account': {'GET', 'HEAD', 'POST'}, '/logout': {'POST'},
 '/revoke-all': {'POST'}, '/oauth/authorize': {'GET', 'HEAD', 'POST'},
 '/style.css': {'GET', 'HEAD'}, '/healthz': {'GET', 'HEAD'},
}

def parse_networks(values):
 if not isinstance(values, list):
  raise ValueError('admin_networks must be a list of explicit CIDRs')
 networks = tuple(ip_network(value, strict=True) for value in values)
 if any(network.prefixlen == 0 for network in networks):
  raise ValueError('Unrestricted administration networks are forbidden')
 return networks

def request_allowed(path, method, peer, networks):
 if path in PUBLIC_METHODS:
  return method in PUBLIC_METHODS[path]
 methods = OWNER_METHODS.get(path)
 if methods is None and re.fullmatch(r'/actions/[A-Za-z0-9_-]{1,128}', path):
  methods = {'GET', 'HEAD', 'POST'}
 if not methods or method not in methods:
  return False
 try:
  address = ip_address(peer)
 except ValueError:
  return False
 return any(address in network for network in networks)
