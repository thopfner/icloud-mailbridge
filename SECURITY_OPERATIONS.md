# Security operations

## Network boundary

Expose only HTTP/HTTPS as required for TLS renewal and the public MCP/OAuth
endpoints. Restrict SSH to the administrator's private VPN device and require
key authentication. Preserve provider-console recovery and verify a second
private SSH connection before tightening firewall rules.

Caddy's exact public route allowlist is in deploy/Caddyfile. Owner login,
dashboard, account, OAuth consent and health routes additionally require a
trusted source CIDR. The application enforces the same restriction; unknown
routes fail closed.

Keep these allowlists identical:

- /etc/caddy/mailbridge-admin.caddy: @owner remote_ip
- /etc/mailbridge/config.json: admin_networks

Empty admin_networks denies owner access. Unrestricted /0 networks are rejected.
The browser used for initial OAuth consent or reauthorization must reach the
server through the allowed private network, using the same HTTPS hostname and
a valid certificate. Connected MCP calls use public HTTPS.

Caddy checks the direct socket peer. Uvicorn trusts proxy headers only from
loopback Caddy and binds to 127.0.0.1:8765. Do not expose this backend or trust
arbitrary proxies. The supplied deployment is for direct Caddy ingress; adding
a CDN/load balancer requires a separate trust-boundary review.

Configure VPN ACLs and firewall behavior deliberately; a VPN alone does not
imply device-only access. Monitor device-key expiry and retain recovery access.

## Credentials and service isolation

Keep /etc/mailbridge/master.key root-owned mode 0600. systemd LoadCredential
delivers it only to the service. App code is root-owned and not writable by
the mailbridge runtime user. State is mode 0700 and owned by mailbridge.

Never serve /opt/mailbridge, /etc/mailbridge or /var/lib/mailbridge as static
web directories. Do not log request authorization headers, bodies or mailbox
content. Do not commit runtime state, keys, backups or actual configuration.

The master key encrypts credentials and sensitive records. The independent
SQLCipher index key is derived from it. Root or running-service compromise
can still expose mail credentials. Encryption does not remove this risk.

## Revocation and incidents

Privately run /opt/mailbridge/bin/mailbridge revoke-all to revoke sessions,
OAuth families and pending reviews. Disconnect the mailbox through private
administration when necessary. Revoke the app-specific password at Apple if
compromise is suspected; local revocation alone is insufficient.

Investigate the VPS, administrator device, registrar, provider account and
ChatGPT account. Recover on a trusted host; replace exposed keys/passwords and
reauthorize only after the incident is contained. setup-owner replaces owner
authentication and revokes old access.

## Backups and recovery

The backup timer creates authenticated encrypted main-database/config backups
in /var/backups/mailbridge and retains seven. The master key and rebuildable
index are deliberately excluded. Maintain independent, access-controlled
off-server copies of backups and the key; local backups do not survive VPS loss.

Before recovery, stop the app and timers. Use only a trusted backup and its
matching key; verify authentication and SQLite integrity. Restore mailbridge.db
and config.json to their documented paths with correct ownership/permissions.
Do not combine a restored database with stale WAL/SHM files. Revoke all
connections after recovery, restart, verify health and rebuild the index.

Do not blindly restore older network configuration: it may reopen access.
Validate sshd/Caddy configuration before changes and retain a working recovery
session. With Caddy admin off, validate then restart Caddy rather than reload.

## Regular checks

- Monitor service health, indexing freshness, disk space and backup success.
- Apply OS updates; audit and test pinned dependency updates before deployment.
- Check VPN device/key expiry, OAuth revocation and administrator access.
- Verify public owner routes remain denied and unauthenticated MCP rejected.
- Review metadata-only audit records without exposing mail content.
