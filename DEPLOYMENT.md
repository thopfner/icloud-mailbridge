# Deployment on your own VPS

This guide is for an experienced Linux administrator. Use your own domain,
trusted device addresses and fresh credentials. Examples are placeholders.
Do not run this over an existing production installation without a backup and
a reviewed migration plan. The source is not an automatic server installer.

## 1. Prepare the host

The source deployment uses Python 3.14, systemd, Caddy and SQLCipher. On a
Debian/Ubuntu host install Python/venv/development headers, a compiler,
pkg-config and libsqlcipher-dev through your supported distribution. Install
Caddy from its official repository. Use a supported OS and enable security
updates. Check installed versions before proceeding.

Provision a private VPN between your administrator device and VPS. Restrict
SSH to that device, use keys and disable password/keyboard-interactive login.
Test a second login and provider-console recovery before closing the first.
The management commands check SSH configuration before accepting credentials.

Point your public DNS hostname to the VPS for HTTPS MCP access. The owner
browser must resolve the same hostname to the VPN address (private DNS or a
device hosts entry) to reach private owner routes. Keep certificate validation
enabled; do not use a self-signed bypass.

## 2. Install source and dependencies

The supplied units expect /opt/mailbridge. On a new host, as root:

```sh
useradd --system --home /var/lib/mailbridge --shell /usr/sbin/nologin mailbridge
git clone https://github.com/thopfner/icloud-mailbridge.git /opt/mailbridge
cd /opt/mailbridge
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip check
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider
```

Confirm that your Python version is compatible with the pinned dependencies.
sqlcipher3 may compile against your installed SQLCipher library; verify actual
SQLCipher support, not merely ordinary sqlite3:

```sh
.venv/bin/python -c "from sqlcipher3 import dbapi2; c=dbapi2.connect(':memory:'); print(c.execute('PRAGMA cipher_version').fetchone())"
```

A missing result is not a working SQLCipher installation. Test suite failures
must be resolved before connecting mail. Do not alter pinned dependencies just
to suppress errors without running regression tests.

## 3. Create fresh private configuration

```sh
install -d -o root -g mailbridge -m 0750 /etc/mailbridge
install -d -o mailbridge -g mailbridge -m 0700 /var/lib/mailbridge
install -d -o mailbridge -g mailbridge -m 0700 /var/backups/mailbridge
install -o root -g mailbridge -m 0640 deploy/config.example.json /etc/mailbridge/config.json
```

Edit /etc/mailbridge/config.json privately:

```json
{
  "base_url": "https://mail.example.com",
  "admin_networks": ["192.0.2.10/32"]
}
```

Replace the hostname and documentation-only address with your own hostname and
administrator device VPN address. The shipped empty array denies all owner
access. Never use a /0 network or an entire shared VPN when only one device
should administer the service.

Generate a new master key without printing it, using exclusive creation so an
existing key can never be overwritten by rerunning this command:

```sh
.venv/bin/python - <<'PYKEY'
import os
from cryptography.fernet import Fernet
fd = os.open('/etc/mailbridge/master.key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as stream:
    stream.write(Fernet.generate_key() + b'\n')
PYKEY
```

Keep an independently secured copy of the key. Losing it makes encrypted data
unrecoverable. Never commit it or enter it in chat.

## 4. Configure Caddy and systemd

Review deploy/Caddyfile; replace mail.example.com with your hostname.
Integrate it into /etc/caddy/Caddyfile, preserving any existing services.
Install deploy/mailbridge-admin.example.caddy as
/etc/caddy/mailbridge-admin.caddy and replace its documentation-only address.
Its @owner remote_ip must match config.json admin_networks.

Permit public TCP 80/443 as needed, keep TCP 8765 loopback-only, and keep SSH
private. The supplied config assumes direct Caddy ingress, without a CDN or
another proxy. Review both IPv4 and IPv6 exposure. Do not loosen proxy-header
trust to bypass access problems.

Make code root-owned/readable by the service, then install units:

```sh
chown -R root:mailbridge /opt/mailbridge
chmod -R g+rX,o-rwx /opt/mailbridge
install -m 0644 deploy/*.service deploy/*.timer /etc/systemd/system/
systemctl daemon-reload
caddy validate --config /etc/caddy/Caddyfile
```

The service uses systemd LoadCredential for the root-only key. Never change
its mode to make it readable by every process. Run exactly one Uvicorn worker.

## 5. Establish the owner and connect iCloud

Before starting the application, run privately in a trusted SSH terminal:

```sh
/opt/mailbridge/bin/mailbridge setup-owner
/opt/mailbridge/bin/mailbridge setup-mail
```

Choose a unique password, enroll the authenticator and enter a fresh TOTP.
Use an Apple app-specific password for iCloud, not the main Apple Account
password. Setup checks IMAP and SMTP authentication without sending mail.

For future owner/mailbox replacement, stop the app and indexing workers first;
setup initialization and revocation are maintenance operations. Do not run
setup commands concurrently with live mailbox actions.

Start the app and reverse proxy after configuration is complete:

```sh
systemctl enable --now mailbridge
systemctl enable caddy
systemctl restart caddy
systemctl enable --now mailbridge-maintenance.timer mailbridge-backup.timer
systemctl enable --now mailbridge-index.timer mailbridge-index-nightly.timer
```

The example nightly timer and briefings use Europe/Amsterdam. Review the
timer and documented date semantics before changing them for another region.

## 6. Verify and connect the client

- Check systemctl status mailbridge caddy and service logs for startup errors.
- From the trusted private path, /login should load over valid HTTPS.
- From outside that network, /login and other owner routes must return 404.
- Public OAuth discovery must work; unauthenticated /mcp must reject access.
- Verify both direct-ASGI and proxy access rules; never expose port 8765.
- Run an encrypted backup and verify it succeeds before relying on storage.

Add https://YOUR_HOST/mcp to a compatible ChatGPT account as a custom MCP
connection using OAuth/dynamic registration. Sign in and approve scopes from
the trusted administration network. Refresh tool descriptions after upgrades.

Test first with synthetic draft content. Inspect recipients and quoted body
in both ChatGPT and Apple Mail. Sending always requires an explicit user
instruction; do not send unsolicited test messages.

## Updates

Back up first. Stop indexing timers/workers and the app, install a reviewed
release with its pinned dependencies, run isolated tests, review configuration
changes, then restart and check readiness before restarting timers. Keep the
previous source/configuration and backup for rollback. Refresh MCP tools when
descriptions or schemas change.

See SECURITY_OPERATIONS.md for revocation, recovery and trust boundaries.

## Using a deployment agent

Give the agent administrator access to your own fresh Linux VPS and point it
to this guide. Have it check Python 3.14 availability before creating the
virtual environment, verify SQLCipher returns a version, and run the suite with
the pinned dependencies. Use the Python 3.14 interpreter explicitly if your
distribution's default python3 is older.

The agent can configure the service, DNS and private access where you grant
the required permissions. Take over in a private terminal for owner password,
authenticator enrollment and Apple app-specific password entry. Complete the
ChatGPT OAuth consent in your browser over the trusted network. Confirm a
synthetic reply draft appears in Apple Mail before using your real conversations.
