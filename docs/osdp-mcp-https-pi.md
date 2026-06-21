# Running osdp-mcp over HTTPS on a Raspberry Pi

This sets up the `osdp-mcp` HTTP transport behind a **reverse proxy that
terminates TLS with a self-signed certificate**, so LAN clients reach the
PD-control surface over `https://<pi>:8443/mcp`.

Design: `osdp-mcp` itself has **no TLS code**. It keeps serving plain HTTP
bound to **loopback** (`127.0.0.1`), and a proxy (Caddy, recommended, or
nginx) handles HTTPS on the LAN-facing port. Binding osdp-mcp to loopback
means the unencrypted, unauthenticated PD-control surface is never exposed
directly — the only way in is through the proxy.

> The MCP streamable-HTTP transport uses **Server-Sent Events** for its
> side channel. A proxy in front of it **must not buffer responses** and
> must allow long-lived connections, or streamed messages stall. Caddy
> does this out of the box; the nginx config below sets it explicitly.

---

## 1. Run osdp-mcp on loopback HTTP

Build/copy the binary to the Pi (cross-compile target is
`aarch64-unknown-linux-gnu`). Run it on the HTTP transport, loopback only.
Serving the reader UI on the same port keeps it behind the one proxy too:

```bash
osdp-mcp --transport http --bind 127.0.0.1:8080 --ui-bind 127.0.0.1:8080
```

### systemd unit (`/etc/systemd/system/osdp-mcp.service`)

```ini
[Unit]
Description=osdp-mcp (virtual OSDP PD, MCP HTTP transport)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/osdp-mcp --transport http --bind 127.0.0.1:8080 --ui-bind 127.0.0.1:8080
# Auto-start the PD on a serial port (optional — omit to configure via MCP).
Environment=OSDP_MCP_PORT=/dev/serial0
Environment=OSDP_MCP_BAUD=9600
Environment=OSDP_MCP_ADDRESS=0
# Secure Channel (optional): none | install | scbk
# Environment=OSDP_MCP_SC_MODE=install
Restart=on-failure
# Serial access without running as root:
SupplementaryGroups=dialout
DynamicUser=yes

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now osdp-mcp
curl -s http://127.0.0.1:8080/mcp -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'   # expect an HTTP response, not connection refused
```

---

## 2. Generate the self-signed certificate

Clients must reach the Pi by a name/IP that appears in the certificate's
**Subject Alternative Name (SAN)**. Cover every form you'll use: the short
hostname, the `.local` mDNS name, and the LAN IP.

```bash
# On the Pi — find what to put in the SAN:
hostname            # e.g. osdp-pi
hostname -I         # e.g. 192.168.1.50

sudo mkdir -p /etc/osdp-mcp

sudo openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /etc/osdp-mcp/osdp-mcp.key \
  -out    /etc/osdp-mcp/osdp-mcp.crt \
  -days 825 \
  -subj "/CN=osdp-pi.local" \
  -addext "subjectAltName=DNS:osdp-pi,DNS:osdp-pi.local,IP:192.168.1.50"
```

Verify the SAN landed (the proxy and clients match against this, not the CN):

```bash
openssl x509 -in /etc/osdp-mcp/osdp-mcp.crt -noout -text | grep -A1 "Subject Alternative Name"
```

### Permissions — the proxy runs as a non-root user

Do **not** `chmod 600` the key as root. Caddy (and nginx) run as their own
service user, so a root-only key gives `permission denied` at startup even
though `sudo caddy validate` passes (validate runs as root, the daemon does
not). Grant the service group read access instead:

```bash
sudo chown root:caddy /etc/osdp-mcp/osdp-mcp.key /etc/osdp-mcp/osdp-mcp.crt
sudo chmod 640 /etc/osdp-mcp/osdp-mcp.key      # group-readable, not world
sudo chmod 644 /etc/osdp-mcp/osdp-mcp.crt
sudo chmod 755 /etc/osdp-mcp                    # service user needs +x to enter the dir
```

Use the proxy's actual group (`nginx`/`www-data` for nginx — check with
`systemctl cat caddy | grep -i group`).

**IP-only variant:** for an IP-only cert (no DNS name), drop the `DNS:`
entries and set the CN to the IP. Reserve a static IP first — the cert
breaks if DHCP hands out a different address:

```bash
  -subj "/CN=192.168.1.50" \
  -addext "subjectAltName=IP:192.168.1.50"
```

Notes:
- Replace `osdp-pi` / `192.168.1.50` with your values. Add more `IP:` /
  `DNS:` entries if the Pi has several addresses (e.g. wired + Wi-Fi).
- `825` days is the max validity many TLS clients accept for leaf certs.
- `-nodes` leaves the key unencrypted so the proxy can start unattended.

---

## 3a. Reverse proxy with Caddy (recommended)

Caddy flushes streaming responses automatically, so MCP's SSE channel works
with no extra tuning.

Install: `sudo apt install caddy` (or the official Caddy apt repo). A fresh
install ships a default `/etc/caddy/Caddyfile` with a `:80` welcome-page
block — replace the whole file with the content below (delete the default
block; it serves the "Caddy works!" page on port 80 otherwise).

`/etc/caddy/Caddyfile`:

```caddyfile
{
	# Use ONLY our self-signed cert: never contact an ACME CA. Note that
	# `auto_https disable_redirects` is NOT enough — that still attempts
	# to obtain certificates. `auto_https off` is the one that disables
	# ACME entirely.
	auto_https off
}

:8443 {
	tls /etc/osdp-mcp/osdp-mcp.crt /etc/osdp-mcp/osdp-mcp.key
	reverse_proxy 127.0.0.1:8080 {
		# rmcp rejects any Host header not in its allowlist (defaults to
		# localhost / 127.0.0.1 / ::1) as DNS-rebinding protection. Caddy
		# forwards the original Host (the Pi's LAN IP) by default, which
		# would be rejected with "Forbidden: Host header is not allowed".
		# Rewrite it to loopback so it matches the allowlist.
		header_up Host 127.0.0.1:8080
	}
}
```

> **The leading colon and formatting matter.** `:8443` means "port 8443, any
> host". A bare `8443` (no colon) is parsed as a *hostname* and Caddy then
> binds the default HTTPS port **443**, not 8443 — a common surprise. Caddy
> is also whitespace-sensitive (indent directives with tabs); run
> `sudo caddy fmt --overwrite /etc/caddy/Caddyfile` to normalise it. A
> host-less `:8443` is used here on purpose so it matches whether the client
> connects by IP or by name in the SAN.

Apply and verify it's actually on 8443 (not 443):

```bash
sudo caddy fmt --overwrite /etc/caddy/Caddyfile
sudo systemctl restart caddy
sudo systemctl status caddy --no-pager      # expect active (running)
sudo ss -tlnp | grep caddy                  # expect *:8443 (plus admin 127.0.0.1:2019)
sudo journalctl -u caddy -n 20 --no-pager   # should be quiet: no tls.obtain / acme lines
```

The `tls <cert> <key>` line tells Caddy to use the self-signed pair. Clients
connect to `https://<pi>:8443/mcp` (and `https://<pi>:8443/` for the reader
UI), using a name/IP that's in the cert SAN.

Harmless warnings you can ignore in the log: `no OCSP stapling ... no OCSP
server specified` (expected for self-signed) and `automatic HTTPS is
completely disabled for server` (that's `auto_https off` working).

---

## 3b. Reverse proxy with nginx (alternative)

`sudo apt install nginx`, then `/etc/nginx/sites-available/osdp-mcp`:

```nginx
server {
    listen 8443 ssl;
    server_name osdp-pi.local osdp-pi 192.168.1.50;

    ssl_certificate     /etc/osdp-mcp/osdp-mcp.crt;
    ssl_certificate_key /etc/osdp-mcp/osdp-mcp.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_http_version 1.1;
        # rmcp only accepts loopback Host headers (DNS-rebinding guard).
        # Forwarding the original $host (the Pi's LAN IP) gets a
        # "Forbidden: Host header is not allowed". Rewrite to loopback.
        proxy_set_header   Host 127.0.0.1:8080;
        proxy_set_header   Connection "";

        # Critical for the MCP SSE side channel:
        proxy_buffering    off;          # stream chunks straight through
        proxy_cache        off;
        proxy_read_timeout 1h;           # don't time out a long-lived stream
        chunked_transfer_encoding off;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/osdp-mcp /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

---

## 4. Firewall

If `ufw` is enabled, open the HTTPS port (and ensure 8080 stays closed to
the LAN — osdp-mcp is loopback-only, so this is belt-and-suspenders):

```bash
sudo ufw allow 8443/tcp
```

---

## 5. Trusting the cert on clients

A self-signed cert is not in any system trust store, so each client must be
told to trust it. Copy `/etc/osdp-mcp/osdp-mcp.crt` to the client and:

- **curl test** (note the `accept` header — rmcp requires *both* types):
  ```bash
  curl --cacert osdp-mcp.crt https://osdp-pi.local:8443/mcp \
    -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'
  ```
  Without the `accept` header you'll get `Not Acceptable: Client must accept
  both application/json and text/event-stream` — that's the server being
  reached successfully, just a missing client header. Real MCP clients send
  it automatically.
- **Node-based MCP clients:** point `NODE_EXTRA_CA_CERTS` at the file:
  ```bash
  export NODE_EXTRA_CA_CERTS=/path/to/osdp-mcp.crt
  ```
- **OS trust store (system-wide):**
  - Linux: copy to `/usr/local/share/ca-certificates/osdp-mcp.crt`, then
    `sudo update-ca-certificates`.
  - macOS: add to the login keychain and mark "Always Trust".
  - Windows: import into "Trusted Root Certification Authorities".

Always connect using a name/IP that is in the cert SAN (step 2), or
verification fails even with the cert trusted.

A healthy end-to-end test (`curl -v`) shows the TLS handshake completing with
`subjectAltName: host "<ip>" matched cert's IP address!` and
`SSL certificate verify ok`, then an HTTP status from osdp-mcp. osdp-mcp
answers a bare `ping` with **`HTTP/2 200`** and an empty body
(`content-length: 0`) — that empty 200 is success: it proves TLS terminated
*and* the proxy reached osdp-mcp on `127.0.0.1:8080`.

---

## 6. Connecting a Claude MCP client

osdp-mcp is a **remote streamable-HTTP** endpoint, so add it as an HTTP MCP
server (not a stdio `command`). The client (Node, under the hood) must trust
the self-signed cert — point `NODE_EXTRA_CA_CERTS` at the copied `.crt`.

### Claude Code (CLI)

Claude Code speaks HTTP transport natively:

```bash
claude mcp add --transport http osdp-mcp https://192.168.105.115:8443/mcp
```

- `-s user` makes it available in every project; default scope is `local`
  (current project only); `-s project` writes a shareable `.mcp.json`.
- Trust the cert in the environment that launches `claude`:
  - Windows (persistent): `setx NODE_EXTRA_CA_CERTS "C:\osdp\osdp-mcp.crt"`,
    then restart the terminal.
  - Per-session: `$env:NODE_EXTRA_CA_CERTS="C:\osdp\osdp-mcp.crt"` (PowerShell)
    or `export NODE_EXTRA_CA_CERTS=/path/to/osdp-mcp.crt` (bash).
- Verify: `claude mcp list`, or `/mcp` inside a session.

### Claude Desktop

Desktop's config doesn't take a raw HTTPS URL for custom servers; bridge it
with `mcp-remote` (a stdio↔HTTP shim). Edit
`%APPDATA%\Claude\claude_desktop_config.json` (Windows) or
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "osdp-mcp": {
      "command": "npx",
      "args": ["mcp-remote", "https://192.168.105.115:8443/mcp"],
      "env": { "NODE_EXTRA_CA_CERTS": "C:\\osdp\\osdp-mcp.crt" }
    }
  }
}
```

Restart Desktop. (Newer builds also expose **Settings → Connectors → Add
custom connector** for a URL, but the `mcp-remote` route reliably handles the
self-signed cert.)

Connect using the **IP/name in the cert SAN** — a different one fails
verification even with the cert trusted.

---

## Troubleshooting

Symptoms seen while bringing this up, and what they mean:

| Symptom | Cause | Fix |
| --- | --- | --- |
| `sudo caddy validate` passes but the service fails with `open ...key: permission denied` | `validate` runs as root; the daemon runs as the `caddy` user and can't read a root-only `chmod 600` key | `chown root:caddy` + `chmod 640` the key, `chmod 755` the dir (step 2) |
| Log shows `tls.obtain` / contacting `acme-v02.api.letsencrypt.org` or `acme.zerossl.com` | `auto_https disable_redirects` does **not** stop ACME | Use `auto_https off` in the global block |
| ACME identifier is your *port* (e.g. `"8443"`) | site address written without a colon (`8443`) is parsed as a hostname | Use `:8443` (leading colon) |
| `ss -tlnp` shows Caddy on `:443` instead of `:8443` | same missing-colon issue — bare `8443` → default HTTPS port 443 | Use `:8443`; re-check with `sudo ss -tlnp \| grep caddy` |
| `caddy fmt` warns "input is not formatted" / directives ignored | Caddyfile is whitespace-sensitive (tabs to indent) | `sudo caddy fmt --overwrite /etc/caddy/Caddyfile` |
| curl: `SSL: no alternative certificate subject name matches` | connecting by a name/IP not in the cert SAN | reissue cert with the right SAN, or connect via a SAN entry |
| curl: `Connection refused` after TLS | osdp-mcp isn't listening on `127.0.0.1:8080` | `systemctl status osdp-mcp`; confirm `--bind 127.0.0.1:8080` |
| `Forbidden: Host header is not allowed` | rmcp's DNS-rebinding guard rejects the forwarded LAN-IP Host (allowlist is loopback only) | rewrite the upstream Host to loopback at the proxy (`header_up Host 127.0.0.1:8080` / nginx `proxy_set_header Host 127.0.0.1:8080`) |
| `Not Acceptable: Client must accept both application/json and text/event-stream` | client didn't send the required `Accept` header | add `-H 'accept: application/json, text/event-stream'` (real MCP clients do this automatically) — the server was reached, so this confirms the proxy works |
| MCP stream appears to hang (nginx) | response buffering breaks SSE | `proxy_buffering off` + long `proxy_read_timeout` (step 3b) |
| Claude client: `self-signed certificate` / TLS error on connect | client (Node) doesn't trust the cert | set `NODE_EXTRA_CA_CERTS` to the copied `.crt` in the env that launches the client; restart it (step 6) |

Note: a self-signed cert with no `DNS:`/`IP` SAN entry, only a CN, is
rejected by modern clients — the SAN is mandatory (step 2).

---

## Security note

The osdp-mcp HTTP surface (script replies, inject events, force session
loss) is **unauthenticated** — TLS here gives you encryption and server
identity, not access control. On an untrusted LAN, add authentication at the
proxy (e.g. Caddy `basic_auth`, or nginx `auth_basic`) in front of the
`/mcp` route.
