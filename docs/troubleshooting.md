# Jen Troubleshooting Reference

---

## Before opening an issue: attach a support bundle (v5.33.0)

**Settings → System → Support bundle → Download** produces
`jen-support-<host>-<date>.zip` with everything a bug report needs —
versions and channel, Health Center results, HA state, drift, each
server's latest Kea config, plugin state, schema versions, recent audit
and alert rows, and a scrubbed tail of the Jen log. Passwords, keys,
tokens and secrets are masked before anything is written and the
archive is built in memory, never stored. Read `README.txt` inside it
if you want to check what was included. If Jen logs to journald (no
`[server] log_file`), also attach `journalctl -u jen -n 500 --no-pager`.

If Jen itself won't start, the bundle can't be made; the sections
below cover that.

## Jen Won't Start

**Check the logs first:**
```bash
sudo journalctl -u jen -n 50 --no-pager
```

### SyntaxError on start

The application tree is corrupted or incompatible with your Python
version. As of v5.14.0 the live code is under
`/opt/jen/current/app/` (a symlink to `releases/<X.Y.Z>/app/`); older
installs have it flat at `/opt/jen/`.

```bash
sudo /opt/jen/current/venv/bin/python -m compileall -q /opt/jen/current/app/jen
```

Fix: `sudo ./install.sh --repair` from the tarball rebuilds the current
release's `app/` and `venv/` and re-activates it.

### Config file not found

```
FileNotFoundError: Config file not found: /etc/jen/jen.config
```

Fix:
```bash
sudo cp /path/to/jen/jen.config.example /etc/jen/jen.config
sudo nano /etc/jen/jen.config    # fill in your values
sudo chown root:www-data /etc/jen/jen.config
sudo chmod 640 /etc/jen/jen.config
sudo systemctl restart jen
```

### Missing required config values

```
ValueError: Missing required config values: [('kea', 'api_pass')]
```

Fix: Open `/etc/jen/jen.config` and ensure all required fields have values — no placeholders like `your-password`.

### Missing Python packages

```
ModuleNotFoundError: No module named 'flask'
```

Fix:
```bash
sudo pip3 install flask flask-login pymysql requests --break-system-packages
sudo systemctl restart jen
```

### Permission denied on config or files

```
PermissionError: [Errno 13] Permission denied: '/etc/jen/jen.config'
```

Fix — the application tree is root-owned on purpose (read-only to the
service account); only `/etc/jen` and `/var/lib/jen` are the service
user's:
```bash
sudo chown -R root:root /opt/jen && sudo chmod -R a+rX /opt/jen
sudo chown -R www-data:www-data /etc/jen /var/lib/jen
sudo chown "$(id -u www-data):www-data" /etc/jen/jen.config
sudo systemctl restart jen
```

---

## Internal Server Error (500) in Browser

**Check logs for the specific error:**
```bash
sudo journalctl -u jen -n 20 --no-pager
```

### Unknown column in SELECT

```
pymysql.err.OperationalError: (1054, "Unknown column 'X' in 'SELECT'")
```

The Kea MySQL schema differs from what Jen expects. This can happen after a Kea upgrade.

Fix: Check the actual column names:
```bash
mysql -u kea -p -h YOUR-KEA-SERVER kea -e "DESCRIBE dhcp4_options;"
```

### Can't connect to Kea database

```
pymysql.err.OperationalError: (2003, "Can't connect to MySQL server")
```

Causes and fixes:
1. MariaDB not running on Kea server: `sudo systemctl start mariadb`
2. MariaDB not accepting remote connections: check `bind-address = 0.0.0.0` in `/etc/mysql/mariadb.conf.d/50-server.cnf`
3. Firewall blocking port 3306: check firewall rules on Kea server
4. Wrong credentials in `jen.config`: verify host, user, password, database

Test the connection manually:
```bash
mysql -u kea -p -h YOUR-KEA-SERVER kea -e "SELECT 1;"
```

### Can't connect to Jen database

Same troubleshooting as Kea database above, but for the `jen` database and `jen` user.

---

## Subnets Page is Blank

Jen can't reach the Kea API.

**Test the API:**
```bash
curl -su kea-api:YOUR-PASSWORD -X POST http://YOUR-KEA-SERVER:8000/ \
  -H "Content-Type: application/json" \
  -d '{"command":"version-get","service":["dhcp4"]}'
```

Expected: `[{"result": 0, ...}]`

**If result is 1 with "Server has gone away":** Kea DHCP service has crashed.
```bash
# On your Kea server
sudo systemctl status isc-kea-dhcp4-server
sudo systemctl start isc-kea-dhcp4-server
```

**If connection refused:** Kea Control Agent is not running.
```bash
sudo systemctl status isc-kea-ctrl-agent
sudo systemctl start isc-kea-ctrl-agent
```

---

## Kea Crashed After MySQL Restart

If MariaDB restarts (for config changes, updates, etc.) Kea may shut itself down.

**Prevent this** by adding reconnect settings to both `lease-database` and `hosts-databases` in `/etc/kea/kea-dhcp4.conf`:

```json
"on-fail": "serve-retry-continue",
"reconnect-wait-time": 3000,
"max-reconnect-tries": 10
```

Then validate and restart Kea:
```bash
sudo kea-dhcp4 -t /etc/kea/kea-dhcp4.conf
sudo systemctl restart isc-kea-dhcp4-server
```

---

## Subnet Editing Fails

### SSH connection refused or timed out

```
SSH error: [Errno 111] Connection refused
```

Check that SSH is running on your Kea server and the host/user in `[kea_ssh]` config is correct.

### Kea host helper (v5.11.0+)

**Trace says it needs the Kea host helper.** Trace (v5.49.0) is helper-only: it never falls back to the legacy `sudo tail` grant (which cannot serve 1000 lines). Settings → Kea → SSH → **Install helper** (needs the legacy grant present once — see *Legacy grant* in the admin guide), then try again.

Every Kea-side action Jen performs goes through `jen-kea-helper` at
`/usr/local/sbin/jen-kea-helper`, behind one sudoers line. **Settings →
Kea → SSH** shows the version for each host that has it — `v1` through
`v7` (v5.16.0 shipped `v2`, v5.23.0 `v3` for D2, v5.29.0 `v4` for the
https "Set up direct socket" push, v5.49.0 `v5` for bounded `tail-log`,
v5.66.0 `v6` for signed updates, v5.66.0-beta.2 `v7` for a hardened
update path — no protocol change, so a `v7` host also shows a build
number, e.g. **"v7 (build 7)"**; a helper-only fix ships as a higher
build on the same `v7`). A `v1` host works but shows an "upgrade
available" hint; a `v3` host works for everything except the https
socket setup, which says **"https setup needs jen-kea-helper v4+"**
until you press **Update helper**. Either way the fix is the same
button — and once a host shows **v6** or newer, that button needs no
sudoers grant at all; see *"Signed helper update refused"* below.

Two failure signatures, both meaning "Jen fell back to the legacy root
`python3` path for that host":

- `sudo: a password is required` — the **sudoers line is missing** for
  this SSH user. Add
  `youruser ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper` to
  `/etc/sudoers.d/jen-kea-helper` (`sudo visudo -c -f` it).
- `jen-kea-helper: command not found` / `No such file or directory` —
  the **helper isn't installed**. Use **Install helper** in Settings →
  Kea → SSH (needs the legacy `/etc/sudoers.d/jen-kea` grant present
  once), or copy it by hand — the verified one-liner in **Admin Guide
  → Kea host helper** (v5.66.0-beta.2 ships `jen-kea-helper.sig`
  alongside the helper itself in `/opt/jen/current/app/`, so the same
  offline procedure there works straight from the Jen host's own tree,
  no network needed on either side).

Legacy grant: the old `python3` = root file is `/etc/sudoers.d/jen-kea`. Jen
needs it for one run to install the helper, and — below helper v6 — for one
more run to reach v6; after that, press **Remove legacy grant** in Settings →
Kea → SSH (it refuses unless the helper's own sudoers file is valid), or run
`sudo rm -f /etc/sudoers.d/jen-kea`. From v6 on, updates are verified by
signature and never need this grant again — use the collapsed **Grant or
revoke the legacy root path by hand** box on the same card only for a fresh
install or the v5→v6 hop; Jen never grants itself root otherwise. Full
details: **Admin Guide → Kea host helper**. (`/etc/sudoers.d/jen`, no `-kea`,
is a DIFFERENT file — Jen's own self-update grant on the Jen box; removing it
breaks self-update, not anything Kea-side.)

**"No legacy python3 grant" even though the grant is definitely there
(v5.65.13).** The old one-shot probe couldn't tell a missing line apart
from sudo refusing a correct one for an unrelated reason. Press **Test
legacy grant** (next to Check) to see exactly what sudo said without
attempting an install. Three causes, in order of likelihood:
1. **A later `/etc/sudoers.d` file overrides it** — files are read in
   filename order, last match wins per command; sudo says *"a password
   is required"*. Diagnose with `sudo -n -l` (never `-n -l
   /usr/bin/python3` — see the Admin Guide's *Legacy grant* section for
   why that specific form lies).
2. **`Defaults requiretty`/`use_pty`** on a hardened box — sudo without
   a PTY says *"sorry, you must have a tty to run sudo"*.
3. **Wrong host** — the grant was pasted on the Jen box instead of the
   Kea box, or vice versa. The SSH card's own **user@host** names
   exactly who Jen probed as.

**Signed helper update refused (v5.66.0).** Only reachable on a host
already at helper v6 or newer — pressing **Update helper** there needs
no sudoers grant at all, since the helper's own `update` op verifies
the new file itself before installing it. The flash names which check
failed:
- *"refused the signature"* — the release's own signature didn't
  verify. This points at the **release**, not the host: a corrupted
  download, or (very unlikely) a signing problem in `release.yml`.
  Retry once a newer release is out; in the meantime copy the helper by
  hand with the command the flash gives you.
- *"no signature available"* — Jen itself couldn't fetch a signature to
  send (no local `jen-kea-helper.sig`, and the GitHub fetch failed —
  usually a network issue on the Jen host). Retry, or copy the helper
  by hand.
- *"no ssh-keygen"* — the Kea host is missing `openssh-client` (or its
  distro's equivalent); `ssh-keygen -Y verify` has nothing to run.
  Install it there (`sudo apt install openssh-client` on Debian/Ubuntu,
  `apk add openssh-keygen` on Alpine) and press the button again.
- *"not older than this release's helper"* — a benign race: the host
  already reports a version and build at or above what Jen just tried
  to send (shown as a warning, not an error). Nothing to do.
- *"candidate didn't check out"* (v7+, from `unparseable`,
  `preflight-failed` or `postflight-failed`) — the helper verified the
  signature but refused to install: it couldn't find a `HELPER_VERSION`
  / `HELPER_BUILD` line in the signed file, the candidate failed a
  self-check before being installed, or the installed copy failed that
  same self-check right after — in which case the helper has already
  restored the previous file from its own `.prev` backup, so the host
  is never left without a working helper. This points at a bad build
  reaching `release.yml`, not at anything on the Kea host; report it.
- *"no helper to update"* (build 8+, from `not-installed`) — there is no
  regular file at `/usr/local/sbin/jen-kea-helper` for `update` to
  replace (an unusual state; the running copy normally IS that file).
  `update` only ever replaces an installed helper — install one first
  with the by-hand command the flash gives you.
- *"failed to update AND failed to roll back"* (build 8+, from
  `rollback-failed`) — the only signed-update failure that is a real
  incident: the newly-installed candidate failed its postflight check
  AND restoring the previous helper from its `.prev` backup also failed
  (disk full, permissions changed mid-flight). The flash names both
  paths. SSH to the Kea host directly and check which of the two —
  `/usr/local/sbin/jen-kea-helper` (may be the broken candidate) and
  `/usr/local/sbin/jen-kea-helper.prev` (the old, working bytes) — is
  usable, then `sudo cp` the working one back into place by hand
  (`sudo chown root:root`, `sudo chmod 0755`).

None of these except `rollback-failed` touch anything on disk beyond a
verified, working helper — a host that fails a signed update for any
other reason stays on its current, working version rather than silently
reopening the `sudo python3` grant requirement.

### Permission denied on kea-dhcp4.conf

```
PermissionError: [Errno 13] Permission denied: '/etc/kea/kea-dhcp4.conf'
```

The SSH user needs the helper's sudoers line (or, on the legacy path,
the `/usr/bin/python3` grant). On your Kea server:
```bash
sudo cat /etc/sudoers.d/jen-kea-helper   # the one-line helper grant
sudo cat /etc/sudoers.d/jen-kea          # the legacy fallback, if still present
```

The complete line sets are in the **Admin Guide → Kea host helper**.
Validate after editing:
```bash
sudo visudo -c -f /etc/sudoers.d/jen-kea-helper
```

### SSH key permission denied

```
Load key "/etc/jen/ssh/jen_rsa": Permission denied
```

Fix permissions:
```bash
sudo chown www-data:www-data /etc/jen/ssh/jen_rsa /etc/jen/ssh/jen_rsa.pub
sudo chmod 600 /etc/jen/ssh/jen_rsa
```

### Known hosts error

```
Could not create directory '/var/www/.ssh'
```

This means an older version of Jen was deployed. The current version uses `/etc/jen/ssh/known_hosts`. Re-run the installer to update.

---

## Telegram Alerts Not Working

**Test manually from your Jen server:**
```bash
curl -s "https://api.telegram.org/botYOUR-TOKEN/getMe" | python3 -m json.tool
```

If this returns `"ok": true` but messages aren't arriving:

1. Verify chat ID is correct — message `@userinfobot` on Telegram to confirm
2. Check your bot hasn't been blocked — send a message to your bot first to initiate the conversation
3. Check that "Enable Telegram alerts" is checked in Settings and saved

**Test the send directly:**
```bash
curl -s "https://api.telegram.org/botYOUR-TOKEN/sendMessage" \
  -d "chat_id=YOUR-CHAT-ID&text=test"
```

---

## HTTPS Certificate Issues

### Certificate not applying after upload

Check Jen restarted successfully:
```bash
sudo systemctl status jen
sudo journalctl -u jen -n 10 --no-pager
```

If auto-restart failed, restart manually:
```bash
sudo systemctl restart jen
```

### Browser shows "Not Secure" despite certificate

For ZeroSSL certificates, the CA bundle is required for browsers to trust the chain. Ensure you upload all three files (certificate, private key, and CA bundle) — not just the certificate.

### Certificate format error

```
Invalid certificate file — does not appear to be a PEM certificate
```

Jen requires PEM format (base64 text starting with `-----BEGIN CERTIFICATE-----`). If you have a DER format (binary) certificate, convert it:
```bash
openssl x509 -inform DER -in certificate.der -out certificate.crt
```

---

## Lost Admin Password

Reset directly in the Jen MySQL database:

```bash
mysql -u jen -p -h YOUR-DB-SERVER jen -e \
  "UPDATE users SET password=SHA2('newpassword',256) WHERE username='admin';"
```

Replace `newpassword` with your desired password. Log in with `admin` / `newpassword` and change it immediately.

---

## MFA / Authenticator App Stopped Working After a Restore or Migration

Since v5.4.0 the TOTP secret behind each authenticator app is encrypted
at rest with a key stored at `/etc/jen/mfa_key` — **not** in the
database and **not** in database exports. If you restore a Jen database
export onto a different machine, or migrate the database to a new
server, without also copying `/etc/jen/mfa_key` across, the existing
authenticator enrolments can't be decrypted and TOTP codes will be
rejected.

This fails safe, not open — affected users are not bypassed. Recovery:

- **The user still has backup codes** — log in with one of those, then
  re-enroll the authenticator (Settings → Security), which writes a
  fresh secret under the new key.
- **An admin resets the user's MFA** — Users → edit user → reset MFA,
  then the user re-enrols.
- **Best: copy the key from the old host** before decommissioning it:
  `scp old-host:/etc/jen/mfa_key new-host:/etc/jen/mfa_key` (then
  `chown` it to the Jen service user, `chmod 600`), and restart Jen.

A brand-new install generates its own `/etc/jen/mfa_key` on first run.
`/etc/jen` is preserved across in-place upgrades, so a normal
`sudo ./install.sh` upgrade is unaffected.

---

## Passkeys: the prompt never appears, or "This browser can't create a passkey here" (v5.31.0)

WebAuthn only runs on a *secure context*: an https page, or `http://localhost`. On plain http over a LAN address the browser refuses before Jen is even asked, so the Add-a-Passkey card hides its form and says so; the Passkey tab at login shows the same note. Fix: upload a certificate (Settings → Security) or terminate TLS at a reverse proxy listed in `[server] trusted_proxies`.

**"The passkey could not be verified"** right after enrolling, or for every user at once, usually means the address changed: the relying-party id is the hostname of the page (`jen.lan`, not `jen.lan:8443`, not `10.0.0.5` if users type the name). Behind a proxy, the proxy must forward the original `Host` header. Passkeys enrolled under the old name are invalid under the new one — users enroll again (a superadmin's Reset MFA on the Users page clears the stale ones).

**"The passkey challenge expired — start again"**: more than five minutes passed between the two halves of the ceremony, or the page was reloaded in between. Click the button again.

**A user is locked out of passkeys**: failed assertions count toward the same 10-attempt / 15-minute MFA lockout as codes; wait it out, or use a backup code.

## "You are running the latest version" on the beta channel, but a newer stable exists (v5.32.0)

Check the two version numbers. A box on `5.33.0-beta.2` that is told it's current when stable is `5.33.0` is *not* current — but a box on `5.34.0-beta.1` told the same thing while stable is `5.33.0` is: the beta it runs is already newer than any stable release, and switching the channel to stable never downgrades. It will be offered `5.34.0` when that is promoted. If you genuinely want back on a stable build that is older than the beta you're running, that's a manual reinstall of that release's tarball (Upgrading Jen → Rolling back by hand), not something the updater does.

**"No usable release found for the beta channel"** in `journalctl -u jen-update.service` means every release GitHub listed was a draft or had a tag outside Jen's version grammar (`X.Y.Z`, `X.Y.Z-beta.N`, `X.Y.Z-rc.N`). A mistyped tag is ignored on purpose rather than installed.

## Locked Out (Rate Limiting)

If you've locked yourself out and can't log in:

**Option 1 — Wait for the lockout to expire** (default 15 minutes)

**Option 2 — Clear lockouts via MySQL:**
```bash
mysql -u jen -p -h YOUR-DB-SERVER jen -e "DELETE FROM login_attempts;"
```

**Option 3 — Disable rate limiting temporarily:**
```bash
mysql -u jen -p -h YOUR-DB-SERVER jen -e \
  "INSERT INTO settings (setting_key, setting_value) VALUES ('rl_mode','off') \
   ON DUPLICATE KEY UPDATE setting_value='off';"
```

Re-enable after logging in via Settings → Login Rate Limiting.

---

## Reservations Page 500 Error

Usually a database schema mismatch. Check:
```bash
mysql -u kea -p -h YOUR-KEA-SERVER kea -e "DESCRIBE dhcp4_options;"
```

The column should be named `formatted_value` (not `dhcp4_value`). If your Kea version uses a different schema, check the Kea release notes for schema changes.

---

## DHCP Not Working After Subnet Edit

If Jen's subnet edit caused Kea to fail, a backup was automatically created. Restore it manually on your Kea server:

```bash
sudo cp /etc/kea/kea-dhcp4.conf.bak /etc/kea/kea-dhcp4.conf
sudo systemctl restart isc-kea-dhcp4-server
sudo systemctl status isc-kea-dhcp4-server
```

Or, from Jen (v5.16.0+): **Servers → Config history → <a good revision> →
Restore this revision** (superadmin) — it re-validates with
`kea-dhcpX -t` and restarts Kea for you.

### "The Kea config on <host> changed since you opened this form" (v5.16.0+)

The edit was **not** applied — this is the optimistic-concurrency guard,
not a bug. The config file on the host is different from what it was
when you opened the form: another admin saved a change, or someone
edited `kea-dhcp4.conf` directly. Reload the page (Jen re-reads the
current config) and redo your edit. **Servers → Config history** shows
what changed and who did it; an entry marked **external** is a hand edit
Jen noticed rather than made.

If instead you see *"No atomic guard on <host>: helper v1 / legacy"*,
the write went through on a best-effort check because that host is still
on helper v1 or the legacy `python3` path — upgrade it (**Settings →
Kea → SSH** — the button reads *Update helper* once a version is
already recorded, *Install helper* otherwise) to get the atomic guard
and out-of-band change tracking.

### "🛑 ROLLBACK FAILED" after a multi-server change (v5.28.0, wording fixed v5.28.1)

A change to more than one Kea server (a subnet, shared network, DHCP
option, client class, or DDNS/D2 edit) committed successfully to at
least one server, then a later server refused it — and the attempt to
put the earlier server(s) back the way they were **also** failed (the
host went unreachable mid-operation, most commonly). The flash names
three groups explicitly: which server(s) **still have the NEW
config** (their own revert call is the one that failed — despite the
word "failed" here, this is the server with the config you did NOT
want), which were **successfully rolled back** (unaffected, already
back on the old config), and which server was **never changed at all**
(the one whose original commit failed first, triggering the whole
revert). **v5.28.0 shipped this message backwards** — it labeled the
still-new-config group as simply "failed" with no indication which
config they were actually left on; if you're troubleshooting a v5.28.0
box, treat "revert failed" as "this server still has the NEW config,"
not the old one. Either way this needs hand intervention: open
**Servers → Config history** for each named server and use **Restore**
to bring it to whichever version you want every server to agree on,
then confirm with a normal edit that they match. This is different
from the ordinary "changed since you opened this form" conflict below
— that one is refused before anything is written anywhere; this one
means a write already happened and its own undo didn't complete.

### "❌ … did NOT restart on the new config" and "↩️ rolled back" (v5.65.1)

A change was written and validated, but a server's Kea would not restart
on it. Jen now puts every server back on the config it had and restarts
it again ("↩️ rolled back … the change was NOT applied"), so nothing is
left on a new config with a stopped daemon; Jen's own bookkeeping (subnet
list, audit log) is not written, because the change did not happen. The
lines above show the failing restart's own error: fix that (a config
Kea's validator accepts but cannot start from, a broken unit, a missing
file) and repeat the change. If the rollback itself could not finish you get
"🛑 ROLLBACK FAILED" naming the servers, and a red banner on the Servers
page until you dismiss it: check the config on those hosts, restore the last
good one from Config history, and restart Kea there by hand. The banner lists
every unresolved incident (since 5.65.10 a later, clean rollback on another
server no longer replaces it): a clean change that restarts the server it names
clears its incident, and an administrator can dismiss them all. (Before
v5.65.1 this was a warning, `restart_failed`, that left the new config on
disk and the daemon stopped.)

### "Could not verify the current configuration on \<host\> — no changes were written" (v5.28.1)

A write to a v1-helper or legacy-engine host was refused because Jen
couldn't re-read that host's current config to check for a conflict
first (the host was unreachable, or the read itself errored) — a
different failure than an actual detected conflict. Through v5.28.0
this situation let the write proceed anyway, on the reasoning that a
transport failure isn't evidence of a real conflict; in practice that
meant the one host Jen couldn't verify was exactly the one it wrote to
regardless. Fix whatever is stopping Jen from reaching the host over
SSH (see "SSH connection failures" above) and try the edit again — it
was never applied.

### "The Kea config on the primary server changed since you previewed this import" (v5.28.0)

The Windows DHCP import wizard's **Apply** step refuses to push a
config it never actually tested — it reuses exactly what **Preview**
ran `kea-dhcp4 -t` against, and refuses if either that test failed or
the live config on the primary server has moved since (another admin's
edit, a hand change). Go back to **Review** and preview again; Apply
will push the freshly-previewed config once you confirm it looks
right.

### "… answered config-get as the Control Agent, not kea-dhcp4" (v5.28.1)

`connection_mode = direct` is set, but the URL Jen is talking to is
still the Control Agent (`kea-ctrl-agent`), not a real per-daemon
control socket — most often because only the daemon's `unix`
control-socket entry was ever configured, never an `http`/`https` one.
In direct mode Jen sends no `service` field, so the Control Agent
happily answers `version-get` for itself (looking identical to a real
daemon socket — same version string), but `config-get` comes back as
*its own* config with no `Dhcp4`/`Dhcp6`/`DhcpDdns` key, which used to
render every page reading live Kea data as quietly empty. Add a real
`http`/`https` `control-sockets` entry to the daemon (see "Direct
control sockets" in the admin guide) and point `api_url` at that port
instead — Settings → Kea → Probe now identifies this exact mismatch
before you switch modes, so use it to confirm the fix.

### "Set up direct socket": "… restarted with the new socket, but http://… didn't answer" / "answered as the Control Agent, not kea-dhcp4" (v5.29.0)

The Kea side worked — the entry is in the daemon's config, `-t` passed,
the daemon restarted — but the probe from the Jen host didn't get the
daemon on the new socket, so Jen deliberately changed **none** of its
own settings. "Didn't answer" almost always means the port isn't
reachable *from the Jen host*: a firewall on the Kea host, or a bind
address on a network the Jen host isn't on (the form's default is the
SSH host, which is usually right). Check `ss -ltnp | grep 8004` on the
Kea host and the daemon's log for `HTTP server … listening`, then run
the form again — the socket is already there, so it only re-probes.
"Answered as the Control Agent" means the address:port you chose is
the agent's own listener (`:8000`), not a daemon socket; pick the
daemon's port (8004 / 8006 / 53001).

### "tlsmissing" / "config validation failed … /etc/kea/tls/…" during an https setup (v5.29.0)

The apply carries the three TLS paths the socket references, and the
helper refuses to even test a config whose files aren't on the host —
so this means the `install-tls` push didn't land where the config
points. Jen runs the push first and stops if it fails, so seeing this
means something removed or moved `/etc/kea/tls/<service>/` between the
two steps (or a hand-made socket points somewhere else). Re-run the
form; the push is repeated every time.

### "https setup needs jen-kea-helper v4+" (v5.29.0)

The https option pushes certificate material through the helper's
`install-tls` op, which arrived in v4 — a v3 host can still do
everything else, including the http option. **Settings → Kea → SSH →
Update helper** (the legacy `python3` grant must be present for that
one run, as for every helper install), then the option enables itself.

### "Rotate stopped at …" / "ROLLBACK FAILED on …" after Rotate Kea CA (v5.29.0)

Rotate is all-or-nothing: the new CA is staged beside the live one,
every server is pushed, restarted and probed with the new material,
and only then does Jen switch to it. "Rotate stopped at *server*" means
that server's push, restart or probe failed and the servers done
before it were re-issued from the **current** CA and restarted — Jen
still trusts the CA it did before, nothing else changed; fix the named
server (usually the same reachability checks as above) and rotate
again. "ROLLBACK FAILED on *server*" is the one mixed state: that
server's re-issue itself failed, so it now holds a certificate from a
CA Jen never adopted and won't answer Jen. Run **Set up direct socket**
(https) for that daemon again — it re-issues from the current CA and
re-pushes — and the server is back.

### A red "migration failed — not enabled" / "not loaded" chip on the Plugins page (v5.28.1)

One of a plugin's own `db_migrations` failed to apply — a schema
conflict from a manual database change, or a genuinely broken
migration in a plugin release. The plugin is deliberately **not**
enabled (a fresh install) or **not loaded** (an existing one, on the
next Jen restart) with a bad schema underneath it; the chip shows the
underlying SQL error. Fix whatever it names directly against the
database, then reinstall the plugin (fresh install) or restart Jen
(existing install) to retry — the migration tracking table only
prevents re-running an already-applied migration, so a fix followed by
a retry is always safe. If the chip is showing for a plugin that was
working fine before a Jen upgrade and you're confident the schema
itself is fine, this is NOT the v4.4.19 "load anyway" carve-out — that
only ever applies automatically to a version that has already migrated
cleanly once before; it can't be forced from the UI, by design.

### "Could not start the plugin install service" / a plugin install/remove flashes an error after being queued (v5.28.0/v5.27.0)

Installing or removing a plugin on a systemd host is a two-step
hand-off: the page queues a request and a root-privileged service
carries it out, and the page only shows success once that service's
own result confirms it. If the flash names a reason (a `requires_jen`
version mismatch, a checksum failure, a missing tag) act on that
directly. "Could not start the plugin install service" means the
trigger itself didn't fire — run `sudo ./install.sh` to repair
`jen-sudoers` and the `jen-plugin-install.service` unit, then try
again. If a request seems to hang with no result at all, check
`sudo systemctl status jen-plugin-install.service` and
`sudo journalctl -u jen-plugin-install.service` on the Jen host.

### A "baseline" revision appears after upgrading a host's helper (v5.20.0)

This is expected, not a hand edit Jen noticed. The very first config Jen
records for a server/service is always a **baseline**, and a host
crossing from helper v1 to v2 gets a second one — the raw-bytes hash the
v2 helper reports isn't comparable to the hash Jen computed itself under
v1, so Jen records a fresh baseline to compare future reads against
rather than flagging the difference as an **external** change. No action
needed; it happens once per server/service, right after the upgrade.

---

## Upgrades and the versioned layout (v5.14.0+)

Jen installs each release into `/opt/jen/releases/<X.Y.Z>/` and points
`/opt/jen/current` at the live one. `sudo journalctl -u jen-update.service`
has the in-app updater's output.

**"ERROR: no release signature published for vX.Y.Z" or "release
signature verification failed" (v5.26.0+).** Every release from
v5.26.0 on is signed, and the updater refuses to install anything it
can't verify — this is the intended fail-closed behavior working
correctly, not a bug to work around. It means either the release you're
pointed at genuinely has no `SHA256SUMS.sig` asset (check the release
page on GitHub) or the asset is present but doesn't verify against the
key `jen-update-root.py` has embedded — which would mean the release
was tampered with, or you're looking at a fork that signs with a
different key. Don't disable the check; find out which of those it
actually is first.

**An in-app update to 5.14.0 rolled back.** Expected — the updater on a
5.13.x box is the flat one and can't create the versioned layout. Take
5.14.0 with `sudo ./install.sh` once; every in-app update after that
works.

**Roll back to the previous release:**
```bash
ls /opt/jen/releases
sudo ln -sfn releases/<X.Y.Z> /opt/jen/current
sudo systemctl restart jen
```

**`jen.service` fails with "No such file or directory" on the
interpreter.** `/opt/jen/current` is missing or dangling. Point it at a
real release (command above), or `sudo ./install.sh --repair` from the
tarball.

**Disk filling with old releases.** The updater keeps `current` + the
newest other + anything marked `.keep`; it prunes the rest on its next
run. Delete extras by hand with `sudo rm -rf /opt/jen/releases/<X.Y.Z>`
(never the one `current` points at).

---

## Log Locations

| Log | Location | How to view |
|---|---|---|
| Jen application | systemd journal | `sudo journalctl -u jen -f` |
| Kea DHCP | systemd journal | `sudo journalctl -u isc-kea-dhcp4-server -f` |
| Kea Control Agent | systemd journal | `sudo journalctl -u isc-kea-ctrl-agent -f` |
| DDNS updates | File | `tail -f /var/log/kea/kea-ddns-technitium.log` |

---

## High Availability

### Active node not being detected correctly

Jen uses `ha-heartbeat` to identify the active node. Check:

1. Both servers are reachable from Jen (test API URLs manually)
2. HA mode is set in **Settings → Infrastructure → High Availability** and matches `ha-mode` in `kea-dhcp4.conf`
3. The `role` field is set correctly for each server — the active node must have `role = primary`
4. Kea HA is actually running — check `systemctl status isc-kea-dhcp4-server` on both nodes

If `ha-heartbeat` isn't supported by your Kea version, Jen falls back to the first reachable server.

### HA failover alerts not firing

1. Confirm an alert channel is configured with the **HA failover / state change** alert type enabled
2. Check the Jen logs for `ha-heartbeat` errors: `sudo journalctl -u jen -n 50 --no-pager`
3. HA state monitoring only runs when multiple servers are configured — single server setups don't query `ha-heartbeat`

### Servers page shows "HA mode not configured" warning

Go to **Settings → Infrastructure → High Availability** and set the HA mode to match your Kea configuration. If you're not running HA, remove the extra server from **Additional Servers** to clear the warning.

---

## DDNS / D2 (v5.23.0+)

### D2 status shows "D2 did not answer version-get"

1. `dhcp-ddns.enable-updates` must be `true` on the Naming tab first — D2 status is skipped entirely while it's off.
2. In `direct` connection mode, confirm **Settings → Kea → D2 Control Socket** (`[d2] api_url`) is set and points at D2's real control socket (conventionally port 53001) — without it, D2 has no endpoint to answer on.
3. Confirm `kea-dhcp-ddns` is actually running: `sudo systemctl status kea-dhcp-ddns-server` (or `isc-kea-dhcp-ddns-server` on older Debian/Ubuntu packages).

### D2 Configuration tab says "Could not read kea-dhcp-ddns.conf"

The active server needs SSH configured (Settings → Kea → SSH) and a Kea host helper at **v3 or newer** — v1/v2 helpers predate D2 support and refuse the read outright. Check the helper version in Settings → Kea → SSH and click **Update helper** if it's behind.

### D2 statistics — what each error counter means

The Status tab's D2 stats table mirrors `statistic-get-all`'s own names:

| Statistic | Meaning | Likely cause |
|---|---|---|
| `ncr-received` | Update requests dhcp4 handed to D2 | Informational — not an error count |
| `ncr-invalid` | A request D2 couldn't parse | Version mismatch between dhcp4 and D2, or a corrupted install |
| `ncr-error` | D2 accepted the request but failed to act on it | Usually a downstream DNS problem (see `update-error` below) |
| `update-sent` | DNS updates D2 actually transmitted | Informational |
| `update-signed` | Of those, how many were TSIG-signed | Should equal `update-sent` if every zone has a key configured |
| `update-unsigned` | Sent without a TSIG signature | Expected only for a zone with no `key-name` on the D2 Configuration tab — otherwise means the zone/key pairing didn't take |
| `update-timeout` | The DNS server never replied | Check `dns-servers` IP/port on the D2 Configuration tab, and that the target DNS server is reachable from the D2 host specifically (not just from Jen) |
| `update-error` | The DNS server replied with a rejection | Almost always a TSIG key mismatch (wrong secret, wrong algorithm, or the zone's `allow-update` doesn't reference the key by the same name) — re-generate and re-paste the key on both sides rather than guessing which half drifted |

### TSIG key won't delete — "still referenced by a domain"

Jen refuses to remove a TSIG key while any forward or reverse domain on the D2 Configuration tab still names it — remove or repoint those domains first. This mirrors client classes: an in-use key gone missing would leave D2 unable to sign updates for that zone at all.

### Verify tab shows a mismatch that Status doesn't

The Verify tab queries the Jen host's own system resolver (`socket.getaddrinfo`/`gethostbyaddr`) — the same path any ordinary client on that network would take. A mismatch here after D2 shows "ok" on Status usually means either the change hasn't propagated (DNS caching / zone transfer delay) or the Jen host's resolver is pointed at a different DNS server than clients actually use.

---

## Mobile

### Pages are slow to respond on iPhone

If tapping requires two taps or navigation is delayed, you are running a version before 2.5.7. Upgrade to v2.5.7 or later.

### The More sheet does not open

Ensure JavaScript is enabled in Safari. The bottom tab bar's More button, the Filters sheet and the More actions sheet all require JS; the tab bar's other four buttons are plain links and work without it.

### Table data is hard to read on iPhone

Tables reflow into per-row cards on iPhone as of v2.5.4. If you're seeing a wide horizontal table, you may be on an older version or have a browser zoom level set that exceeds the mobile breakpoint.

---

## Alert Channels

### ntfy alerts not arriving

1. Confirm the ntfy server URL is correct (include `https://` or `http://`)
2. Test the channel using the **Test** button in Settings → Alerts — check the response message
3. For self-hosted ntfy, ensure the Jen server can reach your ntfy instance on the configured port
4. For protected topics, confirm the access token is correct

### Discord alerts not arriving

1. Confirm the webhook URL is valid — it should start with `https://discord.com/api/webhooks/`
2. Test the channel using the **Test** button
3. Check that the Discord channel the webhook points to still exists and hasn't been deleted
