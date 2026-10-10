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

### The installer stopped after the database question, or Jen restarts every five seconds (v5.67.0-beta.18)

**Symptom.** `sudo ./install.sh` printed "Could not reach Jen database", you chose to continue (older installers offered that), and the script ended with no service — or the service is installed but `systemctl status jen` shows it restarting every five seconds. **Cause.** Jen runs its schema migrations against the database in `[jen_db]` before it serves anything; if that database does not answer, the process exits and systemd (`Restart=always`, `RestartSec=5`) starts it again, for ever. There is no page to log in to, so there is nothing to "finish in Jen". **Fix.** Make `[jen_db]` in `jen.config` (host, user, password, database) match a MariaDB/MySQL database that answers, then `sudo systemctl restart jen`. On a machine with no database server, run the installer again and answer `y` to "Install MariaDB on this machine and create the database now?" (or set `JEN_DB_INSTALL_LOCAL=yes` for an unattended install); it installs MariaDB, creates the database and user, and tests them. What the installer ran, and what failed, is in `/var/log/jen-install.log`.

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
sudo chown www-data:www-data /etc/jen/jen.config
sudo chmod 600 /etc/jen/jen.config
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

**"Investigation logging is not switched on (early access in 5.68, off by default)" (v5.68.0-beta.30).** Turning logging on is opt-in: a superadmin switches it on under **Settings → Kea → Investigation logging**. Nothing else is affected - a session that is already on is still restored and shown.

**"The Kea host's investigation state file cannot be trusted" (v5.68.0-beta.31, helper build 17, `bad-state`).** A file exists at `/var/lib/jen-kea-helper/investigation-dhcp4.json` and the helper cannot read
it as its own record (not valid JSON, unreadable, not a record this helper wrote). Nothing is known about the session it describes, so Health fails and turning logging on is refused; the helper
never reports this as "no session" and never overwrites it. Look at the file; if it is a stale or damaged record, remove it (`sudo rm /var/lib/jen-kea-helper/investigation-dhcp4.json`) or run
`sudo jen-kea-helper --self-restore --now` on that host - Jen's own sweep also restores the logger at the deadline. If the `kea-dhcp4` logger is still at DEBUG after that, press **Investigation → Turn off**.

**"No way to see Kea's restore" (v5.68.0-beta.31, helper build 17, `no-evidence`).** The arm is refused when the helper could not later prove a restore: the daemon has no control socket the helper can reach
(`control-socket` missing, or only a socket with `socket-type: http` on a non-local address) *and* no readable log file (Kea logging to syslog or stdout). Add a local unix `control-socket` to the
Kea config (the Kea packages' default), or log to a file, then try again. Nothing was changed on the host.

**"The Kea host reports an unresolved investigation session Jen does not recognise" / "needs hand" (v5.68.0-beta.30, helper build 16).** The host's record under `/var/lib/jen-kea-helper/investigation-dhcp4.json`
is authoritative: Jen will not arm over a session it did not start (a second Jen, a Jen restored from an older backup, a hand edit). It restores itself at its deadline; to end it now run
`sudo jen-kea-helper --self-restore --now` on that host. `needs_hand` means ten restore ticks in a row could not be confirmed from Kea's own log - read `last_error` in that file (usually
"Kea refused the restored config: <Kea's line>", a log path Kea does not write to, or a Kea that never restarted), fix it, and run the same command. "Restoration timer is not active": press
**Settings → Kea → SSH → Check** or wait a minute - Jen asks the helper to start the timer again (`investigation-timer`); `systemctl list-timers jen-kea-investigation.timer` shows it.
Build 16 is required; press **Update helper** if Jen says the helper is older.

**"The Kea host helper on <host> must be build 16 or later" when turning investigation logging on (v5.68.0-beta.29).** Investigation logging now needs the helper's self-restore: Jen arms a systemd timer on the Kea host (`jen-kea-investigation.timer`, running `jen-kea-helper --self-restore` as root) so the host puts the logger back at the deadline without Jen. A helper older than build 15 cannot, a host without systemd cannot (the arm answers `timer: none` and Jen reverts the file), and the legacy `sudo python3` path has no such op. Press **Settings → Kea → SSH → Update helper** (from v6 that needs no grant), then try again. Nothing was changed on the host when this is refused. To see what the host holds: `sudo cat /var/lib/jen-kea-helper/investigation-dhcp4.json` (its `last_error` is what the Health row shows); to run its restore by hand: `sudo jen-kea-helper --self-restore --now`; `systemctl list-timers jen-kea-investigation.timer` shows the timer. The legacy-grant fallback has no engine for these ops.

Legacy grant: the old `python3` = root file is `/etc/sudoers.d/jen-kea`. Jen
needs it for one run to install the helper, and — below helper v6 — for one
more run to reach v6; after that, press **Remove legacy grant** in Settings →
Kea → SSH (it refuses unless the helper's own sudoers file is valid), or run
`sudo rm -f /etc/sudoers.d/jen-kea`. From v6 on, updates are verified by
signature and never need this grant again — use the collapsed **Grant or
revoke the legacy root path by hand** box on the same card only for a fresh
install or the v5→v6 hop; Jen never grants itself root otherwise. Full
details: **Admin Guide → Kea host helper**. A host still on this legacy path never
had the ISC-package binary-ownership problem ("kea-dhcp4 is not installed on
this server" although it is — see above); a helper build 7–9 does, and Update
helper fixes it. (`/etc/sudoers.d/jen`, no `-kea`,
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
  download, or (very unlikely) a signing problem in `release.yml`. A
  by-hand install is never offered here (v5.66.0-beta.7, Q109) — the
  identical signature would fail there too. Retry once a newer release
  is out; if it persists, please report it.
- *"no signature available"* — Jen itself couldn't fetch a signature to
  send (no local `jen-kea-helper.sig`, and the GitHub fetch failed —
  usually a network issue on the Jen host). Retry, or copy the helper by
  hand with the command the flash gives you — it works fully offline
  too, straight from a tarball install's own two files.
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

### "kea-dhcp4 is not installed on this server" although it is (helper build 7–9 on a Kea from ISC's packages, fixed in build 10)

ISC's own deb packages install `/usr/sbin/kea-dhcp4` owned by the Kea service account (`ls -l /usr/sbin/kea-dhcp4` shows `_kea _kea`, mode
`-rwxr-x---`), not `root:root`. Helper builds 7 through 9 required `root:root` of every binary they run, so on such a host the helper answered
`missingbinary` and Jen worded it "…is not installed on this server — install it and try again". **Every operation that checks a config first failed
that way: a subnet, option, class, DDNS or investigation-logging change; "Config test passed" never appeared** — from 5.66.0-beta.2, so stable 5.66.0 and
5.67.0 are affected. A host with no helper at all (the legacy `sudo python3` path) was not. Fix: **Settings → Kea → SSH → Update helper** on that host
(helper build 10 runs `kea-dhcpX -t` as the daemon's own account, and trusts the binary when that account owns it as a regular file nobody else can write).
If it still refuses, the message now says why: *"kea-dhcp4 is present but the helper will not run it: is owned by alice, not a system account and not the
daemon's user — update the helper (build 10 or later) / fix the ownership"* — the binary is writable by group or other, is a symlink, or is owned by an
ordinary user; `sudo chown _kea:_kea /usr/sbin/kea-dhcp4 && sudo chmod 0750 /usr/sbin/kea-dhcp4` (the ownership the package ships) or `root:root 0755` are
both accepted. Health Center's "Kea host helper installed" row names a host on an old build with an ISC-packaged Kea.

**The config check fails for a unit with `Group=` or `SupplementaryGroups=` (fixed in helper build 11).** A Kea whose systemd unit sets a group (the
usual reason is TLS material readable through a group) started fine and still failed Jen's *Config test*: build 10 ran the check as the account's
primary group with no supplementary groups. Press **Update helper**: build 11 runs it with the unit's own `User=`, `Group=` and
`SupplementaryGroups=`. If the message says *"its unit names the group 'x', which does not exist on this host"*, the unit refers to a group the host
lacks (`getent group x`): create it or fix the unit, and Jen will not guess. Build 11 also writes the check's copy of the config (it carries the database
credentials) `0600`, owned by the account that runs it, where build 10 wrote it `0644`.

**The config check passes but Kea will not start with the same config (fixed in helper build 12).** Build 11 checked a config as root whenever the Kea
binary was owned by `root:root`, even when the unit says `User=_kea`: a certificate, key or directory only root could read made the check pass for a Kea
that then failed as `_kea`. Press **Update helper**: build 12 resolves the unit's account first and runs the check as it (numeric `User=` included, with its
`/etc/group` memberships and `SupplementaryGroups=`). If the Servers page now says *"its unit runs as User=x, which is not an account on this host"*,
`getent passwd x` finds nothing: create the account or fix the unit — Jen will not run the check as root in its place.

**Kea cannot read `server.key` after a TLS install, or `kea-dhcp4.conf` is unreadable by Kea (fixed in helper build 14).** A unit with `Group=` or a numeric `User=` got a key
whose group came from a simpler lookup than the one validation used, and a brand-new config was created world-readable (`0644`). Press **Update helper**: build 14 uses the one
account lookup for both, creates a new config `root:<Kea's group>` `0640` (or `root:root` `0600` when Kea runs as root), and a TLS install replaces `ca.crt`, `server.crt` and
`server.key` together or not at all. If the Servers page says *"its unit runs as User=x, which is not an account on this host"*, `getent passwd x` finds nothing: create the account or
fix the unit.

**A failed Author Kea Config left a new file on a server (helper build 13).** Authoring writes every server or none: if a later server fails, the
earlier ones are put back, and a server that had no config file before is put back by removing the file Jen wrote. That removal is the helper's
`remove-config` op (build 13), and since 5.68.0-beta.16 authoring refuses to start unless every server has it (*"Author Kea Config needs the Kea host helper at build 13 or
later ... press Update helper on ..."*), so a rollback fails only when the server itself is unreachable at that moment: the Servers page then shows a *rollback failed*
banner naming the server and the file - delete it by hand (`sudo rm /etc/kea/kea-dhcp6.conf`) and run the authoring again. Nothing about Jen's own subnet record changes
on a failed run, and if Jen cannot record it, every server is put back.

**Preview & Validate says a config file already exists, and Write refuses (helper build 13 and the authoring change in 5.68.0-beta.15).** *Overwrite*
replaces the file you previewed, not whatever is there: tick it, preview again, then write. *"changed since you previewed it"* means the file on that
server changed after the preview - run the preview again.

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

The complete line sets are in the **Admin Guide → Kea host helper**. (Helper build 11: the legacy `sudo python3` path never ran the
helper's `-t` check and is unchanged, including at build 12; a host on the helper validates a config with a `0600` copy owned by the account the unit
names.)
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

**The Releases page on GitHub lists out of numerical order** — on a day with several betas, `beta.9` can appear above `beta.12`, because GitHub compares the number after `beta.` as text within a day's releases. Every date and id is in order, nothing is wrong with the releases, and the order is not something this project can change on github.com: the Tags page, the README's version badges (which sort by version) and the in-app updater (which keys on the parsed version, never on the list's order) are the ones in order.

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

## A database migration or a Kea import refuses (v5.67.0-beta.13)

These are refusals, not failures: nothing was written, and each message says what to change.

- **"The target database already has …"** (Jen migration) — a Jen migration creates tables and never replaces or merges into one that exists. Point it at an empty database, or drop those tables on the target yourself first.
- **"No table was selected …"** (Jen migration) — nothing was ticked, or none of the names is one of Jen's. Select at least one table (nothing selected used to be treated as "everything").
- **"The target (…) is not an initialised Kea database"** (Kea migration) — Jen copies data only and never creates Kea's schema. On the new server run `kea-admin db-init mysql -h … -u … -p … -n <database>`, then migrate.
- **"… the major versions must match"** — the target's `schema_version` major differs from the source's. Initialise the target with the same Kea major as the source (or upgrade it with `kea-admin db-upgrade` first), then migrate.
- **"The target is missing …"** — the target is initialised but lacks one of the tables being migrated; it is usually an older or partial schema. Re-run `kea-admin db-init` or `db-upgrade` on it.
- **"Kea migration failed — the target was rolled back"** — usually a collision: the target already has a reservation with the same `host_id` (or the same identifier in the same subnet) as one being copied. Nothing on the target changed. Migrate into an empty initialised database, or export and import instead, which merges host by host.
- **"Import aborted and rolled back — hosts row 12 …"** (Kea import) — row 12 of that table was refused by the database (a foreign-key or type error, or a value too long); the message never shows the value. Nothing was imported. A line that says "skipped" in an import summary now always means a duplicate in skip mode.

---

## A Jen import is refused, fails or rolls back (v5.67.0-beta.14)

- **"Cannot read file: not a Jen export: …"** — the upload is not a Jen export, and the sentence says why (the top level is not an object, a table is not a list, `format` is newer than this Jen reads, …). Nothing was touched. Re-export from Settings → Databases → Export; a file edited by hand or produced by a script must keep the `{"data": {…}, "_meta": {…}}` shape. gzip and plain JSON are both accepted.
- **"Replacing users on its own would leave … pointing at records that no longer exist"** — a replace restore of a parent table needs its dependents ticked (multi-factor, passkeys, saved searches, dashboard layouts, API keys for `users`). Tick them, or restore the whole file. Nothing was changed.
- **"The import failed and was rolled back"** — a table refused a row, or a plugin could not migrate or load its data. The database was put back from the snapshot taken first; the server log names the table. Fix the cause (a file from a much older or newer Jen, a plugin out of date) and import again.
- **"…putting the database back did not complete"** — a replace import failed and so did the automatic rollback. The message names a `pre-import-<time>` folder under the backups directory; its `jen_db.json.gz` is a full export taken just before the import. Fix what the server log names, then import that file with Replace.
- **"Could not take the safety snapshot"** — replace mode will not run without one. Check that the backups directory is writable and has free space roughly the size of the Jen database.
- **A merge result says `N added, M skipped`** — M rows were left out because the same key was already in the table (or the database refused them). The file's row count is not what merge reports.
- **A plugin's data is not on the new box after a restore** — the plugin's code was not installed when you restored, and Jen never creates a table from a file. The restore output names the plugin; its data is still in the backup. Install the plugin (Settings → Plugins), then restore again.

---

## IPv6 pages show strange characters instead of addresses (fixed in 5.67.0-beta.16)

**Symptom.** With IPv6 management enabled on a Kea 3.x database, the IPv6 leases, reservations, devices and search results showed something like `�� � ...` or a long run of escape characters where an address belongs, and searching leases for an IPv6 address found nothing. **Cause (present in every release that has IPv6 management, stable 5.66.0 included).** Kea 3.x stores `lease6.address` and `ipv6_reservations.address` as sixteen raw bytes (`BINARY(16)`); Jen read them as text. IPv6 is off by default, so an install that only ever used IPv4 was never affected. **Fix.** Upgrade; Jen converts the bytes to the address text everywhere it reads them. Nothing in Kea's database was ever changed. **Searching leases:** type a whole address (`2001:db8::10`, in any spelling) for an exact match, or a fragment (`2001:db8`, `db8:1`) to find everything containing it; a whole address no longer also matches the longer addresses it is the start of (`::10` and `::100`).

---

## Reservations restored by an older Jen never match their client

**Symptom.** After restoring a Kea backup or import file through Jen, or migrating the Kea database from the Databases page, a reservation is listed with the right IP and name but the client keeps getting a dynamic address. **Cause (fixed in 5.67.0-beta.11, present in every release before it, stable included).** The export wrote a binary column — a reservation's identifier — as hex text, nothing decoded it, and the restore stored that text: the six-byte MAC `34:13:43:e6:0e:2a` came back as the twelve characters `341343e60e2a`. The row looks right in every listing; Kea simply never matches it.

**Find it.** Health Center → **Kea reservations have plausible identifiers**: `fail` names how many rows. It only recognises what is recognisable: a hw-address that is 12, 16 or 40 hex-digit characters, or a DUID of hex-digit characters that decodes to a DUID type word (1 to 4). A client-id is different (v5.67.0-beta.15): it is opaque, and some embedded clients really do send their MAC as ASCII text, so a client-id counts as damaged — and fails the check — only when a lease shows the client using the decoded bytes. Without a lease to say, the check stays `ok` and mentions how many client-ids are hex text for you to review. Circuit-id and flex-id are never flagged — ASCII hex is legitimate text there.

**Repair it.** Settings → Databases → **Import** → **Check reservation identifiers** (superadmin). The page is a dry run: it lists each damaged row with the text stored now and the bytes it will become. Tick the rows and press **Repair selected**; each row is changed only if it still holds exactly what the preview showed, and only `hosts.dhcp_identifier` is written. If the correct identifier already exists on another reservation (you re-created it by hand) that row is skipped and left as it is — delete the damaged one from Reservations. Jen never changes Kea's schema; this is data, in the table Kea's own tooling would write.

**Ambiguous client-ids (v5.67.0-beta.15).** A client-id made only of hex digits with no matching lease is listed under *ambiguous, review by hand*, **unticked**, with the lease evidence (or the note that no lease matches). Tick one only if you know the client sends the binary form. When a lease shows the client sending exactly the stored text, the row is listed under *left alone* with no checkbox and is never repaired, even if its id is posted.

**Option values (v5.67.0-beta.15).** Per-host values of a few fixed-width DHCPv4 codes (subnet mask, routers, DNS and similar server lists, time offset, interface MTU, broadcast address, lease/renew/rebind times, server identifier) are checked too: a value whose length is exactly twice the code's width, all hex digits, that decodes to a plausible value (a real address, a contiguous mask, a lease time up to ten years) is listed in a second table, **unticked**, for you to review and repair. Text-typed DHCPv4 options (domain name, boot file, vendor data, …) are never listed — their text may legitimately be anything — so check THOSE by hand after a restore made before 5.67.0-beta.11. The DHCPv6 option table and `ipv6_reservations` cannot carry this damage and need no check: no Jen before 5.67.0-beta.11 wrote them at all (they joined the Kea backup in that release, with tagged bytes). Leases come back on their own — they expire and renew.

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

**Layout refusals (v5.67.0-beta.5+).** `install.sh`, `uninstall.sh`, and
the root self-updater all validate `app_dir`/`config_dir`/`data_dir`
through one shared check (`docs/ARCHITECTURE.md` §3.1/§6.1) on every
privileged run, not just at fresh-install time. Each refusal names the
exact fix:

- **"... must be a dedicated directory, not a shared system path" /
  "... must not live under /tmp" (etc.)** — the path you gave is (or is
  under) a shared FHS location Jen refuses to live in or under. Choose
  a dedicated subdirectory instead — `docs/installation.md` Method 1c
  lists every refused root.
- **"... may only contain letters, digits, '.', '_', '-' per path
  segment" / "... must be at most 200 characters"** — the path's
  grammar, not its location, is the problem. Rename the directory.
- **"... existing parent <dir> is not root-owned" / "... is writable by
  group or other"** — an *existing ancestor* of the path, not the path
  itself, fails this check. The writable-by-group-or-other case names
  its own one-line fix: `sudo chmod go-w <dir>`. The not-root-owned case
  means something other than root administers that ancestor at all —
  there's no safe workaround short of choosing a path whose ancestors
  really are root's own.
- **"... already exists and is a symlink"** — refusing to install
  through a symlink at the target path itself (not an ancestor):
  something pre-planted it there. Investigate before removing it; this
  is exactly the attack the ancestor check above also exists to close.
- **"... already exists, is not empty, and does not carry Jen's own
  marker"** — a *fresh install* target must be absent, empty, or
  already marked as Jen's own (`.jen-directory` inside it). The checker
  decides install versus upgrade itself: a recorded layout file, a
  marker, or Jen's own content in the app directory (`releases/`,
  `run.py` or `jen.py`) means an upgrade; an empty directory you
  pre-created is a fresh install, and a directory holding somebody
  else's files is refused — and left exactly as it was (5.67.0-beta.8
  and earlier treated it as an upgrade, then changed its ownership and
  stamped it). A *config* or *data* directory with Jen's content
  (`jen.config`; `icons`, `branding`, `backups` or `keys`) is accepted as
  a reinstall target without a marker. If this is genuinely your Jen
  directory and was refused, check it really contains that content.
- **"... must not live under /root"** (5.67.0-beta.9) — the service runs
  with `ProtectHome=yes`, which hides `/root` (and `/home`) from it, so
  nothing under either can work. Choose a path under `/srv`, `/opt` or
  a dedicated volume.
- **`uninstall.sh`: "The installed /usr/local/sbin/jen-update-root.py
  predates --check-layout and there is no jen-update-root.py beside
  this script"** (5.67.0-beta.9) — the installed updater is from a release
  that does not know the layout check (a 5.66.0 box, or one rolled back to
  it). Run `uninstall.sh` from the extracted release tarball, which carries
  its own copy and is preferred over the installed one.
- **"This install's <role> is already <path> — relocating an existing
  install is a runbook (docs/runbooks.md), not a flag"** — see
  `docs/runbooks.md` §5.
- **"<role> (<path>) does not carry Jen's own marker and isn't
  recognizable as one — refusing"** (uninstall only) — `uninstall.sh`
  refuses to `rm -rf` a directory it can't confirm is genuinely Jen's.
  If it really is, create the marker by hand as root (`role = app_dir`
  — or `config_dir`/`data_dir` — and `version = <installed version>`,
  two lines, in `<dir>/.jen-directory`, mode `0644`) and retry; if it
  isn't, you likely have `/etc/jen-layout.conf` pointing somewhere it
  shouldn't — check it before doing anything destructive by hand.

**A native install shows Docker wording — no Update button, no Restart
button (v5.67.0-beta.2 through beta.5 only).** Settings → System says
"Updates are the container image's job" and the Restart card talks
about `docker compose restart jen`, even though this box was installed
with `install.sh`, not Docker. The bug: `jen/services/plugins.py`'s
`is_systemd_host()` used to answer "is this systemd" by checking
whether `JEN_ROOT` was set in the environment — and the relocatable
install added in v5.67.0-beta.2 made the rendered systemd unit set
`JEN_ROOT` too, so every native install from that release through
v5.67.0-beta.5 answered "not systemd," exactly like a container or a
dev checkout. Fixed in v5.67.0-beta.6
(`jen/services/runtime.py::deployment()` is the one place that question
is answered now, and it never reads `JEN_ROOT`). The button this bug
hides is the only way to reach the fix, so updating a box stuck on one
of the affected betas needs the one line the button itself would have
run — **and the box must be on the beta channel**, because the updater
offers a pre-release only to one (a stable-channel box finds nothing newer
than the beta it is on, and the command does nothing). Put `channel = beta`
under `[updates]` in `jen.config`, then:
```bash
sudo systemctl start jen-update.service
journalctl -u jen-update -f
```
Or skip the updater: extract the newer release tarball and run
`sudo ./install.sh --upgrade`.
Nothing else about the box is wrong — Jen itself, the plugin manager's
root-managed install path, and the data-directory check all silently
fell back to their Docker/dev behavior on the same bug, and all three
are fixed by the same update.

---

## "DEBUG logging left on" (v5.68.0-beta.3)

Investigation logging (Trace or Servers) puts a Kea server's logger at DEBUG for 5, 15 or 60 minutes and the Kea host puts it back by itself at the deadline (since 5.68.0-beta.29: helper build 15 arms a timer on that host; Jen's sweep also checks every minute and shows what the host reports). The Health Center row **DEBUG logging left on** fails when a server's time is up and the restore has not happened — Kea is then writing a packet dump for every client.

1. **Press *Turn it off now*** on Trace or Servers. It is the same restore with no waiting; the flash line says whether the daemon took it by `config-reload` or a restart, and what failed if it did not.
2. **If the button fails too**, the cause is the same one the sweep keeps hitting — usually SSH to the host or the Kea host helper (Settings → Kea → SSH), or a config that changed under it. The banner and the Health row quote the error.
2a. **"Kea's running log level is unconfirmed" (v5.68.0-beta.23).** Jen reads the running Kea (`config-get`) after every reload and restart and only lets go of the entry when it has SEEN Kea back at its original level. The row says *unconfirmed since &lt;time&gt;* when Kea's API did not answer that read, and names what it saw when the logger is at something else (neither investigation DEBUG nor what it was before - a hand edit, or a second tool). Jen looks again every minute and does not reload or restart a Kea it cannot see. Check Settings → Kea → Probe; once the API answers the next sweep reads the logger and finishes or drops the entry. A reload that Kea applied while its reply was lost is found the same way.
2b. **"Kea on &lt;name&gt; is not back at its original log level" on the Servers page (v5.68.0-beta.23).** Jen restored the config file and then LOOKED at the running Kea, and did not like what it saw. Three cases, each with its own sentence: *Jen reloaded 3 times and restarted once; Kea is still at DEBUG 55* - Jen has stopped; run `config-reload` (or restart kea-dhcp4) on the Kea host yourself, then press **Forget** (it looks first and will not forget a Kea still at DEBUG). *Kea's running logger is &lt;level&gt;, neither investigation DEBUG nor what it was before* - a hand edit or another tool changed it; Jen has left it alone; set what you want, then press Forget. *The Kea that Jen's API settings answer for is not running the file Jen wrote* - `[kea] api_url` and the server's SSH host name different Kea servers; fix whichever is wrong (Settings → Kea warns when they resolve to different addresses), and check the Kea on the SSH host - it was restarted on the DEBUG file and may still be running it.
2c. **"Jen's record of investigation logging is unreadable" (v5.68.0-beta.24).** The `investigation_logging` setting (Jen's index of what is on) holds something that is not a record - a partial write, a hand edit, a restore from a damaged backup. Jen no longer reads that as "nothing is on": turning logging on is refused, and the Health row **DEBUG logging left on** fails until Jen has examined EVERY Kea server - its config file and its running Kea - and rebuilt the record (anything it finds at DEBUG is adopted and shown, and put back when its time is up). The scan retries every minute while the record is unreadable, and the row says when it last tried and what it could not examine (*kea-b: config unreadable*, *kea-c: running daemon not observed*). Nothing is rebuilt from a partial look, because the server it could not read may be the one at DEBUG: fix the connection to the server named (SSH, or the Kea Control Agent) and the next minute's scan finishes it. The old value is kept in the settings table as `investigation_logging.damaged`; turning logging on or off is refused until the record is rebuilt (a stored entry that is itself malformed counts as unreadable too, and the row names its server id).
   **The Servers page banner and the button (v5.68.0-beta.26).** While the record is unreadable the Servers page says so, and removing a Kea server in Settings (or blanking its SSH host) is refused with the same reason: Jen cannot tell whether that server is at investigation DEBUG, and removing it would lose the only way to put it back. If the rebuild keeps listing a server it cannot examine (*no Kea server with SSH is configured*, *kea-b: no SSH*) because there is nothing Jen can reach, an admin with access to every subnet can press **I checked every Kea by hand**: it asserts that you have looked at each Kea's `kea-dhcp4` logger yourself and none is at investigation DEBUG. Jen then replaces the record with an empty one, keeps the old value in `investigation_logging.damaged`, and writes an audit row naming you and what could not be examined. The button appears only while there is something recorded that the rebuild could not examine.
2d. **A logger left at DEBUG under Jen's marker is not "on" (v5.68.0-beta.24).** Investigation logging is DEBUG at debuglevel 55. A running `kea-dhcp4` logger that still carries the `jen-investigation` marker but is at another level (DEBUG 0, DEBUG 30) is reported as *DEBUG at debuglevel N, not 55* and left alone, like any other level Jen did not set; set it in the config file, reload Kea and press **Forget**.
2e. **"Changing its ssh_host now would point Jen at a different Kea" when saving Settings (v5.68.0-beta.27).** A server that has investigation logging on, or a restore not finished, keeps the settings that say which Kea Jen reaches: the API URL, the SSH host, the SSH user and the Kea config path. Jen refuses the save (and writes an audit row) because the Kea that is at DEBUG would be left there with nothing that could put it back. Press **Turn it off now** on Servers, wait for it to finish, then save. Credentials and the display name are not identity and can be edited meanwhile. The same refusal appears while Jen's record of investigation logging is unreadable (2c above). "Refused: duplicate or unknown server id" means the Additional Servers form repeated a server id or named one that is not configured - reload the page and try again.
2f. **The same refusal from the setup wizard, or from a direct-socket page, or about the connection mode (v5.68.0-beta.28).** The rule of 2e is enforced by the one place every change to `jen.config` passes, so it applies to every page that saves it: *Investigation logging is on for X ... turn it off from Servers first* appears wherever you were (the wizard's Connect or SSH step, Settings -> Kea, Set up / Remove direct socket) and nothing was saved - and for the two direct-socket pages nothing was sent to the Kea host either. *The connection mode is how Jen reaches EVERY Kea* means the Control Agent / direct switch is global, so ANY server's investigation logging blocks it. *Jen's settings could not be read (its database is unavailable)* means Jen's own database is down: Jen cannot tell whether a Kea is at DEBUG, so it refuses to turn logging on and to change where it reaches a Kea until the database is back (Health -> Jen database). *Jen could not check whether a Kea server has investigation logging outstanding* means the check itself failed: try again, and read the server log if it persists. Do not run `sudo ./install.sh --configure` while logging is on - the installer cannot see Jen's record.
2g. **"this write would remove the marker that tells Jen what to put back" when restoring from Config history, applying an import or authoring a config (v5.68.0-beta.28).** A server with investigation logging on keeps a marker in `kea-dhcp4.conf`; a write that carries a config without it is refused, before anything is sent, because it would leave Kea at DEBUG with nothing to say how to put it back. Press **Turn it off now** on Servers, then repeat the action. The same sentence naming *the settings could not be read* or *the record cannot be read* means Jen cannot tell whether the server has an entry: fix 2c / the database first. Ordinary subnet and option edits are never refused for this reason.
2h. **"Jen restarted Kea once (it had no config-reload to try) and will not again" (v5.68.0-beta.28).** The Kea on that host cannot be asked to re-read its config (no `config-reload`, or its API does not answer), so putting its log level back needs a restart - and the restart failed. Jen tried once and stopped, rather than restart a production daemon every minute. Make the unit start (`systemctl status kea-dhcp4-server`, or `isc-kea-dhcp4-server`), restart it, check the level, then press **Forget** on Servers. **"server N now names <host>" on a removed entry:** the number now belongs to a different Kea than the one logging was turned on for; restore the original by hand (the row says how) and press Forget.
3. **If the banner still shows after the config was fixed**, the file is clean but Kea has not taken it (v5.68.0-beta.9): a reload was refused and the restart failed. Jen keeps trying every minute; fix whatever stops Kea restarting (`systemctl status kea-dhcp4-server`, or `isc-kea-dhcp4-server` on older packages) and the next try finishes it.
4. **A server that was removed from Jen** while its logging was on cannot be reached any more: the Health row says *investigation logging may still be on on &lt;name&gt; (removed from Jen)* and gives the host and the config path. Do the by-hand edit below on that host, then press **I restored it by hand** on the Servers page.
5. **By hand**, on the Kea host: in `kea-dhcp4.conf`, find the `kea-dhcp4` entry in `loggers`, set `severity`/`debuglevel` back to what its `user-context.jen-investigation.restore` says (`"absent"` means delete the key; `{"created": true}` means delete the whole entry), delete the `jen-investigation` key, and `config-reload` (or restart) Kea. A hand edit that removed the marker is fine: the next restore finds nothing to change in the file and still reloads the daemon.
   **The restore marker is unreadable (v5.68.0-beta.13).** If the Health row says *the restore marker on &lt;name&gt; is unreadable — restore by hand*, the `jen-investigation` marker lost its `restore` object (a hand edit or a partial write). Jen changed nothing and will not guess what the logger was before. In `kea-dhcp4.conf` set the `kea-dhcp4` logger's `severity`/`debuglevel` to what you want (usually your old level; remove `debuglevel` if it had none), delete the `jen-investigation` key, and `config-reload` (or restart) Kea; or repair the marker's `restore` object and Jen restores it itself within a minute.
6. A log that still has no packet dump after turning it on usually has a more specific logger entry of its own (`kea-dhcp4.packets`) with its own severity; that one wins for its component.

## "The configuration is locked" when saving a setting (v5.68.0-beta.18)

Jen takes an advisory lock on `jen.config.lock` (in `/etc/jen`) for every save, and `sudo ./install.sh --configure` holds the same lock while its wizard is open
so a save cannot be overwritten by the installer's older copy. A save made during the wizard waits up to 30 seconds and then fails with *`…jen.config.lock is held
by another process (the installer's --configure?)`*. Finish or cancel the wizard (the lock is released when the installer exits) and save again. If nothing is
running, check `fuser /etc/jen/jen.config.lock` for a stuck process. The lock file must be owned by the service user (the installer creates it that way). **If
Jen cannot open it, the save is refused (v5.68.0-beta.19)** - it used to carry on without the lock - and is never "repaired" by swapping in a new file
(v5.68.0-beta.20: a lock belongs to a file, so a second file is a second lock); the message names the file and the fix, on the same file: `sudo chown <the Jen service user> /etc/jen/jen.config.lock; sudo chmod 600 /etc/jen/jen.config.lock`.
A symlink at that path is refused outright; remove it. `sudo ./install.sh --configure` needs `flock` (`util-linux`) and says so if it is missing.

## "Problems inbox sweep" is red (v5.68.0-beta.17)

The Problems inbox is filled by a sweep every five minutes that tails each SSH-configured server's Kea log. A quiet inbox could mean a quiet network or a sweep that cannot read the log; the Health Center row **Problems inbox sweep** tells them apart: it fails when a server's log has not been read for six sweeps in a row (thirty minutes) and names the server, its last successful read and its last error.

1. **`HelperUnreachable` or a timeout**: Jen cannot SSH to the host. Check Settings → Kea → SSH (key, user, host, trust) and the host's firewall; the sweep retries on its own every five minutes and the row turns green on the first successful read.
2. **`no-helper`**: the Kea host helper is missing, or too old to have `tail-log`; press **Update helper** on the Servers page. The sweep reads the log through the helper only.
3. **`missing`** ("log file not found"): the DHCP4 log path in Jen is not where Kea writes; Settings → Kea → the DHCP4 log path must be the file Kea logs to (the file output of the `kea-dhcp4` logger), readable by the helper.
4. **"the sweep itself last ran at …"** means the scheduler is not running the job: check the Background workers row and the service log.

## Log Locations

| Log | Location | How to view |
|---|---|---|
| Jen application | systemd journal | `sudo journalctl -u jen -f` |
| The installer (apt, pip, venv, systemctl, mysql output) | File | `sudo less /var/log/jen-install.log` (v5.67.0-beta.18) |
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
