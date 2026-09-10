# Jen Troubleshooting Reference

---

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

Every Kea-side action Jen performs goes through `jen-kea-helper` at
`/usr/local/sbin/jen-kea-helper`, behind one sudoers line. **Settings →
Kea → SSH** shows `v1` or `v2` for each host that has it (v5.16.0 ships
`v2`; a `v1` host works but shows an "upgrade available" hint — press
**Install helper** to update it).

Two failure signatures, both meaning "Jen fell back to the legacy root
`python3` path for that host":

- `sudo: a password is required` — the **sudoers line is missing** for
  this SSH user. Add
  `youruser ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper` to
  `/etc/sudoers.d/jen-kea-helper` (`sudo visudo -c -f` it).
- `jen-kea-helper: command not found` / `No such file or directory` —
  the **helper isn't installed**. Use **Install helper** in Settings →
  Kea → SSH (needs the legacy `/etc/sudoers.d/jen` grant present once),
  or copy it by hand:
  `sudo install -o root -g root -m 0755 /opt/jen/current/app/jen-kea-helper /usr/local/sbin/jen-kea-helper`
  (`/opt/jen/jen-kea-helper` on a pre-5.14 flat install).

Once every host shows `v1` you can delete `/etc/sudoers.d/jen` (the old
`python3` = root grant). Full details: **Admin Guide → Kea host helper**.

### Permission denied on kea-dhcp4.conf

```
PermissionError: [Errno 13] Permission denied: '/etc/kea/kea-dhcp4.conf'
```

The SSH user needs the helper's sudoers line (or, on the legacy path,
the `/usr/bin/python3` grant). On your Kea server:
```bash
sudo cat /etc/sudoers.d/jen-kea-helper   # the one-line helper grant
sudo cat /etc/sudoers.d/jen              # the legacy fallback, if still present
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
Kea → SSH → Install helper**) to get the atomic guard and out-of-band
change tracking.

---

## Upgrades and the versioned layout (v5.14.0+)

Jen installs each release into `/opt/jen/releases/<X.Y.Z>/` and points
`/opt/jen/current` at the live one. `sudo journalctl -u jen-update.service`
has the in-app updater's output.

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

## Mobile

### Pages are slow to respond on iPhone

If tapping requires two taps or navigation is delayed, you are running a version before 2.5.7. Upgrade to v2.5.7 or later.

### Hamburger menu not opening

Ensure JavaScript is enabled in Safari. The hamburger toggle requires JS.

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
