# Jen Troubleshooting Reference

---

## Jen Won't Start

**Check the logs first:**
```bash
sudo journalctl -u jen -n 50 --no-pager
```

### SyntaxError in jen.py

The application file is corrupted or incompatible with your Python version.

```bash
python3 -c "import ast; ast.parse(open('/opt/jen/jen.py').read()); print('OK')"
```

Fix: re-run the installer to reinstall the application files.

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

Fix:
```bash
sudo chown -R www-data:www-data /opt/jen /etc/jen
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

### Permission denied on kea-dhcp4.conf

```
PermissionError: [Errno 13] Permission denied: '/etc/kea/kea-dhcp4.conf'
```

The SSH user needs sudo access to write the config file. On your Kea server:
```bash
sudo cat /etc/sudoers.d/jen-kea
```

Should contain:
```
youruser ALL=(ALL) NOPASSWD: /usr/sbin/kea-dhcp4, /usr/bin/systemctl restart isc-kea-dhcp4-server, /bin/cp, /usr/bin/tee, /usr/bin/python3
```

If missing:
```bash
echo "youruser ALL=(ALL) NOPASSWD: /usr/sbin/kea-dhcp4, /usr/bin/systemctl restart isc-kea-dhcp4-server, /bin/cp, /usr/bin/tee, /usr/bin/python3, /usr/bin/tail" | sudo tee /etc/sudoers.d/jen-kea
sudo chmod 440 /etc/sudoers.d/jen-kea
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
