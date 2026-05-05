# Jen Installation Guide

---

## Requirements

### Bare Metal / Systemd

- Ubuntu 22.04 or 24.04
- Python 3.10 or newer
- Network access to your Kea server (ports 8000 for API, 3306 for MySQL)
- MySQL/MariaDB server accessible for the Jen database

### Docker

- Any Linux host with Docker and Docker Compose plugin installed
- Network access to your Kea server

---

## Pre-Installation: Kea Server Setup

Before installing Jen, prepare your Kea server.

### Enable Remote MySQL Access

Edit `/etc/mysql/mariadb.conf.d/50-server.cnf` on your Kea server:

```
bind-address = 0.0.0.0
```

Restart MariaDB:
```bash
sudo systemctl restart mariadb
```

### Create MySQL User for Jen (Kea Database Access)

```sql
CREATE USER 'kea'@'YOUR-JEN-SERVER-IP' IDENTIFIED BY 'your-password';
GRANT SELECT, INSERT, UPDATE, DELETE ON kea.* TO 'kea'@'YOUR-JEN-SERVER-IP';
FLUSH PRIVILEGES;
```

### Create the Jen Database

```sql
CREATE DATABASE jen;
CREATE USER 'jen'@'YOUR-JEN-SERVER-IP' IDENTIFIED BY 'your-password';
GRANT ALL PRIVILEGES ON jen.* TO 'jen'@'YOUR-JEN-SERVER-IP';
FLUSH PRIVILEGES;
```

---

## Installation Methods

### Method 1 — Guided Installer (recommended)

```bash
tar xzf jen-v3.4.4.tar.gz
cd jen
sudo ./install.sh
```

The installer will:
1. Run pre-flight checks (OS, Python, disk space, dependencies)
2. Ask: bare metal or Docker
3. Walk you through all configuration values interactively
4. Test Kea API and database connections
5. Install files, set permissions, enable service
6. Start Jen and verify it responds

### Method 2 — Docker (external MySQL)

```bash
cd jen
cp jen.config.example jen.config
nano jen.config    # fill in all values
docker compose up -d
```

### Method 3 — Docker (bundled MySQL)

```bash
cd jen
cp jen.config.example jen.config
# Edit jen.config — set [jen_db] host = jen-mysql
nano jen.config
cp .env.example .env
nano .env          # set MySQL passwords
docker compose -f docker-compose.mysql.yml up -d
```

### Method 4 — Manual bare metal

```bash
sudo apt install -y python3-pip mariadb-client-core openssh-client
sudo pip3 install flask flask-login pymysql requests --break-system-packages

tar xzf jen-v3.4.4.tar.gz
cd jen
sudo mkdir -p /opt/jen /opt/jen/static /etc/jen /etc/jen/ssl /etc/jen/ssh
sudo cp jen.py /opt/jen/jen.py
sudo cp -r templates /opt/jen/templates
sudo cp jen.service /etc/systemd/system/jen.service
sudo cp jen-sudoers /etc/sudoers.d/jen
sudo chmod 440 /etc/sudoers.d/jen
sudo cp jen.config.example /etc/jen/jen.config
sudo nano /etc/jen/jen.config
sudo chown -R www-data:www-data /opt/jen /etc/jen
sudo systemctl daemon-reload
sudo systemctl enable --now jen
```

---

## First Login

Open `http://YOUR-SERVER-IP:5050` in your browser.

| Username | Password |
|---|---|
| admin | admin |

**Change this password immediately** — go to Users → Change My Password.

---

## Post-Installation Steps

1. **Change the admin password** — Users → Change My Password
2. **Upload an SSL certificate** — Settings → SSL Certificate (enables HTTPS on port 8443)
3. **Generate SSH key** — Settings → SSH Key Management (required for subnet editing)
4. **Configure Telegram** — Settings → Telegram Alerts (optional)
5. **Add additional users** — Users → Add User (optional)

---

## Upgrading

Run the installer from the new tarball:

```bash
tar xzf jen-vX.X.X.tar.gz
cd jen
sudo ./install.sh
```

Select bare metal, then **Keep existing config**. Your configuration, certificates, SSH keys, and user accounts are preserved.

---

## Uninstalling

```bash
sudo ./uninstall.sh
```

This removes the application files and service. Configuration files and data are preserved by default — you'll be asked separately if you want a full wipe.
