# Jen User Guide

This guide covers the day-to-day use of Jen for managing your Kea DHCP infrastructure.

---

## Dashboard

The dashboard is the first page you see after logging in. It gives you a live overview of your entire DHCP infrastructure at a glance.

### Subnet Utilization Cards

Each configured subnet has a card showing:

- **Active leases** — total number of devices currently holding a lease
- **Dynamic** — devices using a dynamically assigned address (no reservation)
- **Reserved** — devices with a static reservation

The utilization bar at the bottom of each card fills as the subnet gets more active leases.

### Recently Issued Leases

The lower section of the dashboard shows leases issued within a recent time window. Use the dropdown in the top right of this section to change the window:

| Option | Shows leases from |
|---|---|
| Last 30 min | Default — good for seeing what just connected |
| Last 1 hour | Useful after a network change |
| Last 4 / 8 / 12 hours | Broader activity view |
| Last 24 hours | Full day overview |

Click **View All** to go to the full Leases page.

### Auto-Refresh

Dashboard statistics refresh automatically every 30 seconds. You do not need to reload the page.

### Kea Health Indicator

The small dot in the top right navigation bar shows whether Jen can reach the Kea DHCP service:

- 🟢 **Green** — Kea is online and responding
- 🔴 **Red** — Kea is unreachable (check if `isc-kea-dhcp4-server` is running on your Kea server)

---

## Leases

The Leases page shows all active dynamic leases — devices that received an IP address from the DHCP pool but do not have a static reservation.

### Filtering Leases

**Subnet** — filter to show only leases from a specific subnet.

**Time filter** — show only leases issued or renewed within the last N minutes. Useful for finding recently connected devices.

**Search** — search across IP address, hostname, and MAC address simultaneously.

**Show History** — toggle to show expired leases instead of active ones. Useful for seeing what was on your network recently.

### Converting a Lease to a Reservation

Click the **📌** button next to any lease to convert it to a static reservation. This pre-fills the IP, MAC, and hostname from the lease. You can optionally set a DNS override at this step.

This is the fastest way to reserve an IP for a device that is already connected.

### Releasing a Lease

Click the **✕** button next to any lease to release it immediately. The device will request a new lease the next time it needs one. This is useful for troubleshooting or forcing a device to pick up a new address.

### Deleting Stale Leases

The **🗑️ Delete Stale** button removes expired leases from the database. Kea normally handles this automatically, but the button is useful if you want to clean up immediately.

### IP Address Map

Click **🗺️ IP Map** to see a visual grid of the selected subnet showing which addresses are free, dynamically leased, or reserved. Hover over any cell to see the hostname and lease type.

---

## Reservations

The Reservations page shows all static host reservations — devices that always receive the same IP address.

### Adding a Reservation

Click **+ Add Reservation** and fill in:

| Field | Required | Notes |
|---|---|---|
| Subnet | Yes | Select which subnet this reservation belongs to |
| IP Address | Yes | Must be within the selected subnet's CIDR range |
| MAC Address | Yes | Format: `aa:bb:cc:dd:ee:ff` |
| Hostname | No | DNS-friendly name for the device |
| DNS Override | No | Comma-separated IPs — overrides the subnet's default DNS servers for this device |
| Notes | No | Free-text notes stored in Jen's database |

Jen checks for duplicate IPs and MACs before adding — you'll get a clear error if a conflict exists.

### Editing a Reservation

Click **✏️** to edit a reservation. You can change the hostname, DNS override, and notes. The IP address and MAC address cannot be changed through the edit form — delete and recreate the reservation to change these.

### Deleting a Reservation

Click **🗑️** and confirm to delete a reservation. The device will fall back to dynamic addressing on its next DHCP request.

### Exporting Reservations

Click **⬇ Export CSV** to download all reservations as a CSV file. The export includes IP, MAC, hostname, subnet, DNS override, and notes.

### Importing Reservations

Click **⬆ Import CSV** to bulk-import reservations from a CSV file. The file must have at minimum these columns: `ip`, `mac`, `subnet_id`. Optional columns: `hostname`, `dns_override`, `notes`.

Duplicate IPs are skipped automatically. Any rows with validation errors are reported after the import completes.

---

## Subnets & Scope Options

The Subnets page shows the live configuration of all subnets pulled directly from the Kea API. It is read-only by default unless SSH is configured for subnet editing.

### Reading Subnet Information

Each subnet card shows:

- **Lease Duration** — how long devices hold their lease before needing to renew
- **Renew Timer (T1)** — when devices first attempt to renew their lease
- **Rebind Timer (T2)** — when devices begin broadcasting for any DHCP server if renewal fails
- **Address Pools** — the range of IPs available for dynamic assignment
- **Scope Options** — DHCP options sent to devices on this subnet (router, DNS, etc.)

### Editing a Subnet

If SSH is configured in Settings, an **✏️ Edit** button appears on each subnet card. Click it to edit:

- **Address pool** range
- **Valid lifetime** (lease duration in seconds)
- **Renew timer** (T1 in seconds)
- **Rebind timer** (T2 in seconds)
- **Router** (gateway address)
- **DNS servers**

Changes are validated before being applied. If validation fails, your previous configuration is automatically restored from a backup. Kea restarts briefly when changes are applied — expect a few seconds of DHCP interruption.

---

## DDNS Status

The DDNS Status page shows activity from the Technitium DNS update script that runs alongside Kea.

### Log Activity

The log panel shows the most recent 200 lines from the DDNS log file, newest first. Lines are colour-coded:

- **Green** — successful DNS updates (new leases added)
- **Yellow** — deletions (leases expired or released)
- **Red** — errors

### Hostname Lookup

Enter a fully-qualified hostname in the lookup field and click **Lookup** to query your Technitium DNS server directly. The result shows all DNS records for that hostname including IP address, record type, and TTL.

---

## Audit Log

The Audit Log records every change made through Jen — who did it, when, and what changed.

### What Gets Logged

| Action | Logged when |
|---|---|
| LOGIN / LOGOUT | User signs in or out |
| ADD_RESERVATION | New reservation created |
| EDIT_RESERVATION | Reservation hostname or DNS changed |
| DELETE_RESERVATION | Reservation removed |
| RELEASE_LEASE | Lease manually released |
| DELETE_STALE | Stale leases purged |
| IMPORT_RESERVATIONS | CSV import completed |
| EXPORT_RESERVATIONS | CSV export downloaded |
| EDIT_SUBNET | Subnet configuration changed |
| ADD_USER / DELETE_USER | User account created or removed |
| CHANGE_PASSWORD | Password changed |
| UPLOAD_CERT | SSL certificate uploaded |
| SAVE_SETTINGS | Any settings page saved |
| GENERATE_SSH_KEY | SSH key pair generated |
| CLEAR_LOCKOUTS | Login attempt records cleared |

### Reading the Log

Each entry shows the timestamp, username, action type, the affected entity (usually an IP address or username), details, and the source IP address of the request.

The log is paginated — 50 entries per page.

---

## Dark / Light Mode

Click the 🌙 / ☀️ button in the top right navigation bar to toggle between dark and light mode. Your preference is saved in your browser and persists between sessions.

---

## Device Inventory

The Device Inventory (Management → Devices) shows every MAC address ever seen on your network. Unlike the Leases page which only shows currently active leases, the Device Inventory is a persistent record that survives lease expiry.

### Device Fingerprint Badges

Jen automatically identifies devices by manufacturer and type using OUI (MAC address prefix) lookup. Identified devices show a colored badge with the manufacturer's brand logo next to their hostname — on the Device Inventory, Leases, Reservations, and Dashboard pages.

For devices using randomized MAC addresses (iOS 14+ private MACs), Jen falls back to hostname pattern matching to identify the device type.

### Filtering the Inventory

**Search** — search across MAC address, device name, owner, and IP.

**Subnet** — filter to show only devices last seen on a specific subnet.

**Device type filter bar** — click any type badge (Apple, IoT, Gaming, etc.) to filter the inventory to that device type.

**Show stale only** — show only devices that have been inactive for longer than the configured stale threshold (default 30 days). Adjust the threshold with the "Stale after N days" field in the top right.

### Editing a Device

Click the **✏** button on any device row to open the edit modal. You can set:

- **Device Name** — a friendly label (e.g. "Living Room TV", "Work Laptop")
- **Owner** — who the device belongs to
- **Device Type** — manually override the auto-detected type. Choose from Apple, Android, IoT, Gaming, etc. Manual overrides show a 🔒 indicator and dashed badge border. The background tracking loop will not overwrite manual overrides. Choose "Auto-detect" to clear the override.
- **Icon Override** — choose a specific brand logo from the visual picker, including any custom icons you've uploaded in Settings → Icons
- **Notes** — any notes about the device

### Deleting a Device

Click the **✕** button to remove a device from the inventory. It will reappear the next time it gets a lease.

### Converting to a Reservation

Click the **📌** button to pre-fill the Add Reservation form with this device's MAC, last IP, and hostname.

---

## API Keys

Jen provides a read-only REST API for integration with tools like Home Assistant, Zabbix, and custom scripts.

### Creating an API Key

Go to **Settings → API Keys** and click **Generate Key**. Give the key a descriptive name. The key is shown only once — copy it immediately. If you lose it, revoke it and generate a new one.

Keys use Bearer token authentication:
```
Authorization: Bearer jen_your_key_here
```

### API Documentation

Go to **Settings → API Docs** for full endpoint documentation with parameters, example requests, example responses, and ready-to-paste Home Assistant YAML and Zabbix HTTP agent config.

---

## MFA (Multi-Factor Authentication)

### Enrolling MFA

Go to **Profile → Security → Enable MFA**. Scan the QR code with an authenticator app (Google Authenticator, Authy, 1Password, etc.). Save your backup codes — they are shown only once and cannot be recovered.

### Trusted Devices

After a successful MFA login, you can check "Trust this device for 30 days". Trusted devices skip MFA on subsequent logins from that browser. Manage trusted devices under **Profile → Security → Trusted Devices**.

### Backup Codes

If you lose access to your authenticator app, use one of your backup codes to log in. Each backup code can only be used once. After using one, go to Profile → Security to generate a fresh set.

---

## Settings → Icons

Go to **Settings → Icons** to manage the brand logos used in device fingerprint badges.

- **Bundled icons** — 24 brand logos included with Jen (Apple, Samsung, Cisco, Ubiquiti, Raspberry Pi, etc.)
- **Custom icons** — upload your own SVG to override any bundled icon or add a new manufacturer. Custom icons take priority over bundled ones and survive upgrades.

To upload a custom icon, enter an icon name (e.g. `amazon`, `mydevice`) and select an SVG file (max 100KB). The name must match the manufacturer key used in Jen's OUI database. See Settings → Icons for the list of available name keys.

---

## Mobile Access

Jen is fully usable on iPhone and iPad.

### iPhone
The navigation bar collapses to a hamburger (☰) menu button. Tap it to open the navigation drawer showing Dashboard, Management, Network, Settings, and About. Tapping a section navigates there and reveals the section sub-tabs below the nav bar — the same sub-tabs you see on desktop. All table data reflows into per-row cards on iPhone so there is no horizontal scrolling.

### iPad
The full desktop navigation is shown. Some lower-priority columns (MAC addresses, timestamps) are hidden on narrower iPad screens to keep tables readable — they are still available on desktop.

### Double-tap
All interactive elements respond to a single tap. If you previously experienced a delay before navigation, upgrade to v2.5.7 or later.

---

## Alert Channels — ntfy and Discord

### ntfy
[ntfy](https://ntfy.sh) delivers push notifications to any device with the ntfy app installed.

To add an ntfy channel: go to **Settings → Alerts → Add Channel**, choose **ntfy**, enter your server URL (use `https://ntfy.sh` for the public server or your self-hosted URL), topic name, and optional access token and priority.

### Discord
To add a Discord channel: go to your Discord server → **Server Settings → Integrations → Webhooks → New Webhook**, copy the webhook URL, then go to **Settings → Alerts → Add Channel**, choose **Discord**, and paste the URL.

---

## Kea Servers and HA

The **Network → Servers** page shows the status of all configured Kea servers. In a High Availability setup it shows:

- Which node is currently **⚡ ACTIVE**
- The HA mode (hot-standby, load-balancing, passive-backup)
- The HA state of each node (hot-standby, syncing, partner-down, etc.)

If multiple servers are configured but HA mode is not set, the page shows a warning with a link to configure it.

Configure HA in **Settings → Infrastructure → High Availability**.
