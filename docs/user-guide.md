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

### IPv6 (v5.45.0)

With IPv6 enabled (Settings → Infrastructure), the subnet grid shows IPv6 alongside IPv4 rather than as a separate section: a small **v4**/**v6** tag on each card tells you which is which, and an IPv6 subnet that's paired with one of your IPv4 subnets (configured in `jen.config`'s `[subnets6]` section) nests inside that same card instead of getting a card of its own — an unpaired IPv6 subnet still gets its own card. IPv6 has no pool-size concept comparable to IPv4's, so its cards show active leases and reservations only, with no utilization bar. The Total Summary widget adds IPv6 active/reserved numbers to the same row, tagged the same way.

### Customize and Arrange (v5.54.0)

**Customize** (top right) is where you turn widgets on and off — the original eight plus seven more added in v5.54.0: Pool Exhaustion Forecast, Packet Health, Kea 3.2 Readiness, Recent Events, HA State, DDNS Errors, and Getting Started. Each of the new ones only loads its data once it is actually on the dashboard, the same way the existing sparklines, top-devices and alert-summary widgets already worked — turning one off costs nothing. A widget with nothing to say for your install (HA State on a single-server setup, DDNS Errors when DDNS updates are off) simply doesn't appear. **Save Layout** saves which widgets show; it doesn't touch their order, width or the subnet cards' arrangement.

**Compact subnet cards** collapses each subnet card to its name, active count and utilization bar, dropping the dynamic/reserved detail line and the gateway/DNS/IPv6 extras — useful when you have many subnets and want to see more of them at once.

**Arrange…** puts the page into arrange mode: every widget and every subnet card gets a grip handle, up/down arrows, and (for widgets, on a desktop screen) a width picker — full, half or third of the row. On a desktop you can drag a card by its grip to reorder it; on a phone, use the arrows instead (dragging doesn't work reliably there). Each subnet card also gets a pin button, which moves it to the front ahead of everything else, and a hide button, which removes it from the dashboard without affecting anything else — a hidden subnet is still fully visible and manageable everywhere else in Jen (Leases, Reservations, Subnets), just not shown as a dashboard card. **Save arrangement** writes the new order, widths, and subnet pin/hide state to your account; **Cancel** puts everything back the way it was.

If your account's subnet access changes later, any pinned, hidden, or ordered subnet id you can no longer see is dropped automatically — it never lingers in your saved layout.

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

## Getting started (v5.39.0)

**Getting started** (admins; the nav pill, or `/getting-started`) is the first-hour checklist: each row is one thing worth having in place — SSH and the Kea host helper current, HTTPS, MFA on your account, an alert channel, a backup, a second server for HA — with a **Fix** link on any that isn't. The pill in the top bar shows `done/total` until everything is green. A superadmin can hide the pill for the whole install with **Dismiss the nav reminder**; the page itself stays available.

## Why did this client get this? (v5.35.0)

**Network → Explain**, or *Why this address?* in the action menu of any lease or reservation row. Give it a MAC (and, if you have them, the vendor class, user class, hostname, client id, relay ids or giaddr the client sends) and Jen walks the decision Kea makes, step by step:

1. **Subnet selection** — the subnet you chose, or the lease's / a reservation's; a giaddr is checked against the subnet's relay addresses and range.
2. **Reservation** — by MAC or client id, in this subnet or globally when the subnet allows global reservations. This decides KNOWN / UNKNOWN.
3. **Client classes** — every class in config order, with *matched*, *no*, *undecided* (an input you didn't supply, named) or *not evaluable*. Jen evaluates exactly the expressions its own rule builder writes; anything else is shown verbatim rather than guessed.
4. **Subnet guards** — which subnets in the shared network the client is allowed into.
5. **Pools and address** — the reserved address, else the current lease (renewed), else the first pool whose guard classes are satisfied.
6. **Options** — the reply's options with where each came from and what it overrode (reservation > pool > subnet > shared network > class > global), and the lease lifetime.

Kea has no dry-run, so this is a reconstruction from the configuration Jen holds; it cannot see which interface a request arrived on. Only subnets you can access are shown.

## Trace a client (v5.48.0)

**Network → Explain → "What Kea logged"**, or *Trace in Kea log* in the action menu of any lease or reservation row (admins only). Explain predicts what Kea *should* do; Trace shows what it *did*: Jen reads the tail of the Kea server's `kea-dhcp4` log (through the same helper `tail-log` op the DDNS log tab uses — no packet capture, nothing installed), keeps the lines that name the client's MAC, and shows them in plain English grouped into exchanges — DISCOVER → offer → REQUEST → ACK, a NAK, a release or a decline. Lines are grouped when they are less than two seconds apart. Above the timeline, Explain's answer for the same client ("Jen expects subnet 3, 10.0.1.55") sits next to it so the two can be compared.

**Watch for 60 s** re-reads the log every 5 seconds, then stops on its own.

What it can see depends on the server's log level. At Kea's default (INFO) the log shows packets received and sent, offers, allocations, reuse, releases, declines and errors — but not DISCOVER/REQUEST processing, subnet selection, or most of the reasons for a NAK, which Kea only logs at DEBUG. The page says which case it found; see the [Kea logging section](https://kea.readthedocs.io/en/latest/arm/logging.html) to raise the level. Kea logs no line when it queues a DDNS update — only when sending one fails — so a healthy DNS update leaves nothing to show here.

Only the last 1000 lines are scanned (the helper's own limit), so on a busy server an older exchange may already be out of the window. Trace needs the **Kea host helper** on the server (Settings → Kea → SSH → Install helper): it reads the log through the helper's bounded `tail-log`, never through the old `tail -200` sudo grant, which could not serve 1000 lines. Without the helper the page says so instead of showing a partial log. If your Kea writes its log somewhere other than `/var/log/kea/kea-dhcp4.log`, set `[kea] dhcp4_log_path`. The log can contain other clients' data — and Kea's log has no per-line subnet boundary Jen can trust, so a client's earlier activity in another subnet can sit in the last 1000 lines whatever its current lease says. Trace is therefore admin-only **and needs access to all subnets**: a subnet-restricted admin gets a refusal for every MAC, and the *Trace in Kea log* links are hidden from them. It is never part of the support bundle.

## Timeline (v5.42.0)

**Network → Timeline**, or *Timeline* in the action menu of any lease, reservation or device inventory row — also linked from an Explain result ("What happened to this client?"). Give it a MAC or an IP and it shows everything Jen has recorded about that one client, newest first:

- **Events** — a new lease, an IP or hostname change, an expired lease, a reservation added/deleted/changed, a config push, an HA state change, config drift detected or resolved, and every alert Jen sent, with which channel and whether it landed.
- **Audit log** entries and **alert** deliveries that mention the MAC or IP in their text.
- The device's first-seen/last-seen bookends, and its current lease and reservation, at the top.

An IP with no MAC given resolves to its current lease's MAC automatically. Filter chips narrow the list to one kind of event at a time. Only subnets you can access are shown — a client whose subnet you can't see, or one with no resolvable subnet at all, isn't shown to a subnet-restricted user.

Addresses get reused, so a timeline about a **MAC** shows only that client's own rows: events recorded for the same address under a different MAC are left out, and a row that names only the address (an audit or alert entry, or an event with no MAC) is kept but shown muted as *possibly related — same address, client unknown*. A timeline about an **IP** shows everyone who held it, and marks rows from an earlier holder *previous holder <mac>*.

Jen keeps events for 90 days by default — the same retention job that prunes lease history.

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

## Reports and the exhaustion forecast (v5.36.0)

**Reports** charts each subnet's lease history from the snapshots Jen
takes every few minutes (the interval and retention are set at the
bottom of the page). Each subnet card shows the current active leases,
the peak over the selected range, the pool size and free addresses.

Below that is the forecast: the highest active-lease count in the last
30 days and the day it happened, the trend in leases per day, and — when
the trend is rising — roughly when it reaches 90 % of the pool, with the
date. The chart draws that trend forward as a dashed *Projected (trend)*
line from the last snapshot to the day the pool would fill (at most 30
days ahead).

How it is worked out: the highest active-lease count of each day over the
last 30 days, a straight line fitted through those daily peaks, extended
forward. It needs 7 days of snapshots before it says anything, only uses
snapshots taken since the pool was last resized, and reports a crossing
more than a year out as "beyond the horizon" rather than a date. A flat
or falling trend shows no date. The forecast line turns amber when 90 %
is within 30 days and red within 7 — the same thresholds the **Pool
exhaustion forecast** check on the Health page and the optional
**Pool exhaustion forecast** alert use.

---

## DDNS Status

### Reconcile (v5.47.0)

**Network → DDNS → Reconcile** checks every reservation and active lease that carries a hostname against DNS — does the name resolve to that IP, and does the IP resolve back to the name — and gives each row a verdict (`ok`, `missing-forward`, `wrong-forward`, `missing-ptr`, `wrong-ptr`, `stale-ptr`, `multiple-a`, `lookup-failed`). It is read-only and subnet-restricted; nothing is written to DNS or Kea. `lookup-failed` means the resolver could not answer — it says nothing about the record. Filter by verdict or export CSV; the admin guide has the full table.

## Configuration Doctor (v5.40.0)

**Network → Doctor** (admins with access to all subnets) reads the live Kea config and lists contradictions, unused objects and risky settings, worst first, each with what to change. It only reads. The admin guide's "Configuration Doctor" section lists every check.

## Recovery bundle (v5.44.0)

A superadmin can download one encrypted **recovery bundle** from Settings → Databases: config, keys, content and the Jen database in a single file protected by a passphrase you choose. It is for rebuilding a lost Jen host — see "Recovery Bundle" in the admin guide for the restore steps.

The DDNS Status page shows activity from the Technitium DNS update script that runs alongside Kea.

### Log Activity

The log panel shows the most recent 200 lines from the DDNS log file, newest first. Lines are color-coded:

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

## Theme (v5.55.0)

Click the palette icon in the top right navigation bar (or **Theme** in the phone's More sheet) to pick a look: Dark, Light, High contrast, Phosphor, or Custom once an install has defined one. Your pick is saved in your browser and persists between sessions — it never affects what anyone else sees.

At the top of the menu, **Install default (\<name\>)** switches back to whatever the install's superadmin has set as the default look (Settings → Appearance → Theme), for anyone who hasn't picked one for themselves. A checkmark shows which one is currently active — on a preset only if you've actually chosen it, on **Install default** otherwise.

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

### IPv6 (v5.45.0)

With IPv6 enabled, a device row shows its current IPv6 address(es) in an **IPv6** column whenever Kea itself captured that device's hardware address on an IPv6 lease — Jen only ever links the two by the address Kea reports, never by guessing a MAC from a DUID. An IPv6 client that only ever sent a DUID — no hardware address at all — can't be safely matched to a device, so it appears as its own row at the bottom of the inventory, badged **DUID only**, rather than being merged into an existing one.

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

### Passkeys (v5.31.0)

On the same page, **Add a Passkey** enrolls a passkey as your second factor — Windows Hello, Touch ID / iCloud Keychain, Android, a password manager such as 1Password, Bitwarden or Keeper, or a hardware key such as a YubiKey. Give it a name so you can tell them apart. At login you'll land on a **Passkey** tab and confirm with a fingerprint, face, PIN or touch instead of typing a code; the Authenticator and Backup Code tabs are still there. If the card says the browser can't create a passkey, the page isn't https — ask your administrator. Enrolling a passkey as your first factor also issues backup codes; keep them.

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
A tab bar along the bottom holds Dashboard, Leases, Reservations, Settings (a viewer, who has no Settings page, sees Devices there) and **More**. More opens a sheet that lists every page grouped as on desktop — Management, Network, Settings, plugins — with search, the theme picker, your account links and Logout. The top bar keeps the logo, the Kea status dot and your avatar. The section sub-tabs sit below it, scroll sideways, and start with the current page in view. Tables that have been converted show one two-line row per item; pages not yet converted still show per-row cards, so there is no horizontal scrolling either way.

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

### Packet Health (v5.41.0)

Below each server's status card, the **Servers** page shows a **Packet health (last 60 min)** block — is Kea actually processing DHCP traffic cleanly, not just reachable?

- A status badge: **OK**, **Warn**, **Fail**, or **No traffic** (informational — a standby server in a hot-standby HA pair legitimately sees no traffic).
- A sparkline of packets received per snapshot.
- Rates for received / offered / acked / naked / dropped / parse-failed / allocation-failed traffic.
- A collapsed **All counters** table with every other `pkt4-*`/`v4-*` counter Kea reports — including any newer Kea version's counters Jen doesn't specifically name.

The block reads **Warn** when drops and parse failures exceed 1% of received traffic (over the trailing window) or any allocation failure occurred, and **Fail** when NAKs exceed 10% of ACKs or drops exceed 10% of received. It needs two snapshots before it can show a rate — the snapshot interval is the same one configured in **Reports → History Settings**.

A **Packet Health** alert fires once when a server's status flips to Warn or Fail, and again when it recovers — see **Alert Channels** above to configure where it's sent. The admin guide's Health Center also carries a `packet_health` row with the always-current verdict.
