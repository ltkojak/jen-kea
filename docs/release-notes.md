# Jen Release Notes

---

## Version 1.0.0 — April 2026

Initial public release of Jen — The Kea DHCP Management Console.

### Dashboard
Live subnet utilization cards showing active leases, dynamic vs reserved breakdown. Recently issued leases with configurable time filter (30 minutes to 24 hours). Auto-refresh every 30 seconds. Kea health indicator in the navigation bar.

### Lease Management
Browse active and expired leases with subnet, time, and search filters. Manual lease release — remove a device's lease immediately. Delete stale leases from the database. One-click conversion of a dynamic lease to a static reservation. Visual IP address map showing free, dynamic, and reserved addresses per subnet.

### Reservations
Full add, edit, and delete with per-reservation notes. Duplicate detection checks both IP and MAC before adding. Per-reservation DNS override sends custom DNS servers to specific devices. Bulk CSV import with per-row validation and error reporting. CSV export including all fields and notes.

### Subnet Editing
Edit pool ranges, lease times, and scope options directly from the UI. Changes applied via SSH to the Kea server — no command line needed. Automatic config backup before every change with rollback if validation fails.

### Alerts
Telegram alerts for: Kea going down or recovering, new devices getting a DHCP lease (IP, MAC, hostname, and subnet in the message), and subnet utilization threshold breaches. All alert types individually toggleable in Settings.

### Security
Login rate limiting with configurable attempt limit, lockout duration, and lockout mode (IP, username, or both). HTTPS support with certificate upload through the UI. Session timeout configurable globally and per user. Full audit log of all changes.

### Infrastructure
Prometheus metrics endpoint at `/metrics`. Guided installer handles new installs and upgrades with pre-flight checks, live connection testing, and automatic rollback on failure. Docker support with external or bundled MySQL options. Uninstaller included.

### Interface
Dark/light mode toggle with browser persistence. Sortable columns on all tables. Pagination on leases, reservations, and audit log. Responsive design — works on mobile and tablet.
