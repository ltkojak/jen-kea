# Jen — Frequently Asked Questions

---

## General

### What is Jen?

Jen is a web-based management interface for ISC Kea DHCP Server. It gives you a browser-based UI to manage leases, reservations, subnets, and DHCP settings — similar to the Windows DHCP Server management console, but for Kea.

### Why was Jen built instead of using Stork?

ISC Stork is the official management UI for Kea, but it's designed for large enterprise and ISP deployments with multiple Kea servers, HA pairs, and teams of engineers. For a homelab or small infrastructure setup, it's overly complex, harder to navigate, and lacks some day-to-day conveniences like one-click lease conversion and CSV export. Jen was built to fill that gap.

### Does Jen replace Kea?

No. Jen is a management interface — Kea still does all the actual DHCP work. Jen talks to Kea through its REST API and MySQL database.

### What version of Kea does Jen support?

Kea 3.0+ with MySQL backend. Kea's MySQL schema has changed between versions — if you upgrade Kea, check the Jen troubleshooting guide if you encounter errors.

### Does Jen work on mobile?

Yes. The UI is responsive and works on phones and tablets. Dark mode is the default which works well on mobile screens.

---

## Installation

### Do I need to install Jen on the same server as Kea?

No. Jen is designed to run on a separate server. It connects to Kea's REST API and MySQL database over the network. In a typical setup Kea runs on one server and Jen runs on another.

### Can I run Jen on the same server as Kea?

Yes, though it's not recommended. The benefit of separation is that if Kea crashes or needs maintenance, Jen is unaffected and you can still see what's happening.

### What ports does Jen use?

By default: HTTP on 5050 (redirects to HTTPS when a certificate is installed) and HTTPS on 8443. Both are configurable in `jen.config`.

### Why does Jen need its own MySQL database?

Jen stores things that Kea doesn't know about — user accounts, per-reservation notes, audit log entries, settings like Telegram credentials and session timeouts. Rather than add these to the Kea database (which could cause issues with Kea upgrades), Jen has its own separate database.

### Can I use the same MySQL server for both Kea and Jen databases?

Yes. They just need to be separate databases (`kea` and `jen`) with separate users.

---

## Leases and Reservations

### What's the difference between a dynamic lease and a reservation?

A **dynamic lease** is temporary — the device requested an IP from the pool and Kea assigned one. When the lease expires the IP goes back into the pool. The device might get a different IP next time.

A **reservation** (also called a static reservation or host reservation) permanently associates a specific IP with a specific MAC address. The device always gets the same IP regardless of lease expiry.

### Why do some devices show as dynamic even though they always get the same IP?

If a device consistently gets the same IP from the dynamic pool it's because Kea tends to offer the same IP to a device it has seen before — but this is not guaranteed. To ensure a device always gets the same IP, create a reservation.

### Can I reserve an IP outside the dynamic pool range?

Yes. Reservations can use any IP within the subnet, even IPs outside the dynamic pool range. This is common for servers and network devices that need predictable addresses.

### What happens when I release a lease?

The lease is immediately removed from Kea's database. The device will send a DHCP Discover the next time it needs network access and receive a new lease — possibly the same IP, possibly a different one depending on what's available.

### Why can't I change the IP or MAC on an existing reservation?

Kea stores reservations keyed by MAC address. Changing the MAC is effectively a different reservation entirely. The correct approach is to delete the old reservation and create a new one with the updated details. Jen enforces this to avoid accidental errors.

### What does DNS Override do on a reservation?

It sends a custom DNS server list to that specific device instead of the subnet's default DNS servers. Useful if certain devices should use different DNS (e.g., a device that should bypass your Pi-hole, or one that needs to use public DNS like Quad9).

---

## Subnets

### Why can't I edit subnets without SSH?

Kea's subnet configuration lives in `kea-dhcp4.conf` on the Kea server. Unlike reservations (which are stored in MySQL and can be changed via the API), subnet settings like pool ranges and lease times are only in the config file. Editing them requires writing to that file and restarting Kea — which requires SSH access to the server.

### Will there be DHCP downtime when I edit a subnet?

Yes, briefly. Kea must restart to apply config file changes. The restart typically takes 2-3 seconds. Devices with existing leases are unaffected — they keep their current lease until it expires. New DHCP requests during the restart window may be delayed slightly.

### What happens if I make an invalid subnet edit?

Jen validates the new configuration with `kea-dhcp4 -t` before applying it. If validation fails, your previous configuration is automatically restored from a backup and Kea is not restarted. You'll see an error message explaining what went wrong.

### What are T1 and T2 timers?

**T1 (Renew Timer)** — when a device first tries to renew its lease directly with the server that gave it. Typically 50% of the valid lifetime.

**T2 (Rebind Timer)** — if renewal at T1 fails, at T2 the device starts broadcasting to any available DHCP server. Typically 87.5% of the valid lifetime.

If T1 and T2 are not set, devices calculate them from the valid lifetime automatically.

---

## Alerts

### Why am I not receiving new lease alerts even though Telegram is configured?

The new lease alert works by polling the database every 30 seconds for leases that didn't exist in the previous poll. Make sure:

1. "New device lease" is checked and saved in Settings → Telegram Alerts
2. "Enable Telegram alerts" is checked
3. The Jen service has been restarted since you saved (the polling thread starts at launch)

Also note that **reserved** devices don't trigger new lease alerts — only dynamic leases do.

### Can I get alerted for every DHCP renewal, not just new leases?

No — that would be extremely noisy. Renewals happen constantly as devices maintain their leases. The new lease alert only fires when a device gets a lease it didn't have in the previous 30-second check interval.

### What does the utilization alert threshold mean exactly?

It compares the number of active dynamic leases against the pool size (number of IPs in the address pool range). If 80 IPs are in the pool and 68 devices have dynamic leases, that's 85% — above the default 80% threshold, triggering an alert.

---

## Security

### Is HTTP safe to use internally?

Your username and password are sent in plaintext over HTTP. On an internal network where you trust all devices, the practical risk is low — but it's better practice to use HTTPS, especially if you have IoT devices or untrusted devices on the same network segments.

### How does rate limiting work?

After a configurable number of failed login attempts within the lockout window, further attempts from the same IP or username (or both) are blocked for the lockout duration. The window is rolling — only attempts within the last N minutes count, so old attempts don't accumulate indefinitely.

### Where are user passwords stored?

As SHA-256 hashes in the Jen MySQL database. Plain text passwords are never stored.

### Can Jen access other parts of my network?

Jen only communicates with: your Kea server (API port and MySQL port), your Telegram bot API (outbound HTTPS to api.telegram.org), and your Technitium DNS server if configured. It does not make any other outbound connections.

---

## Maintenance

### How do I back up Jen?

The important things to back up are:
- `/etc/jen/jen.config` — your configuration and credentials
- `/etc/jen/ssl/` — your SSL certificates
- `/etc/jen/ssh/` — your SSH keys
- The `jen` MySQL database — contains users, audit log, notes, settings

The application files in `/opt/jen/` don't need backing up — they're reinstalled from the tarball during upgrades.

### How often does the ZeroSSL certificate need renewing?

Every 90 days. Jen's Settings page shows the expiry date. When it's time to renew, issue a new certificate from ZeroSSL and upload it through Settings → Replace Certificate. No command line work required.

### Does Jen store any data about my network that I should be aware of?

Jen stores: user accounts and password hashes, per-reservation notes you've added, the audit log of all changes, Telegram credentials, and session/rate limiting settings. All of this is in the `jen` MySQL database. Jen does not cache or store lease or reservation data — it reads that live from Kea's database on every page load.
