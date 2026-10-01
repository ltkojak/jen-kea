# Features

The README's own [feature matrix](../README.md#what-jen-does) is the
quick reference — what each area does, and what it needs. This page is
the full detail behind it, one section per area, with the version each
capability shipped in.

## Dashboard
- Live subnet utilization cards with dynamic/reserved breakdown and gateway/DNS display
- Recently issued leases with time filter
- Server status and HA state
- Alert summary feed
- Auto-refresh with configurable interval
- Customizable widget layout
- Seven built-in color themes (Dark, Light, High contrast, Phosphor, Slate, Ember, Retro) or an install-defined custom palette — picked per person, independent of the install default (v5.55.0, more presets in v5.56.0)

## Lease & Reservation Management
- Browse active leases with subnet, search, and time filters
- Manual lease release, stale lease cleanup
- One-click convert dynamic lease to reservation
- Full reservation add/edit/delete with notes
- Bulk CSV import and export
- Duplicate detection (IP and MAC)

## Subnet Management
- Edit pool ranges, lease times, gateway, and DNS directly from the UI
- Changes applied via SSH to Kea with config validation before restart
- Every change is validated (`kea-dhcp4 -t`) and backed up on the host
  before it's written; a multi-server change is pre-flighted on every
  server before the first write and reverted if a later server refuses it
- Gateway and DNS visible on subnet cards
- Shared networks: subnets grouped by network, create/delete a network,
  move a subnet in or out (v5.15.0)
- Config history per server — diff and restore any past config, and a
  write is refused if the file changed under you (v5.16.0)
- DHCP options at the global, shared-network, subnet, and pool level,
  with an effective-options view showing precedence (v5.18.0)
- Client classes — a guided rule builder or a raw expression, a
  config-test preview before you save, and a checklist for attaching
  each one to subnets/pools/shared networks as a guard or additional
  class (v5.19.0)
- Config history is encrypted at rest and masked by default (secrets
  redacted in the diff and the download); a superadmin can still pull
  the real body with a step-up confirmation (v5.20.0)
- HA operations console — live local/remote HA state, a per-subnet
  lease-count comparison across the pair, and the HA commands (sync,
  scopes, maintenance, reset) as confirmed, audited buttons (v5.21.0)
- DDNS as a first-class D2 subsystem alongside the existing provider
  integrations — status/naming/config tabs for Kea's own kea-dhcp-ddns
  daemon (forward/reverse zones, TSIG keys), plus a Verify tool that
  checks real DNS results through the Jen host's own resolver (v5.23.0)
- Import from Windows DHCP — upload an `Export-DhcpServer` XML export,
  review the subnets/pools/options/reservations/classes Jen would create,
  preview a real `kea-dhcp4 -t` + diff, then apply in one guarded push
  (v5.24.0)
- Import from ISC DHCP — upload a `dhcpd.conf` (subnets, ranges, shared
  networks, hosts, classes, pool allow/deny) through the same review →
  preview → apply wizard, every unmappable directive listed with its
  line number (v5.37.0)
- "Why did this client get this?" — give it a MAC (and whatever else the
  client sends) and see the path Kea takes: subnet, reservation, which
  classes matched and why, eligible pools, the answer address, and every
  option with its source and what it overrode. Says plainly what it
  can't evaluate instead of guessing (v5.35.0)

## Diagnose and plan
- **Investigate a client** — one identifier (a MAC, an IPv4 address or a
  hostname) resolved once, with Overview, Explain, Trace, Timeline, DNS and
  Config tabs onto it, every result stamped with when it was read, and the
  same subnet-access rules on every tab (v5.63.0)
- **Getting started** — a first-hour checklist with a nav reminder until
  it's done (v5.39.0), plus a guided `/setup` wizard a fresh install lands
  on once (v5.67.0)
- **Explain** — why did this client get this address? Subnet, reservation,
  classes, pools and options, with what each overrode (v5.35.0)
- **Trace** — what Kea actually logged for one client, in plain English,
  read through the existing helper — no packet capture (v5.48.0)
- **Timeline** — everything recorded about one client: events, config
  changes, alerts, lease and reservation (v5.42.0)
- **Configuration Doctor** — contradictions, unused objects and risky
  settings in the live Kea config (v5.40.0)
- **DNS ↔ DHCP Reconcile** — checks every reservation and lease name
  against forward and reverse DNS, read-only (v5.47.0)
- **Exhaustion forecast** — which pools run out, and when, from lease
  history (v5.36.0)
- **Kea 3.2 readiness** — what to change before the Control Agent goes away
  (v5.38.0)
- **Per-server capabilities** — one place that knows what each Kea server can
  do (its Kea version, connection mode, host helper and hooks), with one plain
  sentence for anything that is off; shown as a Health Center row (v5.64.0)

## Operate
- **Planned maintenance** — a stepper for taking one HA server down and back
  without a split-brain (v5.38.0)
- **Packet health** — DHCP drops, parse failures and NAKs per server from
  Kea's own counters, with the drop reasons Kea 3.2 adds (v5.41.0)
- **Recovery bundle** — one encrypted file with config, keys, content and the
  Jen database; `install.sh --restore` puts it back (v5.44.0). Since v5.65.0 it
  is a chunked, authenticated stream — never held in memory, up to 2 GB — and
  bundles from earlier releases still restore
- **Grafana dashboard** and API health endpoints for monitoring (v5.43.0)

## Health Center
- One page of read-only checks — server reachability, Kea version, HA
  state, hooks, clock sync, config drift, pool utilization, DDNS, TLS
  certificate expiry, database and schema, the Kea host helper
- No SSH at render time; safe to leave open and poll, auto-refreshes
- Each check links to the page that fixes it; JSON endpoint for scripts

## IPv6 (DHCPv6)
- Off by default; enable per-deployment from Settings → Kea
- Leases, Devices, Reservations, Subnets, Dashboard, and global Search
  all support an IPv4/IPv6 view
- Add, edit, and delete IPv6 reservations (address, delegated prefix,
  or both) and subnet pools/timers from the UI, with the same
  validate-before-apply safety as IPv4 subnet edits
- Author a starting `kea-dhcp4.conf`/`kea-dhcp6.conf` from Jen when one
  doesn't exist yet — pulls interfaces and database settings from the
  other protocol's config when it's already running, so adding IPv6 to
  an existing IPv4 deployment doesn't mean re-entering everything by hand
- `/metrics` gains dedicated `jen_subnet6_*`/`jen_kea6_up` series

## Device Management
- Device inventory with type detection (OUI fingerprinting)
- Filter by type, subnet, search, stale status
- Custom device icons

## Notifications
- Multi-channel alerts: Pushover, Telegram, Slack, ntfy, Discord, Email, Generic Webhook
- Alert types: Kea up/down, new lease, new device, rogue device, daily summary, subnet utilization threshold
- Per-channel configuration and test

## Security & Access Control
- Three-tier role system: SuperAdmin / Admin / Viewer
- Subnet-level access control per user
- MFA — TOTP authenticator apps (secrets encrypted at rest) and passkeys / WebAuthn as a second factor (v5.31.0)
- Step-up auth — changing your own MFA re-asks for your password (v5.17.0)
- Trusted device management
- Login rate limiting
- Session timeout (global default with per-user override)
- Full audit log with configurable retention
- HTTPS via SSL certificate upload, or terminate TLS at a trusted reverse proxy (v5.17.0)
- Single sign-on via OpenID Connect (Authentik, Keycloak, Entra ID, Okta…) — role mapped from a claim, re-evaluated on every login; local accounts keep working alongside it (v5.25.0)

## Database & Backup
- Scheduled backups (Jen DB + Kea reservations)
- Manual backup and restore
- Database export/import

## Plugin System
- Install optional add-ins from Settings → Plugins
- Plugin registry fetched live from GitHub
- Enable/disable/update/uninstall from the UI
- Seven plugins bundled with Jen, each an opt-in enable and each obeying the
  same subnet access rules as the core pages:
  - **Network Discovery** — find devices on a subnet that Kea does not know
  - **IPAM Lite** — the whole address space of a subnet, managed or not
  - **Host Watchdog** — probe chosen hosts and alert when one stops answering (v1.0.0)
  - **Local DNS Sync** — push DHCP names into Pi-hole or AdGuard Home, touching only records it created (v1.0.0)
  - **Switch Port Locator** — which switch port a MAC is on, read from managed switches over SNMP (v1.0.0)
  - **Wake & Actions** — Wake-on-LAN from any lease, reservation or device row (v1.0.0)
  - **Presence** — publish tracked devices' online/offline state to Home Assistant, MQTT or an HTTP endpoint (v1.0.0)
