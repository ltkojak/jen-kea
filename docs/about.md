# About Jen

## What Jen is

Jen is a self-hosted web application that manages [ISC Kea DHCP
Server](https://www.isc.org/kea/). One Flask process connects out to
one or more Kea servers over HTTP (the Kea Control Agent, or each
daemon's own control socket) and SSH, and presents leases,
reservations, subnets, DHCP options, and diagnostics through a browser
UI. It is built for an operator running one to a handful of Kea
servers — a home network, a lab, or a small business — not a large
fleet.

Jen is free, open-source software, licensed under the GNU General
Public License v3. The source is at
[github.com/ltkojak/jen-kea](https://github.com/ltkojak/jen-kea).

## What Jen is not

- Jen is not a DHCP server. It does not replace Kea, and it does not
  implement the DHCP protocol itself — Kea does the leasing; Jen
  manages and observes it.
- Jen is not a network monitoring or fleet-management platform for
  servers in general. It manages Kea DHCP specifically.
- Jen does not require an agent on the Kea host. It connects out to
  Kea's existing HTTP API and database, and over SSH for config
  changes; nothing is installed on the Kea server except an optional
  helper script (`jen-kea-helper`) that runs only when Jen invokes it - plus,
  once you have turned investigation logging on, a systemd timer of its own
  that wakes it every minute to put the Kea logger back when the time is up -
  and performs a fixed set of operations: report its version, read, test and
  apply a Kea config, remove a config file Jen itself just created (the
  undo of authoring a new one), control the Kea service, tail a Kea log, install
  the Kea packages, install a TLS certificate, update itself, and arm, disarm and
  report a self-restore of the log level (and keep the timer behind it running).
- Jen is not a DNS server, and does not manage BIND or other DNS
  software directly — it can push DHCP hostnames into a handful of
  third-party DNS/DHCP-aware tools (Pi-hole, AdGuard Home) through an
  optional plugin, and reconcile DNS records against DHCP data
  read-only.

## What Jen requires

- A Linux server (Ubuntu 22.04 or 24.04) to run Jen itself, or Docker.
- Python 3.10 or later.
- ISC Kea DHCP, version 3.0 or later, reachable over HTTP — either the
  Kea Control Agent (deprecated by ISC in Kea 3.0, removed in 3.2) or
  per-daemon HTTP(S) control sockets (required from Kea 3.2 onward;
  Jen can set these up).
- MySQL or MariaDB, used both by Kea (leases, reservations, options)
  and by Jen (users, settings, audit log, config history).

See the [compatibility table](../README.md#compatibility) for the
exact Kea, OS, database, and Python versions tested in CI.

## Jen compared to ISC Stork

[ISC Stork](https://www.isc.org/stork/) is ISC's own graphical monitoring
and management tool for Kea and BIND 9. The two tools overlap but take
different approaches. Everything said about Stork here comes from ISC's pages
and nothing they do not say is claimed. Checked on 2026-10-02 against ISC's pages: <https://www.isc.org/stork/> (what Stork is, PostgreSQL, MPL 2.0, Prometheus/Grafana), <https://stork.readthedocs.io/en/latest/overview.html> (agent per machine, BIND 9 read-only, configuration capabilities not all available), <https://stork.readthedocs.io/en/latest/usage.html> (the three user groups), <https://stork.readthedocs.io/en/latest/dhcp.html> (subnet management needs the `subnet_cmds` or `cb_cmds` hook) and <https://stork.readthedocs.io/en/latest/install.html> (LDAP through a hook).


- **Architecture.** Stork installs an agent (`stork-agent`) on every
  managed server. Jen connects out from a single process and installs
  nothing on the Kea server beyond an optional helper script.
- **Primary focus.** Stork monitors Kea and BIND 9 and also edits Kea
  configuration (subnets, shared networks, host reservations, global
  parameters, DHCP options) through Kea's hook libraries; its
  documentation says some configuration capabilities are not yet
  available through it. Jen's core is day-to-day DHCP management — editing subnets,
  pools, reservations, and options — with monitoring and diagnostics
  built around that.
- **Database.** Stork requires PostgreSQL. Jen requires MySQL or
  MariaDB — the same database family Kea itself typically uses.
- **Access control.** Both support role-based access: Stork has three
  built-in groups (`super-admin`, `admin`, `read-only`) with local
  accounts, or LDAP through a hook; Jen has three roles (Superadmin, Admin, Viewer)
  with per-subnet scoping, local accounts, TOTP/passkey MFA, or OpenID
  Connect SSO.
- **Shape.** Stork is one server plus an agent on each managed machine,
  covering Kea and BIND 9. Jen is Kea only and is built for one to a
  handful of Kea servers.
- **License.** Stork is MPL 2.0. Jen is GPL v3.

Wanting Grafana/Prometheus dashboards (the Stork agent is a Prometheus
exporter) or also managing BIND are reasons to use Stork. Managing day-to-day
DHCP configuration for a small number of Kea servers from a browser is
what Jen is for; the two are not mutually exclusive.

## Glossary

- **Kea host helper** (`jen-kea-helper`) — a small, fixed-function
  script Jen installs on each Kea server (one `sudo` grant, one
  binary). It performs config reads/writes, `kea-dhcp4 -t` validation,
  and service restarts on Jen's behalf; Jen never runs arbitrary
  commands on the Kea host.
- **Recovery bundle** — a single encrypted file containing Jen's
  database, config, keys, and content, downloadable from Settings →
  Databases and restorable with `install.sh --restore`. Not a Kea
  backup — Kea's own lease/reservation data lives in its own database.
- **Change set** — the unit `jen/services/kea_changeset.py` uses to
  push one logical edit (a subnet, option, or class change) to every
  SSH-configured Kea server: every target is validated before the
  first write, writes happen in sequence, and an already-committed
  target is reverted if a later one fails.
- **Subnet map** — the set of Kea subnets Jen knows about and their
  display names, configured in Jen (Settings → Kea, or the `/setup`
  wizard) and kept separate from Kea's own subnet configuration, which
  Jen reads but does not define.
