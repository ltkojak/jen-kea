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
  helper script (`jen-kea-helper`) that performs a small, fixed set of
  config-push and service-restart operations.
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

[ISC Stork](https://www.isc.org/stork/) is the official monitoring and
management dashboard for Kea and BIND. The two tools overlap but take
different approaches:

- **Architecture.** Stork installs an agent (`stork-agent`) on every
  managed server. Jen connects out from a single process and installs
  nothing on the Kea server beyond an optional helper script.
- **Primary focus.** Stork's own documentation describes monitoring
  and metrics as its core, with Kea configuration editing (subnets,
  shared networks, host reservations, global parameters, DHCP options)
  added more recently and some capabilities still unavailable through
  it. Jen's core is day-to-day DHCP management — editing subnets,
  pools, reservations, and options — with monitoring and diagnostics
  built around that.
- **Database.** Stork requires PostgreSQL. Jen requires MySQL or
  MariaDB — the same database family Kea itself typically uses.
- **Access control.** Both support role-based access: Stork has three
  built-in groups (`super-admin`, `admin`, `read-only`) with local
  accounts or LDAP; Jen has three roles (Superadmin, Admin, Viewer)
  with per-subnet scoping, local accounts, TOTP/passkey MFA, or OpenID
  Connect SSO.
- **Scale.** Stork's agent-per-server model is built to centralize
  monitoring across a fleet. Jen is built for one to a handful of Kea
  servers.
- **License.** Stork is MPL 2.0. Jen is GPL v3.

Running a large Kea fleet, wanting Grafana/Prometheus dashboards for
it, or also managing BIND are reasons to use Stork. Managing day-to-day
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
