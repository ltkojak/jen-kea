# Host Watchdog Plugin — Changelog

## [1.0.0] - 2026-09-23

### First release

Network Discovery alerts when an unknown host appears on a subnet;
nothing in Jen alerts when a *known* host stops answering. Host
Watchdog fills that gap: pick a target — a Kea reservation, an IPAM
Lite entry, or any bare IP — and it gets probed on a schedule (ping or
a TCP connect, whichever suits it), with an alert on the way down and
another on the way back up. A single missed check never fires an
alert by itself; only a configurable run of consecutive failures
counts as down, so a network blip doesn't page anyone.

Every due target is probed through one shared thread pool, budgeted
per run so a slow or hung probe can never block Jen's other
background work. Each target keeps a 7-day uptime percentage and a
short history of its last 50 checks. A "Watch this host" action is
available straight from Jen's Reservations page, watched targets show
up in Jen's global search, and a small JSON API lets another tool
read or add targets with a Jen API key.

Built on Jen 5.57.0's plugin API v3 from the first commit: sprite
icons, a phone-ready rowlist, and no inline styles.
