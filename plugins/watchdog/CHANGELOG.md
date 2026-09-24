# Host Watchdog Plugin — Changelog

## [1.0.1] - 2026-09-24

### Fixed: the plugin could not load on any Jen install

1.0.0's periodic probe tick was registered every 1 minute
(`register_periodic(..., 1)`), but every Jen release since v5.30.0
refuses a periodic job registered more often than every 5 minutes —
`register_periodic` raises immediately. Jen's plugin loader catches
that exception per plugin so one broken plugin can't take the whole
app down, logs it, and moves on — which meant Host Watchdog silently
never loaded on ANY box, on ANY version of Jen, since the day it
shipped: no nav item, no routes, no probing, and no error an operator
would ever see short of the log line itself. Installing and enabling
it did nothing.

The tick now registers at Jen's actual floor (5 minutes, imported from
`jen.plugin_api` when the running Jen exports it, or a matching
literal fallback on an older one) instead of a hard-coded 1. Nothing
about a target's own settings changes: the "check every 1 minute"
choice still means what it always did — checked on every tick — it
was never a literal one-minute cadence to begin with, since the tick
that was supposed to run that often could never actually start.

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
