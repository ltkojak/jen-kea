# Host Watchdog Plugin — Changelog

## [1.0.4] - 2026-09-27

Jen's Q100 sweep: onto Jen 5.65.10's shared helpers, plus four smaller findings from the same audit.

### Fixed

- A database failure loading one target (`_load_target`, behind toggle, delete and history) used to
  propagate uncaught into a 500 page; it is now the same generic refusal every other write route already
  gives a database error.
- Adding a target had no check for a second target on an address already being watched — "Watch this
  host" from a Reservation row already refused a duplicate; the Add Target form and the JSON API did not,
  so two identical targets could both probe and alert for the same host. Both now refuse it (a flash for
  the form, `409` for the API).
- The index page ran one `wd_checks` query PER TARGET to compute its 7-day uptime — thirty targets, thirty-
  one queries. It is one query for every target's checks now, grouped in Python.
- Sending a state-change alert (`send_alert`/`emit`) is I/O of its own; doing it INSIDE the open database
  cursor that records the check results held that connection open for as long as every alert took to
  send. Alerts are now collected while recording and sent only after that connection is closed.

### Changed

- The search provider puts the caller's own subnet scope in its SQL, before its own `LIMIT 20`, using
  Jen's shared `search_scope()`/`like_pattern()`.
- The MAC check delegates to Jen's shared `normalize_mac()`; the JSON API's body is read with
  `json_object_body()`/`str_field()`, so a non-object body or a non-string `mac` is a 400 instead of
  raising.
- `tools/test_plugin.py` checks each of the above directly, including that the alert genuinely fires
  after the recording connection's own `close()`.

## [1.0.3] - 2026-09-26

Requires Jen 5.65.2 or later, like 1.0.2.

### Fixed: database error text reached the page

A failed save put the database's own error message into the page and, for the JSON API, into the response body, which can carry a table or column name, a user name or a host address. The details are now written to Jen's log and the page shows a generic message. Jen's test suite now scans every bundled plugin for this and fails on a new one; messages about the outside world this plugin was configured to talk to (a probe's own failure reason for a host you chose) are the deliberate exception, because that text is the diagnostic an operator needs.

### Changed

- `tools/test_plugin.py` runs a failing database through the add route and the API and requires a generic message with no exception text.

## [1.0.2] - 2026-09-25

Requires Jen 5.65.2 or later (the `can_access_subnet` and `api_key_can_access_subnet` helpers in the plugin API).

### Fixed: routes authorised one thing and acted on another

Four places trusted the wrong thing about where a target is.

- **History, pause/resume and delete took a target id and checked nothing.** Any
  logged-in user could read any target's check timestamps, round-trip times and
  error strings, and an admin scoped to one subnet could pause or delete a
  target in another. Every by-id route now loads the target and judges its own
  stored subnet; a target in a subnet the caller cannot see is answered exactly
  as one that does not exist.
- **"Watch this host" believed the query string.** The row action passes a
  `subnet_id` in the URL, and the route used it as the subject of the access
  decision, so a caller could authorise against a subnet they own and add a
  host that lives in another. The subnet is now worked out from the address.
- **An address in no subnet was read as "allow".** Where the subnet came out
  empty, that route skipped the check the Add form applies, and the JSON API
  handed rows with no subnet to a subnet-scoped key and let a scoped key add
  one. The rule is now the same everywhere and comes from one place, Jen's
  `can_access_subnet` / `api_key_can_access_subnet`: a target with no subnet
  belongs to unrestricted callers only, keys included.
- **The Add Target picker offered global reservations to a scoped admin,**
  which belong to no subnet and so exposed hosts from every one. They are now
  offered to unrestricted callers alone.

The pattern, named the way the release notes name it: a route authorises on
one thing (a subnet id the caller typed, or nothing at all for a by-id POST)
and then acts on another (the address's real subnet, a row in a subnet the
caller cannot see).

### Fixed: a new target alerted "answering again"

The state machine moves a new target from `unknown` to `up` on its first
successful probe, and that counted as a transition, so every target fired a
"is answering again" alert (and a Timeline event) the first time it was
checked. A first result is now recorded silently; a target that never
answered and then crosses its failure threshold still alerts as before.

### Fixed: check times were written in the database's local time

`wd_checks.checked_at` took the column default (`CURRENT_TIMESTAMP`, the
session's time zone) while everything that reads it — the due-target
calculation, the 7-day uptime window and the pruning job — works in UTC. On a
database whose time zone is not UTC, targets were checked too early or too
late and pruning cut the wrong window. Rows are now written with
`UTC_TIMESTAMP()`. Rows already stored keep their old values until the 7-day
prune removes them, so for one week after upgrading a database that is not on
UTC may still see a few targets checked at slightly the wrong moment.

### Changed

- The page's static styling moved out of inline `style=` attributes into its
  own `<style>` block, and `tools/verify.py` now fails a template that carries
  one.
- `tools/test_plugin.py` runs the real routes, the JSON API, the picker and
  the result recorder against fakes: a scoped caller is refused on every
  by-id route, the subnet stored is the address's, a scoped key never sees a
  target with no subnet, and a first success sends no alert.

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
