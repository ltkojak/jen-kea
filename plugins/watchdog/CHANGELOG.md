# Host Watchdog Plugin — Changelog

## [1.1.5] - 2026-11-22

Page polish from the look over the pages of Jen 7.2.0-beta.5. Nothing a probe does, stores or sends changes. `requires_jen` (5.68.0) and `plugin_api` (3) are unchanged, and there is no migration.

### Changed: a page with no target yet shows the first steps (a first-run block on each empty plugin page, addition 11; plugin pages differ from each other, V52)

On a fresh install the page showed a card of five filter buttons (*All (0)*, *Up*, *Down*, *Unknown*, *Paused*) with nothing to filter, and under it the headings of a table over one line, *No targets yet. Add one above.* The page said in one sentence what Watchdog is for. It did not say what a target is, what happens after one is added, or where the alerts it promises are switched on, and a person who added a target and never ticked the two alerts on a channel got no message when the host went down (a channel sends only the alerts ticked on it).

Until the first target exists the page now shows one card, *Getting started*, in place of the filters and the table:

1. Add a target. A target is a host Watchdog probes, by ping or by a TCP port. The step carries its own **Add Target** button, which opens the same dialog as the one in the page header.
2. Watchdog then probes each target on its interval (5 minutes unless you pick a longer one) and calls it down after the failed checks in a row you chose (3 unless you change it).
3. Its two alerts, "Watchdog: host down" and "Watchdog: host back up", are set under Settings - Alerts: tick them on the channels that should get them.

A viewer sees the same card without the button and without the link (adding a target and the Alerts page both need an admin). The filters and the table are drawn again as soon as there is a target to show, and the filter script is only sent with them.

### Not changed: "Add Target" keeps its name

The look-over found that this page and DNS Sync's both had a button named *Add Target* for two different things (a host to probe here, a DNS server there). The word stays here, where it has always meant a watched host, and the first step now says what it is. DNS Sync 1.1.6 calls its own a DNS server. The button was already in the page header at the right and already in Title Case, so neither moved.

## [1.1.4] - 2026-11-20

Four fixes from the audit of 1.1.3 (WD-1 to WD-4). `requires_jen` (5.68.0) and `plugin_api` (3) are unchanged, and there is no migration.

### Fixed: a 5-minute target is checked every five minutes (WD-1)

The page says a target on the 5-minute interval that fails three times in a row is called down after about ten minutes. It took twenty. A check was stored with the database's clock at the moment the whole run's results were written, which is after the slowest probe of that run. The next tick starts five minutes after the one before it started, so it found the check a second or so younger than five minutes and skipped the target. A host that does not answer takes a second to say so, which is exactly the case the plugin is for: it was probed every other tick, and so was every other 5-minute target recorded in the same run. Targets on 15, 30 and 60 minutes slipped one tick the same way.

A check is now stored with the start of the tick that made it, read in Python before anything else happens, and a target is due once its last check is within a minute of its interval. The minute covers the few milliseconds by which two ticks' starts differ. Measured through the real tick with a simulated clock and a host that takes 1.2 seconds to fail: 1.1.3 checks at 1, 601, 1201 and 1801 seconds and alerts at 1201; 1.1.4 checks at 0, 300, 600 and alerts at 601.

The times shown on the page for one check can now be up to half a minute earlier than before (the tick's start, not its end).

### Fixed: a probe that could not be made is not a host that is down (WD-2)

A probe had two answers, and one that could not run at all was recorded as a host that did not answer. On a Jen host with no `ping` (a minimal image; Settings → Plugins offers to install it and does not insist), every ping target went down after its failure count and a down alert was sent for each. The same happened when `ping` itself reported an error (exit code 2: it may not open its socket, or this host has no route), and on the TCP path when the Jen process had run out of file descriptors or memory.

There is now a third answer, *could not probe*. It stores no check, so it does not lower the 7-day uptime. It does not count toward the failures that make a target down, and it does not reset them. The sentence is kept and shown under the target's state on the page, for example *could not probe: ping could not be run (No such file or directory)*. The next tick asks again. A reply and no reply (`ping` exit codes 0 and 1), a refused or silent TCP port, and a probe that timed out are judged as before.

One consequence to know: if the Jen host itself loses its route to a target's network, `ping` reports that as its own error, so the target shows *could not probe* and is not announced as down.

### Fixed: a label with `&` or `<` in it no longer stops its own alert (WD-3)

The alert templates put the target's label in bold, and Telegram and Pushover refuse a whole message that is not well-formed HTML. A target labeled `AT&T <gateway>`, or a reservation hostname like it added through *Watch this host*, never sent its down or up alert on those channels. The label and the subnet name are now escaped before they are handed to Jen: with `jen.plugin_api.safe_text` where Jen has it (7.2.0 and later), and with the same escape from the standard library on an older Jen.

### Fixed: the empty-ports message is a note under the field, as in the copy Jen bundles (WD-4)

Jen's bundled copy of the page replaced a browser `alert()` with a note under the port field some releases ago, and that change was never carried into this repository, so an install from the registry still got the `alert()`. The two are the same file again.

## [1.1.3] - 2026-10-12

Cleanup and one clearer refusal; no change to what a probe does or to any stored data. `requires_jen` (5.68.0) and `plugin_api` (3) are unchanged: the helpers this release imports (`require_write`, `is_admin_or_above`) have been in `jen.plugin_api` since 5.65.10.

### Fixed: a TCP probe that cannot be stored is refused in one sentence

`wd_targets.probe` is `VARCHAR(40)`, and the form accepted any run of ports, each checked only for the range 1-65535. A list of eight four-digit ports passed every check, the INSERT then failed on the column length, and the person saw the generic *Could not add target; the details are in Jen's log* with nothing to say what to change. `parse_probe` (which both the Add Target form and the JSON API call before anything is written) now also refuses a probe longer than the column: *That probe is 43 characters long and a probe holds at most 40 - list fewer ports.* The port range keeps its own sentence. There is no edit route (a target is added, paused, resumed or deleted), so this is the only place the value enters.

### Changed: the admin check and the viewer gate are Jen's, not a copy

Each plugin carried its own `_is_admin` and `_require_write`, with a fallback to reading `current_user.role` for a Jen that did not export the helper; copies of that shape had drifted between plugins. The four write routes (add, pause/resume, delete, and the Reservations row action) now use `jen.plugin_api.require_write` with this plugin's sentence and the Watchdog page as the place to land, and the page asks `is_admin_or_above()` directly. For a form post nothing a person sees changes: the same sentence, the same redirect, decided before the route reads the request. A request that is JSON or under `/api/` would now get a 403 body instead of a flash that surfaces on the next page; none of this plugin's session routes is one (its JSON routes are key-authenticated and never flash), so this is a guard, not a change.

### Fixed: the Watch row action stops sending a `subnet_id` nothing read

The "Watch this host" link on a reservation row carried `&subnet_id={subnet_id}`, and `watch_from_row` ignores it on purpose: the subnet is worked out from the address, because trusting what the linking page happened to know let a caller authorise against one subnet and watch a host in another. The parameter was dead weight that read like an input. It is gone from the link; the route's behaviour is unchanged. (The subnet is known where the link is built, but honouring it would undo the rule above, so the right fix was to remove it.)

### Added: Investigate on every target row

A target row names a host, so it carries Jen's Investigate action (the shared `investigate_link` macro), given the target's MAC or its address when it has none.

### Documented, not changed

`wd_targets.created_by`, `created_at` and `source` are written when a target is added and read by nothing here; the README now says they are recorded for the audit trail and not displayed. `derive_subnet_id` and `_when` stay: the first takes the subnet map as an argument so the harness can run it on a fixed map (`plugin_api.subnet_for_ip` reads Jen's live map), and Jen offers no equivalent of the second. `_normalize_mac` stays as a thin wrapper because this plugin treats a bad MAC as "none given" (`""`), where `plugin_api.normalize_mac` answers `None`.

## [1.1.2] - 2026-10-11

Fix. `requires_jen` (5.68.0) and `plugin_api` (3) are unchanged.

### Fixed: an alert is sent only for a transition that was stored

A check run records its results in one transaction: for every target that answered or did not, a `wd_checks` row and the new `wd_state`, and
when a target crossed its threshold the alert for it is queued to be sent once the recording is finished. The queue was filled inside the same
`try` as the INSERTs, and the loop that sends it ran after the `finally` whatever had happened before. So when one INSERT failed (a lock wait
timeout, a connection that went away) the transaction was rolled back, the new state of every target in that run was gone, and the alerts for
the targets recorded before the failure were still sent: an alert for a state the table never held, and a second alert for the same
transition on the next check, which finds the transition again because the table still holds the old state. The alerts and the Timeline events now follow
a successful `commit()` and nothing else. A recording that fails rolls back explicitly, sends nothing, and leaves the transition to be detected
and announced once by the next check; a commit that itself fails is handled the same way. A target that stays down, and a new target answering
for the first time, still send no alert.

The harness runs the real `_record_results` against a transactional fake database, where writes are held until `commit()` and dropped by a
rollback or a close, so "nothing stored" is read from what a later reader would find: a second target's INSERT that raises after the first target
crossed its threshold sends nothing and commits nothing, the next call with a working database sends exactly one alert and commits both
targets' state, the alert follows the commit and the close in that order, and a commit that raises sends nothing.

## [1.1.1] - 2026-10-11

Fix. `requires_jen` stays 5.68.0; the `scoped` argument of `send_alert` this release uses is in Jen 5.68.0-beta.9 and later.

### Fixed: an alert about a target in no Kea subnet no longer goes to channels limited to some subnets

A target whose address is in no Kea subnet has no subnet id, and `send_alert(..., subnet_id=None)` means "not about one subnet", which Jen
delivers to every channel, a channel the operator limited to particular subnets included. Such a channel is the operator's statement of which
hosts they want to hear about, and a host in no subnet at all is not one of them. The down and up alerts for a target with no subnet id are
now sent with `scoped=True`, which Jen reads as "about one host Jen could not place": only channels with no subnet scope receive it. A target
that has a subnet is sent exactly as before, and the alert text, the Timeline event and the page are unchanged.

### Fixed: adding a target says one thing when the address is out of reach

The *Add target* form refused an address with one sentence when it was inside a Kea subnet the caller cannot see, and another when it was in
no Kea subnet at all, so a scoped admin could ask the form which addresses are inside any Kea subnet. Both are now *That address is not in a
subnet you can access.*, which does not say which it was. The *Watch this host* row action, which already refused both with one sentence,
uses the same words.

The harness runs the real `_alert_transition`, `add_target` and `watch_from_row`: the alert carries `scoped=True` exactly when the target has
no subnet, for both the down and the up alert, and the two refusals are the very same text with nothing written.

## [1.1.0] - 2026-10-04

Requires Jen 5.68.0 (a 5.68.0 beta satisfies it): this release registers an **investigation provider**.

### Added: does it answer, and since when, on Jen's Investigation page

Jen's Investigation page (`/client`) now has a "What else Jen knows" section on its Overview, and this plugin
contributes one card to it when a watchdog target matches the client by its MAC or by any of its addresses (the one the
page was opened on, its active leases, its reservations): whether the host answers, since when, how many checks in a row
have failed, the last time it answered, and the probe. A target that is down makes it a "Needs a look" card, and its
sentence also joins the Investigation page's one-line answer at the top. A client with no target adds no card.

Each target is judged on its own stored subnet and the caller's scope is in the query, before its limit, so a
restricted caller never receives a target from a subnet outside the set Jen handed over; a target in no Kea subnet is
for an unrestricted caller only. `requires_jen` moves to 5.68.0 because the hook does not exist before it.

## [1.0.5] - 2026-09-30

### Fixed

- **The periodic schedule has never recorded a single check, for any target, since 1.0.0.**
  `_tick()`'s own query selected every column `due_targets()` needs to decide anything is due
  EXCEPT `enabled` — so every row it fetched had no `enabled` key at all, `due_targets()`'s own
  first line (`if not t.get("enabled"): continue`) skipped every target unconditionally, `due`
  was always empty, and `_tick()` returned before ever writing a `wd_checks` or `wd_state` row.
  The WHERE clause already limited the query to enabled targets — the column just wasn't in the
  SELECT list, so the row dict it produced never carried the key the pure function actually
  reads. One word added to the query. **Manual "Check now" was never affected** — it calls the
  probe directly, not through this path — so a target's current state and its history from a
  manual check are untouched; only the unattended, scheduled checks were silently skipped, for
  every install, on every version before this one. If you've been relying on the schedule, the
  uptime figure you see after upgrading starts filling in from here — it was never being
  recorded before, not lost.

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
