# Switch Port Locator Plugin — Changelog

## [1.1.3] - 2026-10-07

Fix. No change to what Jen needs: `requires_jen` stays 5.68.0.

### Fixed: the wording no longer reveals that a newer position exists on a switch the caller may not see

1.1.2 filtered every surface down to the positions on switches the caller may see, and then changed one word when the newest stored
position was on a switch they may not: the card said *Last seen on …* where it would have said *On …*, and the page *was last seen
on* where it would have said *is on*. A scoped caller could tell that a newer position exists elsewhere. What a scoped caller is shown
is now built from the visible positions alone: the card and the page always say *Last seen on … at <time>* (never *On*, never a
claim about a move), whether or not a hidden newer position exists, so the output is the same with or without it, on the page, the
card and the JSON API. A caller who can see every subnet keeps *On …* and the move note. `positions_in_scope` now returns whether the
CALLER is restricted instead of a fact about the stored positions.

### Changed: the module's design notes state the stored-object contract

The "who sees what" paragraph at the top of the file still said a MAC is shown only when its current subnet is one the caller may
see. It now says what 1.1.1 and 1.1.2 made true (a position belongs to its switch's subnet; one judgement for every surface) and points
at the plugins documentation as the source.

## [1.1.2] - 2026-10-06

Fix: the rule 1.1.1 applied to the Investigation card now applies to every surface of the plugin. No change to what Jen needs:
`requires_jen` stays 5.68.0.

### Fixed: the page, the API and the search provider judge each position by its own switch

1.1.1 filtered the Investigation card's positions by their switches' subnets and left the plugin's other three ways of asking
"where is this MAC" judging the CLIENT's current subnet and then showing the newest position on any switch. A caller scoped to
subnet A who looked up a client now in A saw the client's newest position on a switch in subnet B (switch name, port, alias,
VLAN, time) on the page and from the API, and the search provider reported the client's subnet as the row's `subnet_id`, so
Jen's own defence-in-depth filter passed a result whose text named a switch in B. All four surfaces now go through the one
judgement the card uses, `positions_in_scope`: every stored position is judged by the subnet of its switch (the one its
management address is in; a switch addressed by hostname is for callers who can see every subnet), and the answer is the newest
position the caller may see. A client whose only positions are on switches the caller may not see is simply not located, the
same answer as a MAC no switch has reported, for a session user and for a scoped API key alike (the API used to refuse such a key
with 403 keyed on the MAC's own subnet, which told it which MACs exist elsewhere). When the newest position is hidden the page
says *was last seen on* rather than *is on*, and does not say why. Search rows carry the SWITCH's subnet as their `subnet_id`.
The exact-MAC search now takes 50 candidates, judges them, then keeps five, so hidden positions cannot push a visible one out.

## [1.1.1] - 2026-10-06

Fix to the investigation provider added in 1.1.0. No change to what Jen needs: `requires_jen` stays 5.68.0.

### Fixed: each stored position is judged by its own switch, not by where the client is now

1.1.0 judged the client by the subnet it is in now and then printed its last five stored positions without asking where
each one was. A switch belongs to the subnet its management address is in, and a position is stored data about that
switch, so a client that had been on a switch in a subnet the caller cannot see was shown, switch name and port, to a
caller scoped to the subnet the client has since moved to. Each position is now judged by its own switch's subnet before the
card is built: a client whose positions are all on switches the caller cannot see gets no card, one with a mix gets only
the positions on switches the caller can see, and a switch addressed by hostname (or by an address in no Kea subnet) is
for callers who can see every subnet. When the newest position is on a switch the caller cannot see, the position shown is
not the latest, so the card says "Last seen on ..." with its time instead of "On ...", and makes no claim about a move.
The position query takes every stored position (up to 50) and filters before keeping five, so hidden positions can no
longer push a visible one out of the card.

## [1.1.0] - 2026-10-04

Requires Jen 5.68.0 (a 5.68.0 beta satisfies it): this release registers an **investigation provider**.

### Added: the switch and port, on Jen's Investigation page

Jen's Investigation page (`/client`) now has a "What else Jen knows" section on its Overview, and this plugin
contributes one card to it: the switch and port the client's MAC was last stored on, the VLAN, when it was last seen
there and since when it has been on that switch. Where the MAC has stored positions on more than one switch, the card
says it has moved and names the older position, which clears when that switch is next polled. A port that is now
treated as an uplink — pinned by hand after the MAC was stored, or past the MAC-count threshold — makes the card a
"Needs a look" one, because the real position is further out than the port the MAC is stored on. A MAC the plugin has
never located adds no card.

It answers only for a client the caller may see: Jen hands the provider the caller's own subnet scope, the MAC's
subnet is Jen's one precedence (`client_subnet_for_mac`), and a client in no subnet — or one outside a restricted
caller's — gets nothing, never a card. `requires_jen` moves to 5.68.0 because the hook does not exist before it.

## [1.0.4] - 2026-09-27

Jen's Q100 sweep: onto Jen 5.65.10's shared helpers, plus three findings from the same audit.

### Fixed: a configuration mistake could erase a switch's whole port map

Community-indexed polling reads the FDB once per configured VLAN; with the `vlans` field empty or
entirely non-numeric, the loop ran zero times and returned no MACs at all — indistinguishable from a
switch that genuinely has nothing plugged in. The poll then read "every MAC this switch had is gone" and
deleted every `sp_mac_ports` row for it. Polling now refuses outright when community indexing has no
VLANs configured, the same way an unreachable switch already does, instead of quietly wiping its data.

### Fixed: a poll's own database error could reach the page

A failure recording poll results put the exception's own text into `sp_switches.last_error`, which the
index page renders — the raw-exception scanner Jen added in 5.65.7 only looks at flash messages and JSON
responses, so this site went unnoticed. Logged as before; the stored column gets a generic sentence.

### Fixed: setting a port's uplink override

An unrecognised `value` silently mapped to "auto" instead of being refused, and the route flashed "Port
updated." even when the `ifindex` given did not match any port on the switch (zero rows changed). Both
are refused now, the second naming the port that could not be found.

### Changed

- The MAC check delegates to Jen's shared `normalize_mac()`, and the search provider's `LIKE` escaping to
  `like_pattern()`.
- The search provider's free-text query reads 200 candidates instead of 20 before its own per-row subnet
  check (a MAC's subnet is not a column here, so `search_scope()` cannot filter it in SQL the way
  IPAM/Discovery/Watchdog's own subnet_id can); it still stops once 20 have passed that check, so a
  restricted caller gets a real chance at a full page instead of whatever the newest 20 matches happened
  to be.
- `tools/test_plugin.py` checks all three fixes directly, including that the no-VLANs case raises before
  touching the database at all.

## [1.0.3] - 2026-09-26

Requires Jen 5.65.6 or later (`client_subnet_for_mac` in the plugin API); 1.0.2 required 5.65.2.

### Fixed: database error text reached the page

A failed save put the database's own error message into the page, which can carry a table or column name, a user name or a host address. The details are now written to Jen's log and the page shows a generic message. Jen's test suite now scans every bundled plugin for this and fails on a new one; messages about the outside world this plugin was configured to talk to (an SNMP walk's own failure, shown on the switch) are the deliberate exception, because that text is the diagnostic an operator needs.

### Changed: one place decides which subnet a MAC is in

The plugin carried its own lookup (the device's last known subnet first, then a lease, then a reservation), which disagreed with Wake and Presence about where a client is. It now asks Jen's `client_subnet_for_mac` (current lease, then reservation, then the device's last known subnet), so a MAC is judged on the same subnet by every plugin and by the core pages.

### Changed

- `tools/test_plugin.py` checks that the subnet comes from the plugin API, and runs a failing database through the add route.

## [1.0.2] - 2026-09-25

Requires Jen 5.65.2 or later, like 1.0.1. No code path changed.

### Fixed: the moved alert used a glyph and an icon Jen does not accept

1.0.1 registered the `switchport_moved` alert type with a default template that opened with a glyph outside Jen's four standard ones (critical, warning, recovered, information) and with the `cable` icon, which the dashboard's alert-icon whitelist does not include. Jen's own test suite holds every alert type to both lists, and it failed when 1.0.1 was bundled, so 1.0.1 was never released to an install. The alert now opens with the information glyph and uses the `info` icon. `tools/test_plugin.py` enforces both rules in its `register(app)` stub, so this is caught here next time, before a bundle.

## [1.0.1] - 2026-09-25

Requires Jen 5.65.2 or later (the `can_access_subnet` and `api_key_can_access_subnet` helpers in the plugin API). Adds one migration (a `mac_count` column on `sp_ports`); it runs by itself on the next start.

### Fixed: the uplink heuristic worked but nobody could see it

The MAC table only ever holds MACs that were *not* behind an uplink, and the port table counted rows in it, so the very port the heuristic had just excluded showed 0 MACs, "Auto" with no "(uplink)", and a plain dash for viewers. Nothing told the operator that a port with 37 MACs on it had been classed as a trunk. Each poll now stores every port's real MAC count, uplinks included, and the page shows "Auto (uplink, 37 MACs)" (and "Uplink (37 MACs, auto)" for viewers). The threshold comes from the plugin instead of a literal `8` repeated in the template. Counts fill in at the next poll after upgrading, at most ten minutes.

### Fixed: the moved alert the README promised did not exist

The README and manifest said the plugin alerts when a known MAC changes port; it only emitted a Timeline event. There is now a `switchport_moved` alert type, sent on every move for the MAC's own subnet (off by default per channel, like every alert type), alongside the event.

### Fixed: routes authorised one thing and acted on another

The pattern this release names in every plugin: a route authorises on one thing and then acts on another, or reads "no subnet" as "allow".

- **The locate API** let a MAC with no attributable subnet through to a subnet-scoped key. A MAC with no subnet is now for unrestricted keys only.
- **The search provider** returned `subnet_id: None` for every result after its own visibility check, and Jen drops any result whose subnet is not in a restricted caller's scope, so restricted users never found anything. It now returns the MAC's real current subnet.
- **Switches had no subnet at all.** Every account saw every switch's name, address and port table, and any admin could pause, delete or reclassify any switch's ports by id. A switch now belongs to the subnet its management address is in: a scoped account sees, adds and changes only switches addressed inside its own subnets; a switch addressed by hostname, or by an address in no Kea subnet, is for accounts that can see every subnet.

### Fixed: the host of a switch was passed to `snmpbulkwalk` unchecked

The host becomes an argument of the walk. It is passed as a list (never through a shell), but a value starting with `-` would still have been read by `snmpbulkwalk` as an option. A host must now be a hostname or an IPv4 address and cannot start with a dash.

### Documented: the SNMPv2c community is visible in `ps`

net-snmp takes the v2c community on the command line, so it is visible in the process list on the Jen host for the few seconds a walk runs. net-snmp has no alternative for v2c. Use a read-only community that opens nothing else.

### Changed

- The page's static styling moved out of inline `style=` attributes into its own `<style>` block; `tools/verify.py` now fails a template that carries one.
- The one dynamic `IN (...)` builder carries a one-line `# nosec B608` saying why it is safe.
- `tools/test_plugin.py` now runs the real routes, the poll, the move alert, the API and the search provider against fakes, and calls `register(app)` against a stub that enforces Jen's registration rules (alert type prefix, five-minute periodic floor).

## [1.0.0] - 2026-09-24

### First release

Client Investigation can answer almost everything about a device
except the one question that actually gets someone up from their
desk: which switch port is it plugged into? Switch Port Locator polls
each configured switch's MAC address table over SNMP every ten
minutes — Q-BRIDGE-MIB in one walk for switches that expose every
VLAN's table at once, or BRIDGE-MIB walked once per VLAN for switches
that use Cisco's `community@vlan` indexing instead — and resolves
every bridge port to its real interface name and description.

A port seen carrying more than eight MACs is treated as a trunk to
another switch rather than somewhere a device actually lives, so an
uplink never gets reported as a device's location; any port's
classification can be pinned by hand when the automatic count gets it
wrong. When a known MAC's non-uplink port changes — whether that's a
different port on the same switch or a move to a different switch
entirely — an event fires so the rest of Jen can react to it.

The locate page finds a MAC's switch, port, alias, VLAN, and last-seen
time, and a "Find switch port" action is available straight from
Jen's Lease, Reservation, and Device rows. A small JSON API lets
another tool ask the same question with a Jen API key.

Built on Jen 5.57.0's plugin API v3 from the first commit: sprite
icons, a phone-ready rowlist, and no inline styles.
