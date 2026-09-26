# Switch Port Locator Plugin — Changelog

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
