# Switch Port Locator Plugin — Changelog

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
