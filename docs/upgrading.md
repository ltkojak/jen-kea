# Upgrading from 5.67.0

Everything below changed since v5.67.0 — the last stable release before
this one — that you'd actually notice or need to know about when you
upgrade. Run `sudo ./install.sh` on the new tarball (or use the in-app
updater) the normal way; nothing here needs a manual step beyond what's
called out explicitly. See `docs/runbooks.md` for step-by-step
procedures, and `CHANGELOG.md` if you want the full detail behind any
item below. The previous page, covering everything since 5.66.0 through
the 5.67.0 baseline, is archived at
[`docs/release-history/upgrading-5.66.0-to-5.67.0.md`](release-history/upgrading-5.66.0-to-5.67.0.md).

## The Investigation page is one click from everywhere a client is named

Nothing to do; it is simply there (5.68.0-beta.1). Every row that names a client now
has an *Investigate* action — the dashboard's recent leases, events feed, top
devices and alert strip, the Alerts log, and the header of the Timeline page, as
well as the lease, reservation, device and search-result rows that already had it. The
search box in the top bar behaves differently in one case: typing one whole MAC or
IPv4 address (or, with IPv6 on, an IPv6 address or a DUID) goes straight to that
client's Investigation page instead of a list of results. A hostname, a fragment or a
partial MAC still lists results, and the Investigation page has a *Search results for
this* link back to the list. A bookmark of `/search?q=<a whole MAC>` now lands on
`/client`; add `&list=1` to keep the list.

## The Investigation page takes an IPv6 address or a DUID

If you turned IPv6 management on, the page no longer answers "not supported yet" for an
IPv6 address or a DUID (5.68.0-beta.1). It resolves them through the lease table and the
v6 reservations, shows the IPv6 leases and the reservation (delegated and excluded
prefixes included) beside the IPv4 facts, and follows the client's MAC — the hardware
address Kea captured, or the one a DUID-LL or DUID-LLT embeds, labelled as which — into
the device, the IPv4 leases and the Timeline. Explain, Trace and Config stay DHCPv4
tools and say so. With IPv6 off, nothing changes: the page says IPv6 is off. If you
restrict users by subnet, an IPv6 lease or reservation is judged on the IPv4 subnet its
IPv6 subnet is paired with, as in Devices and search; an IPv6 subnet with no pairing is
visible only to users who may see every subnet.

## A Changes tab: which config changes touched this client

An admin who may see every subnet gets a seventh tab on the Investigation page
(5.68.0-beta.1). It reads each Kea server's newest 50 config revisions and lists the ones
that changed this client's subnet, its shared network, the pools its addresses fall in,
the classes on that path or that it matches, or its own reservation — the lines that
moved, who changed it, when, and whether it was a Jen change or an edit made on the
host. Nothing is stored for it and nothing runs until you open the tab. A reservation
kept in Kea's host database is not part of the config file and so cannot appear.
Restricted admins, and viewers, are not offered the tab, the same rule as the config
history page it reads.

## A restricted admin now sees the last alert about their own client

The Overview's *Last alert* line used to be shown only to users who may see every
subnet (5.68.0-beta.1). It is now shown to a restricted user as well, when the client
they are looking at is in a subnet they may see — its type, status and time, never the
message, which can name a subnet. Nothing changes for a user who may see every subnet.

## Explain evaluates the client Kea actually saw, and says why not

Nothing to do (5.68.0-beta.2). Explain, and the Investigation page's Explain and Config
tabs, no longer start from the MAC alone: they fill in the client id and hostname from the
client's lease, the relay agent's options from the lease when Kea runs with
`store-extended-info`, and — for an admin with access to every subnet, through the Kea host
helper you already have — the vendor class, user class, hostname and relay options from
Kea's own log, each input labelled by where it came from. A class that Kea's log lists as
assigned is decided by what Kea said. What the log carries depends on its level, and was
measured on Kea 3.0.3, 3.2.0 and 3.3.1: the client id at any level; the assigned classes
(and so the vendor class) at debuglevel 45 or higher; the whole packet at 55 or higher. If
you want Explain to read those from Kea, set the `kea-dhcp4` logger to severity `DEBUG` with
debuglevel 55 — a lot of log, so turn it back down afterwards; at Kea's default level Explain
simply asks you to type what the log does not carry. `?auto=0` on the Explain page restores
the MAC-and-typed-inputs-only behaviour.

Explain also says what stands in the way: a pool that is full (with the free count of the
next pool), a reserved address that a different client's lease currently holds (named, with
a link to that client's Investigation page and the time its lease ends), a reservation whose
identifier type is not in `host-reservation-identifiers`, and a relay (giaddr) the subnet
does not match. An admin with access to every subnet gets a link from each to the
Investigation page's Changes tab, filtered to the config element the verdict is about. The
Investigation page's Overview carries one sentence of what Kea would do with the client.
Nothing is stored and nothing runs until a page that needs it is opened.
