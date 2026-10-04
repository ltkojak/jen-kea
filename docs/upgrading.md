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
