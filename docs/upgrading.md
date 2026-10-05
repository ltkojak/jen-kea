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

## Investigation logging: DEBUG on a Kea server for a bounded time, and a live watch

Nothing to do (5.68.0-beta.3). Trace and every Servers card gain *5 min / 15 min / 60 min* controls for admins with access to every
subnet: Jen puts that one server's `kea-dhcp4` logger at DEBUG, debuglevel 55, records what to put back in the Kea config itself
(a `user-context` on the logger entry), tells the running daemon with `config-reload` (a restart only if the daemon lacks or refuses
it) and puts the level back itself when the time is up; a banner shows the time left. It writes through the same checked config
change as every Kea edit, adds no helper op and no sudo line, and is not in the API. The Health Center gains a row, **DEBUG logging
left on**, that fails if a server's time is up and the restore has not happened. Trace's watch now re-reads the log every 3 seconds
for ten minutes (it was every 5 seconds for one minute), and Explain shows the classes Kea assigned beside its own evaluation and
says when they disagree. If you already keep a Kea logger at DEBUG on purpose, nothing changes until you press a button, and the
restore puts back exactly what was there.

## Plugins contribute to the Investigation page: seven plugin updates

Nothing to do on Jen (5.68.0-beta.4). The Investigation page's Overview gains a **What else Jen knows** section with one card per plugin
that has something to say about the client: the switch port, whether it answers a ping, the DNS records that carry its name, what the
last scan saw, IPAM's entry for its address, whether it is a favourite, whether it is tracked. A card that needs a look is also summed up
in the line at the top of the page. Each card follows the page's own rule for subnets: a user restricted to some subnets sees a card only
for a client in a subnet they may see.

The cards come from new plugin releases — IPAM Lite 1.7.0, Network Discovery 1.3.0, Host Watchdog 1.1.0, Local DNS Sync 1.1.0, Switch Port
Locator 1.1.0, Wake & Actions 1.1.0 and Presence 1.1.0 — which need this Jen (they require 5.68.0). Settings → Plugins offers them as
updates once this Jen is installed, and refuses them before it: upgrade Jen first, as with every plugin update that needs a newer Jen. A
plugin that is not enabled adds no card; a plugin you install from elsewhere can add one through `register_investigation_provider`, documented
in `plugins/README.md`.

## The Problems inbox: which clients had DHCP trouble

Nothing to do (5.68.0-beta.5). Migration 30 creates a table on the first start; a new core job reads each Kea server's log (the last 1000 lines, through the helper's existing `tail-log`) and the lease database every five minutes, and **Network → Problems** lists the clients that had a NAK, a decline, a failed DNS update, a declined lease or a held reservation, each with an Investigate button. The Servers page's NAK and Dropped counters link to it, the dashboard can show a **Clients with problems** widget (Customize), and a channel can opt into the new **Client had DHCP trouble** alert, which fires when one client has the same kind of trouble three times within an hour (change the number with the optional `[alerts] client_problem_threshold`) and at most once per client and kind per day. The packet-drop and subnet-selection kinds appear only while a server logs at DEBUG. Nothing is added to the helper or the sudoers files.

## Press Update helper on every Kea host: a Kea from ISC's packages could not have its config validated

**Do this after upgrading to 5.68.0-beta.6.** If your Kea came from ISC's own packages, `/usr/sbin/kea-dhcp4` is owned by the Kea service account
(`ls -l /usr/sbin/kea-dhcp4` shows `_kea _kea`, mode `-rwxr-x---`), and the Kea host helper in builds 7 to 9 — shipped since 5.66.0-beta.2, so in stable
5.66.0 and 5.67.0 too — refused it for not being `root:root` and answered that Kea was not installed. On such a host, every change that checks the
config first (subnets, options, classes, DDNS, investigation logging) failed with "kea-dhcp4 is not installed on this server". A host with no helper
installed (the legacy path) was not affected. Build 10 runs the config check as the daemon's own account and trusts the binary when that account owns it
as a regular file nobody else can write; the fix is in the helper file on the Kea host, so **Settings → Kea → SSH → Update helper** on each host is what
delivers it (the update is signed and needs no sudoers change). The Servers page now names the real reason when the helper refuses a binary it found,
and Health Center warns about a host on an older build whose Kea version string shows ISC's packaging.

## The Update helper button now appears for a build-only helper update

Nothing to do (5.68.0-beta.7). Settings → Kea → SSH showed "v7 (build 7, build 10 available)" for a Kea host but offered no **Update helper** button, because the
button compared the helper's version alone and the helper releases since 5.66.0-beta.2 (builds 8, 9 and 10) changed the build and not the version. The button now
appears when the host has no helper, or its version is below this Jen's, or the versions are equal and the host's build is below this Jen's (a helper that reports
no build counts as below any build). If you could not press Update helper after upgrading to 5.68.0-beta.6, you can now: press it on each Kea host.

## What a subnet-scoped account sees of IPv6 changed

This changes what some accounts see (5.68.0-beta.8). An account limited to certain subnets now sees an IPv6 subnet only through the IPv4 subnet it is paired with, on every page that shows IPv6. A paired IPv6 subnet follows its IPv4 subnet; an IPv6 subnet with no pairing is visible only to accounts with no subnet restriction. Before this release several IPv6 pages applied the rule on some paths and left it off the rest: a hand-typed IPv6 subnet id the account could not see fell back to a list of every IPv6 lease, device or reservation, deleting an IPv6 reservation and editing an IPv6 subnet checked nothing about the account, and the Dashboard and Subnets pages counted and listed every IPv6 subnet. If a scoped account loses IPv6 rows it used to see, give the IPv6 subnet a pairing in `[subnets6]` (or lift the restriction); unrestricted accounts and superadmins see no change. Nothing to do on upgrade.
