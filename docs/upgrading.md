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

## Investigation logging that cannot forget, and a Problems inbox that attributes truthfully

Nothing to do on upgrade (5.68.0-beta.9); migration 31 adds one column by itself. Investigation logging now records whether the config file is restored and whether Kea has taken it, and drops its record only when both are true, so a restore that Kea did not take is retried every minute and the Health row says so. A Kea server that has investigation logging on can no longer be removed from Settings (or have its SSH host or API URL blanked) until you turn the logging off from Servers; a server that vanished some different way keeps a failing Health row with the by-hand restore and an *I restored it by hand* button on the Servers page. The Problems inbox places a row by what the event itself says and never by where the client is now, so a NAK that names no address is shown only to users who may see every subnet, and a subnet-scoped alert channel no longer receives a Problems alert for a client Jen could not place. Times on a row are the events' own, in UTC, converted from the Kea host's log clock with an offset Jen measures from the lease records (hover Last seen); a first read of a server never alerts; and a Problems alert is marked sent only when a channel took it, with a failed one retried every half hour.

## Explain: current leases, one exchange, the right server, and option 77 as bytes

Nothing to do on upgrade (5.68.0-beta.10). A lease counts as the client current lease only while it has not expired (Kea keeps an expired lease in its table until it reclaims it), so an expired lease no longer decides who holds an address, which client a hostname belongs to, or what Explain reads the client id and hostname from, and the IPv6 lists count only active leases; the Leases page with show expired still lists everything. What Explain reads from Kea log now comes from one exchange (one transaction), read from the HA-active server first and then the rest in order, and the Inputs card names the exchange and the server. Option 77 (user class) and the relay circuit id are compared as the bytes Kea saw: a client sends its user class as the bare string or, like Windows, with a length byte in front, and a class rule written for one form does not match clients that send the second. The class rule builder therefore has two user class fields, plain text (what it always wrote) and length-prefixed; existing classes keep working unchanged. Explain reads the bytes from the packet dump (debuglevel 55) and takes them by hand in the user class as sent box. A scoped user whose client has a current lease in a subnet they cannot see and a reservation in one they can is now explained in the visible subnet.

## Plugin cards on the Investigation page follow the subnet they were stored in, and the Changes and DNS tabs look at the whole client

Nothing to do on Jen (5.68.0-beta.11). Three plugin updates come with it, offered under Settings → Plugins: Wake & Actions 1.1.1, Presence 1.1.1
and Switch Port Locator 1.1.1. Each card now follows the subnet its row was stored in: a favourite or a tracked device saved in a subnet
a restricted user cannot see is not shown to them because the client has since moved into one they can, and a switch position is shown
only if the switch is in a subnet they may see (a switch addressed by hostname is for users who can see every subnet). Where a client is
now appears on the card as *Now in* only when the user may see that subnet. Providers are now bounded: a plugin card or a plugin search
section that takes longer than one second shows *unavailable (over 1 s)* instead of holding the page. The Changes tab also lists changes
to the global DHCP settings every client inherits (global options, lifetimes and timers, reservation modes), and the DNS tab checks every
reservation and lease the client has, with IPv6 addresses checked as AAAA records, instead of the first one. The device timestamp on the
Overview reads *Device*, not *Config*.

## Plugin pages, searches and APIs follow the subnet an object was stored in; Presence's subnet no longer follows the client

Nothing to do on Jen (5.68.0-beta.12). Three plugin updates come with it, offered under Settings → Plugins: Wake & Actions 1.1.2, Switch Port
Locator 1.1.2 and Presence 1.2.0. The rule the Investigation cards already followed now holds on every page, search and API of the three: a
favourite, a tracked device or a switch position is shown to an account only if it may see the subnet the object was stored in (for a
position, the subnet of its switch), whatever subnet the client is in now. A wake is the exception that follows the host: it is sent where the
host is now, and it never uses the SecureOn password of a favourite the account may not see. Accounts with no subnet restriction see no change.
For Presence this changes what the subnet of a tracked device means: it is the subnet the tracking belongs to, set when the device is tracked
and changed only by the new *Move* button (an admin who can see both subnets; audited), and no longer follows the device when it moves to a different
subnet. A device that had followed its client keeps the subnet it has; if a restricted account lost sight of a device it used to see,
move the device to a subnet that account can see, or lift the restriction.

## Press Update helper again: the config check runs with the unit's own groups on a private copy

Migration 32 runs on the first start (5.68.0-beta.13): two columns on the Problems table so a Problems alert that failed to deliver is retried from what qualified it,
not from the log tail. A channel limited to some subnets is now told about a client's trouble in those subnets only, counted from those subnets' rows alone, so a
count it received before may be lower than the number of rows across all subnets. Press **Update helper** on every Kea host (Settings → Kea → SSH shows
"v7 (build 10, build 11 available)"): build 11 writes the copy of the Kea config that it checks `0600` and owned by the account that runs the check, where
build 10 wrote it `0644`, and runs the check with the unit's `Group=` and `SupplementaryGroups=` so a Kea whose TLS material is readable through a group passes
the check it used to fail. A unit that names a group the host does not have is refused with the reason on the Servers page. The by-hand install line shown in
the flash and the docs embeds the new build. A restore marker for investigation logging that lost its `restore` object is no longer treated as proof that the
logger had no settings: Jen changes nothing and the Health row says how to restore it by hand.

## Press Update helper again: the config check runs as the account the unit names; the Problems inbox starts again

Migration 33 runs on the first start (5.68.0-beta.14) and **empties the Problems inbox**: a row is now kept per client, kind and subnet, and the rows already
there may have mixed one subnet's history into another's. The next sweep fills it again from the Kea logs (a server's first read after this records without
alerting, as before), so nothing is lost that the logs still hold. Three plugin updates come with it, offered under Settings → Plugins: Wake & Actions 1.1.3,
Presence 1.2.1 and Switch Port Locator 1.1.3 (a failed existence check now refuses instead of being read as "not found", and a subnet-scoped account is
told the same thing about a switch position whether or not a newer one is hidden from them). Press **Update helper** on every Kea host (Settings → Kea → SSH
shows "v7 (build 11, build 12 available)"): build 12 runs the config check as the account the Kea unit names even when the Kea binary is owned by root, which
build 11 checked as root; a unit whose `User=` or `Group=` the host has no account for is refused with the reason on the Servers page. The by-hand install line
shown in the flash and the docs embeds the new build. A damaged investigation-logging marker is now reported on the next scan instead of at its deadline, and the
Servers page says where to find the old values (Config history) and offers **Forget** once you have put them back.

## Press Update helper again: private files and authoring that undoes itself; the service now runs with a private umask

Migration 33 now checks its own end state (5.68.0-beta.15): a box whose upgrade to 5.68.0-beta.14 was interrupted between its two schema steps finishes the
second one on the next start instead of recording the migration as done with the old key still in place; nothing else changes for a box that upgraded cleanly.
`jen.config`, the SSL private key and the encryption keys are now written private from their first byte, and the service runs with `UMask=0077`: the unit file is
re-rendered by the next `sudo ./install.sh` or the in-app update (Docker and a hand-run server get the same umask from `run.py`). Three plugin updates come with
it, offered under Settings → Plugins: Wake & Actions 1.1.4 and Presence 1.2.2 (adding, tracking, moving or removing an item now judges and writes in one step, so
an item another admin changes at the same moment is never overwritten) and Switch Port Locator 1.1.4 (a switch-move alert and its Timeline entry go to the
subnet of the switches it names, and to unrestricted channels only when they are in different subnets). Press **Update helper** on every Kea host (Settings → Kea
→ SSH shows "v7 (build 12, build 13 available)"): build 13 writes every file it creates private from its first byte, makes the copy of your config that it checks
root-owned and not writable by Kea's account, takes its lock for every operation, requires the execute permission of Kea's account on a Kea binary that account
owns, and adds the operation that lets Jen undo an authored config. **Settings → Kea → Author a starting config** now writes every server or none, guards each
write with the file the preview showed (so *overwrite* replaces the file you previewed), and records Jen's own subnets only when every server succeeded. The by-hand
install line shown in the flash and the docs embeds the new build.


## Press Update helper again: a new Kea config is never world-readable; the installer, the migrations and the certificate set keep their promises

Nothing to do beyond the usual (5.68.0-beta.16): `sudo ./install.sh` or the in-app update. **Press Update helper on every Kea host** (Settings → Kea → SSH shows
"v7 (build 13, build 14 available)"). Build 14 creates a brand-new Kea config `root:<Kea's group>` `0640` (or `root:root` `0600` when Kea runs as root) instead of
`0644`, takes the group of `server.key` from the same account lookup the config check uses (a unit with `Group=` no longer gets a key its daemon cannot read), stops
ignoring an ownership change that fails, and installs `ca.crt`, `server.crt` and `server.key` as a set that is replaced together or not at all. **Author Kea Config**
now needs build 13 or later on every server it writes to (a server with an older helper is named and nothing is changed), checks every subnet name before touching
anything, and saves Jen's own subnet list as part of the same change, so a failure on any server puts every config and the list back. On the Jen host the
installer's rollback snapshot of `run.py` and the `jen` package now lives under `/opt/jen/.rollback` (root-owned) and nothing root copies into the application
directory ever comes from `/etc/jen` or `/var/lib/jen`; `jen.config` and its backup are written `0600` from their first byte; Docker's first-start config is written
atomically. Uploading an HTTPS certificate, rotating the Kea CA and issuing a client certificate replace their files as a set, so a failure leaves the previous
working set in place. Migrations 3, 4, 6, 8, 22 and 24 now finish themselves after an interrupted upgrade: a box whose upgrade stopped between two schema steps
completes the rest on the next start, and a box that stopped after migration 6 widened the role column but before it raised the legacy administrators to superadmin still gets
that done. A box that upgraded cleanly sees no change. The by-hand install line shown in the flash and the docs embeds the new build.

## IPv6 history starts, the Alert Log is pruned, and the Health page can tell a blind Problems sweep from a quiet network

Nothing to do (5.68.0-beta.17); `sudo ./install.sh` or the in-app update does it and no Kea host needs touching. **The Alert Log now keeps 180 days:** the
first snapshot pass after the upgrade removes deliveries older than that (a box that has run for years loses its oldest rows; Prometheus'
`jen_alerts_sent_total` does not go down, the removed ones are counted into a stored total first). The number of days is the settings key
`alert_log_retention_days`. **With IPv6 on, Reports gains a chart per IPv6 subnet:** the table behind it was never filled before, so the history begins at
the first snapshot after the upgrade and shows counts only (no pool, no forecast). The Health page gains **Problems inbox sweep**, which turns red when Jen
cannot read a Kea server's log for thirty minutes, and an empty inbox next to a red row means blind, not quiet. Behind the scenes: two Settings saves at
once no longer lose one, two people opening an Investigation page together no longer get "busy" plugin cards, and several people watching the same server on
Trace cost the Kea host one log read per three seconds.

## Expired leases stop counting, pool sizes are the whole subnet's, and alerts remember across a restart

Nothing to do beyond the usual (5.68.0-beta.18); four plugin updates are offered under Settings → Plugins (DNS Sync 1.1.1, Network Discovery 1.3.1, Presence 1.2.3
and IPAM 1.7.1) and need this Jen. A lease that has passed its expiry but that Kea has not yet cleaned up no longer counts as active anywhere: the Leases page's
default view, the subnet counts on the dashboard, Subnets, Reports and the API, the history and its forecast, the device scan, DDNS and the plugins now all read
only current leases, so a count may drop by the number of such rows (the *show expired* view still lists them). A subnet's pool size is now the total of **all**
of its pools - ranges and CIDR pools - where the last range used to win and a CIDR pool was skipped, and a subnet's utilisation counts only the leases inside
those pools; the history written before this release carries the old size and the forecast reads the newest row, so it corrects itself at the next snapshot.
The **Pool exhaustion warning** is sent once per episode instead of at every check, and a new **Pool exhaustion recovery** type (tick it on a channel to receive
it) is sent when the free addresses climb back past a small margin; utilization and packet-health alerts keep their state across a restart, so an upgrade no
longer repeats them (the first check after this upgrade sends once for conditions that are true at that moment). `sudo ./install.sh --configure` now keeps
anything its wizard does not ask about (OIDC, extra Kea servers, `[kea6]`, the update channel) and a setting you saved in Jen while the wizard was open; Jen's
saves and the installer share a lock file, `/etc/jen/jen.config.lock`. IPv6 history is removed after `history_retention_days` even when IPv6 is turned off.

## Capacity is measured by pool use, alerts know whether anyone was told, and the restore tool writes safely

Nothing to do beyond the usual (5.68.0-beta.19). The history table gains a `pool_used` column (migration 34): every snapshot from now on records how many leases are
inside the pools, and every capacity number - the Health page's pool check, the forecast, the *Pool exhaustion forecast* alert, the Prometheus utilisation ratio, Reports
and the dashboard's history - reads that, so a subnet with reservations or out-of-pool leases is no longer reported fuller than its pools are. Rows written before
the upgrade have no such figure and are ignored by the forecast (it needs a few snapshots to start again; the Health row says it is waiting for the first one).
Reports charts **Reservations configured** where it used to chart a "dynamic leases" line. A warning now counts as sent only when a channel that handles it accepted
it: with every channel down, or none enabled yet, Jen keeps trying (1, 2, 4 ... 60 minutes) for as long as the condition holds, and a recovery is sent only after its
warning was delivered. History, event and alert-log retention now runs even when Kea is unreachable, and the audit log's retention - which had been deleting by a
column the table does not have, so it never removed a row - works: the first run after the upgrade removes audit rows older than `audit_retention_days` (90; 0 keeps
everything). Health's *Background workers* and *Problems inbox sweep* rows now go red when the scheduler or a loop is genuinely not running. Prometheus label values
are escaped. `sudo ./install.sh` now requires `flock` (installed with `util-linux` automatically); a Settings save is refused, with the fix named, when the config lock
file cannot be opened; and `install.sh --restore` / `--rollback` write each file the way the installer does (never through a symlink, never partly written, the
recorded owner applied or the restore aborts).

## The last concurrency and privileged-boundary edges

Nothing to do beyond the usual (5.68.0-beta.20). The config lock is never replaced any more: if a save is refused with *the config lock ... cannot be opened*, run the `chown`/`chmod` it prints (the installer does the same, in place, on every upgrade and `--configure`). The installer's `jen.config` backups now live in `/opt/jen/.rollback/config/` (root-owned, 0700) instead of `/etc/jen/backups/`, and root no longer deletes anything under `/etc/jen`: **an existing `/etc/jen/backups` is left exactly as it is** - the old `jen.config.*.bak` copies in it are yours to keep or remove, and any `run.py.*`, `jen.<timestamp>.bak` or `ext.*` entries an old release left there can simply be deleted by hand (nothing reads them).

Alert delivery gets the rest of its contract: a recovery (*... recovery* types) that no channel accepted is retried with backoff until one does, certificate and forecast warnings are re-attempted every 15 minutes (they ran once a day, so a failed one-day certificate warning was next tried after the certificate had expired), and a beta.18 alert state is no longer assumed delivered - **the first check after this upgrade sends once more for a condition that was still active when you upgraded from 5.68.0-beta.18** (one possible duplicate rather than a missed warning). Where pool use cannot be measured the dashboard says *pool use unavailable* and the API reports `pool_used: null` instead of showing the dynamic-lease count in its place, and Prometheus leaves out the utilisation ratio for that subnet. Health's *Background workers* row now also watches the event dispatcher (a warning when only it is down). The alert-log retention pass no longer over-counts `jen_alerts_sent_total` when two passes overlap, and a failed pass is logged as failed rather than as zero rows removed.

## --configure keeps the Kea connection, About is scoped, and the Problems inbox has a cap

Nothing to do beyond the usual (5.68.0-beta.21). **`sudo ./install.sh --configure` now keeps the Kea connection, the Kea database, the SSH target and the DDNS settings** it does not ask about: the sentence in the 5.68.0-beta.18 section above promised that, and it was not true until this release - the wizard wrote those sections blank on a configured box (so Jen restarted into /setup and the DDNS token was gone). If you ran `--configure` on a beta between beta.18 and beta.20 and lost them, your backup of the old file is in `/etc/jen/backups/` (before beta.20) or `/opt/jen/.rollback/config/`. **Restricted users no longer see every subnet on the About page**, and the Explain tool gives a restricted user the same answer for a MAC whose only reservation is in a subnet they cannot see as for a MAC nobody has seen. The Problems inbox records at most 200 new (kind, client, address) keys per server per sweep; the Health page's *Problems inbox sweep* row warns when a sweep dropped some.

Investigation logging is never turned on by a restart any more: if Kea's API does not answer when you press *Turn on*, Jen now refuses (nothing written, nothing restarted) instead of treating the silence as "this Kea has no `config-reload`" and restarting kea-dhcp4 - check Settings → Kea → Probe and try again. Turning it off, and the expiry sweep, still restart if they must (DEBUG 55 has to come off) and say that the API did not answer. A `/client` page no longer waits for a down Control Agent to render its Overview: the HA question that orders the log reads is asked at most once per server per 30 seconds, and never for a read that is not fetched or already cached.

Background work keeps its promises: **the daily summary is sent at or after its configured time, once a day** (it was skipped whenever the alert loop's cycle was longer than a minute - one Kea server down was enough), and it is remembered across a restart; after this upgrade a start past the configured time does not send an extra summary. With the Jen database down, pages and the alert loop no longer wait 10-20 seconds per settings read - the last settings keep being used and the database is retried every few seconds. The Health page's *Background workers* row now fails when a plugin's scheduled job has been running far longer than its interval (it would never run again) and when the event dispatcher thread is dead (it warned in beta.20), and warns when the dispatcher is stuck or dropping events or a job failed three times in a row. Alert state and per-server bookkeeping for a subnet or Kea server you have removed are cleared, and the alert loop retries reading the device list at start instead of calling every known device new when it first returns.

## Turning logging on never restarts Kea, and `--configure` keeps the ports and the database

Nothing to do beyond the usual (5.68.0-beta.22). The 5.68.0-beta.21 sentence "investigation logging is never turned on by a restart any more" was true of the first of two calls: **turning it on now never restarts Kea because its API failed** - if `config-reload` is not confirmed (a refusal, a connection failure, a timeout), the file is put back and nothing is restarted (turning it off, and the expiry sweep, still restart if they must). `sudo ./install.sh --configure` now also keeps the HTTP and HTTPS ports and the Jen database's host, user and name (Enter used to write 5050, 8443, localhost, jen, jen over them). The IP map shows nothing to a user who may see no subnet (it showed the first configured subnet's addresses and reservations), and the Explain page's log reading picks the newest complete exchange across your Kea servers instead of the first in order, naming another server that logged the client at about the same time.

