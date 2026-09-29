# Upgrading from 5.56.3

Everything below changed since v5.56.3 — the last stable release before
this one — that you'd actually notice or need to know about when you
upgrade. Run `sudo ./install.sh` on the new tarball (or use the in-app
updater) the normal way; nothing here needs a manual step beyond what's
called out explicitly. See `docs/runbooks.md` for step-by-step
procedures, and `CHANGELOG.md` if you want the full detail behind any
item below.

## The Kea host helper stays exactly where it is until you press Update

Jen never updates `jen-kea-helper` on its own — a host keeps whatever
version it's already running until you press **Update helper** in
Settings → Kea → SSH, the same as it always has.

If a host is still on helper v5 or older, that one press needs the
legacy `NOPASSWD: /usr/bin/python3` sudoers grant present — exactly as a
fresh install always needed it. Once it's made that hop to v6 (5.66.0-beta.1),
every update after that is verified by a release signature and needs no
grant at all, ever again. The SSH card shows **"signed updates"** next to
a host once it's there. If **Update helper** says there's no legacy
grant even though you're sure one exists, press **Test legacy grant**
next to it to see exactly what `sudo` said rather than a generic refusal
(5.65.13-beta.1).

The helper itself was hardened further in 5.66.0-beta.2 — nothing changes
for you here either. The SSH card now shows a build number alongside the
version (`v7 (build 7)`), since a helper-only fix can ship without
changing what the helper's protocol looks like; the one by-hand install
command (for a host with no working sudoers line at all yet) now verifies
a signature locally before installing anything, with no unverified
fallback offered anywhere — see `docs/runbooks.md` if you ever need it.

A second helper-only fix ships as build 8 (5.66.0-beta.4): the one case
the build-7 rollback didn't cover — a signed update failing right after
being installed with no way back, on a host with no helper file there yet
to begin with — now refuses before writing anything at all. Nothing
changes for you either, beyond the SSH card reading **"v7 (build 8)"**.

## The public health endpoint answers with one field

`/api/v1/health` — the endpoint the self-updater and a recovery restore
poll to confirm Jen is back up, unauthenticated by design — carries
`jen_version` alone now. It changed shape a few times along the way
(added a live Kea probe and a `subnets` count in 5.65.6-beta.1; briefly
added a full per-server `kea_servers` list in 5.65.8-beta.1) before
settling here: the per-server list moved to the key-gated
`/api/v1/health/kea` (5.65.10-beta.1) and the remaining Kea summary
fields followed it in 5.65.12-beta.1, since nothing that actually reads
the public endpoint — the updater, a restore, the system test suite —
ever wanted more than the version string, and there was no reason to
hand an unauthenticated caller a live inventory of your Kea servers. If
you had a script polling `/api/v1/health` for anything besides
`jen_version`, point it at `/api/v1/health/kea` (an API key) instead.

The same endpoint also no longer makes Jen wait on Kea to answer at all
(5.65.6-beta.1) — it used to call Kea inline, which meant it could take
up to 20 seconds to answer with Kea unreachable, occasionally fooling
the self-updater's own health check into rolling back a perfectly good
update. It now answers from Jen's own background-refreshed cache.

## Network Discovery's "known" hosts list — who manages it, and when it updates

Marking a host known (or forgetting one) writes an entry with no subnet
of its own, since the same MAC can matter to more than one subnet's
rogue-device alert — which meant a subnet-scoped administrator could
silence or re-arm the alert for a host outside subnets they can see. The
known-hosts list is now for administrators who can see every subnet
only; the **Known** and **Forget** buttons no longer appear for a scoped
account (5.65.9-beta.1). If a scoped administrator has been maintaining
this list, an unrestricted one needs to take it over — entries already
on the list are untouched.

Separately, a host's known/unknown status used to get written into each
scan's own stored results at the moment you marked it — so the results
page, an export, and the dashboard's rogue count all kept showing the
OLD status until that subnet's next scan ran. Status is now derived at
read time from the current known-hosts list every time it's shown, so
marking a host known (or forgetting one) is reflected everywhere
immediately (5.65.11-beta.1).

## Bundled plugins upgrade together with Jen, not ahead of it

Every bundled plugin now requires at least Jen 5.57.0, and several
require 5.65.2 or later for authorization fixes that landed there — a
5.56.3 box checking for plugin updates used to be offered ones it
couldn't actually take. The Plugins page now says **"Update needs Jen
vX.Y.Z — upgrade Jen first"** in place of the button when that's the
case (and **"Upgrade Jen to vX.Y.Z to install"** for a plugin you don't
have yet), and the install/update routes themselves refuse before
fetching or requesting anything (5.65.10-beta.1). Upgrade Jen first, then
the plugin updates become available the next time you check.

Five new plugins were bundled since 5.56.3, each its own opt-in install
from the Plugins page: **Host Watchdog** (uptime monitoring with
alerting, 5.58.0-beta.1), **Local DNS Sync** (pushes DHCP names to
Pi-hole, AdGuard Home, or exports Unbound `local-data`, 5.59.0-beta.1),
**Switch Port Locator** (SNMP: which switch port is a MAC actually
plugged into, 5.60.0-beta.1), **Wake & Actions** (a Wake-on-LAN button on
every Lease/Reservation/Device row plus a favourites page, 5.61.0-beta.1),
and **Presence** (publishes a device's online/offline state to Home
Assistant, MQTT, or a plain HTTP endpoint, 5.62.0-beta.1). None of them
do anything until you install and enable them.

## Your browser's theme may need picking again, once

Every browser gets the install-default theme on its first load after
this upgrade — the old, permanently-tainted storage key that used to
shadow whatever you picked was cleared on purpose (a genuine bug: the
picker had been writing its own fallback into every browser's storage on
the very first page load since the theme system shipped, so nothing
could ever actually change what a browser showed afterward). If you'd
picked something other than the install default, pick it again once;
after that it sticks normally.

## The Servers page tracks every unresolved rollback, not just the last one

A config push that had to roll back — because a server wouldn't restart
on it, say — used to occupy one banner slot on the Servers page that a
LATER, unrelated rollback simply overwrote: an unresolved "this server
may still be stopped" notice could vanish the moment a different,
successful rollback happened on any other server. The banner is now a
list of every unresolved incident; each is cleared only when a later
clean run actually covers the same servers it named, or an administrator
dismisses it by hand (5.65.10-beta.1). Both a clean rollback and a failed
one are also now written to the audit log (5.65.8-beta.1), and a
rollback whose OWN restart fails is correctly shown as a failed rollback
rather than silently logged as an ordinary abort (5.65.6-beta.1). An
unresolved incident is never dropped from that list to make room for a
newer one, either, even in the extreme case of twenty or more genuinely
unresolved failed rollbacks at once (5.66.0-beta.3) — the only real
bound left is a hard ceiling of two hundred, since a stored note still
can't grow forever, but you'd see the Servers page in a very bad state
long before that ever mattered.

A multi-server config push that fails partway through an SSH round trip
now reverts every server it had already written, rather than leaving
some on the new config and others on the old one; a revert that itself
can't be applied is reported by name as needing hands, not silently
called "still fine" (5.65.1-beta.1).

## If you're running the Docker image

The shipped Docker image failed to start at all — `gunicorn` crash-looped
with "No module named 'jen'" — for every release since gunicorn arrived
(v5.5.0): 5.56.3 itself carried the identical bug. Fixed with an explicit
working directory in the image plus a fallback in
the launcher itself (5.65.1-beta.1). The image also now installs `nmap`,
`iputils-ping`, and `snmp` so Network Discovery, Host Watchdog, and
Switch Port Locator all actually work inside a container, and hides the
self-update / Restart controls that don't apply without systemd
(5.65.10-beta.1).

## Recovery bundles moved to a streaming format

A recovery bundle (Settings → Databases → Recovery) is now written and
read as a streaming, chunked format instead of held whole in memory —
the practical effect is the size ceiling went from 200 MB to 2 GB, and
building or restoring a large bundle no longer needs roughly three times
its own size in free memory. This is fully backward compatible: a bundle
from before this change still restores normally, the format is
auto-detected, and there's nothing for you to do (5.65.0-beta.1).

The database export inside the bundle gets the same treatment in
5.66.0-beta.4: it's written straight to disk, one row at a time, instead
of built as one Python object first — `audit_log` is the table this
matters for on a long-running install. A new **"Without audit history"**
checkbox on the recovery form leaves that one table out entirely if you'd
rather export it separately. Restoring still needs memory in proportion
to the export's size (a bigger change to fix that is out of scope here),
so `jen.tools.restore` now checks — before it stops or touches
anything — that the machine has enough free memory for the bundle it's
about to restore, using a measured factor recorded in the manifest; see
`docs/runbooks.md`'s "Before you start: size" step if a restore ever
refuses on this.

## A few things that will just already be fixed

None of these need anything from you — they're upgrades you get for
free by being on this version at all, worth knowing existed:

- The Investigate page (Network → Investigate, or the **Investigate**
  action from a Lease/Reservation/Device row) — one page, six tabs, for
  a given MAC, IP, or hostname (5.63.0-beta.1) — had several places
  where it could show a subnet-restricted administrator information
  about a device outside their scope; all fixed (5.65.2-beta.1).
- Health Center gained a **Server capabilities** row per Kea server
  (5.64.0-beta.1).
- Settings → System's Plugins table briefly rendered its column headers
  between rows instead of above them (5.57.1-beta.1); separately, sticky
  table headers on every desktop page — added 5.56.4-beta.1 — never
  actually worked at all, which 5.57.1-beta.1's own attempted fix didn't
  catch either; the real cause was fixed properly in 5.58.1-beta.1 (a
  build that was mistagged and shouldn't be installed directly — take
  5.58.2-beta.1 or later, which is the identical fix with its version
  number corrected). A wide table's sideways scroll is now an explicit
  opt-in that trades away the sticky header, since the two can't coexist.
- API-key callers of IPAM Lite's JSON API (added 5.57.1-beta.1) got a
  server error on every call from 5.57 through 5.65.8 — fixed in
  5.65.9-beta.1; if you tried it in that window and gave up, it works now.
- A plugin bundled onto a box after its initial install used to show up
  in Plugin Manager as permanently "writable — reinstall to harden," and
  reinstalling never actually fixed it; fixed in 5.58.3-beta.1.
- Host Watchdog and Local DNS Sync (bundled 5.58.0-beta.1 and
  5.59.0-beta.1) failed to load at all, on any Jen install, from the day
  each shipped — one bad periodic-job interval, one bad alert-type name;
  fixed in 5.60.1-beta.1. If either never seemed to do anything, it
  works now.
- Plugin API v3 (5.57.0-beta.1) is what every plugin bundled since is
  built on — Timeline events, custom alert types, row actions and JSON
  API routes for plugin authors. The DDNS Errors dashboard panel started
  naming the actual reason it skipped a record instead of a bare
  "nothing to report" in the same release.
- A nav icon that rendered as the literal word "cable" instead of a
  glyph, and every other unrecognized plugin icon name, now falls back
  to a generic icon instead (5.65.3-beta.1).

Everything else in this window (5.58.2-beta.1's own version-numbering
correction, 5.62.1-beta.1's test-infrastructure work, and the steady run
of cross-subnet authorization hardening across 5.65.4-beta.1 through
5.65.9-beta.1 — including 5.65.5-beta.1's fixes and Presence's sink
configuration becoming superadmin-only, and 5.65.7-beta.1's plugin error
messages becoming generic instead of raw database/socket text — for
every bundled plugin) is either invisible from the outside or already
folded into the sections above.
