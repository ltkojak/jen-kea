# Upgrading from 5.66.0 (archived)

*This is the archived "Upgrading from 5.66.0" page, kept for anyone
still running that release or an intermediate beta. Current releases
are documented in [`docs/upgrading.md`](../upgrading.md) at the
current baseline.*

Everything below changed since v5.66.0 — the last stable release before
this one — that you'd actually notice or need to know about when you
upgrade. Run `sudo ./install.sh` on the new tarball (or use the in-app
updater) the normal way; nothing here needs a manual step beyond what's
called out explicitly. See `docs/runbooks.md` for step-by-step
procedures, and `CHANGELOG.md` if you want the full detail behind any
item below. The previous page, covering everything since 5.56.3 through
the 5.66.0 baseline, is archived at
[`docs/release-history/upgrading-5.56.3-to-5.66.0.md`](upgrading-5.56.3-to-5.66.0.md).

## install.sh can be scripted

`sudo ./install.sh --answers <file> --unattended` drives a fresh
install from a `KEY=value` file instead of the interactive wizard —
the same `JEN_*` names `.env.example` and the Docker path already use,
so there's nothing new to learn if you've ever filled in a `.env` for
the container path. The same names also work as plain environment
variables with no file at all. Nothing changes for an existing install
running `sudo ./install.sh` to upgrade in place — it still auto-detects
and keeps your configuration exactly as before (5.67.0-beta.1).

## A fresh install's connection failures behave differently

If you run the wizard by hand and Jen's own database test fails, you're
offered retry / edit / continue instead of a bare warning that just
carries on; when it's local and root can already connect, you're offered
to create it (the SQL shown first either way). None of this affects an
existing install or an upgrade — it's the fresh-install wizard only
(5.67.0-beta.1).

## Kea connects after install now, not during it

The installer no longer asks for Kea's API, database, subnets, SSH
access, or DDNS at all — it only asks for Jen's own database, the ports,
and an admin password. Log in once installed (as a fresh install always
has, same as before) and a six-step guided **`/setup`** wizard connects
Kea live, in the browser — the same connection testing the old terminal
prompts did, with a real retry loop instead of a terminal re-prompt, plus
installing the Kea host helper, capturing a config baseline, making a
recovery point, and investigating your first client. An `--answers` file
or `JEN_*` environment variable can still supply `JEN_KEA_API_URL`,
`JEN_SUBNETS`, `JEN_KEA_SSH_HOST`, `JEN_DDNS_PROVIDER`, or any of their
companions directly. There is no per-step skipping: `/setup` is a one-time
redirect that fires only while Jen has no Kea API URL and no named subnet, so
supplying both means you are never sent there (it stays reachable from Getting
started). None of this
affects an existing install or an upgrade — it only changes what a fresh
install's terminal session asks (5.67.0-beta.3).

## jen.config tightens to 0600

The config file holding every DB password, API credential and DDNS
token this install has moves from `0640` to `0600` — owner and group
have been the same service user since v5.10.4, so the group-read bit
never actually granted anyone anything. A fresh install creates the file
`0600`; an existing one is tightened the next time Jen writes it — any save
under Settings. An upgrade on its own does not touch the mode, so if you want
it now: `sudo chmod 600 /etc/jen/jen.config` (the path follows `--config-dir`
on a relocated install). Nothing else for you to do (5.67.0-beta.1).

## Two bugs that only ever affected a genuinely fresh install

If you've installed Jen since `relfmt`/`hostname` became real Jinja
filters, a fresh install's own post-install verification step has been
failing silently right after the service started — the service itself
came up fine, you'd just never see the "Installation complete!" summary
box. And a fresh install's admin password (typed in the wizard, or
given as `JEN_INITIAL_ADMIN_PASSWORD`) was silently discarded, with
Jen falling back to its own auto-generated token instead — the
`sudo cat /var/lib/jen/initial-admin-password` instruction already in
this doc's own First Login guidance was the actual working path the
whole time. Both are fixed; neither affects an existing install or an
upgrade, since neither bug was ever in the upgrade path (5.67.0-beta.1).

## A fresh install can relocate app/config/data

`sudo ./install.sh --app-dir DIR --config-dir DIR --data-dir DIR` puts
the app tree, the `/etc/jen` equivalent, or the user-writable data
directory somewhere other than the historical defaults — the common
case being a separate volume for uploads, database backups and
plugins. The choice is recorded in `/etc/jen-layout.conf` and every
later `--upgrade`/`--repair`/`--configure` run reads it back
automatically. This changes nothing for an existing install: absent
that file (every install made before this release, and any made since
that never asked to relocate), everything stays exactly at
`/opt/jen`/`/etc/jen`/`/var/lib/jen` as always. Moving an *existing*
install's data directory afterward is a short runbook, not a flag —
see `docs/runbooks.md` §5 (5.67.0-beta.2).

## Nothing to do: the README and repository front door

5.67.0-beta.4 rebuilds the README (one positioning sentence, a feature
matrix, a compatibility table, a new `docs/about.md` and
`docs/features.md`) and updates the GitHub repository's own description,
topics and social-preview image. None of it touches installed code,
config, or behavior — there is nothing for an existing install to do.

## A permissive app_dir now blocks an upgrade until fixed

The layout checker that validates `app_dir`/`config_dir`/`data_dir` on
every privileged run (added 5.67.0-beta.2) now hard-refuses when an
*existing ancestor* directory of one of them is writable by group or
other — a local user could otherwise rename the root-owned directory
aside and plant a symlink in its place for the next update to follow.
5.67.0-beta.2 only warned about this case (to accommodate a CI
runner's own `/opt`); that was the wrong trade — the CI accommodation
now lives in CI itself. On the historical default layout this almost
never matters (Ubuntu's own `/opt` ships `755`), but if `install.sh`
refuses with "... is writable by group or other", the message names the
exact directory — `sudo chmod go-w <that directory>` and re-run.
`docs/troubleshooting.md` has the full list of layout refusals and
their fixes (5.67.0-beta.5).

## Nothing to do: a relocated install no longer writes /etc/jen into itself

A relocated install's generated `jen.config`, rendered systemd unit, and
updater log messages used to still say `/etc/jen`/`/opt/jen` in a few
spots regardless of where the install actually lives — cosmetic only
(the app itself already derived the real paths correctly), but
confusing to read. Fixed; nothing for any install, relocated or not, to
do (5.67.0-beta.5).

## /setup gets TLS-aware, tells the truth about IPv6, and merges instead of replacing

All four changes below are to the fresh-install `/setup` wizard only —
none of them affect an existing install or an in-place upgrade:

- **Connect** now has an Advanced TLS expander (CA bundle, client
  certificate/key, "do not verify") so a site with a private CA or
  Kea's default mutual-TLS control socket can actually connect from
  this step, the same as it already could from Settings.
- **What Jen found** no longer renames a subnet you've already named,
  and no longer silently drops one Kea didn't report this time —
  anything orphaned is offered as an explicit, unchecked removal
  instead. **IPv6** now says "not checked" until you press **Check for
  DHCPv6** yourself; nothing v6-related runs before that.
- **Recovery point** only marks itself done once a bundle from that
  setup run has actually finished downloading, not just because a
  button was clicked — Getting started also gains its own "A recovery
  bundle exists" row, separate from the existing backup row.
- **Investigate a client** opens the full six-tab Investigation page
  now, not just the narrow Explain tab (5.67.0-beta.5).

## A native install is no longer misdiagnosed as a container

If you installed or upgraded to 5.67.0-beta.2 through 5.67.0-beta.5,
Settings → System may have shown "Updates are the container image's
job" and a Restart card talking about `docker compose restart jen`,
even though this box runs `install.sh`, not Docker — the relocatable
install added in beta.2 made the rendered systemd unit set `JEN_ROOT`,
which a detection check had relied on to mean "not systemd" since long
before that. Fixed; since the hidden button was the normal way to reach
this fix, a box stuck on one of the affected betas has two ways out. Either
extract the newer release tarball and run `sudo ./install.sh --upgrade`, or let
the updater do it: it offers a pre-release only when `[updates]` in `jen.config`
says `channel = beta`, so set that first, then run
`sudo systemctl start jen-update.service` (with the default `channel = stable`
that command finds nothing newer than the beta it is already on and does nothing).
See `docs/troubleshooting.md` for the full detail. Nothing else about
an affected install was wrong, and Docker/dev checkouts were never
affected (5.67.0-beta.6).

## A security audit's fixes — nothing for most installs to do

A review of the layout/installer work and the first-hour setup wizard
found seven issues, all fixed; `sudo ./install.sh` (fresh, `--upgrade`,
`--repair`) and the in-app updater pick up every one automatically —
none need a manual step:

- Two places in `install.sh` ran Python as root when they should have
  run as the service account (a theoretical privilege-escalation path,
  never observed in practice); the root self-updater's own layout
  marker write is now immune to a symlink planted in a directory the
  service account owns; an upgrade's rollback snapshot of root's own
  files (the sudoers grant, the systemd units, the updater itself) moved
  to a directory only root can write, closing a gap present since the
  very first versioned-release installer.
- The self-update service now actually runs the layout checks four
  documents already said it did; Settings → Health gains an "install
  path is trusted" row reflecting the result.
- A Docker container started with no Kea configured at all (the
  README's own advertised path) used to crash-loop forever — fixed; an
  already-running container is unaffected.
- `/setup`'s recovery step, and `/getting-started`, could 500 for every
  admin once a recovery bundle had actually been downloaded — fixed; a
  box that never hit this needs nothing.
- A subnet name that predates this project's own name validator (added
  in 5.67.0-beta.5) could make an unrelated later subnet change fail
  after Kea's own side had already gone through — fixed; an existing
  odd name is preserved exactly as it was, or repaired automatically if
  it genuinely can't be stored, logged either way (5.67.0-beta.7).

## The setup wizard's remaining fixes — one thing to check if you used it

The first-hour wizard's remaining defects are fixed; `sudo ./install.sh`
or the in-app updater picks all of it up with no manual step. One thing
is worth a look if you ran **Connect** on an earlier beta: it saved a
Kea daemon's own control socket as *Control Agent* mode (every Kea 3.2
site, and any direct-mode install that re-submitted the form). Settings →
Kea shows the mode that was saved; re-submitting **Connect**
(`/setup/connect`) now identifies what answered and saves the right one,
or **Probe** on the Settings page reports the same thing.

What changed, for anyone who uses the wizard from here on:

- Connect tries the URL exactly as typed (a custom port included),
  guesses `:8004`/`:8006` only when you gave no port, and reports the
  error for the URL you typed. A blank password field means "use the
  saved one", for the test as well as the save.
- A new optional `[kea_db] port` key (and `[kea6_db] port`, inheriting
  it) sets the Kea database's TCP port; absent means 3306, as before.
  Every connection the application makes honours it now — earlier
  releases always dialled 3306.
- "Manage IPv6 in Jen" merges into `[subnets6]` instead of replacing it,
  and the DHCPv6 check requires a real kea-dhcp6 answer.
- The Found step shows Kea's HA peers and the servers Jen manages as two
  facts, with an **Add this peer to Jen** action; submitting it while Kea
  is unreachable saves nothing and leaves it open.
- A host Jen cannot reach over SSH is reported as a message (on
  `/setup` and on Settings → Kea → SSH) naming the user, host and
  reason; the recovery step offers **Continue** once the bundle has
  downloaded. Getting started links a plain administrator only to pages
  an administrator may open (5.67.0-beta.8).

## The installer and uninstaller: what behaves differently

`sudo ./install.sh` (fresh, `--upgrade`, `--repair`) and the in-app
updater pick all of this up automatically. Nothing needs a manual step,
but several behaviours that were documented and did not hold now do —
worth knowing if you script the installer:

- **`JEN_APP_DIR` / `JEN_CONFIG_DIR` / `JEN_DATA_DIR` in an `--answers`
  file now take effect.** They were silently ignored: an install that asked
  for a relocated layout through the file alone went to `/opt/jen`. If an
  answers file of yours carries those keys and you were relying on them
  being ignored, drop them.
- **A reinstall keeps the `jen.config` that is already there.** After
  `uninstall.sh` level 1, `sudo ./install.sh` finds your config and does not
  rewrite it from the answers file or blank Kea sections; `--configure`
  rewrites it on purpose. A config or data directory an older uninstall left
  without a marker is recognised by its content.
- **`install.sh` decides install versus upgrade from Jen's own record and
  content, not from whether the directory exists.** A pre-created empty
  `--app-dir` is a fresh install; a directory holding somebody else's files
  is refused and left untouched.
- **`uninstall.sh` uses the checker that ships beside it**, so it works on a
  box whose installed updater is older (run it from the extracted release
  tarball). Level 3 now also removes `/usr/local/sbin/jen-update-root.py` and
  the `jen-update` and `jen-plugin-install` units.
- **The pre-upgrade backup is the application's own** (the same file the
  Settings page and the scheduled backup write, into `<data dir>/backups`),
  says plainly whether it was written, and asks whether to continue if it
  was not. Kea's own database is not part of it.
- `--upgrade` and `--repair` no longer need a terminal; the answers parser
  accepts spaces around `=`, quoted values and `export`; and a layout path
  under `/root` is refused (5.67.0-beta.9).

## Things that now do what the pages said

Nothing here needs a manual step; `sudo ./install.sh` or the in-app updater
picks it up. Worth knowing because each used to behave differently from how it
was described:

- **The DDNS answer given at install time takes effect.** The installer and
  the Docker start-up wrote the provider under a key the application never
  read. A box installed with `JEN_DDNS_PROVIDER` set (an answers file, or the
  Docker environment) has been running with none; check Settings → DDNS and
  choose it there if that was you. Nothing already saved in the application
  is changed.
- **Save & Restart, the port change and the certificate upload and removal
  restart Jen in Docker too.** They ran a systemd command that cannot work in a
  container while the page said Jen was restarting. Under systemd they run the
  same command as before; in Docker the process stops and Docker restarts it;
  on a host that is neither, the page now tells you to restart it yourself.
- **The Grafana dashboard download works from the Docker image**, which never
  shipped the file.
- **Pages show the directories your install actually uses.** The database page
  named `/opt/jen/backups` — wrong on every install since 5.13, where backups
  live under the data directory — and several others printed `/opt/jen`,
  `/etc/jen` or `/var/lib/jen` on a relocated install.
- **A missing `lease_cmds` hook is no longer reported as a problem.** Jen sends
  no lease command to Kea; leases are read from Kea's database. `host_cmds`
  is still what reservation add, edit and delete use, and Health still checks
  for it.
- **The manual install guide's commands are run on every build**, and it renders
  the systemd unit with `jen-update-root.py --render-unit` instead of copying a
  file that stopped shipping. If you installed by hand from an older copy of
  that page, nothing changes for you; the page no longer cuts a pre-release
  version down to its release number when it names the release directory
  (5.67.0-beta.10).

## Kea reservations restored or migrated through Jen may need repair

This one is older than the rest of this page: it is in every earlier release,
5.66.0 included. Restoring a Kea backup, importing a Kea export file, or migrating
the Kea database from the Databases page stored each reservation's identifier as
the **text of its own hex** — a MAC `34:13:43:e6:0e:2a` came back as the twelve
characters `341343e60e2a`. The row looks right in every listing; Kea never matches
the client to it again. Jen's own database and the recovery bundle were never
affected.

**Who may be affected:** anyone who ever restored or migrated Kea reservations
through Jen. Nothing is wrong if you only ever *exported* them, or never used
those pages.

**What to do:** nothing, unless you did. The Health Center now has a row,
*Kea reservations have plausible identifiers*; if it is not `fail`, you are
clear. If it fails, Settings → Databases → Import → **Check reservation
identifiers** lists each damaged row with what is stored now and what it will
become, and repairs the ones you tick. Per-host option values restored the same
way cannot be recognised automatically — check them by hand. Backups made before
this release still restore correctly: the importer now decodes the hex they hold
(5.67.0-beta.11).

## Backups and restores that now behave differently

- **The scheduled and manual Kea backup now holds every reservation, IPv4 and
  IPv6** (`hosts`, `dhcp4_options`, `dhcp6_options`, `ipv6_reservations`),
  labelled *Kea host reservations (IPv4 and IPv6)* everywhere. It used to be the
  first two tables only, under the name "Kea's database". It still contains no
  leases, which are transient; export those separately if you want a snapshot.
- **The Kea export is streamed**, so a large lease table no longer has to fit in
  memory. Export files are format 3; an older file imports as before.
- **A restore whose plugin data fails now stops and rolls back** instead of
  printing a warning and exiting 0. For a plugin whose code is installed, a failed
  migration replay, row import or consistency check is an error that names the
  plugin and the table, and the whole restore is undone. If you would rather have
  everything else and handle that plugin by hand, add `--lenient-plugins`
  (`sudo ./install.sh --restore <bundle> --lenient-plugins`); what it accepted is
  recorded in `restore-report.txt` beside the snapshot. A plugin that is not
  installed on the machine is still only a warning (5.67.0-beta.11).

## Reports: every chart can show its projection, and none shows a crossed-out label

Nothing to do; this is how the Reports page reads now. Each subnet's chart used
to list "Projected (trend)" in its legend crossed out unless that subnet's trend
was rising, so on most installs one chart drew a dashed line and the rest looked
as if the feature were switched off. Now:

- **The dashed line is drawn for a rising, a flat and a falling trend** whenever
  there are at least 7 days of history, thirty days ahead and kept between zero and
  the pool size. Only a rising trend also gets an exhaustion date, as before.
- **A chart with nothing to project has no dashed line and no legend entry for it**;
  one sentence under it says why ("No projection yet: 4 more day(s) of history
  needed", or "No projection: this subnet has no pool").
- **Each chart has a thin *Total active* line** (dynamic plus reserved, the series
  the forecast is fitted on) that the dashed line continues; its legend entry is
  *Projected total (trend of daily peaks)*.
- **The card's sentence says where the trend is heading** for falling and flat
  subnets too: "falling — about 12 in 30 days", "flat — holding near 80".

The Health Center check and the optional alert are unchanged: they act on the
exhaustion dates, which are still rising-only. The dashboard's forecast panel shows
the same sentence as the card, so a falling or flat subnet's line there gains the
same ending (5.67.0-beta.12).

## Database tools that can no longer destroy what is already there

This is older than the rest of this page: it is in every earlier release, 5.66.0
included. It matters if you have ever migrated a database from Settings → Databases,
or merged a Kea export into a Kea database that already had reservations.

- **Migrating Kea now needs an initialised target and copies data only.** Run
  `kea-admin db-init mysql` on the new server first (the same Kea major version as
  the old one), then migrate. Jen no longer creates Kea's tables on the target and no
  longer drops anything if the copy fails — before, a failed copy dropped whatever
  tables it believed it had created, including a freshly initialised target's own.
  If you migrated Kea into a non-empty target before and it failed, check that the
  target's `hosts`, `dhcp4_options`, `dhcp6_options` and `ipv6_reservations` tables
  are all still there.
- **Migrating Jen's own database needs the target tables to be absent** (use an empty
  database), and nothing ticked on the page is refused rather than meaning
  "everything".
- **Importing a Kea export matches reservations by identifier, type and subnet, never
  by the id in the file.** Before, a file host whose id matched a different host in
  your database was dropped while its options attached to the wrong one. If you
  merged an export into a populated Kea database, look over the reservations that
  existed before: their options are the rows that could have gained extras.
  *Overwrite* now updates in place and no longer deletes anything; an import error
  now aborts and rolls back with the table and row named, instead of reading
  "skipped".
- **The reservation backup carries host-scoped options only.** Older backups also
  hold global, subnet and class options; importing one no longer writes those
  anywhere, and the result line counts them.

Existing backups still import. Nothing needs doing on upgrade (5.67.0-beta.13).

## Restores and imports that now keep their word, and what an uninstall leaves behind

Like the section above, this is older than the rest of this page: it is in every
earlier release, 5.66.0 included. Migration 29 (one small table) runs by itself on the
first start; there is nothing to do, but a few things behave differently.

- **A restore is exact or it stops.** Replace mode, `sudo ./install.sh --restore` and
  the rollback that undoes a failed restore used to insert with `INSERT IGNORE` and
  report the file's row count, so a row the database refused could be stored mangled
  and still be counted. They now insert plainly, report what the database says it
  inserted, and fail — rolling back — on a missing table, a file with no column this
  schema knows, a count that does not match, or a skipped row. A restore that used to
  finish and now stops names the table; the cause is a row the database never
  accepted. `--lenient-plugins` still relaxes only the plugin half.
- **The Databases import page's Replace mode saves a snapshot first and puts it back
  if anything fails**, including a plugin. It needs free room in the backups directory
  about the size of your Jen database for the length of the import (a
  `pre-import-<time>` folder, removed afterwards; kept and named if the rollback
  itself fails). **Merge mode takes no snapshot**: core tables commit together, then
  each plugin's tables one plugin at a time, and its result lines now say `N added, M
  skipped` rather than the file's row count.
- **Replacing `users` on its own is refused** unless the tables that point at it
  (multi-factor, passkeys, saved searches, dashboard layouts, API keys) are ticked
  too, or you restore the whole file.
- **An uploaded file that is not a Jen export gets a message, not an error page**, and
  a plain-JSON export is accepted as well as a gzip one.
- **An uninstalled plugin's data now stays in every backup**, as the Plugins page
  always said it would: the recovery bundle, scheduled and manual backups, snapshots
  and a Jen database migration all carry it, and reinstalling the plugin reconnects
  it. A plugin you uninstalled **before** this version was never recorded: its data is
  still in your database, but a backup will not include it until you reinstall that
  plugin and uninstall it once more. Restoring onto a new machine without the plugin
  installed cannot recreate its tables; the output names the plugin, and its data stays
  in the backup until the plugin is installed and the restore is run again.

Existing backups still import (5.67.0-beta.14).

## Smaller things that now behave differently

Nothing here needs doing on upgrade (5.67.0-beta.15); each is something you might
notice.

- **The reservation identifier repair is more careful about client-ids.** If you used
  Settings → Databases → Import → **Check reservation identifiers**, a client-id that is
  only hex digits is now ticked for repair only when a lease confirms it; with no
  lease it is listed unticked as *ambiguous*, and when a lease shows the client sends
  that exact text it is left alone. Per-host option values of a few fixed-width codes
  (addresses, masks, times) that were restored as hex text are listed in a second
  table, unticked, for you to review.
- **A Podman container restarts itself.** Jen now recognises Podman (`/run/.containerenv`)
  as a container like Docker. "Save & Restart", a port change and a certificate change
  stop Jen's process and rely on the container's restart policy, so run it with one
  (`--restart=unless-stopped`, or a systemd unit or Quadlet that restarts it).
- **The migration page and the setup Connect step have a CA bundle field.** Both are
  optional; leave them empty and nothing changes. Set one to connect to a database over
  verified TLS. On the Connect step an empty field clears a `[kea_db] ssl_ca` that was
  already saved, so leave the pre-filled value alone if you use one.
- **A backup schedule must back up something.** An enabled schedule with neither the Jen
  database nor the Kea reservations ticked is refused when saved, and one saved that way
  earlier no longer counts as protection on the Getting started checklist; its last
  status says nothing was backed up until you tick a target.
- **The restore warning for a plugin that is not installed is plainer:** its data is not
  restored by that run, it stays inside the bundle, and you reinstall the plugin and
  run the restore again.

## IPv6 addresses show as addresses (only if you turned IPv6 management on)

Like the sections above, this is older than the rest of this page, and it matters only
if IPv6 management is on (it is off by default; an IPv4-only install is untouched).
Kea 3.x stores the address columns of its IPv6 tables as raw bytes, and Jen printed those
bytes where an address belongs — the IPv6 Leases, Reservations, Devices and search
results — and could not search a lease by address. From 5.67.0-beta.16 they show as
addresses (`2001:db8::10`) and sort in address order. Nothing in Kea's database changed
and there is nothing to do. One search detail differs: typing a **whole** address finds
exactly that address (not the longer addresses it begins), while a fragment such as
`2001:db8` still finds everything containing it.

## A Kea migration moves a reservation's own options, and says what it left behind

Older than the rest of this page, and only for someone who migrates the Kea database from
Settings → Databases. The migration page describes the group as reservations with their
host-scoped options; the copy itself moved every row of Kea's options tables. If your Kea
uses its configuration backend (subnet, pool, class or global options stored in the
database), that either failed the whole migration on the target's empty subnet tables (rolled
back, nothing damaged) or wrote the global options into the target's config backend. From
5.67.0-beta.17 the migration copies a reservation's own options only — exactly what the
backup holds — and its result says how many rows of the config backend it left behind.
Nothing to do on upgrade; if you had to work around the failure by hand, the migration now
completes. Global search also finds an IPv6 reservation that is more than twenty hosts into
its subnet (IPv6 management only).

## The installer: Jen's database cannot be skipped, MariaDB can be installed for you, and there is a log

Only for a **fresh install** or a **reinstall that asks for new configuration**; an
upgrade of an installed Jen keeps its configuration and none of this appears. From
5.67.0-beta.18 `sudo ./install.sh` has no "continue without it" for Jen's own database:
Jen cannot start without it, and an installer that "continued" ended without installing
anything. If the database does not answer you can retry, edit the values, **install
MariaDB on this machine and create the database** (offered only when the host is this
machine, never without your `y`), or quit. An unattended install (`--unattended` or an
answers file) whose Jen database does not answer now **stops with a non-zero status and the
SQL to create it** instead of ending silently; add `JEN_DB_INSTALL_LOCAL=yes` to the answers
file to let it install MariaDB locally and create the database. Everything the installer
runs — `apt-get`, `pip`, the virtualenv, `systemctl`, `mysql` — now writes its output to
`/var/log/jen-install.log` (root-only) and the screen shows only the progress line. If you
script the installer and relied on it carrying on past an unreachable Jen database, point
`JEN_DB_HOST` at a reachable one or set the opt-in. `uninstall.sh` still never removes the
database server or Jen's database.
