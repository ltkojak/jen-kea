# Changelog

*Detailed per-series notes for the 3.x line live in [docs/release-history/](docs/release-history/).*

## [5.68.0-beta.18] - 2026-10-07

Beta channel. Stacked on 5.68.0-beta.17. **One definition, every use: the current-lease predicate in every query in the tree, one pool-size utility behind every capacity number, every threshold alert with a transition state that survives a restart, a config lock the installer honours, and retention that does not depend on a feature flag.** These come from the review of beta.17 (seven items, all confirmed) plus one finding of our own sweeps, and they share a cause that is named here so it stops: beta.10 (Q145) defined `ACTIVE_LEASE4` and applied it to "every current-lease query named above" - a list written from one grep of one module and pinned by a source test over three files - so the audit confirmed that three files used the definition, not that the rest of the repository did. The same shape produced a pool size computed four ways with two bugs each, a transition state that existed for two alerts and not the third, and a config lock that covered the process and not the installer. **A fix to a definition is a fix to every use**: from here a change to what something means carries the repository-wide grep of its uses as a deliverable and a source test over the whole tree, never a file list. Four bundled plugins ship new versions (offered under Settings → Plugins); nothing else needs a manual step beyond `sudo ./install.sh` or the in-app update.

**An expired lease still counted as active in twenty-eight query lines across twelve files of Jen and seven lines in four plugins.** Kea keeps a lease row at state 0 past its expiry until reclamation removes it, so `state = 0` alone calls an expired lease current. The definition now lives in one Flask-free module (`jen/services/leases_sql.py`: the two constants, an aliased form and the negation) and is used by every current-lease query: the default Leases view and its release and reservation-guard lookups, every per-subnet count (dashboard, Subnets, Reports, Users, the REST API summary, Prometheus' gauge), the delete-safety check, the snapshot that feeds history, high-water and the forecast, the daily summary, the alert lease map and the device scan (which stamped `last_seen` for an expired lease every cycle), DDNS' current rows and its expired-names set, the setup wizard, a login's client hostname, the Problems inbox's held-reservation query, and the plugin queries in DNS Sync 1.1.1 (an ended lease supplied a name that was pushed to Pi-hole or AdGuard), Network Discovery 1.3.1 (an expired lease classified a live host as known), Presence 1.2.3 (three queries, two with no expiry test at all) and IPAM 1.7.1 (already right, now through the one definition). Plugins reach the constants through `jen.plugin_api`. The guard is no longer a file list: `tests/test_active_lease.py` parses every Python file under `jen/` and `plugins/` and fails on a SQL string that spells `state = 0` / `state != 0` by hand - docstrings are prose, the literal parts of f-strings are scanned, and a stale allowlist entry fails too. The allowlist has exactly one entry: the Leases page's *delete expired/stale* housekeeping (`state != 0`), which removes rows Kea has already moved out of state 0 and deliberately does not delete a state-0 row from under Kea's own reclamation. A thirteen-surface test seeds one expired state-0 row beside one live row and asserts the expired one is on none of them.

**Pool size was the last pool's, and a CIDR pool was skipped.** The snapshot and the dashboard kept `pool_sizes[id] = ...` per pool (the last range won) and skipped a pool written as a CIDR; the API summed ranges but still skipped CIDR; and the utilisation alert counted the subnet's whole active count and compared it with each pool in turn - 100 leases over pools of 50 and 200 read as 200 % of one and 50 % of the other, and an address outside every pool (a reservation) counted as pool consumption. `jen/services/pools.py` is the one utility (parse a range or CIDR, merge the pools into a union, total them, test membership, count the active leases inside them with one `BETWEEN` per range) and three older parsers are gone. Capacity is the total of every pool; consumption is the active, unexpired leases inside the union; utilisation and exhaustion are judged per subnet over it. The snapshot's `pool_size` is what history, Health, Reports, Prometheus and the forecast read back, so all of them now say the same number; one test seeds a subnet with two ranges and a CIDR pool and asserts the snapshot, the forecast, Prometheus, the dashboard, the REST API and the alert all say 174. A limit worth knowing: the stored history keeps `active_leases` as the subnet's whole active count, so a history-based utilisation includes active leases that sit outside the pools; the live surfaces and the alert use the in-pool count. Rows written before this release carry the old size; the forecast reads the newest row and corrects itself at the next snapshot.

**Pool exhaustion repeated every cycle, and a restart forgot every alert.** `pool_exhaustion` had no state at all - every check while a subnet was low sent it again to every channel - and the state that did exist (`utilization_high`, `packet_health`) was a local set of the alert loop: a Jen restart, which is every upgrade, re-sent every alert whose condition was still true and never sent the recovery for one that had cleared while Jen was down. All three now keep their state in the settings table (`alert_state:<type>:<subnet or server>`), read on every pass. `pool_exhaustion` warns at the configured free count and recovers with hysteresis at that count plus a fifth of it (at least 2), with a new `pool_exhaustion_ok` type (tick it on a channel to hear recoveries; existing channels keep the types they had). Tests repeat the check while exhausted, walk the hysteresis, put two pools in one subnet, restart in the middle of a condition and clear one while Jen is down. The first check after upgrading sends once for conditions that are true at that moment, because nothing had been recorded before.

**`--configure` could lose a save, and dropped what it never asked.** The config lock covered Jen's threads; the installer is another process that runs an interactive wizard and rewrote `jen.config` with Jen running, so a Settings save made during it was overwritten by the installer's older copy - and because it wrote the file from the wizard's variables alone, everything Jen keeps there that the wizard never asks about (OIDC, extra Kea servers, `[kea6]`, the update channel) was dropped. Every writer now also takes an exclusive advisory lock on `jen.config.lock` for its whole read-modify-replace, `--configure` holds the same lock from before it reads anything until it has written, a save made meanwhile waits (up to 30 s, then says why), and the wizard's answers are merged INTO the live file at the last moment: a key it did not ask about keeps its live value, a key you changed in the wizard wins, and one you left as it was never undoes a newer save. A writer called from inside `AppConfig.mutate`'s callback now raises instead of writing to disk and being silently overwritten by the outer write (the previous test codified exactly that). Tests run a writer in this process and one in another at the same time and keep every write (and lose some with the locks removed), and real bash covers the installer end to end.

**IPv6 history kept growing when IPv6 was off, and was counted lease by lease.** The `lease6_history` purge sat inside the snapshot that runs only while IPv6 is on, so turning IPv6 off left months of rows past `history_retention_days` forever; it is part of the unconditional retention pass now, beside the IPv4 history's. The IPv6 snapshot read every lease of every subnet through the page reader (a MAC lookup per row) to count them in Python; it now asks two aggregate queries for the whole map and a test compares their counts with the readers' against the real tables.

CI caught four things in this release, none in the code under them: a bandit finding for one new SQL fragment, and three faults in my own new tests - a lease another test had left in the subnet, a by-name import the test's patch could not reach, and a settings row read on a connection that predated the write.

Upgrade: nothing beyond `sudo ./install.sh` or the in-app update. See [docs/upgrading.md](docs/upgrading.md).

## [5.68.0-beta.17] - 2026-10-07

Beta channel. Stacked on 5.68.0-beta.16. **The config writer takes a lock, the provider pool is sized for more than one page, `alert_log` and `lease6_history` get a lifecycle, the Problems sweep gets a Health row, and the live watch costs one tail per server.** These six come from sweeps run over the whole repository deliberately outside the classes the previous releases had audited (mutating GET routes, SQL built with interpolation, naive-versus-aware datetimes, `|tojson` in scripts, API-key scoping and background-job wrappers all came back clean): config-file concurrency, pool sizing, table growth and retention, and the cost of one feature per watcher. Nothing in this release needs a manual step: `sudo ./install.sh` or the in-app update, and no Kea host needs touching.

**Two saves at the same moment could lose one.** Every `AppConfig` writer reads `jen.config`, changes one thing and replaces the file, and Jen serves from one worker with several threads - so two Settings saves at once (two admins, or a save racing the setup wizard or Author Kea Config's `[subnets]` write) made the second read miss the first write, and one change silently vanished. One class-level re-entrant lock is now held from the read to the end of the reload in `write_value`, `write_values`, `write_subnets`, `write_subnets6` and `mutate`; readers take none, since the file is replaced whole. The test runs two threads writing different keys 200 times each and finds all 400 present - and the same run with the lock replaced by a no-op loses writes, so the green result is the lock's doing.

**The second page got "busy" cards.** Investigation and search providers (one per bundled plugin) run on a shared pool with a bound so the one-second budget is real. That pool had four workers and a ceiling of eight calls outstanding, and a page submits seven (one per bundled plugin): a second admin opening an Investigation page while the first's seven calls were in flight got one slot and six "unavailable (busy)" cards, because a call over the ceiling was turned away at the door. The workers now follow `[server] threads`, the ceiling is `max(16, 2 × threads × registered providers)`, and a call over it waits for a slot until its own page's deadline and is called busy only if the deadline passes while it waits. A provider that hangs still keeps its slot until it really ends. The test runs two pages of seven providers at once and gets fourteen answered cards.

**`alert_log` was the one history table nothing pruned.** Every delivery writes a row (and the Problems alert one per client and kind per day), and the Alert Log page, the dashboard, the Timeline and a client's alert status all read it. Rows older than `alert_log_retention_days` (a settings key, default 180; a value that is not a positive whole number is the default) are now removed by the same pass that prunes the lease history, and the Alert Log page says how long a row is kept. A Prometheus counter, `jen_alerts_sent_total`, is built from that table, and a counter that drops is read as a reset, so what the job removes is first counted into a stored total in the same transaction and the metric is the live rows plus that total: the exported number never goes down. The first pass after the upgrade removes whatever is older than 180 days.

**`lease6_history` had existed since v5.0 and nothing wrote it.** Migration 11 created it, the backup listed it as "Historical IPv6 lease count snapshots", and every install had it empty, so an IPv6 subnet had no history anywhere. With IPv6 on, the snapshot pass now writes one row per IPv6 subnet - active leases by type (addresses, temporary addresses, delegated prefixes) and reservations by type - through the same readers the pages use, and prunes with the IPv4 history's retention; with IPv6 off nothing in that path runs. Reports draws a chart per IPv6 subnet the caller may see (the same visibility rule as every other IPv6 surface), counts only, with one sentence saying an IPv6 subnet has no finite pool to project against: no pool-size line and no forecast, because inventing a utilisation for a /64 would be the wrong answer. The history starts at the first snapshot after the upgrade.

**A Problems sweep that could not read was a log line.** The Problems inbox is filled by a sweep that tails each SSH-configured server's Kea log every five minutes, and a server it could not read added a line to a summary that was logged and not displayed - so a blind inbox looked exactly like a quiet network. The sweep now records, per server, its last successful read, its last error and how many reads in a row have failed, and its own last run; a new Health Center row, **Problems inbox sweep**, turns red after six misses (thirty minutes) naming the server, the last read and the error, or when the sweep itself has stopped, and green on the next successful read. It reads those records, never SSH; with no SSH server it is skipped. The test injects a tail failure and watches the row go red on the sixth miss and green on the next success.

**The live watch cost the Kea host one tail per watcher.** Trace's live watch re-reads the log every three seconds for up to ten minutes, each poll an SSH round trip making the helper read a thousand lines; two admins watching one server doubled that, and an Investigation page's Explain tab read the same log again. One read per server and path is now kept for the three-second step and shared by every reader - a reader arriving mid-read waits for it rather than starting another, and a failed read is kept for the window too, so a hanging host is not asked again by every watcher - which makes the cost of the watch the same for one watcher or ten. The Problems sweep does not use it: it needs a current read every five minutes.

CI caught three faults, all in my own new tests and none in the code under them: an empty database fetch is a tuple where the test compared it to a list, and on the Reports page with IPv6 off the test then tripped twice over words a script comment on the same page also uses (`chart6-`, then `finite pool`), so it now asserts on the canvas id and on the visible sentence.

Upgrade: nothing beyond `sudo ./install.sh` or the in-app update. See [docs/upgrading.md](docs/upgrading.md).

## [5.68.0-beta.16] - 2026-10-07

Beta channel. Stacked on 5.68.0-beta.15. **Every participant keeps the promise: the root installer, Docker's bootstrap, the legacy authoring path, the certificate set and the old migrations now meet the private / atomic / all-or-nothing guarantees beta.15 made for the running app - and the sweeps that found them are CI tests, so the next beta cannot regress them.** Beta.15 fixed the writers the review named; this release re-ran the same questions over every other place that writes, copies, installs or migrates (who creates a secret and with what mode, who copies from a directory the service can write into, who replaces a file and what is left if the next step fails, which migration statement shares a guard with another) and fixed each hit. Press **Update helper** on every Kea host (Settings → Kea → SSH shows build 14 as available); no plugin changes; `sudo ./install.sh` or the in-app update does the rest.

**Root's rollback snapshot was root's only if nobody had planted something.** An upgrade copied `run.py` and the `jen/` package into a backup directory the service user owns, and a rollback copied them back into the application tree as root, which then runs `run.py`. A process running as the service could replace the snapshot between the two. The snapshots now live under `/opt/jen/.rollback` (root-owned, mode 0700, next to the root-owned release tree), are made with `cp -a --no-dereference`, and are refused on restore unless they are root-owned, not a symlink, contain no symlink, and resolve under that directory. Nothing root copies into the application directory ever comes from `/etc/jen` or `/var/lib/jen`: a source test (S9) refuses a `cp`/`install`/`mv` into the app tree whose source is one of those directories, and the planted-`run.py` test proves a replaced snapshot is not restored. The old service-owned `run.py.*.bak` and `jen.<n>.bak` copies are removed on the next upgrade (`jen.config.*.bak` stays).

**`jen.config` was written 0644 and tightened afterwards - by the installer, and by Docker's first start.** The installer wrote the config and its backup with a shell redirect and `chmod`ed them afterwards; `run.py` wrote the environment-derived config of a first Docker start with a plain `open()`. Both now go through the same discipline as the running app: a unique exclusive temp file created 0600 in the target's directory, written and synced, owner and mode applied on the open file (a failing `chown` aborts instead of carrying on), then renamed over the target - a symlink at the target is refused. For the installer that is `tools/private_write.py`, shipped in the tarball; for `run.py` it is `write_private_file`. A directory watcher under `umask 022` with a deliberately slow writer never sees a group or other bit on either file, and a symlink planted at the path is refused with the target untouched.

**Author Kea Config's own record could disagree with the servers, and its legacy path could run.** Beta.15 made it a change set but left Jen's own `[subnets]` list written after the change set returned, so a failure there left every server changed and the record not. The record is now written inside the change set by a `finalize` step whose failure puts every server's config back (the whole change reports as rolled back, naming `finalize-failed`). Every target must report helper build 13 or later before anything is checked: an older helper is named and nothing is touched, because the pre-5.11 `sudo python3` script cannot create a file private or put a failed write back. Every subnet name is validated before the first write. A brand-new config on a host that had none is removed again if a later step fails. The legacy script itself is kept for the fallbacks CLAUDE.md rule 9 requires, but is hardened (private unique temp file, backup with the original owner and mode, a new file `root:<group>` 0640) and a source test refuses any call to it from the authoring path.

**Helper build 14: one identity, ownership that cannot silently fail, TLS installed as a set.** The helper resolved "which account does Kea run as" twice: validation used the full lookup (`Group=`, supplementary groups, a numeric `User=`), but `install-tls` took `server.key`'s group from a simpler one (the unit's `User=`'s primary group), so a unit with `Group=kea-config` got a key its daemon could not read. The second resolver is deleted and `server.key` takes its group from the same `_unit_account`; an account that cannot be resolved is a named refusal, never a guess. A brand-new Kea config was created `root:root` 0644 and carries the database password; it is now `root:<Kea's group>` 0640 (or `root:root` 0600 for a daemon that runs as root). The swallowing `chown` wrapper is gone and `_finish_private` aborts before the rename when `fchown` fails, where it used to ignore the failure and install a file owned by the wrong account. `install-tls` writes `server.key`, `server.crt` and `ca.crt` as a set: staged privately, the live ones read into memory (not moved), replaced in order, and put back byte for byte if any step fails. `op_update` rolls back when the directory fsync fails with anything other than "this filesystem cannot do that". The ops list and the sudoers line are unchanged; the installed build is pinned (`tests/kea_helper_build.json`).

**The certificate set on the Jen host was replaced one file at a time.** `write_atomically` moved the live file to `<name>.prev` before the replacement existed (a failure right after left no live file at all); the HTTPS upload wrote the certificate, key, CA bundle and combined chain one after another; and the Kea CA's rotation promoted its four staged files one by one after the remote servers had already moved to the new CA, so a failure at any step could leave a new key beside an old certificate (gunicorn refuses to start on that) or a half-rotated CA. `certs.commit_file_set` is now the one place a set is installed and the only place a `.prev` is made: stage every member, snapshot every live member into memory and write `.prev` as a copy, replace each in turn, and on any failure put every member already replaced back and remove every temp. The HTTPS upload, `commit_rotation`, `ensure_ca` and `issue_client_cert` use it, and the failure injection breaks the install before and after every member and asserts the live set equals the original.

**Interrupted migrations finish on the next start.** Migrations 3 and 4 tested only their first column and then added all of them, so a crash after the first `ALTER` (each commits on its own) left the others missing for good, and migration 4's width fix was an `elif` of that test; each statement now reads its own end state. Migration 6 detects a legacy install by the role column lacking `superadmin` - the very thing its `ALTER` changes - so a crash between the `ALTER` and the `UPDATE` left a schema that read "not a legacy install" and the legacy administrators were never raised to superadmin, while doing it unconditionally would raise every mid-tier admin on every start. The decision is now recorded in `settings` (`legacy_admin_promotion_pending`) before the `ALTER`, the `UPDATE` runs whenever that marker exists, and the marker is removed after it. Migrations 8, 22 and 24 already guarded each statement and are now covered by interrupt-and-rerun tests too (the review's claim that 8 and 22 did not was checked against the code and was wrong); migration 6's whole crash matrix runs against a stand-in at every statement. The migrations module's header states both rules, and the only edit a released migration may take is a tighter guard.

**The audits are tests now.** `tests/test_invariant_sweeps.py` holds the whole-repo sweeps as source guards: S1 no secret is written by a plain `open`, redirect or `cp` (with a reviewed allowlist that has to say why), S2 a `.prev` is made only by `commit_file_set`, S3 every migration statement has its own guard, S4 the helper has one identity resolver and no swallowed `chown`/`replace`/`fsync`, S5 the legacy config script is never reached from authoring, S9 root never copies into the app tree from the config or content directories. Each was written first as a strict expected failure, so it was red against the tree as it stood and went green with the commit that fixed it (against the tree as it stood 14 of the 16 failed; S1 and S9 went green with the installer commit, S5 with the authoring commit, S2 and S4 with the helper commit, and S3 with the migrations commit).

CI caught three things in this release, all in tests or lint and none in the code under them: a shellcheck warning for an unused local in the new rollback code; an older test that still asserted the installer's chown line instead of the owner now applied by `_private_write`; and a test of mine that made a host unreachable for every helper call, which the new helper-build check now (correctly) reports before the config is read.

Upgrade: nothing beyond `sudo ./install.sh` or the in-app update, and **Update helper** on every Kea host. See [docs/upgrading.md](docs/upgrading.md).

## [5.68.0-beta.15] - 2026-10-07

Beta channel. Stacked on 5.68.0-beta.14. **A migration that proves its own end state, every secret written private from its first byte, Author Kea Config that writes every
server or none, stored-object writes that judge and write in one step, and a switch-move alert scoped by the switches it names.** These come from re-running pattern sweeps over
the whole tree (every alert and event and the subnet it carries, every migration for partial-DDL idempotency, every config push that bypasses the change set, every temp file and
lock in the Kea helper, every upsert that follows an authorization check, every place a secret is written) rather than re-reading the last release's lines, plus the findings of
the review of beta.14. Press **Update helper** on every Kea host (Settings → Kea → SSH shows build 13 as available); three bundled plugins ship new versions; the service unit
gains `UMask=0077` the next time it is rendered by `sudo ./install.sh` or the in-app update.

**An interrupted migration recorded itself as done.** Migration 33 (beta.14) adds a column and then swaps a unique key: two statements that each commit on their own. It returned as soon
as the COLUMN existed, so a failure between them left the new column and the old four-column key, and the next start saw the column, returned, and recorded 33 as applied - the
cross-subnet mix-up it exists to remove survived an interrupted upgrade. The guard is now the whole end state read from `information_schema` (the column with its type and default AND
the key with exactly its five columns, in order, as a unique key); anything short of that runs only the missing steps, clearing the inbox again (it refills from the logs). The
migrations module's header now states the rule for every migration after it, and the tests interrupt the migration between its statements.

**Secrets were created world-readable and tightened afterwards.** `jen.config` (every database password and API credential), the SSL private key and the encryption keys were written
with `open(path, "w")` - the process umask, 0644 under systemd's default - and `chmod`ed once the secret was already on disk; only the directory's own mode kept that window closed. One
routine (`jen/services/private_files.py`) now writes them: a unique exclusive temp file created 0600 in the same directory, written and synced, given its final mode on the open file, and
renamed into place (the Flask secret key and the SSL key are 0600 until complete and only then the 0640 they are meant to be). `run.py` sets `umask 0077` first thing and the unit
template carries `UMask=0077`, so anything else the service creates is private to it. The root self-updater and the plugin installer are separate units and are not given it. A test
runs each real writer 300 times under a directory watcher that stats every entry in a tight loop and never sees a group or other bit before a file is complete, and a source test
refuses a new write-mode `open()` in `jen/` that nobody reviewed.

**Author Kea Config wrote server by server.** It looped over your servers calling `apply_config` for each, with no check of the others first, no expected file (so *overwrite* replaced
whatever was on a host at that moment, whatever the preview had shown), no rollback, and Jen's own `[subnets]` written when ANY server succeeded. It is now a change set like every other
multi-server edit: every server's config is built and checked before anything is written; each write is guarded with the file Preview & Validate showed (a server with no file is guarded
as "must not exist"); a later failure puts the earlier servers back - a file Jen created is removed again (a new helper operation, `remove-config`), one it replaced is restored; a rollback
that cannot finish is a banner on the Servers page; and Jen's subnet record is written only when every server succeeded. *Overwrite* now means "replace the file I previewed", and an
existing file that was not previewed is not replaced.

**Wake & Actions and Presence judged on one connection and wrote on another.** Add favourite, track, move and untrack read the row, judged its owner subnet, closed the connection, and
wrote with `INSERT ... ON DUPLICATE KEY UPDATE`, or an `UPDATE`/`DELETE` that named only the MAC: an item another admin created or moved in the moment between was rewritten. Each now reads the
row `FOR UPDATE` on the connection it writes with, judges it, and writes with the judged owner as a condition and the count checked; a new item is a plain insert, and a lost race (duplicate
key, or a deadlock between two inserts of one MAC) re-judges the row that won. Wake & Actions 1.1.4, Presence 1.2.2. Presence's online/offline Timeline event also carries the tracking's
owner subnet now (it carried none, so its owner never saw it).

**A switch move was announced in the client's subnet.** The alert and Timeline entry name two switches and two ports, but were sent with the subnet of the client's lease, so switches in
subnets B and C reached a channel and a Timeline scoped to A. Switch Port Locator 1.1.4 sends a move with the subnet BOTH switches are in; when they are in different subnets, or either is
addressed by a hostname or lies in no Kea subnet, only unrestricted channels get the alert and only unrestricted viewers see the entry.

**The Kea helper (build 13) wrote its own files the same way, and its lock was optional.** `apply-config` wrote the whole candidate config - database passwords included - to a fixed-name temp
file with the default permissions and copied the destination's mode on afterwards; `install-tls` wrote the private key 0644 and tightened it after it was on disk; the backup copy was made the
same way; and the lock was taken only when a sha was supplied, so a config check never waited for an apply of the same file and two helper runs shared a temp name. Every file is now created
by one routine (unique name, exclusive, 0600 from the first byte, final owner and mode applied to the open file, then renamed); the copy of your config that `kea-dhcpX -t` reads is root-owned
and group-readable by Kea's account but not writable by it; the lock is taken for every check, apply and TLS install; and a Kea binary owned by its service account must have **execute
permission for that account** (the check asked "may anyone execute it?", which is true for a file with only the other-execute bit and then failed to start as that account). The new
`remove-config` operation deletes a config only if it still is exactly the file Jen wrote. No sudoers change.

## [5.68.0-beta.14] - 2026-10-07

Beta channel. Stacked on 5.68.0-beta.13. **A Problems row that keeps its own subnet, existence checks that fail closed in two plugins, a Kea config check that
runs as the account the unit names, a switch page that says the same thing with and without what you may not see, and a damaged logging marker reported the
minute it is seen.** Eight findings from the review of beta.13, each confirmed against the code. Migration 33 runs on the first start and **empties the Problems
inbox** (it refills from the logs within one sweep); the helper change reaches a Kea host when you press **Update helper**; three bundled plugins ship new versions.

**A Problems row's subnet was reassigned by the newest event.** Beta.13 made the alert decision per (kind, client, subnet) but left the stored row keyed by
(server, kind, client, address), so a client's NAKs that name no address in subnet B, B, and A were one row whose subnet the newest event rewrote while its count,
times and alert state stayed: B's history, and a qualification B had earned and failed to deliver, ended up on an A row and was retried there. Migration 33 adds a
`scope_key` (the subnet id, or -1 for "no attributable subnet", because a NULL cannot be part of a unique key) to the row's identity; the sweep groups by it and no
upsert assigns the subnet on a duplicate, so the same client in two subnets is two rows with their own count, first and last time, alert state and resolution. The
migration deletes the existing rows (they may already be mixed) and each server's log watermark, and keeps the clock offsets; the next sweep records what is still
in the log tail, as the first read of a server always has, without alerting.

**A delivered alert left its qualification behind.** A successful delivery set `alerted_at` but left `qualified_at` and `qualified_count`, the two fields a
retry reads, for the 24-hour expiry to clear. It now clears them on that subnet's rows; a failed delivery keeps them for the retry.

**A failing lookup was read as "no such record" in Wake & Actions and Presence.** Both plugins start a write by asking whether the MAC already has a favourite or
a tracked row, and the answer decides whose it is. A SELECT that raised was treated as "not found", so with the database failing for that one statement the route
carried on as if the MAC were new, judged it on the client's current subnet, and the upsert that followed could rewrite a row stored in a subnet the caller cannot
see. The lookup now has three outcomes (found, not found, failed): on a failure the route says *Could not check the existing record — nothing was changed*, logs,
writes nothing and audits nothing. Wake & Actions 1.1.3 (add favourite) and Presence 1.2.1 (track, track from a row, untrack, move subnet) carry it; the other
bundled plugins were checked and have no such lookup. `plugins/README.md` and ARCHITECTURE section 2 state the rule, and both plugins' own descriptions of who may
do what now say the stored-subnet contract (Presence's still said "the subnet its MAC is in now").

**Switch Port Locator told a scoped caller that a newer position was hidden.** The page, the card and the API said "was last seen on" instead of "is on" only when
the newest stored position was on a switch the caller may not see, which is information about a row they cannot see. Switch Port Locator 1.1.3 builds a scoped
caller's output from the positions they may see alone, always says "Last seen on ... at <time>" to them, and computes no "newer hidden" state at all; an
unrestricted caller still gets "On ..." when the newest position is theirs. A test shows the page, the card and the API identical with and without the hidden
newer position.

**The config check ran as root for a root-owned Kea binary.** Helper build 11 looked at the unit's account only after it had decided the binary was not
`root:root`, so a binary owned by root under a unit that says `User=_kea` was checked as root: the check could pass on a certificate, a key or a directory the
daemon, running as `_kea`, cannot read, and Jen would push a config that then failed to start. Build 12 resolves the unit's identity first (`User=` by name or by
numeric uid, `Group=`, `SupplementaryGroups=`), verifies the binary second (root:root and executable by that account, or owned by exactly it), and runs the check as
the unit's account whenever the unit names one; root only when it names none. A `User=` or `Group=` the host has no account for is refused with the reason and is
never run as root in its place. The supplementary groups are now the account's own `/etc/group` memberships plus `SupplementaryGroups=`, which is what systemd gives
the daemon. kea-compat records who the helper would run the check as beside who the daemon runs as on each of ISC's images. The by-hand install one-liner
embeds build 12. No sudoers change.

**A damaged marker was not reported until it was due.** A marker that lost its `restore` object was refused when the restore ran, which is at its deadline: with an
hour to go the full scan indexed it as healthy and the Health row stayed green. The question "can the way back be trusted" is now asked separately from "is it
due", and by everything that reads a marker: the restore step, the turn-on, and every full scan. A damaged marker is indexed (once, with an audit row), the Health
row goes red on that scan, the log level is left exactly as it is, and turning logging on over it is refused. A marker that is not even an object is treated the
same. **The guidance no longer points at the damaged object**: it sends you to Servers, Config history, to the revision recorded just before the logging went on
(linked on the Servers page while the server is still in Jen), then to put the logger back from that config or a backup, delete the `jen-investigation` entry,
check the file, reload or restart Kea, and press **Forget**. Forget now works for such an entry, after Jen reads the config and finds no marker in it.

## [5.68.0-beta.13] - 2026-10-06

Beta channel. Stacked on 5.68.0-beta.12. **Problems alerts that respect the subnet boundary and survive log rotation, a Kea config check that runs with the
daemon's real credentials on a private copy, and a restore marker that fails closed.** Five defects from an outside review of beta.11, each confirmed
against the code. Migration 32 runs on the first start; the helper change reaches a Kea host when you press **Update helper**.

**A Problems alert counted across a subnet boundary the page keeps.** The Problems inbox shows a user only the rows in subnets they may see, but the
alert threshold was counted per client across every subnet and then sent to a channel scoped to one of them: two NAKs in a subnet a channel cannot see plus
one in its own read as the three that fire, and the message said "3" where the page would have shown that channel's users one. The count and the alert
decision are now kept per (kind, client, subnet), "no attributable subnet" a key of its own that only unrestricted channels receive, and a delivery is
recorded on that subnet's rows alone. The page still groups by client.

**A failed alert stopped retrying when the lines rotated out.** A delivery that failed was retried every half hour, but each retry first re-checked the
threshold against the current 1000-line tail of the Kea log. On a busy server the lines that qualified the alert are gone from that tail within the 30-minute
bound, so an alert the sweep had decided to send was never sent, although its row said it had failed. Migration 32 adds `qualified_at` and `qualified_count`
to `client_problems`: the sweep records them when a client's trouble in a subnet first crosses the threshold, and the retry reads those, not the tail, until
the alert is delivered, the row is resolved, or the qualification is a day old (then it is cleared and must be earned again). The default message now says
the count and when it qualified ("4 in the last hour (as of 2026-10-06 14:05 UTC)").

**The helper's validation copy of your Kea config was mode 0644.** To check a change before it is written, the helper writes the whole config, database
credentials included, beside the real file and runs `kea-dhcpX -t` on it. It was written mode `0644` so the daemon's account could read it, which made a different
local account's access depend on `/etc/kea`'s own mode on whichever package was installed. Helper build 11 creates it `0600` and owned by the account that
runs the check (the daemon's own, or root for a `root:root` binary), whatever the umask, and removes it on every exit path as before. kea-compat now records
`/etc/kea`'s owner and mode on each of ISC's images, so the window that closed is on record.

**The check ran with fewer groups than the daemon.** The helper took the daemon account's primary group and no supplementary groups, so a unit with `Group=` or
`SupplementaryGroups=` (TLS material readable through a group) started fine under systemd and failed Jen's check. It now reads `User`, `Group` and
`SupplementaryGroups` from the unit in one `systemctl show` and runs the check with exactly that identity; a group the unit names that the host does not have
is refused with the reason on the Servers page instead of being guessed. The by-hand install one-liner's embedded build number moves with it (10 to 11).

**A damaged restore marker deleted logger settings.** Investigation logging records what to put back in a marker on the `kea-dhcp4` logger. A marker that
lost its `restore` object (a hand edit, a partial write) was read as an empty one, so every key looked "absent" and the logger's severity and debuglevel were
removed together with the marker. The marker is now validated before anything is changed: `restore` must be `{"created": true}` or carry both `severity` and
`debuglevel`, each `"absent"` or a real value. Anything else leaves the logger and the marker exactly as they are; the sweep records it every minute, the
Health row **DEBUG logging left on** goes red with *the restore marker on kea-a is unreadable — restore by hand* and the steps, *Turn it off now* says
the same, and turning logging on again over a damaged marker is refused too. Once the marker is repaired, or the logger set back by hand, the next sweep
finishes the job.

## [5.68.0-beta.12] - 2026-10-06

Beta channel. Stacked on 5.68.0-beta.11. **The rule beta.11 stated for the Investigation cards, applied to every surface of the three plugins.**
An outside review of beta.11 found that Wake & Actions, Switch Port Locator and Presence still judged stored data by where the client is now
everywhere except the card. There is no migration and nothing to do on Jen; the three plugin updates are offered under Settings → Plugins.

**Stored object versus live act.** beta.11 wrote down that a stored object (a favourite, a tracked device, a port a MAC was seen on) belongs
to the subnet it was stored in, and that where the client is now never widens access. It applied that to the three Investigation cards. The
plugins' own pages, their add, delete and move routes, their search providers and their JSON APIs kept the earlier habit, taken from the
wake: judge the client's current subnet, with the stored one only as a fallback. A wake really is judged that way, because a wake acts on a
live host and goes where the host is. Everything else is a stored object and is not. The plugins documentation and ARCHITECTURE §2 now
draw the line in those words, and add the second half of it: a live act never borrows what a hidden stored object holds.

**Wake & Actions 1.1.2.** The favourites list, *Add favourite* over an existing MAC, delete and the label were judged on the MAC's current
subnet, so a favourite saved in subnet B (its label, whether a SecureOn password is set) listed for a caller scoped to A once the client
moved to A, and that caller could rewrite its label, address and SecureOn password or delete it. All of them judge on the favourite's own
stored subnet now; a favourite with no subnet is for an unrestricted caller only, and the list says where the host is now only to a caller
who may see that subnet. The wake itself still goes where the host is now, and needs that subnet, but it no longer reads the stored favourite
first: the wake from a row and the wake API used the SecureOn password of a favourite stored in B for a caller scoped to A waking a host in A,
a secret crossing a subnet boundary. A favourite out of the caller's scope (the session's, or the API key's) now contributes nothing to a wake,
neither its password nor its stored subnet as a fallback, so the wake goes ahead without it and a NIC that wants the password ignores the
packet: the honest outcome, with no hint that a hidden favourite exists. A test records what reaches the packet builder.

**Switch Port Locator 1.1.2.** A position (switch, port, alias, VLAN, time) belongs to its switch's subnet. The page and the JSON API judged
the client's current subnet and then showed the client's newest position on any switch, so a caller scoped to A looking up a client now in A
saw its newest position on a switch in B; the search provider reported the client's subnet as the result's `subnet_id`, so Jen's own
defence-in-depth filter passed a result whose text named a switch in B. The page, the API, the search provider and the card now go through
the one judgement, and each returns the newest position the caller may see. A client whose positions are all hidden reads as not located, the
same answer as a MAC no switch has reported, for a scoped API key too (which used to be refused with 403 keyed on the MAC's own subnet, telling
it which MACs exist elsewhere). When the newest position is hidden the page says *was last seen on* and does not say why.

**Presence 1.2.0.** The plugin held two contradictory ideas about the subnet of a tracked device. The page, untrack and the card judged on
`pr_tracked.subnet_id` as a stored subnet, while every lease event rewrote it to the client's current subnet, so a device tracked in B was
handed to A by its next lease and its label and state showed to a caller scoped to A. The column now has one meaning, the owner subnet of the
tracking: written when the device is tracked, and changed only by an explicit *Move* by an admin who can see both subnets, which is audited.
A lease event updates state and nothing else. Where the device is now is derived when the page is read and shown only to a caller who may see
that subnet. This is a changed contract (a minor release of the plugin, no schema change): a device that had followed a client under the
earlier release keeps the subnet it has, and one that should belong elsewhere is moved by hand.

**One fixture for the three.** The authorization matrix gained a shared moved-client fixture and a module per plugin: a client in A whose
favourite (with a SecureOn password), tracked row and newest switch position are stored in B, and a client in B with everything stored in A,
driven through the page, add, delete, move, search and API for a caller scoped to A, one scoped to B, one with no restriction and a scoped
key. The few existing rows that modelled a favourite stored in A for a host in B with a leak marker as its MAC now use a client that is not a
marker, because what is stored in A is the A caller's own data.

## [5.68.0-beta.11] - 2026-10-06

Beta channel. Stacked on 5.68.0-beta.10. **The Investigation page's plugin cards, Changes tab and DNS tab, made to match what they
say.** Five defects found by an outside review of beta.7 and confirmed against the code, with three plugin releases to go with them.
There is no migration and nothing to do on Jen; the plugin updates are offered under Settings → Plugins.

**Three plugin cards judged stored data by where the client is now.** Wake & Actions, Presence and Switch Port Locator each add a card
about the client to the Overview. The first two decided whether a caller may see the card from the subnet the client is in now and
only fell back to the subnet stored on the row, which is the right question for a wake (an act on a live host, sent where the host is)
and the wrong one for showing what was saved: a favourite or a tracked device saved in subnet B appeared to a caller scoped to subnet A
the moment the client's lease moved to A. Switch Port Locator judged the client the same way and then printed its last five stored
positions without asking where each switch was. The rule, now written in `plugins/README.md` and ARCHITECTURE §2, is the one the core
already follows for a reservation or a device: a stored object belongs to the subnet it was stored in (a switch's subnet is the one
its management address is in), and where the client is now never widens that. Wake & Actions 1.1.1 and Presence 1.1.1 judge the row by
its own stored subnet and show where the client is now (*Now in*) only to a caller who may see that subnet, because naming a subnet is
access to it; a row with no subnet is for an unrestricted caller only. Switch Port Locator 1.1.1 filters each position by its switch's
subnet before the card is built, so a client whose positions are all on switches the caller cannot see gets no card, a mix shows only
the visible positions, and when the newest position is hidden the card says *Last seen on …* with its time rather than claiming the
client is there now or has moved. Each plugin's harness carries the client that moved from B to A, and Jen's authorization matrix
drives all three through a real `/client` request.

**The one-second provider budget was a log line.** Investigation and search providers ran in the request thread and the elapsed time was
compared with the budget afterwards, so a provider that hung held the web worker for as long as it liked. They now run on one shared pool
of four threads, each inside a copy of the caller's request (the same user the page loaded), and the page waits at most one second for
the group: several slow providers cost one second, not one each. One that has not answered shows *unavailable (over 1 s)* and the page
goes on. A running thread cannot be stopped, so such a call keeps its slot until it really ends, is logged once and is counted; at most
eight calls are outstanding, and when they are all taken a provider is not started and reads *unavailable (busy)* instead of queueing
behind the ones that hung.

**The Changes tab left out what changes a client's answer most often.** It compared a revision over the client's subnet, shared network,
pools, classes and reservation, on the reasoning that a global setting is not this client's. It is every client's: the global
options, the valid lifetime and the renew and rebind timers, the host-reservation identifiers and the reservation modes, the client-id
handling. They are one more component, *global DHCP settings*, and only keys that decide what a client is given are in it; a change
to loggers, the control socket, hooks, interfaces or the lease database is not client behaviour and does not appear.

**The DNS tab looked at one record.** It was built from the first reservation and the newest lease, so a client with a good first record
and a wrong second one read as fine. Every v4 reservation and lease the caller may see is now a row (the same name and address from a
reservation and a lease is one row), and with IPv6 on so is each v6 reservation address and lease, checked as an AAAA record. The
reconciler gained the record type to do it honestly: the system resolver answers a name with its A and AAAA records together, so a
dual-stack host used to read as *multiple-a* against either address; a row is now judged only on the addresses of its own family, and a
name that has records but none of the row's type is *missing-forward*. The first twenty records are checked and the tab says when there
are more.

**One label named two things.** The freshness line under the Overview's facts printed *Config* before the device timestamp and *Config*
again before the config's SHA. The device fetch is now *Device*; the SHA keeps *Config*.

## [5.68.0-beta.10] - 2026-10-06

Beta channel. Stacked on 5.68.0-beta.9. **Explain evidence that is current, coherent and byte-exact.** Six defects in how the
Investigation page and Explain decide what is true about a client, found by an outside review of beta.7 and confirmed against the
code. There is no migration and nothing to do on upgrade.

**"Active" meant three different things.** One query asked for a lease that is state 0 and not past its expiry; four asked for state 0
alone. Kea keeps a state-0 row past its `expire` until reclamation removes it, so an expired row was "the current lease": it decided who
holds an address, which MAC a hostname resolves to, what the Investigation page called the client's lease, what Explain read the client
id and hostname from, and the IPv6 list counted it as an active lease. There is now one definition, state 0 and an expiry still in the
future, for the client's lease by MAC or by address, the holder of an address, the owner of a hostname, the pool-occupancy and
reserved-address-holder lookups Explain makes, and its IPv6 twin; the historical views (the Leases page with *show expired*) keep
every row. Each of those consequences has a test that seeds an expired state-0 row beside an active one, and a source test refuses a
current-lease query that spells the predicate by hand. (Test fixtures that seeded IPv6 leases with a hard-coded 2026-08 expiry
now use a future one: that date is past.)

**Explain's log inputs were stitched from different exchanges.** The newest client id, the newest class list and the newest packet dump
were each taken on their own, so one "observation" could mix a DISCOVER's classes, an old REQUEST's options and a later client id.
Kea tags every line with the client's transaction id, which was not used. The log is now grouped by MAC and transaction id (a
transaction id is the client's own and repeats, so lines further than a minute apart are a different exchange), the newest exchange
that has a class list or a packet dump is used on its own, and the Inputs card says which one (*the one at 15:10:39, transaction
0x20006, on kea-b*). A class list logged before the live config's newest revision is labelled *observed before the config changed*;
Jen says this only when it has measured the Kea host's clock, because it is a comparison across two clocks.

**Evidence always came from the first server.** `KEA_SERVERS[0]` can be a standby, unreachable or without the helper, while the log
that saw the client is on its peer. Jen now reads the HA-active server's log first, then the rest in order, until one holds an exchange
for the client, skipping a server it cannot read, and names the server that supplied it.

**Option 77 had three meanings, and a binary circuit id was compared as text.** The rule builder wrote `option[77].hex == '<text>'`,
Explain evaluated that accessor against the typed text, and the compatibility test that real Kea matched uses the length-prefixed
wire form (`0x08…`). A client sends its user class either as the bare string (dhclient's `send user-class`) or length-prefixed (RFC 3004,
Windows) and the choice is the client's, so there is no one right literal, only the bytes Kea received. This was measured first, on real
Kea 3.0.3, 3.2.0 and 3.3.1 (identical): a length-prefixed client is dumped as `08:6a:65:6e:2d:75:73:65:72` and matches
`option[77].hex == 0x086a656e2d75736572` and `substring(option[77].hex,1,8) == 'jen-user'`, and does not match the string or
`substring(…,0,8)`; a raw client is dumped as `6a:65:…:72 'jen-user'` (hex, then the printable text) and matches the string, its bare hex
and `substring(…,0,8)`, and none of the length-prefixed forms; a circuit id of `DE AD BE EF` matches `relay4[1].hex == 0xdeadbeef` and
no text. Explain now carries the display text and the bytes apart (`user_class` / `user_class_bytes`, `circuit_id` / `circuit_id_hex`),
takes the bytes from the packet dump (or the lease's extended info) and compares those. With only the text known it judges a test under
both client forms and calls it decided only when they agree, and undecided, with *supply user class as sent (option 77 bytes)*. The
rule builder offers two user-class fields, plain text (what it always wrote) and length-prefixed, whose *starts with* skips the length
byte; the grammar Explain reads accepts a non-zero `substring` start. The compatibility test boots one daemon with a class per spelling,
sends a length-prefixed, a raw and a binary-circuit client, and requires the builder, real Kea and Explain to agree about every class.
A side effect of the measurement: a raw client's option 77 row was unreadable before (the text after the hex defeated the parser) and
showed no user class at all.

**Standalone Explain used the lease it had just filtered out.** The route built the lease the caller may see for the inputs and then let
the unfiltered one choose the subnet, be refused, and still reach the engine. The filtered lease is now the only lease the route knows:
a scoped user whose client has a current lease in a hidden subnet and a reservation in a visible one is explained in the visible subnet from
the reservation, and nothing of the hidden lease is on the page.

## [5.68.0-beta.9] - 2026-10-05

Beta channel. Stacked on 5.68.0-beta.8. **Investigation logging that cannot forget, and a Problems inbox that attributes, times
and alerts truthfully.** Six defects in code that shipped earlier this round (investigation logging in beta.3, the Problems inbox
in beta.5), found by an outside review of beta.7 and confirmed against the code. This release adds migration 31 (one nullable
column, applied automatically).

**A restore the daemon never took was forgotten the next minute.** Putting a Kea log level back is two steps that can each fail on
their own: the config file, and the running daemon, which has to re-read it. When the reload was refused and the restart then failed,
the file was already clean, so the next minute's change set found no marker, answered "nothing to change", and that was read as "done":
the entry was dropped and the Health row went green while Kea was still writing a packet dump for every client. The enable side
mirrored it: the file was written with the marker, the daemon never took it, and no entry was saved, so a restart in between turned
DEBUG 55 on with nothing indexed. The index entry now says, separately, whether the file is back and whether the daemon has taken it,
and what is still owed; it is dropped only when both are true. A "nothing" change set with a daemon step still owed runs the step,
and a half-finished restore is retried every minute even before its time is up. Turning logging on saves the entry as soon as the file
is written and before the daemon is asked, and when the daemon does not take it Jen puts the file straight back; if that fails too the
entry stays and the sweep finishes it. The Health row names the server and says the file is restored but Kea is still at DEBUG.

**A server removed from Jen took its marker with it.** The sweep dropped any entry whose server was no longer in Jen, as "nothing
for Jen to restore", while the remote config kept DEBUG 55 and the marker for good. Now the settings forms refuse to remove a Kea server,
or blank its SSH host or API URL, while it has an entry, until logging has been turned off. If a server vanishes some different way (a hand
edit of the config file), its entry is kept and marked removed with its name, SSH host and config path; the Health row fails with
the by-hand restore, the Servers page shows the same with an *I restored it by hand* button, and an adopted marker or a refused
removal each write an audit row.

**A problem was scoped by where the client is now.** A NAK at Kea's default level names no address, so the sweep placed it by the
client's current subnet; a client refused in one subnet and since moved to another showed that event to the second subnet's users.
A row's subnet is now what the event itself says: its address's subnet, else the subnet Kea selected for that very transaction (a
DEBUG line), else none, and a row with none is for users who may see every subnet. The alert had the same hole from the other side: an
alert with no subnet went to every channel whatever its subnet scope. The alert type is now marked as being about one client, and
for such an alert a channel with a scope does not receive one that has no subnet (a channel with no scope still hears everything).

**A DNS-update failure was blamed on whoever held the address last.** The map from address to client was built over the whole tail
before the failures were read, so the newest allocation won, even when it came after the failure. The tail is now walked in order and
a failure goes to the allocation nearest before it, preferring the same transaction when the line names one. The kea-compat probe now
records what a real failure line carries on 3.0, 3.2 and 3.3.

**Old events were stamped with the sweep's clock, and the alert window with the newest line.** Rows now carry their events' own
times. Kea writes its log in its host's local time, so the sweep measures the host's offset from UTC against the lease database (the
newest allocation lines of the tail against the lease rows' expiry, to the nearest quarter hour), remembers it per server, assumes UTC for a
server that has shown it nothing, and the Problems page says which when you hover *Last seen*. The alert window is judged against now,
and a server's first read sets its watermark and records what it finds without alerting: three NAKs from six hours ago, still inside
the last thousand lines, are history and not an alert.

**A failed alert was marked sent for a day.** The sweep discarded the sender's per-channel answers and set `alerted_at` whatever
happened. Now `alerted_at` is set only when a channel took the alert, a new `alert_attempted_at` records every try, and a failing
delivery is tried again after half an hour while the client's trouble is still in the window. The sweep's log line counts attempted,
delivered and failed.

**What an operator must do.** Nothing. A scoped user may see fewer Problems rows than before (a NAK that names no address is for users
who may see every subnet), and a channel with a subnet scope no longer receives a Problems alert for a client Jen could not place.

## [5.68.0-beta.8] - 2026-10-05

Beta channel. Stacked on 5.68.0-beta.7. **One rule for what a subnet-scoped account may see of IPv6, and every IPv6
page on it.** This changes what some accounts see: a scoped account that could reach IPv6 data through a hole now
gets "not found" or a shorter list, and an IPv6 subnet with no pairing is now invisible to it.

**What was wrong.** A user's scope is a list of IPv4 subnets, and an IPv6 subnet has an id space of its own, so the
only honest way to decide whether an account may see an IPv6 subnet is through the IPv4 subnet it is paired with (the
third field of its `[subnets6]` line). The Leases, Devices and Reservations IPv6 views each carried a private copy of
that rule, and they used it in the wrong place: it judged an explicit `?subnet=` and, when the answer was no, fell
back to the "all" view, which read every IPv6 subnet and filtered nothing. Typing an IPv6 subnet id the account could
not see therefore returned a list of every IPv6 lease, device or reservation. The paths that carried no copy at all were
worse: deleting an IPv6 reservation checked only that the subnet existed, the three IPv6 subnet-edit routes checked
nothing about the account, the add-reservation form compared IPv6 subnet ids with the account's IPv4 list, the
Dashboard's "Active (v6)", "Reserved (v6)" and "+ N IPv6" totals were summed over every IPv6 subnet, and the Subnets page
and the global search's subnet names were built from the whole map. All of it predates this round; none of it needed an
unusual setup, only a scoped account and an IPv6 subnet it should not see.

**The fix.** The policy is written once, in `jen/services/access.py`: an unrestricted account sees every IPv6 subnet; a
paired IPv6 subnet is visible exactly when its IPv4 subnet is in the account's list; an unpaired IPv6 subnet is visible
to unrestricted accounts only; a subnet that is not in Jen's map is visible to no one. `subnet6_visible()` is the pure
form for the services that stay free of the web framework, `can_access_subnet6()` and `accessible_subnet6_map()` are
the session forms (the second is the only IPv6 map a template or a loop is now given), and `assert_subnet6_access()`
answers 404 for a hidden subnet and for one that does not exist alike, so an id cannot be probed. A forbidden explicit
`?subnet=` is a 404 on all three lists. The "all" view is filtered after the read. A device that holds leases in two
IPv6 subnets is grouped from the visible leases only, so a hidden subnet's address cannot ride along inside a visible
row. The add form offers only visible subnets and its POST refuses a hidden one before anything is written; delete and
the three edit routes ask first. The Dashboard totals and cards, the Subnets page, global search, the Investigation
page and its timeline use the same functions, the Dashboard's IPv6 cards carry `paired_v4_id` for nesting only, and
the private copies are gone. `can_access_subnet6` is re-exported from `jen.plugin_api` (no bundled plugin looks at an
IPv6 subnet today, so nothing calls it yet).

**How it is held.** `tests/test_ipv6_access.py` runs one topology against a scoped viewer, a scoped admin, an unrestricted
admin and a superadmin: an IPv6 subnet whose id equals an allowed IPv4 id but is paired with a denied one (denied), one
whose id equals a denied IPv4 id but is paired with an allowed one (allowed), and two unpaired subnets (denied), over every
list, the add, delete and edit routes, the Dashboard, the Subnets page, search and the Investigation page, asserting that
a hidden subnet's name, CIDR, addresses and hostnames appear in no page. A source test refuses the string
`paired_subnet4_id` anywhere in the routes and services except where the pairing is written or shown as configuration.
The first commit of the series carried the matrix against the unchanged callers and was red in 53 places (51 matrix rows and both source tests); the second moved
the callers.

**What an operator must do.** Nothing, unless a scoped account used to see IPv6 data it should not have: give each IPv6
subnet it should see a pairing in `[subnets6]`. Unrestricted accounts and superadmins see no change.

## [5.68.0-beta.7] - 2026-10-05

Beta channel. Stacked on 5.68.0-beta.6. **The Update helper button now appears for a build-only helper
update.** The previous release's own fix is delivered by pressing Update helper on each Kea host, and on the
maintainer's host the page said "v7 (build 7, build 10 available)" with Check and Test legacy grant beside it and
no Update helper button — the one control the message told the operator to use.

**What was wrong.** The label in that cell had always known the build: it compares the host's reported build with
the one this Jen ships and says "build 10 available" when it is behind. The button's condition, two lines below, compared
the helper's version alone — "no helper, or a version below the shipped one" — and the route that fills the row
never passed the build or the shipped build to the template at all. Every helper release that changed the build and
not the version, which is builds 8, 9 and 10, was therefore invisible to the button; the same page had already lost
its button once before for a different condition, and a test pins the shipped version to the helper file for exactly
that reason without ever learning about the build.

**The fix.** The row now carries the build the host last reported (nothing before helper v7, which reports none) and
the shipped build. The button renders when there is no helper, or its version is below the shipped one, or the
versions are equal and its build — counted as 0 when the host reports none — is below the shipped build, so a helper
too old to say its build is below any build. The label stays "Update helper"; the cell for a version below the one this
Jen wants now names the build when it knows it, so the text and the button agree. A test pins the shipped build to the
helper file's, the twin of the version pin, and the SSH card's row is rendered for a build-only update (button),
a current host (none), a host that reports no build (button), a version behind (button), no helper (Install helper)
and a non-superadmin (none). One existing test, which recorded the shipped version and no build as "current", now
records the build too: under the new rule a host reporting none is correctly offered the button.

**What an operator must do.** If you could not press Update helper after upgrading to 5.68.0-beta.6, you can now: press it on each Kea host.

## [5.68.0-beta.6] - 2026-10-05

Beta channel. Stacked on 5.68.0-beta.5. **A bug fix for a defect that has been in every release since
5.66.0-beta.2 — stable 5.66.0 and 5.67.0 included.** On a Kea host whose Kea came from ISC's own packages, no
config change reached Kea through the helper at all, and Jen told the operator that Kea was not installed.

**What was wrong.** From helper build 7 the helper resolves every binary it runs through a fixed list of
directories and requires each to be `root:root` with no group or other write bit, so a planted file can never be
run as root. That rule was applied to the Kea daemon binary as well. ISC's packages do not ship it that way:
on a Kea 3.0.4 ISC deb (`3.0.4 isc20260728182757 deb`) `/usr/sbin/kea-dhcp4` is owned `_kea:_kea`, mode `0750`.
Every operation that checks a config before writing it — and that is `test-config` and `apply-config`, so every
subnet, option, class, DDNS and investigation-logging change — therefore answered `missingbinary`, which Jen
worded "kea-dhcp4 is not installed on this server — install it and try again". The maintainer's host showed it the
first time investigation logging was pressed: the binary was exactly where the helper looks, in a directory that
passed, and the file was refused for its owner. A host still on the legacy `sudo python3` path (no helper
installed) was never affected, because that path has no such check; a host that had been moved onto helper builds 7
to 9 was.

**How the test suite never saw it, said plainly.** The system suite's Kea node is ISC's own image, which ships the
binary owned by its service account, and a fixup in the release that introduced the rule changed the image to
`root:root` — under a comment asserting that "a real Ubuntu/apt install puts the BINARY under root:root". That
was never checked against ISC's packages, which are the ones Jen targets (Kea 3.0 and later; Ubuntu's own package
is 2.4). The test host was altered to fit the check. When a fixture has to change for a check to pass, the change
is a claim about production, and it is verified against a real target before the check ships. The fixture is back
to what ISC ships and the change is explained where the line used to be.

**What changed.** Build 10 runs `kea-dhcpX -t` as the account the daemon runs as, which is what the daemon does on
every start, and the trust rule now says who executes the file. A binary the helper runs as root is trusted exactly
as before: `root:root`, no group or other write bit. The Kea daemon binary is run through the standard library's
`user=`/`group=` as the unit's `User=`, else its own owner, and is trusted only when it is a regular file owned by
exactly that account, a system account (a uid below 1000, never root), with no group or other write bit. A binary
owned by anyone else, or writable by group or other, or a symlink, is still refused, and the Servers page now says
why ("is owned by alice, not a system account and not the daemon's user") instead of "not installed". Because
the helper, which is root, never executes a file an unprivileged account can replace, and the account that runs it
can already do whatever the daemon can, nothing was loosened for root. The file the test reads is written
mode 0644 explicitly rather than by the umask, and the helper's clean environment gains `HOME=/`.

**What ISC's images record, measured on 3.0.3, 3.2.0 and 3.3.1.** A new compatibility check reads it from each
image's running container and fails the day it changes: `/usr/sbin/kea-dhcp4` is owned by the service account `kea`
(uid 100), mode `0754`, group `root` on 3.0.3 and `kea` on 3.2.0 and 3.3.1; the daemon's process runs as root;
the image sets no user. The packaged deb is `_kea:_kea` `0750`. All of it satisfies the new rule. The comment in the
helper that said "ISC's own packages run the daemons as root" was wrong and now says this.

**Messages.** When the helper refuses a binary it found, the line on the page and the config-test results name the
reason and the fix. A helper older than build 10 says nothing of the sort, so the line says that too: on a Kea
from ISC's packages that helper cannot run the binary and reports it as not installed. Health Center's helper row
warns "helper build < 10 on an ISC-packaged Kea cannot validate configs" for a host whose Kea version string shows
the packaging.

**What an operator must do.** Press **Update helper** on every Kea host after upgrading Jen: the fix is in the
helper file on the Kea host, not in Jen, and Settings → Kea → SSH shows the host as "v7 (build 9, build 10
available)" until it is done. The update is signed and needs no sudoers change. Hosts that were never affected need
nothing.

## [5.68.0-beta.5] - 2026-10-05

Beta channel. Stacked on 5.68.0-beta.4. An investigation used to start when a person already
had a MAC. Nothing in Jen said "these clients had trouble in the last hour", although the
log names the client on every NAK and decline and the lease table records declines. This
release joins them into a Problems inbox: a page, a dashboard widget and an alert, each row
one click from its investigation.

**The sweep and the table.** Migration 30 creates `client_problems`, one row per server,
kind, client and address, with a unique key the upsert depends on (the hardware and IP
address columns are NOT NULL with an empty default so the key is real: MySQL treats NULLs as
distinct). A core scheduler job runs every five minutes beside the investigation-logging
sweep. For each SSH-configured Kea server it tails the DHCPv4 log through the helper's
existing bounded `tail-log` (no new helper op, no sudo line) and reads the problem lines for
every client they name: a NAK, a decline, a dropped packet, a failed subnet selection, a failed
DNS update. Two more kinds need no log and come from the lease database in one query each: a
declined lease (a `lease4` row in state 1 that has not expired — Kea clears the declining
client's hardware address, so that row is about an address) and a reservation whose fixed
address is leased to a different client, which is Explain's "held" verdict computed
fleet-wide. Those two are states, not events: they resolve the moment they are gone, where a
log kind resolves after a day without a repeat. Resolved rows are kept 30 days and pruned by
the daily audit cleanup whatever its retention.

**What the log shows at each level, measured.** The NAK Kea sends is visible at Kea's default
INFO level as a `DHCP4_PACKET_SEND` line carrying `DHCPNAK`, and at DEBUG the NAK's own message
adds the requested address and the reason; the two lines share a transaction id, so a NAK is
one event keeping whichever line named the address. The reader is pinned to the real log lines
the compatibility probe captured on Kea 3.0.3, 3.2.0 and 3.3.1. The packet-drop and
subnet-selection messages and the NAK reasons beyond the first are DEBUG-only, so they appear
only while a server logs at DEBUG — the investigation logging of the previous release is how to
see them on demand.

**A line read twice is one event.** Each sweep reads the same last 1000 lines the previous one
did, so a per-server watermark in the settings table records the newest time already counted
and only newer lines are added. Log rotation between sweeps loses nothing that was counted;
a server that writes more than 1000 lines between two sweeps loses the oldest, which is why
the page calls itself a lead and not a ledger. A sweep that cannot read a server records
nothing for it and the Health Center's server rows already say why.

**The page, the widget, the links.** `/problems` lists open rows one entry per client, newest
first, filtered by `add_subnet_restriction` on the row's own subnet: a user restricted to some
subnets sees only rows in them, and a row Jen could not place in a subnet is shown only to a
user who may see every subnet, the rule every unattributed row follows. A row's subnet is where
its address is, else where its MAC is now. Each row has an Investigate button from the one
macro and a Why? that computes the Investigation page's one-line answer only when asked,
judged exactly as that page judges a client, so a client outside the caller's subnets is the
same empty answer as one that does not exist. Both routes are diagnostic surfaces with rows in
the authorization matrix, seeded with a problem in each of two subnets and an unattributed one.
A "Clients with problems" dashboard widget (count by kind in the last hour, the five most
recent) joins the picker, and the NAK and Dropped counters in the Servers page's packet-health
block link to the inbox filtered to that server.

**The alert.** A new core alert type, `client_problems`, is opt-in per channel like every
type. It fires when one client has the same kind of trouble at least `[alerts]
client_problem_threshold` times (an optional key, 3 by default) within an hour of the newest
log line, at most once per client and kind per 24 hours, with the subnet id attached so a
channel scoped to subnets filters it. A chattering client is one alert, not sixty; the two
database kinds never alert.

**Tests.** The log reader on the real fixtures and on lines built from ISC's message ids,
including the NAK de-duplication; the watermark and the alert rule as pure functions; the sweep
against the real database for each kind, resolution, recurrence as a fresh episode, pruning, an
unreadable server and the once-a-day rule; the page and the widget by caller scope; migration
30; and system scenario 18, in the critical subset, in which three requests for an address
the server did not offer are NAKed by a real kea-dhcp4, one sweep puts the client in the inbox
with its subnet, a second adds nothing, and the page, the lazy answer, the widget and the
Investigate link resolve.

## [5.68.0-beta.4] - 2026-10-04

Beta channel. Stacked on 5.68.0-beta.3. The Investigation page lays out what the core
knows about a client, and each bundled plugin knows a fact about it the core cannot: the
switch port its MAC sits on, whether it answers a ping, which DNS records carry its name,
what the last scan saw, whether its address is designated, whether it is a favourite or a
tracked device. None of that reached the page. This release gives plugins one way in and
puts all seven bundled plugins through it.

**The hook, mirrored on the search provider.** `register_investigation_provider(plugin_id,
*, title, fn)` is exported from `jen.plugin_api` (the API version stays 3; adding a name
is additive). `fn(subject, accessible_subnet_ids, all_subnets)` is handed the client Jen
has already resolved and authorized — a deep copy of the view, so a provider can read it
and cannot change what the page or the next provider sees — and answers a card (a
sentence, rows with optional links, a link to its own page, a status of ok, warn or
none) or `None` for "nothing to say", which renders nothing. Providers run in registration
order in the request with a 1.0 s advisory budget each; one that raises, or answers
something that is not a card, shows as "unavailable" and is logged, and never breaks the
page. Jen does not take the card on trust: text is length-capped, rows are capped at
twenty, an unknown status reads as ok, and every link must be a single-slash path inside
Jen or it is dropped.

**Scope is the plugin's duty and the page's check.** The Overview only asks providers
about a client the caller can place in a subnet they may see — the same gate that makes a
denial and a client that does not exist the same "No client matched" answer — and hands
each provider the caller's own subnet scope to put in its own query, before its limit. A
page for a client outside the caller's subnets therefore calls no provider at all, and a
plugin's second row for an in-scope client that is stored in a subnet outside the scope
stays out of the card. The authorization matrix gains a row per bundled provider, driven
through the real page with every plugin enabled: a scoped admin sees all seven cards for
the client in their subnet and none of what the same plugins hold under a different subnet,
sees nothing for the client in that different subnet, and an unrestricted admin sees both.

**What the Overview shows.** Under the core facts, a "What else Jen knows" section carries
one card per plugin that has something to say, and none when none does. A card that needs
a look says so, and its sentence is also added to the line at the top of the page under
"Worth a look": a host that has stopped answering, a DNS record that points somewhere the
client does not live, an address IPAM marks static that a DHCP client now holds, a host a
scan found that nothing Jen knows accounts for.

**Seven plugin releases.** Each is a new capability and so a minor version, requires Jen
5.68.0 (a 5.68.0 beta satisfies it), and was released through its own repository's
pipeline first — build, harness, CI, tag, tag CI — and is bundled here byte-identical to
its tag with the registry re-pinned: IPAM Lite 1.7.0 (the entry for each address the client
holds and whether it is the one it was designated for), Network Discovery 1.3.0 (what the
newest scan of each subnet found on its MAC or addresses), Host Watchdog 1.1.0 (does it
answer, since when, how many checks in a row have failed), Local DNS Sync 1.1.0 (the
records pushed under its name or onto its addresses and whether they match), Switch Port
Locator 1.1.0 (the switch, port and VLAN, and whether it has moved), Wake & Actions 1.1.0
(favourite, whether a SecureOn password is set, last wake) and Presence 1.1.0 (state, last
seen, and to an admin the sinks it publishes to). Two places differ from what was first
sketched, on purpose: the scan stores what it found rather than the ports it probed, so
Network Discovery shows no ports, and the next-free hint stays on IPAM's subnet page, which
its card links to. A contract test now asserts that every bundled plugin registers exactly
one provider and that each one runs against the freshly migrated tables without raising.

## [5.68.0-beta.3] - 2026-10-04

Beta channel. Stacked on 5.68.0-beta.2. Beta.2 measured what Kea's log carries at each
level and found the decision itself — the classes Kea assigned, the packet's options —
only appears at debuglevel 45 and 55, which no production DHCP server should sit at all
day. This release lets an operator turn that on for one server, for five, fifteen or
sixty minutes, from the page they are already investigating on, and guarantees it is
turned off again.

**One logger entry, with its undo written beside it.** Turning investigation logging on
sets the `kea-dhcp4` logger to DEBUG, debuglevel 55, and adds a `user-context` marker to
that same entry recording when it ends and exactly what to put back: the previous
severity, the previous debuglevel (or that there was none), or that Jen created the
entry and should remove it. Nothing else in the config is touched — not the output
options, not any more specific logger, not any `user-context` key already there. The
marker lives in the Kea config itself on purpose, so it survives a Jen restart, a
restored database, a second Jen and a person reading the file with no Jen at all.
Pressing the button again on a server already on only extends the time and keeps the
original restore.

**Applied like every Kea edit, and reloaded rather than restarted.** The change goes
through the same checked path as every subnet or option edit — a `kea-dhcp4 -t`
preflight, the sha guard, revert on failure, an audit row and a config revision — to one
server at a time, never two. The daemon is then told with `config-reload` on the control
channel Jen already uses. That was verified on real daemons first, not assumed: on Kea
3.0.3, 3.2.0 and 3.3.1 alike it answers result 0, no process or container restarts,
the new level takes effect on the next packet, leases survive, the `user-context` is
preserved in `config-get`, a deliberately broken file is refused with result 1 while the
daemon keeps answering, and restoring is the same two steps. A Kea that does not list
`config-reload`, or refuses it, is restarted through the existing helper `service` op
instead, and the result says which happened. No helper op and no sudo line were added.

**A sweep that cannot forget.** A scheduler job runs every minute. Its cheap path reads
only an index of what this Jen knows is on and restores whatever has expired. Every tenth
run it reads each SSH server's config as well, to restore an expired marker nobody
indexed and to adopt a live one so the banners show it. A restore that fails stays in the
index with its error and is retried next minute. The Health Center gains **DEBUG logging
left on**, which fails when a server is more than two minutes past its time; it reads
the index, never SSH at render time.

**Who, and where.** Admins with access to every subnet — the Trace and config-history
rule, because the log names every client — see *5 / 15 / 60 min* on the Trace page and on
every Servers card; the sixty-minute choice asks for confirmation and names the disk. A
banner with the time left and *Turn it off now* shows on Trace, Servers, the dashboard
and the Investigation page. The route is session and CSRF only: there is no API route
for it and the unattended installer never touches it, and the page the person returns to
is an allowlist, never a URL taken from the request.

**The live watch, and Explain beside Kea.** Trace's *Watch this client* now re-reads the
log every 3 seconds for ten minutes (it was every 5 seconds for one minute; the server
stops it at ten minutes whatever the page does), so an operator can ask a device to renew
and watch the exchange arrive. With logging off it says in one line what turning it on
would add. Explain now shows the classes Kea assigned beside its own evaluation of each
class, and where Jen worked a class out from the inputs it has and Kea's list says
differently, the difference is a **Kea disagrees** verdict naming the class and what to
suspect — an input Jen lacks, or a config that changed since that packet — rather than a
silent override either way.

**Tests.** Mutation tests for the marker (create, restore, extend, due-only clearing, an
unreadable time counts as due); service tests for reload, the restart fallback and the
sweep without a database; route tests for who may press the button, where they land and
what each page shows; a compatibility test that `config-reload` really applies a log
level on 3.0, 3.2 and 3.3; and a system scenario, 17, that runs the whole life against
real Kea hosts — on, a packet dump appears, the sweep puts it back, no process was
restarted — and joins the critical subset.

## [5.68.0-beta.2] - 2026-10-04

Beta channel. Stacked on 5.68.0-beta.1. The Investigation page's Explain tab used to
evaluate a client from its MAC alone, so every client class whose test reads the vendor
class, the user class, the hostname, the client id or the relay agent's options came back
"undecided — supply …" with nowhere on the page to supply them. It now evaluates the
client Kea actually saw, says where each input came from, and says why not.

**What Kea's log carries was measured, not assumed.** A new compatibility probe boots a
throwaway kea-dhcp4 per log level, sends it one relayed DISCOVER and REQUEST carrying a
vendor class, a user class, a client id, a hostname and a relay agent option, and records
what the daemon logged and what it stored. The answer is the same on Kea 3.0.3, 3.2.0
and 3.3.1. Every log line about a client carries its client id (`cid=[…]`) at any level,
INFO included. At debuglevel 45 and up `DHCP4_CLASSES_ASSIGNED` lists the classes Kea
assigned, and the built-in `VENDOR_CLASS_<option 60>` in that list is the vendor class.
At 55 and up `DHCP4_QUERY_DATA` dumps the whole packet — hostname, vendor class, user
class, client id, and the relay agent's circuit and remote ids. At INFO, and at DEBUG
with a debuglevel of 0, 15 or 30, none of that is there. And with `store-extended-info`
on, the lease row keeps the relay agent's options at any level. The probe now pins all of
it on every run against the parsers Jen ships, which are also checked against the three
versions' real log excerpts.

**Inputs, each labelled by source.** Explain's client is built from the MAC, the lease
row's client id and hostname, the lease's extended info, what Kea's log says, and what was
typed — in that order of precedence — and an **Inputs used** card lists every input with
where it came from. A class Kea listed as assigned is decided by what Kea said ("assigned
by Kea at 15:10:39"), over Jen's own reading of its test. On the Investigation page's tab
an inline form of the eight fields, pre-filled and marked by source, re-runs the evaluation
with what you typed, and a hint names the log level that would let Jen read what is still
missing — or says who may read the log, or that the Kea host helper is missing. Kea's log
is read through the same helper-only `tail-log` Trace uses, for an admin with access to
every subnet only (a log line has no subnet boundary Jen can trust), cached for thirty
seconds and never for a host with no SSH; a lease in a subnet the caller may not see
contributes nothing to the inputs. `?auto=0` is the old MAC-only behaviour. Nothing new
runs as root and no sudo line changed.

**Why not.** A full pool is a verdict — "pool X: eligible but FULL (254 of 254 addresses
leased)" — with the next eligible pool and its free count as the answer, or "every
eligible pool is full" when there is none. A reserved address held by a different client
names the holder and when its lease ends (Kea offers the reservation only once that lease
expires or is released) and links to the holder's own Investigation page; the holder is
never named when its lease is in a subnet the caller cannot see. A reservation whose
identifier type is not in `host-reservation-identifiers` is "never matched" instead of
shown as honoured. A giaddr the subnet does not match makes the subnet-selection step
"NOT selected". Each of these carries the config element it is about and, for an admin who
may see every subnet, links to the Changes tab filtered to that element.

**One sentence on the Overview.** "Would get 10.0.0.5 from the reservation", "Would be
NAKed: every eligible pool is full", "Undecided: … need …" — computed from the
lease-derived inputs and any Kea-log read already cached, so opening the Overview never
costs a trip to the Kea host.

Docs: the user guide's new "What Explain can and cannot know", with the measured levels;
`docs/ARCHITECTURE.md`.

## [5.68.0-beta.1] - 2026-10-04

Beta channel. Stacked on 5.67.0, the first release after that promotion. The
Investigation page (`/client`, 5.63.0) has been the product's best idea since it
shipped — one identifier resolved once, with Explain, Trace, Timeline, DNS and
Config onto it — and nobody who had not read the code knew it was there. This
release makes it the front door.

**It is one click from everywhere a client is named.** Every row that names a
client carries the same *Investigate* action, written by exactly one macro
(`templates/_investigate.html`, with a JavaScript twin for the three dashboard
widgets that are built in the browser) so the next page cannot forget it. It was
already on lease, reservation and device rows and in search results; it is new on the
dashboard's recent-leases table, events feed, top-devices table and alert strip,
on the Alerts log (for an alert whose message names a client — read out of the
message, so offered only to a caller who may see every subnet, since the message is
what a restricted caller is not shown), and in the Timeline page's own header. A
scan test refuses any core template that prints a MAC without importing the macro
unless it is on a short list of pages that are themselves part of the
investigation, each with its reason. The Reports page draws charts, not client rows,
so it has nothing to link. The search box now goes straight to the client for one
whole identifier — a MAC, an IPv4 address, or (with IPv6 on) an IPv6 address or a
DUID — and a hostname, a fragment or a partial MAC still searches; the Investigation
page links back to the list (`/search?q=…&list=1`) for anyone who wanted it.

**IPv6 addresses and DUIDs are accepted.** The page used to answer "IPv6 and DUID
lookups are not supported yet". An address now resolves through the lease table (or
a v6 reservation of it) to the DUID that holds it, and a DUID goes straight to its
leases and its reservation, delegated prefixes and excluded prefixes included. The
MAC — the hardware address Kea captured on a lease, else the one a DUID-LL or
DUID-LLT embeds — carries the subject on into everything keyed by MAC, so the
device, the IPv4 leases and reservations and the Timeline show for the same
client, and the page says which of the two the MAC is: *captured by Kea*, or *read
from the DUID*, which is Jen's own inference. Explain, Trace and Config are DHCPv4
engines and say so in one line on the tab; a client Jen can find no MAC for says it
has no IPv4 identity Jen can see. All of it is gated on `ipv6_enabled` (with it off,
the page says IPv6 is off and looks nothing up), and a v6 object is judged on its v6
subnet's paired v4 subnet — the rule Devices and global search already apply, an
unpaired v6 subnet being for callers who may see every subnet. A subject found only
through objects the caller may not see loses its MAC, DUID, device and v4 side
together; the one thing kept is the MAC inside a DUID the caller typed themselves.

**A seventh tab: Changes.** For the newest 50 config revisions of each Kea server, Jen
compares each revision with the one before it over only the parts of the config that
decide what this client gets — its subnet (by id or by CIDR, so a renumbered subnet is
still found), the shared network it sits in, the pools its addresses fall in, the
classes that guard that path or that it matches, and its own reservation with any
option on it — and lists the revisions where something there moved: the lines that
moved, who changed it, when, the summary, and whether it was Jen's or someone editing
the file on the host. A change to a neighbour's reservation, to a pool it is not in or to a
global option is not on the client's path and is not shown. Values are masked as on
the history page; revisions follow that page's access rule, so the tab is offered only
to an admin who may see every subnet. A reservation kept in Kea's host database is not
part of the config file, so a change to one cannot appear here, and the tab says so.
The cost is measured in the module's docstring and re-measured by a test on every run
(about 0.2 s per server for 51 revisions of a 200-subnet config).

**The alert line is judged on the client.** The Overview's "last alert" was
unrestricted-only because `alert_log` rows carry no subnet. It is now shown to a
restricted caller when the client they are looking at is in a subnet they may see —
an alert about *their* client — as its type, status and time, never its message. The
authorization matrix gains the rows, and `docs/ARCHITECTURE.md` section 2 says
exactly that.

The first run of the upgrade-from-stable CI job from the newly promoted 5.67.0 caught
its own script: the job installed the pinned stable release by feeding the 5.66.0
wizard's twenty answers to that release's installer, and 5.67.0's installer asks three
questions, so the old answers landed on a menu it never expected and the job looped on
"Please enter r, e or q". It now installs the stable release the way an operator
scripts one (`--answers` and `--unattended`), accepts none of the failures the older
release was allowed, and drops the two steps that existed only for its bugs; nothing in
Jen changed for it.

Docs: a rewritten "Investigating a client" section of the user guide, the features page,
`docs/ARCHITECTURE.md`, and a screenshot of the page on the demo dataset as the
README's first image.

## [5.67.0] - 2026-10-04

*Stable. Everything below shipped beta-first between 2026-09-30 and 2026-10-04.*

**Beta history:** 5.67.0-beta.1, 5.67.0-beta.2, 5.67.0-beta.3, 5.67.0-beta.4, 5.67.0-beta.5, 5.67.0-beta.6, 5.67.0-beta.7, 5.67.0-beta.8, 5.67.0-beta.9, 5.67.0-beta.10, 5.67.0-beta.11, 5.67.0-beta.12, 5.67.0-beta.13, 5.67.0-beta.14, 5.67.0-beta.15, 5.67.0-beta.16, 5.67.0-beta.17, 5.67.0-beta.18.

An operator on 5.66.0 upgrades the normal way — `sudo ./install.sh` on the new
tarball, or the in-app updater — with no manual step required. The upgrade runs
one core migration, `plugin_tables` (migration 29), which is idempotent, backfills
nothing, and runs by itself on the first start. `jen.config` is not re-moded by
the upgrade itself: it becomes `0600` the next time Jen saves it (any Settings
save), or now with `sudo chmod 600 /etc/jen/jen.config`. The layout check that
runs on every privileged install and update now refuses an application directory
whose existing parent is writable by group or world and names the directory
(`sudo chmod go-w <it>`; Ubuntu's own `/opt` is `755`, so almost nobody sees
this). Kea's API, database and hosts are no longer asked by `install.sh`; a fresh
install connects them from `/setup` after first login, and an existing install
has nothing to do. Two things are worth a look, because they are older than this
release: if you ever restored or migrated Kea reservations through Jen — on 5.66.0
or earlier — the Health Center row *Kea reservations have plausible identifiers*
and the repair page under Settings → Databases → Import find any identifier that
was stored as the text of its own hex; and take a fresh recovery bundle and a fresh Kea reservation
backup once you are on this release, since they now carry what the older ones did
not (the bundle: the new plugin-ownership record and an uninstalled plugin's tables;
the Kea backup: IPv6 reservations, with binary values tagged). Older files still
import. If you ran an earlier 5.67.0
pre-release and used the setup wizard's Connect step, re-submit it once: it used to
save a Kea daemon's own control socket as Control Agent mode. The long form, with
every item, is `docs/upgrading.md`.

### The first hour

`/setup` is a six-step wizard a superadmin lands on once, the first time they log
in with Kea not yet connected: connect Kea, see what it found, install the Kea
host helper, capture a baseline, make a recovery point, investigate a first
client. Every step can be skipped and picked up later from Getting started, and
the wizard calls the same code Settings does — no new privileged path.

The Connect step tests what it saves. It asks what answered (a Kea daemon's own
control socket answers a command carrying a `service` field exactly as it answers
one without, so every Kea 3.2 site had been saved as Control Agent mode) and keeps
the mode already saved for a URL it cannot identify. The URL you typed is the one
tried and the one blamed; ports are guessed only when none was given and IPv6
literals stay bracketed. It shares one TLS-aware probe with Settings, so a private
CA or a client certificate works here too, and the Kea database gets its own port
and CA fields (`[kea_db] port` and `ssl_ca`, honoured by every connection the
application makes). The connection pool is rebuilt when Connect saves.

What Jen found is reported truthfully. DHCPv6 is checked against a real
`kea-dhcp6` answer before anything v6 is offered, and enabling it merges into
`[subnets6]` instead of replacing it. Subnet names survive a second run (an
existing name is kept when the id and network still match, and anything Kea no
longer reports is an explicit unchecked removal). High-availability peers and the
servers Jen manages are two facts, with an **Add this peer to Jen** action. An SSH
failure is a message naming the user, host and reason rather than a server error;
the recovery step is done only once a bundle has really been downloaded, and
offers **Continue** when it has. Getting started links an administrator only to
pages an administrator may open.

### The installer

A fresh install can be scripted: `sudo ./install.sh --answers <file> --unattended`
drives the wizard from a `KEY=value` file using the same `JEN_*` names as the
Docker path (parsed, never sourced; spaces around `=`, quotes and `export` are
accepted). A failed connection test is a real choice. **Jen's own database cannot
be skipped**, because Jen runs its migrations against it before serving anything
and a service without it restarts every five seconds for ever: the menu is retry,
edit, install MariaDB on this machine, or quit, and an unattended install whose
database does not answer stops with the SQL and a reason. With `y` at the prompt or
`JEN_DB_INSTALL_LOCAL=yes`, and only for a local host, the installer installs
MariaDB, starts it, creates the database and user and tests them; `uninstall.sh`
never removes it. Everything the installer runs (`apt-get`, `pip`, the virtualenv,
`systemctl`, `mysql`) writes to `/var/log/jen-install.log`, a failing step prints
the last twenty lines, and apt no longer scrolls through the progress line.

Where things live is a choice: `--app-dir`, `--config-dir` and `--data-dir` (or the
matching answers-file keys) relocate a fresh install, recorded root-owned in
`/etc/jen-layout.conf`. One checker in `jen-update-root.py` validates the layout
for the installer, the in-app updater and the uninstaller; the systemd unit is
rendered from a template with the chosen paths, and a relocated install no longer
writes the default paths into its own config or pages. Install versus upgrade is the
checker's decision (a recorded layout, a marker, or Jen's own content), an existing
`jen.config` is kept unless `--configure` is given, and the uninstaller uses the
checker that ships beside it and at its last level also removes the root updater and
its two units. `--restore` and `--rollback` export the whole layout, a failed
verification rolls an upgrade back, a fresh install writes its layout record last,
the pre-upgrade backup is the application's own streamed primitive run as the
service user and says exactly what it wrote, and the installer sets `umask 022` and
takes secrets on standard input. `jen.config` is `0600` for good.

### Deployment truth

Whether Jen runs under systemd, in a container or from a checkout is answered in
one place, `jen.services.runtime.deployment()`, never from `JEN_ROOT` (which the
rendered unit sets too, so a native install had been diagnosed as a container: the
Update button and the plugin install path were wrong). Docker and Podman both count
as containers, and "Save & Restart", a port change and a certificate change restart
by deployment — the exact command the sudoers file grants, a stop of the gunicorn
master under a container, or an honest instruction to restart by hand. The
root-privileged updater runs the real layout checks on both entry points and
Settings → Health shows an "install path is trusted" row. A Docker container with no
Kea configured now boots (a config is written whenever Jen's own database is
configured). Eight pages that printed a literal `/opt/jen`, `/etc/jen` or
`/var/lib/jen` render the layout's directories, the installer and `run.py` write the
`[ddns] dns_provider` key the application reads, and the image ships `contrib/`.
`docs/manual-install.md` is rebuilt around `jen-update-root.py --render-unit` and is
run, command by command, by CI.

### Kea data that survives

Kea's binary columns used to come back as text — in every earlier release. An
export wrote each binary value as a bare hex string and nothing decoded it, so a
restore, an import or a migration stored the six-byte MAC `34:13:43:e6:0e:2a` as the
twelve characters `341343e60e2a`; the row looked right and Kea never matched the
client. Export format 3 writes `{"$bin": "<hex>"}` and the importer decodes by the
target's own column types (older files still import: a bare string bound for a
binary column is decoded as hex, and a value that is not hex refuses that table,
naming the column and row). A migration copies the driver's own bytes. The Kea
backup is now every reservation, IPv4 and IPv6, with its host-scoped options,
streamed row by row; leases stay a separate explicit export.

The repair for damage already done is a Health row and a superadmin page that
preview and fix exactly the rows you tick. It is careful: a hardware address or
DUID of plausible shape is offered ticked, a client-id (opaque; some clients really
send their MAC as text) only with lease corroboration, else listed unticked or
left alone, and fixed-width DHCPv4 option values that look like hex text are listed
unticked for review; text options and the DHCPv6 tables cannot carry the damage and
are never listed. Kea 3.x stores IPv6 addresses in `lease6` and `ipv6_reservations`
as `binary(16)`, which the IPv6 pages printed as raw bytes and could not search;
every reader now converts them (a whole address is an exact match, a fragment is
filtered over both spellings), and global search filters every IPv6 reservation of a
subnet before it caps the list.

### Database moves that cannot destroy what was there

A migration used to create tables with `IF NOT EXISTS`, record every table as
created, and on failure drop them all, including a freshly initialised Kea target's
own. A Jen migration now needs absent target tables and refuses an empty selection;
a Kea migration copies data only into an initialised database of the same schema
major version, in one transaction with plain inserts, verified per table, and copies
a reservation's own host-scoped options only (never the config backend's global,
subnet, pool or class options), saying how many it left behind. A Kea import matches
reservations by identifier, type and subnet — never by the id in the file — inserts
without ids, updates in place instead of `REPLACE`, replaces only the child tables
the file contains, and treats only a duplicate key in skip mode as skipped; anything
else aborts, rolls back and names the table and row, never a value. The reservation
backup exports exactly the host-scoped options, one fixed query per table, shared by
the export and the migration.

### Restores that keep their word

Replace mode restores with a plain `INSERT` and reports the count the server
confirms, where `INSERT IGNORE` stored a coerced row and counted it; a strict mode
(always on for `install.sh --restore`) fails on a missing table, a count mismatch or
a skipped row, and a plugin whose code is present that loses data now fails the
restore with a rollback unless `--lenient-plugins` is given. The Databases import
page's replace mode takes a snapshot first and puts the database back on any
failure, plugins included; merge mode takes none and says so. A scoped restore of a
parent table takes its dependents or is refused. Which database tables each plugin
owns is persisted (`plugin_tables`), so an uninstalled plugin's data stays in every
backup, bundle, snapshot and migration and is reconnected on reinstall. An export's
envelope is validated before use (`not a Jen export: <reason>`, `format` bounded,
gzip detected by its first bytes, plain JSON accepted), and an enabled backup
schedule must back up something. The restore messages say what is true: a plugin
whose code is absent keeps its data in the bundle and returns when the plugin is
reinstalled and the restore run again.

### Reports

A projection is drawn for every trend, rising, flat or falling, clamped between zero
and the pool, as a dashed line that continues a thin *Total active* line; where
there is nothing to project the dataset is not added (a hidden dataset's legend
label is drawn struck through) and one sentence says why. The sentence on each card
carries the horizon for falling and flat trends.

### Security audit fixes

An audit of the layout, installer and wizard work found seven problems, all in
shipped code. The installer built the whole app as root through two inline snippets
(a plugin planted by a compromised service account would have been imported as uid
0; they now run as the service user and a test refuses any that do not); the
root-owned layout marker was written by following a symlink in a service-owned
directory (now written through an atomic swap that never walks a symlink); an
upgrade's rollback snapshot of root's own files lived in a service-owned directory
(moved under the root-owned tree); the updater never ran the layout checks four
documents said it ran; a recovery bundle's freshness check compared an aware and a
naive clock and could 500 the wizard; and one oddly named subnet could break every
later subnet change (an untouched legacy name is left alone, an unstorable one is
repaired and logged).

### Tests and CI

CI can fail now: every workflow step runs under `bash -eo pipefail`, negated and
piped `grep` assertions that could not fail are explicit checks guarded by a test,
and the upgrade from the latest stable is its own job on a clean runner with the
stable version pinned, the signature checked against the repository's key, and the
stable release's own updater driven through its real `main()` for the first hop. The
install job runs the real installer on both Ubuntu releases against a real MariaDB
and a real `kea-dhcp4` — fresh install, relocated life cycle, `--repair`, every
uninstall level, a refused layout, an unreachable database that must stop loudly —
and a separate job on a machine with no database server proves the installer can
install MariaDB, create the database, keep apt off the screen and leave the server
alone on uninstall. A kea-compat module drives Jen's import, merge, overwrite and
migration against ISC's real schema on Kea 3.0.3, 3.2.0 and 3.3.1 and records the
column types the IPv6 readers rely on; the unit suite's Kea tables are ISC's own
definitions (unique keys, foreign keys, lookup tables, binary address columns). New
system scenarios cover the failing restore, and a browser journey walks `/setup`.
Source guards refuse a hardcoded layout path, root-run application code, a deployment
decision read from `JEN_ROOT`, and an installer function that ends in a bare
`[[ ]] &&`.

### Docs

`docs/upgrading.md` is the 5.66.0 to 5.67.0 page. The README is rebuilt around one
sentence of positioning with a feature matrix and a compatibility table generated
from CI and guarded by a test, ISC Stork claims checked against ISC's own pages,
release badges sorted by version, and `docs/about.md` and `docs/features.md` for
indexers and evaluators. The runbooks gain the relocation procedure, the
administrator's guide the installer, import, restore and migration contracts, and
troubleshooting every refusal and its fix.

## [5.66.0] - 2026-09-30

*Stable. Everything below shipped beta-first between 2026-09-23 and 2026-09-30.*

**Beta history:** 5.56.4-beta.1, 5.57.0-beta.1, 5.57.1-beta.1, 5.58.0-beta.1, 5.58.1-beta.1, 5.58.2-beta.1, 5.58.3-beta.1, 5.59.0-beta.1, 5.60.0-beta.1, 5.60.1-beta.1, 5.61.0-beta.1, 5.62.0-beta.1, 5.62.1-beta.1, 5.63.0-beta.1, 5.64.0-beta.1, 5.65.0-beta.1, 5.65.1-beta.1, 5.65.2-beta.1, 5.65.3-beta.1, 5.65.4-beta.1, 5.65.5-beta.1, 5.65.6-beta.1, 5.65.7-beta.1, 5.65.8-beta.1, 5.65.9-beta.1, 5.65.10-beta.1, 5.65.11-beta.1, 5.65.12-beta.1, 5.65.13-beta.1, 5.66.0-beta.1, 5.66.0-beta.2, 5.66.0-beta.3, 5.66.0-beta.4, 5.66.0-beta.5, 5.66.0-beta.6, 5.66.0-beta.7, 5.66.0-beta.8, 5.66.0-beta.9.

An operator on 5.56.3 upgrades the normal way — `sudo ./install.sh` on the new
tarball, or the in-app updater — with no manual step required. There is no core
migration, no new dependency, and no sudoers change. `jen-kea-helper` stays at
whatever version it's already running on every Kea host until you press
**Update helper** in Settings → Kea → SSH, the same as always; a host still on
helper v5 or older needs the legacy `NOPASSWD: /usr/bin/python3` grant present
for that one press, exactly as a fresh install always needed it, and never
again afterward — updates from there on are verified by a release signature.
Five plugins are newly bundled alongside the existing IPAM Lite and Network
Discovery — Host Watchdog, Local DNS Sync, Switch Port Locator, Wake & Actions,
and Presence — each an opt-in install from the Plugins page that does nothing
until enabled. A recovery bundle or scheduled backup taken before 5.66.0-beta.5
holds no bundled plugin's data, even though the plugin itself shows as
installed again after a restore; take a fresh backup or bundle once you're on
this release. The public `/api/v1/health` endpoint — unauthenticated by design,
polled by the self-updater and a restore — answers with `jen_version` alone.

### Plugins and the plugin API

Plugin API v3 (5.57.0) opened five things a plugin previously had no way to
do: writing to the events feed and Timeline, registering an alert type, adding
row actions to Leases/Reservations/Devices, a Bearer-authenticated API route
under `/api/v1/plugins/<id>/…`, and a search-results provider. Five new
plugins were bundled on top of it across round 5: **Host Watchdog** (uptime
probing with alerting), **Local DNS Sync** (pushes DHCP names to Pi-hole,
AdGuard Home, or an Unbound export), **Switch Port Locator** (SNMP: which
switch port a MAC is plugged into), **Wake & Actions** (a Wake-on-LAN button
plus a favourites page), and **Presence** (publishes online/offline state to
Home Assistant, MQTT, or a plain HTTP endpoint).

A wide review pass then moved every bundled plugin — all seven — onto a set
of shared helpers (subnet resolution, MAC normalization, search scoping,
JSON body parsing) in place of each plugin's own private, drifted copy, and
fixed a shared bug shape found while doing it: a search provider's own result
limit ran before its subnet filter, not after, so a restricted caller's own
match could be crowded out by matches they can't see. Every bundled plugin's
own tables are now included automatically in every export, scheduled backup,
and recovery bundle — previously silently excluded. A box that can't take a
plugin's update because it needs a newer Jen is now told to upgrade Jen first,
rather than being offered an update that only fails partway through.

Host Watchdog's scheduled probing has never actually recorded a check, on any
install, since it first shipped — its due-target query never fetched the one
column the selection logic needed, so the schedule silently skipped every
target forever, while manual "Check now" worked correctly the whole time.
Fixed in Watchdog 1.0.5. A new test now runs every bundled plugin's periodic
job once against a real app and database and confirms it actually writes
what it's supposed to.

### Who can see what

A repeated pattern across the bundled plugins: a route authorized access on
one thing — a subnet id typed into a query string, or nothing at all — and
then acted on another, a MAC or address's real subnet, reading "no
attributable subnet" as "allow." Closed plugin by plugin across a sustained
audit: Wake & Actions, Presence, Switch Port Locator, Host Watchdog, Local
DNS Sync, IPAM Lite, and Network Discovery each had at least one route fixed.
The Client Investigation page (new this window) had its own version of the
same gap — an ambiguous hostname, an address held by a lease outside the
caller's subnets, and the overview tab's alert line could each expose
something about a subnet a restricted user can't see — all closed. The
authorization matrix that catches this class of bug is now enforced by CI
rather than convention: every route touching a client is required to be
either decorated as part of that surface or explicitly justified elsewhere,
and the check runs against every bundled plugin with a real database. Add
Reservation no longer silently opens on the first subnet in the list when it
can't resolve where a device actually is.

### Kea hosts

The Kea host helper can now update itself. A signed `update` op — verified
with `ssh-keygen -Y verify` against the project's own release key — replaces
needing the legacy sudo grant for every update; a host takes one last hop
through the legacy path to reach the signed helper, and never needs the grant
again after. This was hardened over several follow-up releases: the helper no
longer trusts `$PATH` for anything it runs including itself, a preflight
check plus an automatic rollback protects every signed install, the build
number and protocol version are checked independently so a version bump can
no longer mask a stale build, and the directory a trusted system binary lives
in — not just the binary itself — is now checked for safe ownership.

Diagnosing a refused legacy-grant update got much more specific: the refusal
now reports what `sudo` actually said instead of a blanket "no grant," and a
**Test legacy grant** button checks on demand. The SSH user Jen connects with
is now derived in exactly one place, used everywhere, instead of two
definitions that could quietly disagree. A capabilities layer now derives
what each Kea server can do — from its version, connection mode, and
recorded helper version — in one place, and every page that used to work
this out for itself asks it instead.

### Changes across servers

A multi-server configuration push that fails partway now reverts every
server it had already written, rather than leaving some on the new
configuration and others on the old one; a revert that itself can't be
applied is reported by name as needing hands. The Servers page banner is now
a list of every unresolved rollback incident instead of one slot a later,
unrelated rollback could silently overwrite — and an unresolved incident is
never evicted to make room for a newer one, short of a 200-incident ceiling.

### Backup and recovery

Recovery bundles moved to a streaming, chunked format: the size ceiling went
from 200 MB to 2 GB, and building or restoring a large bundle no longer needs
roughly three times its own size in free memory. Bundles made before this
change still restore normally. The database export inside a bundle, and a
scheduled or manual backup, now stream to disk one row at a time instead of
building the whole export in memory first — a new "without audit history"
option leaves out an install's largest table. A restore's memory check now
weighs the database already on the box as well as the incoming bundle, and
confirms free disk space for the snapshot before stopping anything. A
scheduled backup is now published atomically — written to a temporary file
and renamed into place only once complete — so a crash or full disk mid-write
can no longer leave a truncated file that still counts toward retention. The
ordinary database import page gained a size limit and the same memory check a
restore already used; it previously had neither.

### Updates and releases

A release build now resolves its tag to one commit SHA at the start and uses
that same SHA through testing, signing, and publishing, rather than trusting
a tag that could move mid-build; the publish step refuses if the tag no
longer names that commit. The one by-hand line an operator is shown for
installing the Kea host helper directly now verifies a signature locally
before installing anything — no unverified fallback exists anywhere in the
app or its docs — and it self-tests what it downloads before installing,
offered only where installing around a refusal is genuinely safe.

### The interface

Sticky table headers, added earlier, never actually worked at all; the real
cause (a scrolling ancestor competing with the sticky positioning) is fixed,
with sideways scroll on a wide table now an explicit opt-in that trades away
the sticky header. Keyboard focus visibility, a skip-to-content link, a
progress indicator for slow requests, and a wide-monitor layout for the
multi-tab Settings pages were all added. The public health endpoint no longer
waits on a live Kea call — it used to take up to twenty seconds to answer
with Kea unreachable, occasionally fooling the self-updater's own health
check into rolling back a perfectly good update.

### Docker

The shipped Docker image has failed to start at all since gunicorn arrived —
including the prior stable release itself — for want of a working directory;
fixed, with a system-test job that boots the shipped compose file so this
can't regress unseen. The image now installs `nmap`, `iputils-ping`, and
`snmp` so Network Discovery, Host Watchdog, and Switch Port Locator work
inside a container, and hides the self-update and Restart controls that
don't apply without systemd.

### Tests and CI

A new real-process system-test suite drives sixteen boundary scenarios — a
partial rollback, a resolver stall, an updater killed mid-update, a broker
going silent, a full recovery restore with every bundled plugin's data, and
more — against a real Docker Compose stack of Jen, two Kea hosts, and
MariaDB. The plugin authorization matrix now runs against every bundled
plugin with a real app and database, checking both that a restricted caller
is refused and that an unrestricted one gets a real answer. A raw-exception
scanner, previously limited to Jen's own routes, now covers every bundled
plugin and fails the build on a newly introduced leak of database or socket
detail into a user-facing message.

### Docs

`docs/runbooks.md` is new: four standalone procedures for rotating the
helper signing key, recovering from a signed-but-broken helper build,
installing the helper by hand on a host with no route to the internet, and a
full scratch-VM restore drill. `docs/upgrading.md` is new: a living page for
an operator still on the last stable release, one section per thing they'd
actually notice coming forward, kept current by a test that fails when a
later release adds something an operator would notice without a matching
section. `docs/ARCHITECTURE.md` now names the application's entire
unauthenticated surface and the reason each route is on it.

## [5.56.3] - 2026-09-23

Stable. The UI round; everything below shipped beta-first between
2026-09-21 and 2026-09-23.

**Beta history:** 5.50.0-beta.1, 5.51.0-beta.1, 5.52.0-beta.1, 5.53.0-beta.1,
5.54.0-beta.1, 5.55.0-beta.1, 5.55.1-beta.1, 5.55.2-beta.1, 5.55.3-beta.1,
5.56.0-beta.1, 5.56.1-beta.1, 5.56.2-beta.1, 5.56.3-beta.1.
Upgrading from 5.49.0 is automatic (`sudo ./install.sh`, or the in-app
updater): migration 28 (the wider dashboard-prefs column) runs at startup,
and nothing needs doing by hand. Every browser gets the install-default
theme on its first load after the upgrade — the old, permanently-tainted
storage key that used to shadow it forever was cleared on purpose — and
anyone who wants their own look simply picks it once more. The two
bundled plugins, IPAM Lite and Network Discovery, offer their updates
(1.5.2 and 1.1.2) from the registry on the next check.

### Icons and look

- **One icon system** — roughly 600 emoji used as interface chrome (nav
  items, card titles, buttons, status marks, empty states) across 78
  files are now [Lucide](https://lucide.dev) icons from a single inlined
  SVG sprite: consistent across operating systems and themes, and
  colored/sized by the surrounding text instead of baked in. Alert
  message templates keep emoji on purpose (they travel to Telegram,
  Discord and ntfy), now standardized to one glyph per severity.
- **Quick wins** — Doctor groups repeated findings instead of one card
  each; the Kea host helper's version is worded the same way everywhere
  it appears; the Servers page's packet counters no longer overflow
  their card; the dashboard header and the Subnets header buttons each
  settled onto one row.

### On a phone

- **A real mobile layout**, not a squeezed desktop one: a bottom tab bar
  (Dashboard, Leases, Reservations, Settings, More) with a More sheet
  for everything else, a dense two-line row pattern for tables, Select
  mode for bulk actions, a filter bar that collapses into a labeled
  sheet, and an action bar that folds secondary buttons into a "More
  actions" sheet. Every page was converted to it, one at a time.
- **Settings pages collapse** to their first card on a phone, with a
  jump-list of chips that expand and scroll to the one you tapped,
  instead of one very long scroll through every card at once.
- **A touch-navigation bug fixed** that had been there since v2.5.10:
  every link listened for touchstart/touchmove/touchend and navigated
  on touchend unless the finger's movement looked like a horizontal
  swipe, so scrolling past a link and lifting a finger anywhere on it
  navigated — worst on the Settings page, where the tiles are full-width
  links. The same block had also silently broken iOS's long-press link
  preview and Android's link context menu, everywhere, the whole time.
  Removed outright; nothing replaces it.
- **1,699 inline `style=` attributes became 492**, extracted into
  generated utility classes so the phone layout didn't mean rewriting
  every template's styling by hand.

### Dashboard

- **Arrangeable, not just toggleable** — Arrange mode adds drag (desktop)
  and up/down arrows (phone) for widget order and width, and per-subnet
  pin/hide/reorder on the subnet panel, on top of the existing show/hide.
- **Seven more widgets** — Pool Exhaustion Forecast, Packet Health, Kea
  3.2 Readiness, Recent Events, HA State, DDNS Errors and Getting
  Started, each reusing a read another page already makes; a widget
  with nothing to say for a given install doesn't appear at all.
- **The subnet stat grid** now fits four cards per row instead of
  stranding a fourth one alone on its own row.

### Themes

- **A real theme system** replaces the dark/light toggle that had been
  there since v4.4.5: seven built-in presets (Dark, Light, High
  Contrast, Phosphor, Slate, Ember, Retro), a per-user picker, and an
  install-wide custom palette — eleven colors, corner radius, a
  monospace-UI option, a live preview and WCAG contrast warnings. Every
  submitted color is validated server-side against a hex-only whitelist
  regardless of what the client sent; that whitelist is the entire
  injection boundary a saved palette's CSS has to pass, since it reaches
  every page unescaped. The default look is unchanged — Dark is pinned
  byte-for-byte against what it always was.
- **Retro** reads as an early-90s desktop (a teal background behind grey
  panels, a navy accent, beveled borders and a navy title-bar nav) via a
  small fixed CSS string a preset can carry that a custom palette can
  never produce.
- **The install default actually applies now.** It silently never had:
  the picker wrote its own fallback into every browser's storage on the
  very first page load since the theme system shipped, so nothing could
  ever change what a browser showed afterward. Fixed at the root, and
  the picker gained an "Install default" entry to return to it in one
  click. The theme now also applies before the page's own content
  paints, so a non-Dark pick no longer flashes Dark first.
- The Install Default form's missing CSRF field (a plain oversight, not
  an exploitable one — the app correctly refused the unverifiable
  submission) is fixed, with a new test scanning every POST form across
  Jen's own templates the same way an existing one already scanned every
  plugin template.

### Correctness

A second look at the theme and dashboard work above turned up fifteen
smaller things, each verified against the code rather than assumed from
a screenshot: a subnet's name and CIDR reaching the dashboard's
sparkline cards unescaped, inconsistent with the rest of that file; two
dashboard widgets each independently re-running the full Health Center
check when both were enabled at once; a restricted account's Recent
Events widget that could report nothing when older, accessible events
existed past an internal fetch window; a sheet that claimed to be a
modal dialog but never actually trapped keyboard focus or returned it on
close; a preferences value where the string `"false"` was silently
treated as true; a saved custom palette trusted on every load without
being re-checked against the rules it had to pass to be saved in the
first place; a leftover pre-release script enforcing a README policy the
project dropped two years ago; and an installer script that couldn't
read a beta's own version off an upgrade candidate.

### Plugins

- **IPAM Lite 1.5.2** — every write route (save, delete, a range action,
  both steps of a CSV import) used to check only subnet access, never
  the caller's role: a viewer could create, overwrite, delete or
  bulk-import entries even though the interface looked read-only to
  them. A viewer is refused before any write route even looks at the
  subnet or the submitted form, and an import is capped at 2 MB.
- **Network Discovery 1.1.2** — the same gap: a viewer could start an
  nmap scan from the Jen host, and could silence or un-silence the
  rogue-device alert for any MAC, since the known-hosts list has no
  subnet column by design. Fixed the same way, plus a real race where
  two clicks on different subnets while one scan held the shared lock
  could queue a duplicate scan of the second.
- The registry offers 1.5.2 and 1.1.2 to every install's Settings →
  Plugins Update button, and both bundled copies are resynced to them.

### Docs and README

- The README's screenshots are generated in CI, on every run, from a
  fictional homelab dataset — never from a real install — so the
  project's front door never carries a real hostname, a real person's
  name, or the maintainer's own addresses.

## [5.49.0] - 2026-09-21

Stable. The first promotion through the release channels; everything below
shipped beta-first between 2026-09-14 and 2026-09-21.

**Beta history:** 5.32.1-beta.1, 5.33.0-beta.1, 5.34.0-beta.1, 5.34.0-beta.2,
5.35.0-beta.1, 5.36.0-beta.1, 5.37.0-beta.1, 5.38.0-beta.1, 5.39.0-beta.1,
5.40.0-beta.1, 5.41.0-beta.1, 5.42.0-beta.1, 5.43.0-beta.1, 5.44.0-beta.1,
5.45.0-beta.1, 5.46.0-beta.1, 5.47.0-beta.1, 5.48.0-beta.1, 5.49.0-beta.1,
5.49.0-beta.2, 5.49.0-beta.3, 5.49.0-beta.4, 5.49.0-beta.5, 5.49.0-beta.6.
Upgrading from 5.32.0 is automatic (`sudo ./install.sh`, or the in-app
updater): migrations 25–27 (the API-key write flag, packet
statistics, the event stream) run at startup, and nothing needs doing by hand.
A Kea host's `jen-kea-helper` stays at whatever version it has until you press
Update helper; nothing stops working without it (Settings → Kea → SSH offers
v5, which bounds the memory Trace uses).

### Release channels

Every release since 5.32.0 ships beta first: a `-beta.N` tag is a GitHub
prerelease that only boxes set to the beta channel (Settings → System →
Updates) are offered, and the plain tag is a version-only promotion of the
newest beta. This release is the first one promoted that way. The root updater
also refuses to install a release older than the one on disk, so switching a
beta box back to stable can never downgrade it.

### Security and sign-in

- **Support bundle** — one redacted zip (versions, Health results, HA state,
  drift, configs, recent audit and alert rows, a log tail) to attach to a bug
  report; a test asserts no secret survives redaction.
- **OIDC group → subnet scope** — an SSO login can be scoped to subnets from
  its groups; blank configuration stays unrestricted, and an unmatched login
  gets no subnets unless a default says otherwise.
- **The legacy root grant** — Settings → Kea → SSH has a Remove legacy grant
  button (the grant deletes itself, refusing unless the helper's own sudoers
  file is valid) and a by-hand box with the grant and revoke commands.
  Jen never adds the grant back: handing itself root stays a manual act.
- **Two rounds of audit fixes**, each checked against the code: a subnet-scoped
  user or key can no longer reach a client's lease or reservation in a subnet
  they cannot see (including a client that moved subnets, devices Jen has never
  placed, and address-only rows), Trace and Doctor need access to all subnets,
  the API's device writes and docs page respect scope, and one authorization
  matrix test now drives every diagnostic page and API endpoint for every kind
  of caller.

### Migrate

- **Import from ISC DHCP** — upload a `dhcpd.conf` (subnets, ranges, shared
  networks, hosts, classes, pool allow/deny) through the same review → preview
  → apply wizard the Windows importer uses; every directive it cannot map is
  listed with its line number, and `dhcpd.leases` is counted, never imported.
  A deterministic fuzz and a real-file fixture harness guard the parser.
- **Dual-stack views** — the Dashboard and Devices pages show IPv4 and IPv6
  together, and the IPv6 subnet edit page is folded into the IPv4 one.

### Diagnose

- **Explain** — "why did this client get this?": subnet, reservation, matched
  classes, eligible pools, the answer address and every option with its source,
  saying plainly what it cannot evaluate.
- **Configuration Doctor** — contradictions, unused objects and risky settings
  in the live Kea config that `kea-dhcp4 -t` cannot see.
- **Timeline** — everything recorded about one client, newest first: events,
  config changes, alerts, its lease and reservation. A MAC timeline shows only
  that client's rows (a reused address never merges the previous holder's
  history), and an IP timeline is about the address and labels earlier holders.
- **Trace** — what Kea actually logged for one client, in plain English, read
  through the helper's `tail-log` (no packet capture); admin-only, all-subnets
  only, helper-only, with a 15-second bound.
- **DNS ↔ DHCP Reconcile** — every reservation and lease name checked against
  forward and reverse DNS, read-only, with a verdict per row (including
  `lookup-failed` for a resolver that could not answer and an informational
  `multiple-a`); one bounded worker pool, single-flight.
- **Packet health** — drops, parse failures and NAKs per server from Kea's own
  counters, restart-aware, with the eight extra drop reasons Kea 3.2 adds
  (names read from a real 3.2 run), a Health check and an alert pair.
- **Exhaustion forecast** — which pools run out and when, from lease history,
  on Reports, in Health, and as an optional alert.

### Operate

- **Planned maintenance** — a guided stepper for taking one HA server down
  and back; it also fixes the old "Start Maintenance" button, which named the
  wrong server.
- **Kea 3.2 readiness** — a Health group and a one-line Servers summary for
  what to change before the Control Agent goes away.
- **Recovery bundle** — one encrypted file with config, keys, content and the
  Jen database (including which migrations ran); `install.sh --restore` is a
  lifecycle: it stops Jen, snapshots what it replaces, applies, restarts, waits
  for a real 200-with-JSON health answer, and rolls back on any failure.
  `--rollback`, `--no-stop`, `--start` and `--force` are its flags.
- **Grafana dashboard** and API health endpoints (`/api/v1/health/checks`,
  `/api/v1/health/readiness`) for monitoring.
- **`no-store` and clearer cards** — every database and bundle download is
  never cached, and the Recovery card is visibly not the redacted support one.

### Plugins and API

- **`jen.plugin_api`** — the single versioned import surface for plugins (with
  an event stream: `subscribe`, `unsubscribe`, run on one bounded worker), and
  the bundled IPAM Lite 1.5.1 and Network Discovery 1.1.1 use only it.
- **API v1 writes**, behind a per-key "Allow writes" flag (off by default),
  plus `GET /api/v1/openapi.json`, servers, events and timeline endpoints.

### First hour

- **Getting started** — a checklist with a nav reminder a superadmin can
  dismiss, empty states on list pages, and an admin-guide Runbooks section.

### Tests and CI

- A Playwright suite of browser journeys (login, MFA and passkeys, subnet and
  class editing, both import wizards, HA maintenance, API keys, support bundle,
  Health, Doctor, Timeline, Trace, Reconcile, Getting started), and a weekly
  real-Kea workflow that runs Jen's client against Kea 3.0.3, 3.2.0 and 3.3.1.

## [5.32.0] - 2026-09-14

### Release channels: beta first, stable on promotion

5.31.0 needed three same-day patches, each found by the maintainer on
the box minutes after installing. That is what a beta channel is for.
From this release on, every feature release is published first as a
**pre-release** — `5.33.0-beta.1`, then `-beta.2` if something needed
fixing — and becomes the **stable** `5.33.0` only when it has been run
for real and promoted. The stable release is the last beta with
nothing but the version number changed.

**What an install chooses.** Settings → System → Updates gains a
release-channel selector (superadmin, password confirmation):
`stable`, the default, is offered only stable releases; `beta` is
offered the newest release of either kind. The choice is stored as
`[updates] channel` in `jen.config` rather than the database because
the root-privileged updater reads the INI file and never the database
— both halves of the updater now read the same key, so they can never
disagree about what to install. Switching back to stable never
downgrades: the box keeps the beta it is running until a stable
release is newer than it. A beta is the same signed tarball through
the same checksum and signature verification, the same staged install,
the same rollback; the difference is soak time, not safety.

**One version parser.** Five places used to parse a version string
independently, each assuming three plain integers; a suffixed version
would have parsed as `0.0.0` in the update check, been refused by
plugin `requires_jen` gating, and sorted wrongly on the About page.
`jen/version.py` is now the single parser for the grammar `X.Y.Z`,
`X.Y.Z-beta.N` and `X.Y.Z-rc.N`, ordered the way semver does
(`5.31.3 < 5.32.0-beta.1 < 5.32.0-rc.1 < 5.32.0`), and it carries the
channel-aware release picker, which chooses by parsed tag rather than
by list position — GitHub lists releases by creation, not by version.
The root updater cannot import the package, so it embeds a
byte-identical copy of the marked block and a test diffs the two. A
plugin that requires Jen `5.33.0` loads on `5.33.0-beta.1`: the
comparison is on the numeric version, because the beta *is* that
version, early.

**Both discovery paths list releases now.** The Updates page check and
the root updater used to ask GitHub for `/releases/latest`, which is
GitHub's own definition of "newest non-prerelease" — correct for
stable, blind to everything else. Both now fetch the release list and
filter per channel. The release workflow marks any tag with a
prerelease suffix as a GitHub pre-release and includes beta headings
in the generated release notes.

**Why this release is stable, not a beta.** An install older than
5.32.0 only ever asks for the latest stable release, so a 5.32.0 beta
would have been invisible to every box that exists. This one ships
straight to stable to bootstrap the channel; the next release is the
first to go through it.

The admin guide's "Upgrading Jen" section documents the channels and
the `[updates]` config section; `plugins/README.md` records the
`requires_jen` rule; CONTRIBUTING.md and CLAUDE.md carry the
maintainer's release flow.

## [5.31.3] - 2026-09-14

### The MFA challenge page's script didn't run at all

Reported by the maintainer on the next login after 5.31.2: on the
verification page the Passkey / Authenticator / Backup Code tabs
didn't switch, ticking *Remember this device* on the Passkey tab
never showed the "for how long" choice, and **Use passkey →** did
nothing.

One cause: the passkey code added in 5.31.0 had an unescaped
apostrophe inside a single-quoted JavaScript string (`'Follow your
browser's prompt…'`). A syntax error anywhere in a `<script>` block
means the browser runs none of it — and the tab switching and the
remember-toggle handlers, which predate passkeys, live in that same
block. The string is double-quoted now.

The suite never saw it because every test read the HTML from Python
and none executed the JavaScript. A new test renders the three MFA
pages through the app (every factor combination of the challenge
page) and hands each inline script to `node --check`; GitHub's
runners ship node, and the check skips rather than passes where it's
absent. The nonce-based CSP means Jen can't lean on the browser to
report this either — a page that fails to parse fails silently.

### A wider spread of "remember this device for"

Every tab of the challenge page — Passkey, Authenticator, Backup
Code — now offers the same choices: 24 hours, 7, 14, 30 (default),
60, 90, 120 days, or forever. The server side already accepted any
day count; only the three menus were narrow.

## [5.31.2] - 2026-09-14

### "could not start the passkey check" on the first real passkey

Reported by the maintainer minutes after 5.31.1: enrolling a passkey
worked, but **Use passkey** on the step-up page (and the Passkey tab
at login, same code) answered *could not start the passkey check —
see the Jen log*. The log showed py_webauthn's option serialiser
failing on `allowCredentials`.

At enrolment the browser reports which transports the authenticator
supports — Windows Hello says `["internal"]`, a phone via QR says
`["hybrid"]`, a YubiKey `["usb", "nfc"]` — and 5.31.0 stored that list
so later `get()` calls could hand it back and let the browser pick
the right authenticator without prompting for every kind. Storing it
was right; reading it back wasn't: the list came out of the database
as plain strings, and py_webauthn requires its `AuthenticatorTransport`
enum there (it calls `.value` on each entry while building the JSON).
The test suite never hit it because every faked enrolment reported no
transports at all.

The stored list is now converted to the enum on read; unknown or
malformed entries are dropped, and an unusable list becomes "no
hint", which the browser handles by trying everything. The round-trip
test now enrols with `["internal", "hybrid"]` and asserts the
authentication options carry them back out — the exact call that
failed.

## [5.31.1] - 2026-09-14

### The TOTP enrolment QR code was a broken image — since v4.4.5

Reported by the maintainer on the first visit to Profile → Security
after 5.31.0: the "Scan with your app" square rendered as a broken
image. Not a 5.31.0 regression — it has looked like that since the
HTTP security headers arrived in v4.4.5 (2026-08-07), and the manual
secret next to it always worked, which is presumably why nobody said
so.

The cause is the Content-Security-Policy. The QR is a `data:image/png;
base64,…` URL (so are uploaded avatars), and the policy had no
`img-src` directive of its own, so images fell through to
`default-src 'self'` — and `'self'` does not include the `data:`
scheme. Every browser blocked the image and said so only in the
console. The header now carries `img-src 'self' data:`. Only images
get the scheme: a data: image can't execute anything under this
policy, and scripts, styles and everything else keep `'self'`.

Two tests keep it that way: the header must contain exactly that
directive and no other directive may pick up `data:`, and the
rendered enrolment page must embed a real base64 PNG (the `iVBOR`
magic), so a change to the QR library shows up here rather than on
someone's screen.

## [5.31.0] - 2026-09-14

### Passkeys as a second factor

The enrollment page has said *Passkeys (Coming Soon)* and the README
has said "planned" for long enough. Passkeys — WebAuthn / FIDO2:
Windows Hello, Touch ID and iCloud Keychain, Android, password
managers such as 1Password, Bitwarden and Keeper, and hardware keys
such as a YubiKey — now sit beside TOTP as a second factor behind the
password. Not passwordless login; the password stays the first factor
and that is a deliberate scope line, not a gap.

**What a user sees.** Profile → Security gains an **Add a Passkey**
card: name it, follow the browser's prompt, done. A passkey can be the
first factor (forced enrollment accepts one exactly like an
authenticator app, and issues backup codes the same way) or an
addition beside TOTP. The login verification page opens on a
**Passkey** tab when one is enrolled, with Authenticator and Backup
Code still there; "remember this device" works for all three.
Step-up confirmations accept a passkey in place of a code. Removing
the last factor is refused while MFA is required, and both admin
"Reset MFA" routes clear passkeys with everything else.

**What is under it.** `jen/services/passkeys.py` on py_webauthn 3.x.
The relying-party id and origin are derived from the request Jen is
serving — the hostname users type, without the port; the scheme the
trusted-proxy middleware already corrected — pinned into a single-use
session state with a five-minute expiry when the challenge is issued,
and verified against on the response. The state is popped before
verification, so a failed attempt can't be replayed. Only the public
key, credential id, signature counter and name are stored (migration
24 adds nullable `transports` and `aaguid` to the table the v4.2.0
baseline already had); a counter that doesn't advance is refused as a
cloned authenticator. Failed assertions count toward the existing
10-attempt MFA lockout. Every `<script>` is nonce'd as the CSP
requires; the page feature-detects WebAuthn and a secure context and
says plainly when plain http is the reason nothing happens.

**What an operator must know.** A passkey is bound to the address
users type — rename or re-address Jen and every passkey has to be
enrolled again. Browsers only create passkeys on https (or
localhost). Both are in the admin guide's new "Passkeys" subsection
and a troubleshooting entry.

Housekeeping folded in: the two duplicated "second factor verified"
blocks on `/mfa/verify` became one helper shared with the passkey
path (the trusted-device cookie is set in one place now — the
source-scanning test that counted four `set_cookie` calls counts two),
and `mfa.user_factors()` reports TOTP and passkeys separately so a
page only offers what the user actually has.

## [5.30.0] - 2026-09-13

The plugin release. IPAM Lite v1.5.0 and Network Discovery v1.1.0 both
draw on things Jen already knows — the gateway and DNS servers, the
DHCP pools, the devices table, the Kea and Jen hosts' own addresses —
and on an OS package (nmap) that only root can install. Rather than
each plugin re-deriving that, this release gives plugins three small,
deliberate hooks, and ships a guard Jen's own exports needed too.
Nothing here changes behaviour on an install that has no plugin asking
for it; the plugins that do require this version.

### Plugins can declare the OS packages they need — and Jen installs them

A manifest may list `"os_packages": ["nmap"]`. Settings → Plugins then
shows *needs on the Jen host: nmap* with an **Install** button on a
systemd host, or the `apt install` command anywhere else. The web
process never runs `apt`: the button writes an empty `<id>.deps`
marker and triggers the same zero-parameter root-run service that
installs plugins (v5.27.0); that script re-derives the package list
from the registry it fetches itself, refuses anything outside a
built-in allowlist (`nmap`, today — the allowlist is the control,
exactly like the Kea helper's op table) or not shaped like a Debian
package name, and reports back through the same result file the
install flow uses. The sudoers grant is unchanged. Docker keeps the
command.

### Plugins can schedule work without owning a thread

`create_app()` must not start background work — so a plugin that
wants "scan this subnet every N hours" had no honest way to do it.
`jen.services.background.register_periodic(plugin_id, name, fn,
every_minutes)` registers a callable at `register(app)` time; the one
periodic loop Jen starts (only in the real entrypoint, never in the
factory or the test suite) runs each job on its interval in its own
thread, records a failure on the job instead of propagating it, and
skips a run that's still going rather than stacking another.

### One call for everything Jen knows about a subnet

`jen.services.subnet_context.subnet_context(subnet_id)` returns the
gateway(s) and DNS servers from the effective DHCP options (global →
shared-network → subnet), the pools, network and broadcast, the Kea
servers' and the Jen host's own addresses inside the subnet, the
subnet's notes, and an `infrastructure` map from address to what it
is — behind one 30-second-cached `config-get`. IPAM Lite uses it to
stop calling the gateway "available"; Network Discovery uses it to
stop calling the gateway "rogue".

### CSV exports can't smuggle a formula

A spreadsheet opens a CSV cell that starts with `=`, `+`, `-` or `@`
as a formula, and every export cell Jen writes is operator- or
device-supplied text — a DHCP hostname of `=HYPERLINK(...)` would
execute on the operator's machine when they opened the file. The
reservation export (both variants) now quotes such cells, through a
small shared helper both plugins' exports use as well.

`plugins/README.md` documents all three hooks; `docs/ARCHITECTURE.md`
§3.10 records the dependency path's trust boundary.

### The plugins themselves: IPAM Lite v1.5.0, Network Discovery v1.1.0

The registry pins both new releases and the bundled copies under
`plugins/` are resynced byte-for-byte to the tagged zips (the
lockstep test from v5.28.2 keeps it that way). Each plugin's own
CHANGELOG has the detail; the short version:

- **IPAM Lite v1.5.0** — the gateway, DNS servers, Kea and Jen hosts
  and network/broadcast show as *infrastructure* instead of
  *available*; a static or planned address that a DHCP client
  currently holds is a *conflict*; the address list collapses long
  runs of available space and offers "next free" (in or out of the
  pools); every row shows Jen's device name and vendor; a range of
  addresses can be designated at once; per-address history; a Netbox
  CSV export; unmanaged subnets take an optional gateway. Migrations
  14–15.
- **Network Discovery v1.1.0** — a found host is no longer "in Kea or
  rogue": it is a lease, a reservation (this subnet's or a global
  one), infrastructure, an IPAM entry, a device Jen has seen, one you
  marked known, or — only then — unknown. The gateway stops being
  reported as rogue. Vendor from the OUI table, since-last-scan
  changes, scheduled scans, an **Install nmap** button through the
  new dependency path, MAC-keyed alerts so an IP hop doesn't re-alert,
  subnets above a /20 refused with a reason and the failure reason
  stored. Migrations 3–9.

Both require this version, so an install on 5.29.x keeps the
previously pinned 1.4.6 / 1.0.7 until it upgrades.

## [5.29.3] - 2026-09-13

### Fix: "Set up direct socket" probed before the daemon was listening

The maintainer's first https setup did everything right on the Kea
side — CA created, certificates pushed, `kea-dhcp4.conf` updated,
daemon restarted — and then reported *"didn't answer a version-get
(Connection refused)"*. `systemctl restart` returns as soon as the
process is up, but kea-dhcp4 opens its HTTP listener *last*, after
parsing the config and connecting to the lease database — a few
seconds with MySQL — and Jen probed exactly once, immediately. The
probe after a restart is now retried for about fifteen seconds (eight
attempts, two seconds apart, stopping at the first answer), in the
setup flow and in Rotate Kea CA alike; a socket that genuinely never
answers says so with the attempt count. As before, a failed probe
changes nothing in Jen and re-running the form only re-probes.

And for the state that leaves behind — Jen still pointed at the
Control Agent, a certificate already issued for the daemon — the
**Probe** button now also tries the https socket Jen set up (the bind
address from the certificate it issued, the conventional port, Jen's
CA and client certificate) and says either that it answers as the
daemon, so re-running the form will switch Jen over, or that it
doesn't, with the reason and the `journalctl` command to look at on
the host.

## [5.29.2] - 2026-09-13

### Fix: "Update helper" answered "v3 is already installed"

v5.29.1 put the **Update helper** button back in front of a v3 host,
but pressing it came back with *"jen-kea-helper v3 is already
installed"*: `install_helper()` still decided "already" against the
same want version (2) the button used to be gated on. It now targets
the `HELPER_VERSION` declared by the helper file it is about to copy —
the only honest "what will the host report afterwards" number — for
the already-installed short-circuit, the manual-copy hint, and the
post-copy re-check alike. A v3 host on a v4 install now upgrades; a
v4 host still gets "already installed". Second same-day patch for the
same gate; the test now covers the exact case.

## [5.29.1] - 2026-09-13

### Fix: no way to update the host helper to v4 from the UI

v5.29.0's https socket option needs the v4 host helper and says so —
but the **Update helper** button in Settings → Kea → SSH only appeared
for a host below `JEN_HELPER_WANT_VERSION`, which is still 2 (the
v5.23.0 decision not to nag every operator about a helper version only
an optional feature needs). A host on v3 therefore showed a green
`v3`, no button, and an https option that pointed at a button that
wasn't there — the maintainer hit exactly this on the first try. The
table now offers **Update helper** whenever a host is below the helper
version this install ships (a new `JEN_HELPER_SHIPPED_VERSION`, pinned
to the file by a test), with a neutral *"v4 available (needed for
https sockets)"* note; the amber "upgrade available" nag is unchanged
and still keyed to the want version. No change on the Kea host.

## [5.29.0] - 2026-09-13

One of Jen's goals from the start has been that an operator should
have to edit as few `.conf` files as possible — fill in the options,
let the app fix the files. The one place that promise was still broken
was the move off Kea's Control Agent: ISC deprecated it in 3.0 and
removes it in 3.2, and switching to per-daemon control sockets meant
hand-editing `control-sockets` in three config files, restarting three
daemons, and — as the maintainer found on 2026-09-13 — a Probe
recommendation that said *what* to add but not *where*. This release
makes Jen do it, and gives the http-vs-https choice a real answer
instead of a warning.

### Jen sets up direct control sockets itself

Settings → Kea gains a **Set up direct socket** button for each daemon
on each server — kea-dhcp4 on the Control Plane card, kea-dhcp6 on the
Kea6 card, kea-dhcp-ddns on the D2 card, and each additional server's
own row. The form needs almost nothing (a bind address that defaults to
the server's SSH host, a port that defaults to 8004/8006/53001, the
credentials Jen already uses), and Jen does the rest on that one
server: adds the entry to the daemon's `control-sockets` (the `unix`
entry stays), validates with `-t`, writes, restarts, then **probes the
new socket** — a `version-get` and then a `config-get` that must answer
*as that daemon* — and only then writes its own settings: the URL,
`connection_mode = direct` for kea-dhcp4, and for https the trust
anchor and client certificate. A failed probe changes nothing in Jen
and says exactly what didn't answer; running the form again just
re-probes. The Control Agent answering on the same host, `0.0.0.0`, a
hostname where an IP is needed, the agent's own port, and a Kea older
than 2.7.2 are all refused before anything is touched. The whole
change goes through the same multi-server change-set machinery every
subnet edit uses (v5.28.0), so a `-t` failure reverts cleanly. A
**Switch back** button per daemon reverses it: the entry is removed,
the daemon restarted, the remembered Control Agent URL restored, and
Jen returns to `ca` mode once no server is still on its own socket.

The Probe recommendation the maintainer hit ("add an http control
socket … conventionally :8004" — but where?) now names the file and
the key — an `http` entry in the `control-sockets` list of
`/etc/kea/kea-dhcp4.conf`, keeping the unix entry — and points at the
button; the Dashboard's "answered as the Control Agent" error does the
same.

### https with a Jen-managed private CA — mutual TLS, not the appearance of it

The security question behind "http vs https" for the Kea link is not
encryption alone: a control socket that accepts any client holding the
basic-auth password is exactly as strong as that password crossing the
wire, and ISC's own guidance is that over `http` it crosses in the
clear. Choosing **https** in the new form makes Jen a certificate
authority for that link. A private CA is created on the Jen host the
first time it's needed (`/etc/jen/ssl/kea-ca.crt` / `.key`, EC P-256,
10 years); a 5-year server certificate is issued per daemon (SAN = the
bind address and the SSH host) and pushed to
`/etc/kea/tls/<service>/{ca.crt,server.crt,server.key}` on the Kea host
through a new host-helper op, `install-tls` (helper protocol **v4** —
the op writes exactly those three basenames under that fixed
directory, owned `root:<daemon group>` with the key `0640`, refuses
symlinks and anything not PEM-shaped, and has deliberately no
legacy-path equivalent: certificate keys never travel in a generated
root script); Jen's own client certificate goes to
`/etc/jen/ssl/jen-kea-client.pem` / `.key`; and the socket is written
with `cert-required: true`, so the daemon accepts *only* Jen. The
material is pushed before the config that references it is applied,
and the apply names the three files, so a missing one is a `tlsmissing`
refusal rather than a daemon restarted into a config it can't load.
One CA serves every server. Health Center gains a **Kea mTLS
certificates** check (warn at 90 days, fail at 14 or expired, and fail
outright if Jen's client certificate isn't signed by the current CA),
and the Control Plane card shows the CA, its expiry, and every
certificate issued, with a **Rotate Kea CA** button: superadmin, asks
for your password again, and all-or-nothing — the new CA and client
certificate are staged beside the live ones, every server is pushed,
restarted and probed with the staged material, and only when all of
them answer is the new CA adopted; a failure part-way re-issues the
already-pushed servers from the still-current CA. The https option
needs the v4 helper on that host (the SSH card's Update helper) and
says so; http works with any helper version. An operator who already
runs their own CA keeps it — Jen refuses to overwrite a CA bundle that
isn't its own, and the by-hand https setup is unchanged.

Why a private CA rather than Let's Encrypt, and the tradeoff of the CA
key living on the Jen host (readable by the service user that already
holds the SSH key pushing root-level config to every Kea host — no new
capability, only persistence, which Rotate revokes), are recorded in
`docs/ARCHITECTURE.md` §3.12.

### Under the hood

The control-socket entry the author-from-blank flow has written since
v5.10.2 is now built by one shared function, `build_control_socket()`,
used by both that flow and the new `set_control_socket()` /
`remove_control_socket()` config mutations — one shape, key order
included, verified byte-identical against the pre-refactor output. A
singular pre-2.7.2 `control-socket` map is converted to the list form
in place (same position in the daemon block; the unix entry kept
verbatim), and a Control Agent's own `control-sockets` *map* is refused
so the wrong daemon's file can never be edited as a list.
`kea_changeset.apply_change()` accepts `tls_paths` and passes them to
both the preflight and the commit. The atomic tmp+replace PEM writer
the SSL upload used moved to `jen/services/certs.py` so the CA shares
it. New tests: `test_settings_direct_socket.py` (the http flow, every
refusal, switch-back, the https flow's ordering and material,
Rotate's staging/promotion/rollback, the page's per-server gating),
`test_kea_tls.py`, `test_kea_helper.py::TestInstallTls`,
`test_kea_host.py::TestInstallTls`, and the Health check's bands.

## [5.28.2] - 2026-09-13

Plugin cleanup, prompted by finally bringing the two plugin repos
(`jen-plugin-ipam`, `jen-plugin-network-discovery`) back in sync with
Jen. Both had drifted from the copies bundled here for a year in both
directions; reviewing them turned up real bugs on both sides.

### Plugin migrations were MariaDB-only

A plugin's `db_migrations` are plain SQL strings, and the only way to
write an idempotent `ALTER TABLE` in plain SQL was MariaDB's
`ADD COLUMN IF NOT EXISTS` / `DROP INDEX IF EXISTS` — which MySQL 8
does not have. The IPAM plugin used those forms for every schema
change since its v1.3.0, so on a Jen running against MySQL its first
`ALTER` was a syntax error and (since v5.28.1 gates activation on
migrations) the plugin never enabled. Jen supports both databases;
the shipped plugin only ever worked on one, and nothing noticed
because the bundled copy CI tests was the older v1.2.3, which had no
`ALTER`s yet.

`run_plugin_migrations()` now treats three specific errors — duplicate
column (1060), duplicate key name (1061), can't `DROP` because it
doesn't exist (1091) — as "the schema is already where this migration
puts it": it records the migration as applied and continues. That
gives plain, portable `ALTER`s the same safety the tracking table
already gave `CREATE TABLE IF NOT EXISTS` — a re-run, or a fresh
database that never had the index a migration drops, is not a
failure — while a genuinely wrong statement (syntax error, unknown
table or column) still fails exactly as before. IPAM v1.4.4 relies on
this and requires Jen 5.28.2; its manifest is now plain DDL in the
explicit `{version, description, sql}` form, with versions 1–13
mapping one-to-one onto the old positions so an existing install runs
nothing new.

### Bundled plugin copies resynced, and kept in sync by CI

The copies under `plugins/` are what a fresh install sees before the
registry is ever fetched, and what CI tests against. Bundled IPAM was
v1.2.3 (registry pinned v1.4.1); bundled Network Discovery still had
a post-scan prune whose `LIMIT` inside an `IN` subquery MySQL and
MariaDB both reject — so every scan that found hosts was recorded as
`error` — a bug the repo copy fixed today in v1.0.2. Both bundled
trees are now byte-identical to the tagged releases the registry pins
(IPAM v1.4.6, Network Discovery v1.0.7 — both repos also adopted Jen's
own ruff configuration and pinned ruff version, so a resync can never
fail Jen's lint), the never-used bundled
`plugin.zip` files and the pre-v5.13.0 `.enabled` marker are gone, and
a new test fails CI if a registry re-pin ever lands without a resync
(or vice versa): bundled manifest version, description, `requires_jen`,
`db_migrations` and nav must equal the registry entry's. Each plugin
repo also gained its own CI (`tools/verify.py`) that rejects a
release whose `plugin.zip` isn't a byte-for-byte rebuild of the tree,
any inline event handler or un-nonce'd `<script>` (both dead under
Jen's CSP since v5.22.0), and a manifest version that doesn't match
the top changelog entry.

Highlights of what the plugin releases themselves fixed, for anyone
updating them from Settings → Plugins: IPAM's unmanaged subnets now
honor Jen's subnet restrictions (a subnet-restricted viewer could
previously read and edit all of them); Network Discovery now reads the
kernel neighbour table after its unprivileged nmap sweep, so every
live host on an attached subnet is found with its MAC and the Kea
cross-reference works by MAC rather than IP alone, alerts fire only
for unknowns the previous scan hadn't seen, and a scan orphaned by a
Jen restart no longer shows "Scanning…" forever.

## [5.28.1] - 2026-09-13

Review follow-ups: a maintainer-reported dashboard bug plus ChatGPT's
independent review of v5.28.0, all confirmed against the code before
being fixed.

### A rollback failure message that read backwards

`kea_changeset.py`'s multi-server rollback, when a revert itself
failed, reported the affected server as simply "revert failed" — with
no indication of which config that server was actually left on. Read
naively, that phrasing suggests the server is back on its old config
and something separate went wrong; the truth is the opposite: a
"failed" revert means the server's own revert call didn't go through,
so it **still has the NEW config** — the one the whole change set was
being rolled back away from. An operator following the old message's
apparent meaning would restore the wrong servers. The message now
names three groups explicitly: which servers still have the new
config (the ones whose own revert failed), which were successfully
rolled back, and which were never touched at all (the one whose
original commit failed first and triggered the revert). A revert that
succeeds but whose own service restart then fails is now its own
warning line too, rather than folding into either "success" or
"failure."

### Two fail-closed gaps in the write path

A v1-helper or legacy-engine host's optimistic-concurrency check —
Jen's own best-effort re-read-and-compare, used where a v2 helper's
atomic `expect_sha256` guard isn't available — used to let a write
proceed when the re-read itself failed (host unreachable, SSH error),
on the reasoning that a transport failure isn't evidence of a real
conflict. In practice, the one host Jen couldn't verify was exactly
the one it wrote to regardless: an unreachable host now refuses the
write outright. Separately, a v1/legacy `apply_config()` success used
to return no `sha256` at all; `kea_changeset`'s own rollback stores
that value to guard its *later* revert call, so with nothing to store
that later write was completely unguarded. It now backfills the same
canonical sentinel a read would produce, computed from what was just
written.

### Restart failures no longer look like success

A restart failure in a multi-server change used to append a line
reading "✅ … restart Kea manually" — a checkmark next to a problem —
while the change set's own `status` stayed `"ok"`, identical to a
clean run. It's now a warning line with no checkmark ("… did NOT
restart"), and `restart_failed` is its own status distinct from `ok`,
even though it's just as safe for Jen's own bookkeeping (the config
did apply). Nine call sites across `routes/subnets.py` that used to
compare a bare status string now check the full result and append a
"restart failed on …" suffix to their own audit detail.

### Plugin lifecycle: retry-safe, restore instead of discard, and migrations that actually gate

Three related gaps in the plugin request/install path, all found by
tracing what a crash or exception at each specific point would lose:

- `consume_plugin_results()` used to delete a root-run result file
  *before* applying it — a crash or exception in between lost the only
  authoritative record of what the privileged side actually did. It
  now applies first and deletes only once that succeeds, retrying on
  the next call if it doesn't (safe, since every state change it makes
  is idempotent).
- `jen-update-root.py`'s startup sweep for stale `.staging-`/`.old-`
  plugin directories (v5.28.0) had the same shape of gap one step
  earlier: a crash in the exact window between the crash-safe swap's
  two renames — live moved aside to `.old-<ts>`, staging not yet moved
  into place — left no live directory at all, and the old sweep simply
  deleted the `.old-<ts>` right along with the never-verified-complete
  staging copy, discarding the one intact copy that existed. It now
  restores the newest `.old-<ts>` back to live when that happens,
  rather than just deleting it.
- A plugin's own database migrations now actually gate whether it
  activates. Through v5.28.0, a failing migration only ever logged
  loudly (the v4.4.19 fix) or, on the root-owned install path, was
  reported back but the plugin was enabled anyway. A fresh install
  (in-process or root-owned) whose migration fails is now left
  disabled with a red "migration failed — not enabled" chip on the
  Plugins page; on Jen restart, a plugin whose migration fails is
  skipped entirely **unless this exact version already migrated
  cleanly once before** — the original v4.4.19 case (a manifest-format
  or unrelated-table quirk on an already-working install), which still
  loads exactly as it always has.

### The Windows DHCP import wizard's plan gains an explicit state

The import wizard's in-memory plan now tracks which step it's actually
at (uploaded → previewed → config-applied-but-restart-failed →
complete) instead of inferring it from which fields happen to be set.
Apply refuses unless the plan is genuinely in "previewed" — catching
both a call made too early and a second Apply after the config already
went live — and the reservation-retry route (for a restart failure)
refuses unless Apply's own restart genuinely failed, re-reading the
primary's live config and comparing it against what was actually
applied before adding anything. The retry window is now a fresh 30
minutes from the moment the restart failed, not the original upload,
and the result page is explicit that re-importing the export is *not*
a way to recover a missed window — the importer skips any scope whose
CIDR already exists in Kea before it ever reaches that scope's
reservations, so a second import would add none of them back.

### A dashboard bug reported by a maintainer, traced to direct-mode identity

A maintainer reported the dashboard rendering blank in `direct` mode.
Traced live against a real host: `connection_mode = direct` was set,
but only the daemon's `unix` control socket had ever been configured —
`api_url` was still reaching the Control Agent on `:8000`. Direct mode
sends no `service` field, so the Control Agent answered `version-get`
identically to a real per-daemon socket (same version string, hence
"Connected"), but `config-get` came back as the Control Agent's own
config with no `Dhcp4` key — every page reading live Kea data went
quietly blank with no error anywhere. Three fixes: `kea_command()` now
treats a direct-mode `config-get` that answers as the wrong daemon as
an error naming which daemon actually answered; the Kea probe
identifies the same mismatch before recommending direct mode as
"working" (a warning below Kea 3.2, where the Control Agent is still
usable while the sockets get added; a hard error at 3.2+, where it's
removed outright); and the Dashboard and Subnets pages both show a
plain banner instead of silently leaving gateway/DNS/pool fields
blank.

## [5.28.0] - 2026-09-13

Audit rollup 3 — the stabilization pass before a feature freeze. Source:
ChatGPT's independent review of v5.27.0 plus one finding of our own that
turned out to be the most serious item here.

### A root-owned request writing its own result file, as root, by path

`jen-update-root.py`'s plugin-request processor (v5.27.0) wrote its
`<id>.result` file as root into `/var/lib/jen/plugin-requests/` — a
directory `www-data` owns. A compromised web process could pre-create
that result path as a symlink to anywhere on the box, or replace the
whole requests directory with one, and have root follow it on the next
plugin install/remove — truncating or overwriting an arbitrary file.
Fixed with `os.lstat`/`stat.S_ISDIR`/`stat.S_ISREG` checks before
trusting any path in that directory, and `O_CREAT | O_EXCL | O_NOFOLLOW`
for the result write itself, so root never follows a symlink planted
there. A directory named like a marker is left alone rather than
processed or deleted; a symlinked marker is unlinked, never followed.

### Plugin lifecycle: "queued" no longer means "done"

Installing or removing a plugin used to record the database row, set
`restart_pending`, and audit the action the moment the request was
*queued* — before the root-privileged service had actually run it. A
request that then failed root-side still looked like a success
everywhere except a result file nobody read, and — worse — a plugin
installed through the v5.27.0 root path could never actually be
enabled, because `_plugin_dir()` never looked in the root-owned
directory `enable_plugin()` needed to find it in. Both are fixed:
`consume_plugin_results()` is now the only thing that applies install/
remove state, called from both the page render and the status poller,
and only once a `.result` file (renamed `<id>.<action>.result`, so
install and remove can't collide) confirms the root side finished. The
plugin-install trigger's own failure is now checked and surfaced
("Could not start the plugin install service — run `sudo ./install.sh`
to repair jen-sudoers and jen-plugin-install.service") instead of
silently assumed to have worked. A plugin's own `requires_jen` version
requirement is now enforced on the root side too, and the plugin
directory swap during an install is crash-safe (rename-old-aside,
rename-staging-in, delete-old — never delete-then-create), with a
startup sweep for `.staging-`/`.old-` leftovers from an earlier crash.

### The legacy Kea-host engine trusted stdout, not the exit code

A host still on the pre-5.11.0 `sudo python3` fallback determined
success or failure by pattern-matching the remote script's stdout — and
`service_action`'s restart path appended an unconditional trailing
token after `cmd1 || cmd2`, so it printed "done" whether or not systemd
actually restarted Kea. Every legacy call site now reads the real SSH
exit status (read after stdout/stderr, since `paramiko` blocks on it
until the channel closes) and trusts stdout only when that status is 0.
Separately, a v1/legacy host's optimistic-concurrency check ran, when
it ran at all, **after** the write had already gone out — a stale-config
guard that closed the barn door after the horse left. Every caller now
goes through one pre-write `_jen_side_conflict()` check that compares a
canonical-hash sentinel before anything is sent to the helper.

### Multi-server config pushes are now all-or-nothing

Every route that edits a subnet, shared network, DHCP option, client
class, or DDNS/D2 setting used to push to each SSH-configured Kea
server independently — read, mutate, apply, restart, one server at a
time, with no idea whether an earlier server in the same request had
already committed. A validation failure or concurrency conflict on
server B left server A's write in place, sometimes with Jen's own
`SUBNET_MAP` recording a change that didn't actually land everywhere.
`jen/services/kea_changeset.py` is now the one place this logic lives:
every target is preflighted (`kea-dhcp4 -t`) before the first real
write, targets are committed in order, and if one fails, every
already-committed target is reverted back to what it was — a revert
that itself fails is reported as "🛑 ROLLBACK FAILED" rather than
hidden. A restart failure is reported per-server and never reverts an
already-valid config. The Windows DHCP import wizard's Apply step now
reuses this same discipline in miniature: it pushes exactly the config
Preview already tested, and refuses if the live config moved since or
Preview never actually passed.

### The Windows DHCP importer, against a real export

The v5.24.0 importer was validated only against a hand-authored fixture
built from Microsoft's documented export shape — every field as an XML
*attribute*. A real `Export-DhcpServer` file puts every field in a
*child element* instead, so the shipped parser read nothing from one:
zero scopes, every reservation skipped, an empty preview, and a 500 on
the review page. A maintainer-supplied real export (sanitized into
`tests/fixtures/windows-dhcp-export-real.xml`) exposed all of this, plus
several real-world shapes the synthetic fixture never exercised:
reservation `Type="Both"` (Windows' own default, "DHCP and BOOTP" — Kea
only speaks DHCP, so it's just a reservation) was being silently
skipped; a reservation's own per-reservation DNS-server override wasn't
read at all; options 51/58/59 (lease/renewal/rebind timers) were being
written as plain `option-data` instead of the subnet's actual lease
timers; option 81 (client FQDN flags) isn't option-data at all — it's
DDNS behavior; and a vendor/user-class-scoped option value needs a Kea
client class, not a plain value. All fixed, plus a broken/incomplete
scope (a missing required field) is now dropped with a warning instead
of reaching the pool math and raising `AddressValueError`, and the
review page catches any per-scope mapping exception instead of ever
500ing. Validated end to end against the real file: two scopes, 57
reservations (53 importable), per-reservation options. Exclusions,
superscopes, policies, and options 121/249 aren't present in the real
export we have, so those paths are still exercised only by the
synthetic fixture — read the preview diff before you apply.

### OIDC step-up, proper HTTP error pages, and DDNS IPv6 addresses

An OIDC-managed account has no usable local password — `find_or_create_user`
sets one to a discarded random value — so a route requiring a "recent"
login (MFA management, an unmasked config-history download) used to
send that account into a password form it could never fill in. It now
goes through a fresh sign-on round trip with the identity provider
instead (`prompt=login`, so the IdP can't silently re-assert an
existing session), confirming the same identity is still behind the
keyboard without creating a new session or re-running role mapping.

Separately, every `abort()`-raised HTTP error (400, 401, 403, 405, ...)
used to be caught by the same catch-all handler as an unhandled
exception, always rendering the generic 500 page regardless of the
real status — a 405 read as "Internal Server Error" and lost its
`Allow` header, a 401 lost `WWW-Authenticate`. A dedicated handler now
keeps the real status and headers for everything except a genuine 5xx.

And the D2 domain-server form now accepts a bracketed IPv6 address
(`[2001:db8::53]:53`) — a bare one was never parseable safely, since a
real IPv6 address can itself end in a colon plus digits, making a
trailing ":port" ambiguous without brackets. The DDNS naming form's
server address/port are now validated before being pushed anywhere; a
non-numeric port used to reach a bare `int()` and 500.

### What this release does not do

The external `jen-plugin-ipam`/`jen-plugin-network-discovery` registry
plugins still carry the Q18-era inline-handler CSP limitation — that
depends on those repositories' own next release, tracked separately.
The Windows importer's real-export validation covers what a real
export actually contains; exclusions, superscopes, policies, and
options 121/249 remain validated only against a hand-authored fixture,
not genuine `Export-DhcpServer` output.

## [5.27.0] - 2026-09-13

Root-owned plugin installs: a registry-installed plugin's files are no
longer writable by the running Jen process, closing the one remaining
persistence foothold a compromised web process would otherwise have.

### Root-owned plugin installs

Through v5.26.x, a registry-installed plugin was downloaded, checksum-
verified, and extracted by Jen itself, landing in `/var/lib/jen/plugins/<id>`
— a directory the running `www-data` process also imports code from on
every restart. A bundled plugin (`ipam`, `network-discovery`) was
already root-owned and read-only as part of the versioned release tree
(v5.14.0); a registry-installed one was not. A `www-data` process that
could get a malicious file into that directory by any means short of a
full root compromise — a bug elsewhere, a vulnerable dependency — had a
way to plant code Jen would load and re-execute indefinitely across
restarts.

`install_plugin()` / `uninstall_plugin()` (`jen/services/plugins.py`)
now use the same request/execute split the self-updater has used since
v5.2.6: on a real systemd host, they write an empty install/remove
marker and trigger a new `jen-plugin-install.service` unit — a second,
zero-argument-beyond-one-fixed-flag root `oneshot` running the same
already-hardened `jen-update-root.py`. That script re-derives the
plugin's tag-pinned download URL and checksum from `plugins/registry.json`
fresh, as root, the same verification `install_plugin()` always did,
and lands the verified files at `/opt/jen/plugins-installed/<id>`,
`root:root`, read-and-execute only for `www-data`. Nothing the web
process reads or writes reaches the privileged step as trusted input —
not even the registry entry it fetched moments earlier. Docker and dev
checkouts have no systemd unit to trigger this with and keep installing
plugins in-process, unchanged.

`discover_plugins()` gained a third scan tier for this between the
bundled tree and the legacy writable one; a plugin can exist in more
than one at once during the transition, and whichever was scanned last
wins, so an existing writable install keeps working exactly as before
until it's reinstalled. Settings → Plugins now marks each installed
plugin root-owned or "writable — reinstall to harden," with a one-click
Reinstall button that requests the move; the page polls a new
`GET /settings/plugins/install-status/<id>` route to show the result.
No enable/disable/uninstall workflow changed, and a plugin's own
database tables are never touched by any of this, matching the
existing "uninstall preserves data" behavior.

## [5.26.0] - 2026-09-12

Signed releases: from this version on, every Jen release is
cryptographically signed, and the in-app updater refuses to install
anything it can't verify.

### Signed release manifests

Through v5.25.x, `jen-update-root.py` (the root-owned self-updater)
verified a downloaded release by checksum alone — real protection
against a corrupted download, but not against a forged one. Anyone who
could publish an arbitrary `SHA256SUMS`/tarball pair to this
repository's releases — a compromised PAT, a hijacked Actions run —
could get every Jen instance's auto-updater to install it, since
nothing tied the checksum file back to a human decision to cut a
release.

`release.yml` now signs `SHA256SUMS` with `ssh-keygen -Y sign`
(ed25519) and publishes `SHA256SUMS.sig` alongside it. The private key
exists only as this repository's `RELEASE_SIGNING_KEY` GitHub Actions
secret — generated for this, never written anywhere else.
`jen-update-root.py` gains `verify_release_signature()`, checked
against `RELEASE_SIGNERS` (the public half, embedded as a permanent
trust root) before the — potentially large — release tarball is even
downloaded, let alone installed. No new dependency: `openssh-client`
is already a baseline assumption for every OS this project targets,
the same as the SSH-based config push it already relies on. A release
with a missing or invalid signature is refused outright, exactly like
a missing or mismatched checksum already was — there's no "signing
becomes mandatory later" transition window; v5.26.0 is both the first
release whose updater can verify a signature and the first one that
ships with one.

## [5.25.0] - 2026-09-12

Single sign-on: **Settings → Access & Security → Single Sign-On** lets
users log in through an OpenID Connect identity provider — Authentik,
Keycloak, Entra ID, Okta, or anything else that speaks the protocol —
with a role mapped from a claim, re-evaluated on every login. Local
accounts keep working exactly as before; this is an additional login
path, not a replacement. Also folded into this release: every table
that names a user by id now has a real foreign key, so deleting a user
can no longer leave orphaned rows behind.

### Single sign-on (OIDC)

A new `[oidc]` config section (optional, fully backward-compatible —
every field defaults to off) and migration 22
(`users.auth_provider`/`external_id`, unique on the pair) back the
whole feature. `jen/services/oidc.py` handles the parts that matter
most for correctness: `map_role()` picks the highest of
superadmin/admin/viewer among the groups a token's role claim actually
carries, and `find_or_create_user()` implements the linking rule this
was built around from the start — a repeat login is matched **only**
on the IdP's own `sub` claim, never on username or email, since both
of those can be reassigned or reused at an IdP in ways `sub` by
definition never is. A first login for a new `sub` creates a local
user row with a random, immediately-discarded password (never usable
for local login) and the mapped role; a username collision with an
existing local account is refused outright rather than guessed around
with an auto-suffix. `establish_session()` — the `login_user()` +
session-cache block that used to live only inside the local password
login route — is now shared code, so the SSO callback and the
password form can never drift apart on what "signed in" actually
means for session state.

The login page grows a **Sign in with SSO** button when configured
(hidden if a config typo left the client unregistered, rather than
linking to a dead route), and can hide the local password form
entirely — `/login?local=1` is always available regardless, as a
break-glass path if the identity provider is ever unreachable. A local
login attempt against an SSO-linked username is refused with the
exact same generic "invalid username or password" message a wrong
password gets, checked *before* the password comparison even runs, so
the login form itself can't be used to enumerate which accounts are
locally-managed. MFA is entirely the identity provider's problem for
these accounts: the callback never sets Jen's own MFA-pending state,
and the enrollment page says so instead of offering to add a factor
Jen would never actually check.

The Users page shows a badge on a linked account, disables its role
selector (the role is recomputed from the IdP on every login — a
manually-set one would just be overwritten anyway) and hides password
reset, and gains a superadmin-only **Link to SSO** action for
converting an existing local account by hand once its external ID has
been confirmed out of band. New admin-guide "Single sign-on (OIDC)"
section with Authentik/Keycloak/Entra ID setup notes (including Entra
ID's group-claims-as-GUIDs default) and the linking rules in full.

### Database foreign keys

Migration 23, folded in from an older backlog item: `mfa_methods`,
`mfa_backup_codes`, `mfa_trusted_devices`, `mfa_attempts`,
`webauthn_credentials`, `saved_searches`, and `dashboard_prefs` all
get a real `FOREIGN KEY ... ON DELETE CASCADE` to `users.id` —
checking the actual `delete_user` route first showed it runs no
manual per-table cleanup today, so this is the first thing that
actually enforces referential integrity here, not a belt-and-braces
addition to something already there. `api_keys.created_by` becomes
nullable with `ON DELETE SET NULL` instead, since an API key a
since-deleted user created should keep working, just with no
attributable creator. Any pre-existing orphan row is deleted before
its table's constraint is added (an orphan would otherwise make the
`ALTER TABLE` fail outright), and the whole migration is idempotent —
a fresh install and an upgraded one land in the same place.

## [5.24.0] - 2026-09-12

A guided path off Windows DHCP: **Subnets → Import from Windows DHCP**
(superadmin only) takes the XML `Export-DhcpServer` produces and builds
the Kea config it implies — scopes, pools, options, reservations, shared
networks, and a best-effort translation of the Windows policy engine
into Kea client classes — then shows you exactly what it would change
before it changes anything. No migration; this is a new wizard, not a
new config format.

### What it reads and how it maps

`jen/services/win_dhcp_import.py` parses the export with `defusedxml`
(a hand-authored `Export-DhcpServer` file is untrusted input the moment
it comes from someone else's DC, and `xml.etree` has no protection
against an entity-expansion bomb) and is deliberately tolerant of the
export's namespace and attribute-casing quirks, so an export copied
between Windows Server versions still parses. A scope's start/end range
minus its exclusion ranges becomes one or more Kea pools — a Windows
scope that excludes its entire range still imports, as a reservation-only
subnet with zero pools, since that's a real and legal Kea shape. Lease
durations, the option catalog already built for the DHCP-options page,
and MAC/IP reservations (skipping `Both`/`Bootp`-type entries and
anything without a real MAC — Kea's host database wants one) all
translate directly. A superscope becomes a Kea shared network only when
two or more of its scopes are actually selected for import; with just
one, it stays a plain top-level subnet, since Kea has no equivalent of a
single-member superscope. Windows policies — the piece with no direct
Kea analogue — become client classes built the same way the guided
class builder (v5.19.0) already expresses rules, with a policy's IP
range carving a guarded sub-pool out of the scope rather than gating
the whole subnet; anything that can't collapse to one Kea expression
(mixed `Equals`/`NotEquals` conditions, mostly) is skipped with a
warning rather than silently dropped or guessed at.

### The wizard itself

Upload → review → preview → apply, each step read-only until the last.
Review lists every scope with an include checkbox (active scopes
checked by default) and lets you adjust the subnet ID or name before
anything touches live state. Preview computes the merged config,
validates it with `kea-dhcp4 -t`, and shows a real diff against what's
running now — apply is refused if Kea would reject the result. Applying
pushes the config, restarts Kea, adds the queued reservations one at a
time through the live API (one bad row doesn't block the rest — failures
are listed at the end, same per-row error handling as the existing bulk
reservation CSV import), and registers the new subnets with Jen. It
only ever writes to the primary Kea server — an HA partner needs syncing
the way any other config change already does. In-flight import state
lives in a module-level dict keyed by a one-time token rather than a
database table, safe because Jen runs as a single gunicorn worker; it's
lost on a restart, same tradeoff as the existing config-history plan
cache.

### One honest caveat

No maintainer had a real Windows DHCP export on hand for this release,
so `tests/fixtures/windows-dhcp-export.xml` is hand-authored from
Microsoft's documented export shape rather than pulled from a live DC —
the parser's option-value decoding, especially the classless-static-route
bytes (option 121, and Microsoft's duplicate encoding of it at 249),
is reasoned through against the RFC rather than confirmed against
genuine `Export-DhcpServer` output. Run it against a lab Kea instance
before trusting it with production scopes, and treat the preview diff
as the real safety net it's designed to be — this is called out on the
wizard's own page too, not just here.

## [5.23.0] - 2026-09-12

DDNS becomes a first-class D2 subsystem: Jen can now configure and
monitor Kea's own `kea-dhcp-ddns` daemon, not just the external DNS
provider integrations it already talked to. No migration; `[d2]` and
`[ddns] mode` are both new, entirely optional config sections.

### D2 (kea-dhcp-ddns), end to end

The DDNS page grew from a single log-and-lookup screen into four tabs.
**Status** shows which mode is active (`provider`, `d2`, or `both` —
derived automatically from what's actually configured unless you set
`[ddns] mode` explicitly), per-server `dhcp-ddns.enable-updates`, and
D2's own up/version/statistics — read through the same live Kea API
`/servers` and Health Center already use, so it needs no SSH to
render. **Naming** writes dhcp4's own DDNS block and the ten knobs
that control how a hostname gets built and sent, pushed to every
SSH-configured server with a restart. **D2 Configuration** reads and
writes D2's own config file directly — add or remove forward/reverse
zones and TSIG keys, each push guarded by that specific server's
current config hash so a stale read elsewhere can't silently clobber a
change made in between, tested with `kea-dhcp-ddns -t` before writing,
same lifecycle as every other config edit in Jen. Reverse zone names
are suggested automatically for any subnet whose CIDR is a classful
`/8`, `/16`, or `/24`. **Verify** runs real forward/reverse DNS lookups
through the Jen host's own system resolver, so a green check means
what an ordinary client would actually see — not just what Kea thinks
it sent.

Settings → Kea gains a D2 Control Socket card (same shape as the
existing Kea6 one) for direct-mode deployments where D2 has its own
control socket separate from dhcp4/dhcp6. `jen-kea-helper`'s protocol
version moves to 3 — `"d2"` joins `"dhcp4"`/`"dhcp6"` as a recognized
service everywhere one is accepted; a host still on an older helper
gets a plain "needs v3+" message on the D2 tabs rather than a cryptic
helper error, and is never routed through the legacy root-SSH fallback
for D2 (that path's binary/unit-name logic would have silently treated
a D2 config as dhcp6's).

Viewers see the Status tab only — Naming, D2 Configuration, and Verify
are all either write surfaces or things without a matching read-only
view.

## [5.22.0] - 2026-09-11

`Content-Security-Policy`'s `script-src` no longer needs `'unsafe-inline'`
— every script on every page now runs off a per-request nonce instead.
No migration, no config change.

### A nonce for every script, and no more inline handlers

Every `<script>` tag across the app now carries a fresh, per-request
nonce (`jen/services/csp.py`, `g.csp_nonce`, exposed to templates as
`csp_nonce`), and the roughly 148 inline `on*=` handlers scattered
across templates and the two bundled plugins are gone — converted to
either a single delegated dispatcher added to `base.html`
(`data-confirm` for the existing confirm-dialog flow, `data-href` for
navigation, `data-submit` for submitting the closest form) or a named
function bound with `addEventListener`, delegated wherever the element
lives inside an HTMX-swapped partial rather than bound directly (a
direct binding doesn't survive the swap). `htmx.config.allowEval` is
now `false`, closing the eval-based escape hatch htmx otherwise keeps
open for `hx-on` attributes and `js:` expression prefixes this app
never used.

`style-src` is unchanged and still allows `'unsafe-inline'` — templates
carry over 1,200 inline `style=""` attributes, and hardening that would
mean rewriting the presentation layer, not converting a fixed,
enumerable set of event handlers. See `docs/ARCHITECTURE.md` §3.8 for
the full reasoning and the tradeoff this leaves open.

The change shipped in two steps so a missed conversion spot couldn't
take the app down: the nonce-based policy ran as
`Content-Security-Policy-Report-Only` alongside the old, still-inline-
permitting enforcing header first, then was promoted to enforcing once
nothing turned up. `tests/test_csp.py` now guards the whole thing going
forward — nonce present on every script, zero inline handlers anywhere
in the app (checked repo-wide), no `javascript:` hrefs, and the header
nonce always matching what the page actually renders.

### Registry-installed plugin copies are not fixed by this release

`plugins/ipam/` and `plugins/network-discovery/` bundled in this repo
got the same conversion as every other template. The plugin *registry*
(Settings → Plugins) installs each plugin from its own separately
versioned repository, pinned to a release tag that predates this work
— installing or updating either plugin from the registry still pulls
the old templates with inline handlers. Under the new script-src those
buttons simply do nothing (no error, no crash) until each plugin's own
repository ships this same fix and `plugins/registry.json` is re-pinned
to a new tag in a later release. Anyone running IPAM Lite or Network
Discovery from the registry should expect this until then.

## [5.21.1] - 2026-09-11

Plugin installs now verify a real checksum unconditionally — closing
the last gap flagged when checksum verification first shipped in
v5.3.3. No migration, no config change.

### A missing plugin checksum is now refused, not a warning

Installing a plugin has checked its downloaded `plugin.zip` against a
`sha256` in the registry since v5.3.3, but a registry entry with no
checksum at all was let through anyway, logged as a warning — a
deliberate transition state at the time, since neither plugin that
existed then (IPAM Lite, Network Discovery) had a trustworthy checksum
to give it. That transition is over: both entries in
`plugins/registry.json` now point at a specific release tag in their
own repository (never the moving `main` branch) and carry the real
checksum of that tag's package. A missing checksum is refused outright
now, exactly like a mismatched one always was.

Auditing the two existing entries for this found IPAM Lite's `main`
had already moved two releases past what the registry still claimed —
this release also brings the registry's version, description, and
migration list back in sync with what's actually shipping, and removes
the mechanism that used to paper over that kind of drift automatically
(live-fetching each plugin's current manifest on every registry page
load, which only worked cleanly while `download_url` pointed at a
moving branch; pinned to a release tag, it could report a version that
no longer matches what actually gets downloaded and checksummed). The
registry file itself is the source of truth again, updated by hand
each release — see the new `plugins/README.md` for the checklist.

## [5.21.0] - 2026-09-11

The Servers page becomes an HA operations console: live local/remote
state straight from Kea, a lease-count comparison across the pair, and
Kea's own HA commands as confirmed, audited buttons — instead of having
to reach for `kea-shell` or a raw `curl` against the Control Agent to
do the same thing. No migration, no config change.

### HA status, at a glance

Any server whose Kea has the `libdhcp_ha.so` hook loaded now shows an
HA Status panel: this server's role and state, the partner's
last-known state and how long ago it was heard from, and
unacked-clients-left with a warning badge once it's down to 2 or fewer
— the point at which the partner is about to be declared down. A
collapsed section underneath shows the HA config itself (mode, timers,
peers) for anyone who wants to confirm it without SSHing in. Below the
server grid, a new Compare Leases table cross-tabulates each subnet's
assigned-address count across every server, highlighting any row where
they disagree — expected to be zero, or a small transient difference
under load-balancing, never a hard failure on its own.

### The HA commands, as buttons

Heartbeat (re-check state right now) needs only admin; sync, scopes,
continue, start/cancel maintenance, and reset all need superadmin,
since they change what Kea is actually doing. Sync in particular
determines the partner's name from this server's own configuration —
never trusting a value a form could be made to submit — so it always
pulls from the correct partner in the pair. Every button asks for
confirmation first and writes an audit row; a command Kea refuses
flashes Kea's own explanation rather than a bare failure.

## [5.20.0] - 2026-09-11

The second half of the same self-audit that produced 5.19.1: the items
that change stored data or a numbering contract, rather than fix an
outright bug, so they land one release later as a MINOR. `sudo
./install.sh` or the in-app update runs a new migration (21) and
re-encrypts existing config history automatically; nothing to do by
hand.

### Server numbers are now permanent, not renumbered on every save

`[kea_server_N]` section numbers used to be renumbered contiguously
every time you saved Settings → Kea → SSH, which quietly reassigned
config history, recorded helper status, and every `/servers/<id>` URL
to whatever server now happened to occupy that number. Delete the
middle server of three and the survivor after it silently inherited
the deleted one's entire history. Saving no longer renumbers anything:
each server keeps its own section number for life, removing one leaves
a gap, and that's the expected, permanent shape now — not a transient
state to clean up.

### Config history: encrypted at rest, masked by default, and a hash that says what it hashes

Three related fixes to the config-history feature added in 5.16.0:

- **Encrypted at rest.** Every stored revision is now encrypted with
  the same key already protecting MFA secrets and alert credentials —
  a database dump no longer hands over Kea DB passwords, HA peer
  credentials, or DDNS TSIG keys in plaintext.
- **Masked by default.** The diff and the download both redact
  password- and secret-shaped keys to `********`. A superadmin can
  still download the real body, gated behind the same 10-minute
  step-up re-auth as other sensitive actions and recorded in the audit
  log every time.
- **A hash that says what it hashes.** The stored SHA used to be one
  of two different quantities — the helper's raw-bytes hash, or a
  Jen-computed stand-in for hosts without one — with no column saying
  which. A host upgrading from helper v1 to v2 got a spurious
  "changed outside Jen" entry on its first v2 read, and every restore
  attempt after that conflicted permanently, because the two
  quantities were being compared against each other. Revisions now
  record which kind of hash they hold, the v1→v2 crossover is recorded
  as a fresh baseline instead of an external change, and restore only
  trusts a stored hash it can actually compare against — reading the
  live one first when it can't.

### Health Center now catches a helper host that still has the old root grant

A Kea host could have the current `jen-kea-helper` installed **and**
still have the old `NOPASSWD: /usr/bin/python3` sudoers grant sitting
around from before it was installed, and nothing said so — Health
Center's helper check only looked at the recorded version. The helper
version check now also records whether that legacy grant is still
present, and both Settings → Kea → SSH and Health Center flag it.

### install.sh rolls back its files outside /opt/jen, too

`install.sh` writes four files outside the versioned release tree on
every install — the systemd unit, the sudoers grant, and the
root-privileged self-update script and its own unit — and until now
rollback only ever flipped the release symlink back, leaving those
four files on the new release if something failed after they were
overwritten. The installer now snapshots them immediately before
writing new ones and restores all four (the sudoers file only after
`visudo` validates it) as part of any rollback, and rollback now fires
automatically on any fatal error during an upgrade, not only a failed
service start. This is exercised on the next real upgrade rather than
in CI, which has no root or systemd to install onto.

## [5.19.1] - 2026-09-11

A self-audit of the 5.16.0–5.19.0 line, cross-checked against an
external review, found five real bugs and two unimplemented spec
items. All are fixed here; none needs a migration or a config change.
`sudo ./install.sh` or the in-app update.

### HA pairs: every subnet edit has conflicted on the second server since 5.16.0

The optimistic-concurrency guard added in 5.16.0 read the SHA of the
**active** server's `kea-dhcp4.conf` once and sent that same value as
the expected SHA to **every** SSH-configured server. Two servers in an
HA pair never have a byte-identical config file — each has its own
`this-server-name` at minimum — so the second server has refused every
single edit with "changed since you opened this form" for three
releases, even though nothing had actually changed on it. The edit
forms now carry one SHA per server, and each server's write is checked
only against its own file. If you run a single Kea server this never
affected you; if you run HA, every edit to a subnet since upgrading to
5.16.0 has needed a second attempt or a manual restart on the standby.

### The helper "Update helper" button was a no-op

Settings → Kea → SSH has shown an "Update" affordance since helper v2
shipped in 5.16.0, but pressing it on a v1 host did nothing — the
install code considered any installed version "already there" instead
of comparing against the version Jen actually wants. It also trusted
the remote script's own printed version number rather than confirming
the copy landed. Both are fixed: the button now upgrades a v1 host to
v2 for real, and verifies the upgrade by asking the freshly-copied
helper its own version. The Settings table and the Health Center now
both flag a helper that's installed but behind, not just one that's
missing entirely.

### Smaller fixes

- **Creating** a shared network had no `all_subnets` check, though
  deleting one has since Q10 — a subnet-restricted admin could add a
  network into the live config.
- A hand-edited config with a gap in its `[kea_server_N]` sections
  (`kea_server_2` and `kea_server_4` with no `_3`, say) silently hid
  every server after the gap, everywhere Jen reads the server list.
- The "Author a starting config" wizard wrote one shared interface list
  into every target server, so an HA pair with different NIC names
  (`ens18` vs `eth0`) got the wrong one on whichever server wasn't
  first; each server can now override it.
- A client class ticked "only in additional list" but never attached
  anywhere as an Additional class is silently never evaluated by Kea —
  Jen now warns about it, both after Save and on the class's edit page.
- The class-expression preview raised a bare 500 if the SSH validation
  step failed instead of showing an error row.

## [5.19.0] - 2026-09-11

Client classes: a guided rule builder for Kea's `Dhcp4.client-classes`,
a config-test preview before anything is saved, and a checklist for
attaching each class to subnets, pools, and shared networks.
`sudo ./install.sh` or the in-app update — nothing to do by hand.

### Client classes, without hand-writing Kea expressions

**Subnets → Client Classes** manages the list Kea evaluates against
every incoming packet, in order. Most classes reduce to one of a small
set of shapes — a vendor class string, a MAC address or OUI, a relay
circuit/remote ID, a hostname, or membership in another class — and the
new guided builder covers exactly those: pick a field, an operator, a
value, combine several with all/any, optionally negate. Anything the
builder can't express drops to an **Advanced** tab for a raw Kea
expression. Opening a class whose expression doesn't match what its
saved guided rules would produce — because it was hand-edited — opens
in Advanced mode with a notice, rather than quietly clobbering the hand
edit on the next save.

As you edit, Jen shows the expression it's about to write and runs it
past Kea's own config test with the candidate class inserted into a
copy of the live config, so a broken expression shows Kea's own
rejection before Save pushes anything.

### Guard or additional, and the 2.7.4 rename

A class can gate eligibility for a subnet/pool/shared-network (a
*guard*) or just attach options without gating anything (*additional*).
Once a class exists, its edit page lists every subnet, pool, and shared
network with a checkbox for each. Kea 2.7.4 renamed the attachment keys
(`client-class` → `client-classes`, `require-client-classes` →
`evaluate-additional-classes`, `only-if-required` →
`only-in-additional-list`); Jen reads both spellings everywhere and,
when writing, keeps whatever spelling a config already committed to.

Deleting a class still attached anywhere, or still named in another
class's `member(...)`, is refused with the list of what's using it.
Subnet cards gain a "Classes: a, b" line alongside the existing options
line.

## [5.18.0] - 2026-09-11

A catalog-driven editor for DHCP options at every level Kea supports,
with a view that shows which value actually wins. `sudo ./install.sh`
or the in-app update — nothing to do by hand.

### DHCP options, at the level they're actually set

Before this release, an option outside the handful the Edit Subnet form
covers (router, DNS) meant hand-editing `kea-dhcp4.conf`. **Subnets →
Options** now edits `option-data` at global, shared-network, subnet, and
pool level, with a catalog of Kea's common DHCPv4 options — NTP, TFTP
server, boot file, classless static routes, and two dozen more — each
validated against its real type before anything reaches Kea. Anything
not in the catalog is a **Custom code**, written as raw hex.

Each subnet card now shows an "Options: N here · M inherited" line
linking straight to that subnet's view.

### See what's actually in effect, and why

Options set at more than one level don't merge — the most specific one
wins (pool > subnet > shared network > global). The new "Effective
options" panel, shown for a subnet or pool, lists the value that's live
and, struck through, every less-specific value it overrode. No more
guessing why a subnet doesn't seem to be picking up a global NTP server
you *know* you set.

Routers and DNS servers at the **subnet** level stay on the Edit Subnet
form, which already owns those two fields — the Options page shows them
as "managed by Edit form" there and refuses a write, so there's no way
to have the two forms silently fight over the same value. The same
options at every other level are ordinary, editable entries.

## [5.17.0] - 2026-09-11

Authentication and host-hardening polish — seven independent items.
`sudo ./install.sh` or the in-app update; nothing to do by hand. One
new optional config key (`[server] trusted_proxies`) and a small
first-login change (below).

### Changing your own MFA now asks for your password

Enrolling a second authenticator, regenerating backup codes, adding or
removing a trusted device, and a superadmin resetting another user's MFA
all now require that you authenticated — password, plus a code if you
have MFA — within the last 10 minutes. Otherwise Jen shows a short
"confirm your identity" screen first, then returns you to what you were
doing. A stolen live session can no longer be used to quietly swap
someone's second factor. A failed confirmation counts toward the same
lockout as a failed login.

### Sign-out is a button; sessions are cleared

`/logout` is POST-only now — a `GET` shows a confirm page. A stray link,
an `<img>` tag, or a browser prefetch can't end your session. The whole
session is cleared on every login and every logout, so nothing a
pre-authentication request left behind can carry into an authenticated
one.

### Running behind a reverse proxy

New `[server] trusted_proxies` — a comma list of proxy IPs or CIDRs. When
a request comes from one of them, Jen reads the real client IP from
`X-Forwarded-For` and the scheme from `X-Forwarded-Proto`, so rate
limiting, the audit log and MFA device records see the actual client
instead of the proxy. Requests from any other address ignore those
headers. With the setting on, Jen marks its session cookie `Secure` and
sends HSTS (the proxy is expected to terminate HTTPS), and passes the
same list to gunicorn. Documented in the admin guide and
`jen.config.example`.

### systemd sandboxing

`jen.service` now runs with `ProtectSystem=strict` (only `/etc/jen` and
`/var/lib/jen` writable), `PrivateTmp`, `PrivateDevices`, and the
`Protect*` / `Restrict*` family. It deliberately does **not** set
`NoNewPrivileges` / `CapabilityBoundingSet` — Jen shells out to `sudo`
for the self-updater and needs the setuid transition. If a directive
turns out to be wrong on your box, the in-app updater snapshots the unit
and rolls back on a failed health check.

### No default "admin" password

A fresh install with no `JEN_INITIAL_ADMIN_PASSWORD` (and where you
weren't prompted for one) no longer seeds the literal password `admin`.
Jen generates a random one, writes it to
`/var/lib/jen/initial-admin-password` (mode 0600) and prints it to the
log, still forces a change on first login, and deletes the file once you
complete that change. The guided installer is unchanged — it always
prompts.

### Also

- The audit log and the rate-limit counter resets are written
  synchronously now, not on a background thread — a security event can't
  be lost to an error nobody sees, and it's there the instant the
  response returns.

## [5.16.0] - 2026-09-11

Kea config history, and an optimistic-concurrency guard on every config
write. `sudo ./install.sh` or the in-app update; then, once per Kea host,
press **Settings → Kea → SSH → Install helper** to move it to helper v2
(a v1 host keeps working with a weaker guard — see below).

### Every config Jen writes is now saved, diffable, and restorable

Before this, a subnet edit that broke something left you with a
`.bak` file on the Kea host and `journalctl`. Now every config Jen
applies to a host is recorded in Jen's database — who, when, why, and the
full config — under **Servers → Config history** on each server card. A
revision page shows a unified diff against the previous one (every line
HTML-escaped — the config never renders as markup), a **Download JSON**
link, and, for superadmins, **Restore this revision**: it re-validates
the old config with `kea-dhcpX -t`, re-applies it, and restarts Kea.

Jen also notices changes made *outside* Jen. If someone hand-edits
`kea-dhcp4.conf` on the host, the next time Jen reads it the difference
is captured as an **external** revision, so the history stays complete.

How many revisions are kept per server and service is **Settings →
System → Kea Config History** (default 50). The history pages show a
server's whole config, so — like other cross-subnet views — they require
access to all subnets, not just admin.

### A write is refused if the file changed under you

Open the Edit Subnet form, go make a coffee, come back and save — and in
the meantime another admin changed the same file. Previously one of the
two edits was silently lost. Now the form carries the config's checksum
as it was when you opened it; if the file on the host moved on, the write
is refused before anything is touched:

> The Kea config on kea-01 changed since you opened this form — your
> edit was NOT applied. Reload and try again.

The add-subnet, delete-subnet and shared-network routes carry the same
guard using the checksum read at the top of the request.

### Helper protocol v2

This needs a new capability on the Kea host, so `jen-kea-helper` goes to
`HELPER_VERSION = 2`:

- `read-config` returns the SHA-256 of the raw config-file bytes
  (whitespace included — the point is to catch hand edits).
- `apply-config` takes an optional `expect_sha256` and, when given,
  holds an exclusive `flock` on a sidecar lock file while it re-checks
  the hash and does the atomic replace — so the guard above is enforced
  on the host, not just in Jen.
- Every response now carries `helper_version`, so Jen learns a host's
  real helper version from any operation.

`JEN_HELPER_MIN_VERSION` stays 1. A host still on **helper v1 or the
legacy `python3` path keeps working** — Jen falls back to a best-effort
"re-read and compare" guard and flashes *"No atomic guard on <host>"*
once per request, and it does **not** capture out-of-band changes on
those hosts (there's no checksum to compare). **Settings → Kea → SSH**
shows an "upgrade available" hint for a v1 host; **Install helper**
re-copies the current file.

### Under the hood

- New table `kea_config_revisions` (migration 20). `MEDIUMTEXT`, not
  `JSON` — the body is stored as `json.dumps(cfg, indent=2,
  sort_keys=True)` so diffs are stable and it sidesteps the MariaDB
  `json_valid` CHECK.
- `jen/services/config_revisions.py` — record / list / diff / prune /
  restore-support, all best-effort: a failed history write never fails
  the config apply that triggered it.
- `kea_host.read_config_versioned()` returns `(config, sha)`;
  `read_config()` is now a thin wrapper, so existing callers are
  unchanged. `apply_config()` gained `expect_sha256`, `summary` and
  `source` keyword arguments.

## [5.15.0] - 2026-09-11

Shared networks. `sudo ./install.sh` or the in-app update — nothing to do
by hand.

### Subnets inside a shared network were invisible

If any of your subnets lived inside a Kea `shared-networks` block, Jen
never showed it. It was absent from the Subnets page and the dashboard,
its pool wasn't counted anywhere, editing it silently did nothing, and
**config-drift reported it as missing from Kea** — a standing false
alarm. Every config-get consumer now iterates shared networks too
(`jen/services/kea_config_view.py`); a config with no shared networks
behaves exactly as before.

### Managing shared networks

On the Subnets page (admin, SSH configured):

- Cards are grouped under a **Shared network: `<name>` · `<interface>`**
  heading, with a **shared** chip on nested cards.
- A per-card dropdown **moves** a subnet between the top level and any
  shared network.
- **New shared network** creates an empty one; the Add Subnet form has a
  shared-network picker; **Delete network** removes an empty one.
- Creating or deleting a network needs access to all subnets; moving a
  subnet needs access to that subnet.

Kea semantics: subnets in one shared network share the whole pool space,
and client classification is per network. Renaming isn't supported (Kea
has no rename) — delete the empty network and recreate it.

### Also

- New admin banner when `/var/lib/jen` is missing or unwritable ("content
  directory not set up — run `sudo ./install.sh`"), the same way the
  incomplete-venv banner works. A box that upgraded 5.12 → 5.13 with the
  in-app button never ran the root-side content migration, so backups and
  uploads were failing with no visible cause.

## [5.14.1] - 2026-09-10

Housekeeping. A `sudo ./install.sh` upgrade (or, from 5.14.0, the in-app
button) is all that's needed.

### Changed

- **Spelling is now American throughout** — comments, docstrings, log
  lines, UI labels and docs. ~130 words: `colour` → `color`,
  `behaviour` → `behavior`, `utilisation` → `utilization`,
  `initialise` → `initialize`, and so on. No configuration keys, form
  fields, route names or database values were British to begin with, so
  nothing an operator has stored changes.
- One Health Center check id changed with it: the JSON at
  `/health-center/data` now reports `pool_utilization` (was
  `pool_utilisation`). If you script against that endpoint, update the
  key name.
- The README shows real screenshots (dashboard, leases, subnets,
  settings) instead of the mock SVG preview.

Versioned release directories and an atomic upgrade. **The first upgrade
to 5.14.0 must be run with `sudo ./install.sh`** — see "Upgrading" below.

### Why

Through 5.13.x an upgrade overwrote `/opt/jen` in place: a copy of the
new files on top of the old, a shared virtualenv that `pip` mutated
before anything was proven, and a rollback that copied a snapshot back.
If a release needed a new library the rollback couldn't truly undo it,
and a failure mid-copy left the tree half-updated.

### What changed

- **Each release is its own directory.** `/opt/jen/releases/<X.Y.Z>/`
  holds `app/` (the full tree) and `venv/` (a virtualenv built for that
  release's `requirements.txt`). `/opt/jen/current` is a relative symlink
  to the live one.
- **The install is atomic.** Both the installer and the in-app updater
  build the entire release under a staging directory — extract, build the
  venv, `pip`, byte-compile, import-check — and then do one
  `os.rename()` into place plus one `os.replace()` of the `current`
  symlink. Nothing the running install depends on is touched until that
  flip.
- **The rollback is a true point-in-time revert.** A failed upgrade flips
  `current` back to the previous release directory, which was never
  touched — its code *and* its exact dependencies. The previous release
  stays on disk as a hand-rollback target:
  `sudo ln -sfn releases/<old> /opt/jen/current && sudo systemctl restart jen`.
- **`jen.service`** now runs `/opt/jen/current/venv/bin/python
  /opt/jen/current/app/run.py`. `run.py` keeps a re-exec shim as a safety
  net for Docker and still-flat boxes.
- **The flat `/opt/jen/{jen,run.py,templates,static,plugins,venv}` is
  removed** once the versioned layout is live. Docker stays flat (the
  container is the isolation).
- The old `.staging-*` and `.rollback-*` directories, `.failed` releases,
  and all but the newest spare release are pruned automatically.

### Upgrading

The updater already on a 5.13.x box is the flat one. It will install the
5.14.0 files — the new `jen.service` included — but there is no `current`
symlink yet, so the new unit can't start: the box **fails the health
check and cleanly rolls back to 5.13.0**. Run `sudo ./install.sh` once
(it builds the versioned layout, activates it, and removes the flat
leftovers). Every in-app update from 5.14.0 onward is the atomic path.

## [5.13.0] - 2026-09-10

User content moves out of the application tree, and `/opt/jen` becomes
root-owned and read-only to the service account. A `sudo ./install.sh`
upgrade does the whole migration; there is nothing to do by hand.

### Why

Through 5.12.x the `www-data` service account needed write access to
parts of `/opt/jen` that it also executes — custom brand icons, the
uploaded favicon and nav logo, database backups, registry-installed
plugins, and the secret-key / MFA-key fallbacks all lived under the
application tree. That is a persistence foothold: any bug that lets an
attacker write a file as `www-data` lets them drop a `.py` file Jen
imports and have it run on the next restart. Splitting the writable
content out means the entire code tree can be `root:root` and read-only
to the service account, the same posture the bundled virtualenv has had
since 5.8.0.

### What changed

- **New content directory, `/var/lib/jen`** (`$JEN_ROOT/var` in a source
  checkout; override with `JEN_CONTENT_DIR`). It holds `icons/`,
  `branding/` (favicon, nav logo), `backups/` (database backups),
  `plugins/` and `plugins-enabled/` (registry-installed plugins and their
  enable markers), and `keys/` (the `.secret_key` / `.mfa_key` fallbacks
  used when the `/etc/jen` copies are absent). It is `www-data`-owned,
  mode `0750`, and — like `/etc/jen` — never touched by an upgrade.
- **`/opt/jen` is now `root:root`, `a+rX`.** `install.sh` and the in-app
  self-updater both chown the tree to root after copying files and
  byte-compile it as root. `jen/`, `templates/`, `static/` and `plugins/`
  are removed and re-copied wholesale on each upgrade rather than merged,
  so a rollback restores exactly the previous release's files instead of
  leaving new assets mixed in with old templates.
- **Migration is automatic and reversible.** The installer and the
  updater move the old locations into `/var/lib/jen` *before* the file
  swap, so the pre-migration state is inside the rollback snapshot. On
  top of that the app itself best-effort *copies* anything still in an
  old path into the content directory on every boot — idempotent, never
  clobbering, never able to crash startup — which also picks up the
  Docker `jen-icons` named volume.
- **Serving.** Custom icons and branding are served by a new blueprint at
  `/content/icons/<name>.svg` and `/content/branding/<file>`; the old
  `/static/icons/custom/…` and `/static/nav_logo.*` URLs are gone.
- **Removing a custom favicon** now falls back to the shipped default
  instead of leaving the page with none.
- **Bundled vs registry plugins.** `ipam` and `network-discovery` ship in
  `/opt/jen/plugins` and are read-only; a copy installed from the
  registry lands in `/var/lib/jen/plugins` and wins. Uninstalling a
  bundled plugin disables it rather than trying to delete release-owned
  files.

### Docker

The compose files gain a `jen-content` volume at `/var/lib/jen`. The old
`jen-icons` volume stays mounted for this one release so the app can
migrate it; once the first upgraded start has succeeded you can drop that
line and `docker volume rm jen-icons`. See `docs/docker.md`.

### Also — the Settings landing page is fast again

Opening **Settings** took about three seconds. Two of the little status
hints on that page were the cause. The "N backups" hint called a routine
that decompresses and JSON-parses every database backup file just to read
its metadata header — seconds of work once daily backups accumulate, when
all the hint needs is a file count. And the Kea reachability probe used
the default 10-second HTTP timeout, so an unreachable Kea stalled the
whole page. The backup hint is now a directory listing, and the probe
runs on a 3-second timeout. No other page did the backup decompression,
which is why only the landing menu was slow.

## [5.12.0] - 2026-09-10

The Health Center.

### One page that tells you what's wrong

**Network → Health** (`/health-center`) runs a fixed list of read-only
checks and shows `ok` / `warn` / `fail` / `skip` for each, with a
one-line detail and a link straight to the page that fixes it: Kea
reachability and version, HA state, whether the `host_cmds` / `lease_cmds`
/ `ha` hooks are loaded, clock skew between Kea and Jen (read off the
HTTP `Date` header — Kea has no clock command), config drift, pool
utilization and snapshot freshness, kea-dhcp-ddns reachability and its
error counters, TLS certificate expiry, both database round trips, the
schema version, whether the `jen-kea-helper` is installed on each SSH
host, and whether the background workers are running.

It is **read-only** and does **no SSH at render time** — every check
uses the Kea HTTP API, the two databases, local files, or state Jen
already persisted. That's what makes it safe for a `viewer` to open and
safe to poll; the page auto-refreshes every 60 seconds. A
subnet-restricted user sees only their own subnets in the capacity
checks. `/health-center/data` returns the same run as JSON for
scripting.

### Also

- New **TLS certificate expiring** alert — fires once as the certificate
  crosses 30, 7, and 1 days remaining, and resets when a renewed one is
  installed. Configure it under Settings → Alerts & Integrations like any
  other alert type.
- The `openssl x509` certificate-reading logic moved from the settings
  route into `jen/services/certs.py` so the check and the alert share it;
  no behavior change to the Settings → Access & Security page.

## [5.11.1] - 2026-09-10

Housekeeping — a wider lint net and the OUI table out of the code. No
behavior change; a `sudo ./install.sh` upgrade is all that's needed.

### Changed

- Ruff's rule set gains `flake8-simplify` (SIM), `flake8-comprehensions`
  (C4), `flake8-pie` (PIE) and `RUF100` (stale `# noqa`). The one-time
  cleanup pass behind them is mechanical: nested `with` statements
  collapsed into a single multi-context `with`, `try/except/pass` blocks
  that only swallow an error rewritten as `contextlib.suppress`,
  `dict(a=1, …)` call-style construction turned into `{"a": 1, …}`
  literals, and a scattering of redundant comprehensions and `.keys()`
  calls tidied. `SIM108` (rewrite `if/else` as a ternary) is left off on
  purpose — it trades readability for brevity. `run.py`'s venv re-exec
  guard deliberately keeps its literal `try/except`: the test suite
  slices it out and runs it as a standalone script, so it has to stay
  dependency-free.
- The MAC-prefix (OUI) vendor table — roughly 1,350 `"00:1a:2b" →
  ("Vendor", "type", "icon")` entries that made up 1,300+ of
  `jen/services/fingerprint.py`'s 1,700 lines — moved into a plain
  `jen/services/oui_db.json` data file that the module loads once at
  import. Lookups resolve to exactly the same vendors as before.
  `scripts/oui_to_json.py` regenerates the file. It travels inside
  `jen/`, so `install.sh` and the in-app updater pick it up with no
  packaging change.

## [5.11.0] - 2026-09-10

The privilege boundary on the Kea hosts.

### `jen-kea-helper` — one sudoers line instead of root

Until now, everything Jen did on a Kea host — editing a subnet, authoring
a config, restarting a daemon, reading the DDNS log, installing a Kea
package — was done by generating a Python script on the Jen host, piping
it over SSH, and running it as root. The documented Kea-side sudoers grant
was therefore `NOPASSWD: /usr/bin/python3`, which **is** root: a
compromised Jen process was root on every Kea box it managed. This was the
largest unaddressed item in the threat model (`docs/ARCHITECTURE.md`
§3.3).

`jen-kea-helper` replaces that with a small, fixed-function, root-owned
script at `/usr/local/sbin/jen-kea-helper` behind **one** sudoers line:

```
youruser ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper
```

Jen calls it as `sudo -n jen-kea-helper <op>` with a JSON request on
stdin and gets a JSON reply. It exposes a closed set of operations
(`read-config`, `test-config`, `apply-config`, `service`, `tail-log`,
`install-package`), validates every path itself (Kea configs must sit in
`/etc/kea` or `/usr/local/etc/kea`; logs must resolve under `/var/log`),
and **never executes anything it is handed** — stdin is data only. There
is deliberately no self-update operation.

**Install it** from **Settings → Kea → SSH** (one click per host, while
the old grant is still present), or by hand — see the Admin Guide → Kea
host helper. The page shows `v1` for each host once it is reachable.

### The legacy path stays, banner-warned

A Kea host that does not have the helper yet falls back to the old
`sudo python3` path automatically. Jen shows an admin banner naming every
such host and flashes a warning on each use. **The fallback is not
removed** — a host still on it keeps working. Once every host shows the
helper you can delete `/etc/sudoers.d/jen` (the `python3 = root` grant).

### Config editing moved into Jen

As a by-product, the seven near-identical remote-script builders are gone.
Subnet add / delete / edit (v4 and v6) now read the config, mutate it in
pure Python (`jen/services/kea_config_edit.py`), and push the result back
through the helper. The Servers-page restart button and the DDNS log read
no longer shell out to `ssh` directly.

### Also

- Removed a stale committed symlink (`templates/templates`, from v4.4.10)
  that shipped in every release tarball and made a plain `tar xzf` fail.
- `.gitattributes` pins LF on the shipped scripts so a Windows checkout
  can't break a `#!` line.

## [5.10.4] - 2026-09-10

A patch for four small things, two of which have been quietly broken
since 5.9.0.

### The in-app updater refreshes the page again

Trigger an update from Settings and Jen tells you "this page will
refresh automatically once Jen is back." It hasn't, since 5.9.0 — and
not because of the virtualenv work, which is where the finger has been
pointed. The 5.9.0 Settings reorganization moved the update overlay and
its restart-poller onto the System page, but the update trigger kept
redirecting to the Kea page, which has neither. So the update ran to
completion and the browser just sat there until you reloaded by hand.
The trigger now sends you to the page that actually carries the
overlay. The overlay's own "give up and tell the operator" timers were
also too short — 60 and 90 seconds against a server-side health window
that alone is 90 seconds — and now allow three minutes.

### A fresh install could not save its own settings

`install.sh` wrote `/etc/jen/jen.config` owned by `root`, in a step
that runs *after* the one that hands the application tree to the
service user. On a fresh 5.9.0–5.10.3 install that left the file
root-owned, and the running service — which rewrites it on every
Settings save — got permission denied every time, until the next
`sudo ./install.sh --upgrade` happened to fix the ownership as a side
effect. The installer now assigns it to the service user, and Jen
writes the file atomically (to a sibling temp file, then an atomic
rename), which only needs write access to the directory. **An
already-affected box heals itself on the first successful Settings save
after upgrading to 5.10.4** — no manual `chown` needed. The atomic
write also means an interrupted save can no longer truncate the config
to nothing.

### /about and the API docs stop showing deployment detail to viewers

The About page listed the HTTP and HTTPS ports, the on-disk config and
application paths, and the Kea SSH host to every signed-in user; the
API documentation page pre-filled its examples from a list of every
active API key's name and prefix, even though the key-management page
itself is admin-only. Both are now limited to admins and superadmins.
(The About page also now actually fills in the port and SSH-host rows,
which it never did — admins were looking at blank cells.)

### The login-attempt table is pruned hourly, not per attempt

Every failed login ran a "delete rows older than 24 hours" sweep of
the rate-limit table. The row insert that the lockout logic depends on
is still synchronous; the cleanup now runs at most once an hour.

## [5.10.3] - 2026-09-09

5.10.2 made single-server direct mode correct. This makes the
**multi-server** case correct too, and stops accepting mTLS material it
can't actually use. All bug fixes and validation on features that already
shipped — no new config keys, no manual upgrade steps.

### A standby's IPv6 endpoint is its own

In `ca` mode, an HA standby with no `api6_url` was sending **every DHCPv6
command to the primary**, with the primary's credentials. Jen's endpoint
resolution consulted the `[kea6]` globals before falling back to the
server's own `api_url` — and those globals are the *primary's* `[kea6]`
values, which in `ca` mode are just the primary's `[kea] api_url`. Server
status, config-drift checks, v6 subnet reads and v6 reservation writes
all pass a real server, so all of them were affected.

A server's v6 endpoint is now that server's: its `api6_url` /
`api6_user` / `api6_pass`, else (in `ca` mode) its own `api_url` and
credentials. `[kea6]` is the primary's per-daemon override and reaches
the primary the same way it always did.

### Reordering servers no longer swaps their passwords

Settings → Kea → Additional Servers rebuilds every `[kea_server_N]`
section on save. It used to carry a blank password field, and any
hand-added key like `ssh_key`, forward from **whatever section number the
row landed on** — so reordering two rows quietly gave each server the
other's `api_pass`, `api6_pass` and `ssh_key`, and deleting the first of
two handed the survivor the deleted server's password. 5.10.2 documented
the `ssh_key` half as a positional limitation; the password half was a
credential swap.

Each row now carries its original section number, and preservation
follows the server. Sections are also renumbered contiguously: a row with
a blank API URL used to leave a gap, and Jen stops reading
`[kea_server_N]` at the first gap — so every server after a blank row was
invisible.

### Authoring binds each server's own address

"Author a starting config" detected one bind address on the first Kea
server and wrote it into every target server's control socket. An HA pair
has two management IPs, so the second server was told to bind an address
it doesn't have — which pushes you toward `0.0.0.0` just to make the
error go away. There is now one bind picker per server, offering that
server's own detected addresses and defaulting to the address Jen dials
for it. A server with no bind address chosen fails only itself.

Relatedly: in direct mode for DHCPv6 with no v6 socket configured, the
form used to claim the endpoint was plain HTTP on an empty host and only
told you the truth when you hit Preview. It now leads with what's missing.

### The client certificate is checked before it's saved

`api_client_cert` / `api_client_key` were only checked for *existence* —
and existence is a `stat`, which says nothing about whether the files
parse, whether the key matches the certificate, or whether the Jen
service user can read the key at all. A `root:root 600` key passed
validation and then failed every single Kea request. Jen now loads the
pair (and `api_ca`) the way the HTTP client will, as the service user,
and refuses to save material it couldn't use.

### Probe any server, either daemon

Probe always used the primary's URL and credentials, so there was no way
to test a standby. It now takes a server and `dhcp4`/`dhcp6` and resolves
the endpoint the same way the live transport does — the URL and
credentials Jen will actually dial for that daemon on that server. With
no selection it behaves exactly as before.

### Quieter logs with TLS verification off

With `api_tls_verify = false`, urllib3 emitted an `InsecureRequestWarning`
on *every* request, and the dashboard polls. Jen now says it once, as a
log warning naming the setting.

### Not in this release

Per-server client certificates (one `[kea]` pair still covers every
server); replacing the remote `sudo python3` config-push path with a
fixed-function helper; plugin-registry checksums.

## [5.10.2] - 2026-09-09

The Kea 3 direct-control-socket work from 5.10.0/5.10.1 got the transport
right; this release finishes the edges around it — TLS, config lifecycle,
and authoring defaults — from an external review. All of it is optional
and backward-compatible; a `ca`-mode install is unaffected.

### HTTPS direct sockets actually work

5.10.1's "Author a starting config" always emitted an `http` control
socket, even when Jen's own `api_url` was `https://` — so Jen dialled
HTTPS and Kea listened plain HTTP, and they couldn't talk. And Kea's
per-daemon `https` socket defaults `cert-required` to **true** (mutual
TLS), which the admin-guide's HTTPS instructions didn't account for.

- New `[kea] api_client_cert` / `api_client_key` — a client-certificate
  PEM and key on the Jen host, passed to every Kea request. Set both or
  neither; Jen checks each file exists on save. Kea can now demand a
  client cert (its default) and Jen can satisfy it.
- The authoring wizard is scheme-aware: an `https://` endpoint produces a
  `socket-type: https` entry with `trust-anchor` / `cert-file` /
  `key-file`, and `cert-required` is set to `true` only when Jen actually
  has a client certificate configured — never authored as `true` into a
  file Jen then can't connect to.
- The admin-guide's "Direct control sockets" section is rewritten
  secure-first: HTTPS-with-mTLS on a management address is the headline
  example, with a `cert-required: false` variant and a plain-HTTP warning
  box, plus a minimal private-CA `openssl` recipe.

### The authored socket is the endpoint Jen will dial

The generated config is now built **per target server**, from each
server's own `api_url` and credentials via the same endpoint resolution
the live transport uses — not once from the primary's globals. An
HA standby with its own port/credentials gets a config Jen can reach.

- Direct-mode API URLs must include an explicit port (`http://kea:8004`,
  not `http://kea`). A daemon control socket is never on 80/443, and a
  portless URL had Jen dial `:80` while authoring emitted `:8000`. The
  Kea page warns about any portless URL after a mode switch.
- The stale dhcp4 fallback port (`8000`, the old Control Agent port) is
  gone — there's no fallback; a missing port is an error.

### No more 0.0.0.0 by default

5.10.1 hard-coded the authored control socket to bind `0.0.0.0` (every
interface) with no way to choose — a "secure enough on a trusted LAN"
default, not a secure one. The authoring form now offers a **bind
address** picker over the Kea host's detected management IPs, preselecting
the one Jen connects to; `0.0.0.0` is present but flagged "not
recommended" and never the default. A plain-`http` endpoint shows a
"credentials in the clear" warning.

### Config that stays configured

- **Clearing a `[kea6]` override now works.** Blanking a Kea6 API/DB text
  field removes the key so Jen genuinely inherits the v4 value — before
  this a blank field wrote nothing and a stale `…:8006` override could
  survive a `direct → ca` switch and get a CA-shaped payload aimed at the
  v6 daemon's port. Passwords are kept unless you tick a new "Inherit"
  box.
- **Additional Servers no longer drops `api6_url`.** The editor rebuilt
  each `[kea_server_N]` from a fixed field list, so a per-server v6
  endpoint (or a hand-added `ssh_key`) vanished on any unrelated save.
  The form now carries `api6_url` / `api6_user` / `api6_pass`, and keys
  it doesn't manage are preserved.
- Per-server `api6_user` / `api6_pass` now make the full trip from config
  through to the transport.

### Preview no longer shows passwords

The "Preview & Validate" step returned the whole generated config as
JSON, lease-database and control-socket passwords included, into the
browser DOM. Passwords are now redacted (`********`) in that payload; the
real values still reach the remote `kea-dhcpX -t` check.

### Probe a specific URL

The Probe button on Settings → Kea takes an optional URL — it probes just
that endpoint (direct-style, no port-8004 guessing) and, when it answers,
recommends setting it as the API URL. The scheme is never downgraded.

### Not in this release

Per-server or `[kea6]`-specific client certificates (one global
`[kea]` pair for now); replacing the remote `sudo python3` config-push
path with a fixed-function helper (a larger change, tracked separately);
plugin-registry checksums.

## [5.10.1] - 2026-09-09

Completes the Kea 3 work from 5.10.0: **"Author a starting config" now
produces a config Jen can actually reach in `direct` mode.**

5.10.0 added `connection_mode = direct` (talk to each Kea daemon's own
HTTP control socket, since Kea 3.2 removed the Control Agent) but left one
gap: a config generated by Settings → Kea → "Author a starting
kea-dhcpX.conf" still emitted only a Unix `control-socket`. On a fresh Kea
that started with that config, Jen — connecting over HTTP from another
host — had nothing to talk to, and the operator had to hand-add the
`http` socket.

Now, when `connection_mode = direct`, a generated config gets a
`control-sockets` **list**: the Unix socket (kept for `kea-shell` and some
hooks) plus an `http` entry —

- **address** `0.0.0.0` so the Jen host can reach it,
- **port** parsed from `[kea] api_url` (or `[kea6] api_url` for dhcp6),
- **basic auth** from `api_user` / `api_pass`.

The authoring form shows exactly what the `http` socket will be before
you generate, and refuses if the API username/password aren't set (they'd
otherwise become empty basic-auth credentials on a socket bound to all
interfaces). In `ca` mode the generated config is unchanged — the
singular `control-socket` map, exactly as before.

Also: the suggested Unix socket path when no Control Agent config is
found now follows ISC's convention (`/run/kea/kea4-ctrl-socket` /
`kea6-ctrl-socket`).

## [5.10.0] - 2026-09-09

Kea 3 removed the Control Agent. Jen learns to talk to Kea without it.

### Why this matters

ISC deprecated `kea-ctrl-agent` in **Kea 3.0** (it still runs, but logs a
warning at startup) and **removed it entirely in Kea 3.2**. Every release
of Jen before this one could only reach Kea's command API *through* that
Control Agent, so a site that upgrades Kea to 3.2 would find Jen's status
panels, config-drift check, HA state and lease stats all going dark at
once — nothing on the command channel would answer.

Since Kea 2.7.2 each daemon (`kea-dhcp4`, `kea-dhcp6`, `kea-dhcp-ddns`)
exposes its own HTTP control socket. This release adds a second
connection mode that talks to those directly.

### `[kea] connection_mode`

A new, optional config key with two values:

- **`ca`** — the default, and byte-for-byte identical to every prior
  release: one endpoint, commands routed by a `"service"` field. An
  existing `jen.config` with no `connection_mode` line behaves exactly as
  it did before upgrading.
- **`direct`** — Jen posts straight to each daemon's own control socket.
  `[kea] api_url` is the `kea-dhcp4` socket; `[kea6] api_url` is the
  `kea-dhcp6` socket, and in this mode there is **no fallback** from v6 to
  the v4 URL (a `kea-dhcp4` daemon can't answer DHCPv6 commands) — if
  IPv6 is on and `[kea6] api_url` is unset, v6 API calls return a clear
  error instead of being misrouted. The `"service"` field is omitted from
  the payload, which is the portable choice across Kea 3.0.x and 3.2+.

Two more optional `[kea]` keys cover a TLS control socket: `api_ca` (a CA
bundle path on the Jen host that pins verification) and `api_tls_verify`
(default `true`). They only take effect for an `https://` URL, so adding
them changes nothing for a plaintext socket. Client-certificate auth
(`cert-required`) is not yet supported — a follow-up.

This is a backward-compatible, opt-in config addition, so a `sudo
./install.sh` upgrade stays fully automatic with no manual steps —
hence MINOR, not MAJOR. A site staying on Kea 3.0/3.1 with the Control
Agent needs to do nothing.

### Settings → Kea

- A **Connection Mode** selector on the Kea card. The URL field's label
  and help text follow the mode; the IPv6 card's label becomes
  "kea-dhcp6 control socket URL" in direct mode and warns inline when
  IPv6 is enabled with no v6 socket configured.
- **CA bundle path** and **Verify TLS** inputs for an HTTPS socket.
- A **Probe** button. It tries the configured endpoint in the configured
  mode, then a direct socket on the same host at port 8004, and reports
  the running Kea version, which mode answered, and a recommendation
  keyed on the version — "the Control Agent is deprecated, switch to
  direct" for 3.0–3.1 on `ca`, "the Control Agent is gone, you must
  switch" for 3.2+ on `ca`.
- The Kea page shows the same warning as a banner when `ca` mode is
  configured against a reachable Kea ≥ 3.0, and the Settings landing tile
  carries a one-line hint.
- `save-kea` now validates the mode, the URL scheme, and that a given CA
  bundle path actually exists on the Jen host.

### Docs

The Admin Guide gains a **"Direct control sockets"** section: the
`control-sockets` JSON to add to each daemon (keeping the existing `unix`
entry alongside the new `http` one), the 8004/8006 port convention, basic
auth, the TLS knobs, and a warning never to point Jen at an HA peer port
(Kea 3.2's HA hook defaults `restrict-commands` to true). `ARCHITECTURE.md`
and the README requirements list are updated for both paths.

### Not in this release

Authoring a fresh Kea config with the `http` control socket already in it
(so a brand-new Kea is reachable in direct mode without hand-editing) is
deferred to **5.10.1**. Until then, a config generated by "Author a
starting config" needs the `http` `control-sockets` entry added by hand —
the Admin Guide section walks through it.

## [5.9.1] - 2026-09-09

Follow-ups from the 5.9.0 review, plus the capitalisation nit.

### A bad certificate upload can no longer take Jen down

The certificate upload checked its inputs textually — "contains `BEGIN
CERTIFICATE`", "contains `PRIVATE KEY`" — and then overwrote the live
files and restarted. A perfectly valid certificate paired with the wrong
private key passed, gunicorn refused the pair at startup, and systemd's
`Restart=always` spun the console into an outage until someone SSHed in.

- **Upload validates first.** The pair (and the CA bundle, if given) is
  loaded with the same `ssl` API gunicorn uses, on temp files, before
  anything under `/etc/jen/ssl` changes. A mismatched key or a truncated
  PEM is refused with the reason and "Nothing was changed." Writes are
  atomic (`os.replace`) and the previous cert/key are kept beside the new
  ones as `.prev`.
- **Startup never crash-loops on a bad pair.** `run.py` loads the on-disk
  pair before launching HTTPS; if it can't, it logs CRITICAL, comes up
  **HTTP-only** so the console stays reachable to fix it, and sets
  `JEN_SSL_DISABLED=1` so the HTTPS redirect, the Secure cookie flag and
  the settings badges all agree that plain HTTP is what's being served.

### HTTP → HTTPS redirect

- **Query strings are preserved.** The redirect used `request.path`, so
  `/settings/databases?tab=backups` over HTTP landed on
  `/settings/databases` — noticeable now that Settings tabs are `?tab=`.
- **The Host header is validated** before it becomes a `Location`: a plain
  hostname, IPv4 or bracketed IPv6 (port stripped), anything else gets a
  400. Applies to both the in-app redirect and the standalone HTTP
  listener (`jen/httpredirect.py`). Low risk in practice — a browser sends
  the URL's own host — but there was no reason to build a redirect from
  an unchecked header.

### Updater

- **The running-process version is authoritative.** After the restart the
  updater must read the installed version back from `/api/v1/health`
  (retried a few times while the app warms up). The on-disk `JEN_VERSION`
  is no longer accepted as "confirmed running" — it only proves the copy
  succeeded, which is not the question.
- **Pruning keeps what recovery might need.** Stale `.rollback-*`
  snapshots are still pruned, but the newest always survives, and a
  snapshot the CRITICAL path marks with `.keep` is never auto-pruned —
  clicking Update again after a failed rollback must not delete the one
  intact copy of the previous release.

### Also

- ShellCheck runs in CI (`-S error` to start) on `install.sh`,
  `uninstall.sh` and `scripts/release_check.sh`.
- Sub-tab and jump-list labels are Title Case ("Updates & System",
  "Plugin Manager", "Audit Log", "Alert Log", "Ports & Threads", …).
- README still pointed IPv6 at "Settings → Infrastructure"; it's Settings
  → Kea.

## [5.9.0] - 2026-09-09

Settings, reorganized. Plus three small hardenings of the in-app
updater from watching a real box go through the 5.8.4 update.

### Settings is seven groups, not nine tabs and a junk drawer

The old Settings area had grown by accretion: an Infrastructure tab
with fourteen cards, a System tab with nine, the same Ports card on
both, SSH split across two tabs, branding in three places, and Jen
updates, plugin updates and Kea package installs each somewhere
different. Users, the audit log, API keys and API docs lived under
Settings because there was nowhere else. On a phone the nine-tab strip
overflowed and a fourteen-card page was a long blind scroll.

It's now organized by what you're trying to do:

| Group | What's there |
|---|---|
| **Kea** | Control Agent (v4 + v6), SSH — host, user, path *and* the key, one card — servers & HA, package status, config drift |
| **Databases** | Jen / Kea connection settings, plus the export, import, backups, schedule and migrate tools as tabs (superadmin) |
| **Access & Security** | MFA policy, session timeout, rate limiting, SSL certificate; Users, API Keys and API Docs as sub-tabs |
| **Alerts & Integrations** | Thresholds, channels, templates, DDNS/DNS provider, Prometheus |
| **Appearance** | Logo, nav color, favicon, brand icons |
| **System** | Jen updates and the plugin summary in one place, ports & threads (one card), restart, audit retention |
| **Logs** | Audit log and the alert delivery log |

- `/settings` is a **landing page** — a grid of the groups with a live
  hint on each (Kea reachable, certificate expiry, users, enabled
  channels, backups, pending restart). On a phone that grid *is* the
  Settings navigation; group pages get an "All settings" link back and a
  jump list of their cards.
- **Database left the top nav.** The top bar is the same for admin and
  superadmin: Dashboard · Management · Network · Settings · About.
  Superadmin-only tools are gated per card, not by hiding menus.
- The navigation is defined **once**, in `jen/routes/settings/nav.py`,
  and `base.html` renders the top links, the mobile drawer and every
  section strip from it. Before, each was a hand-maintained list of
  endpoint names repeated three times and they had drifted.
- Section strips scroll horizontally on narrow screens instead of
  wrapping.

**Nothing changed for forms, bookmarks or the updater:** every POST
endpoint URL is unchanged; the old page URLs (`/settings/infrastructure`,
`/settings/icons`, `/database`, `/users`, `/audit`) redirect permanently
to their new homes, query strings intact. `tests/test_settings_ia.py`
pins all of that — every old URL's redirect, every group's active state,
and that every literal form action in the settings templates still
resolves.

### Updater

- **The health probe is baselined before the swap.** The updater now
  probes the currently-running Jen first; if it can't see a known-good
  app it aborts with `/opt/jen` untouched and says why, instead of
  installing a release and then rolling it back on a false negative —
  which is exactly what the 5.8.2 updater did to a healthy 5.8.4 on an
  SSL box.
- Stale `.rollback-*` snapshots from earlier failed runs are pruned at
  the start of each run (one box had four).
- The CRITICAL "rollback restart also unhealthy" line now names the
  probe URL and says plainly that if `systemctl is-active jen` reports
  active, the probe is what's wrong, not the restored app.

## [5.8.4] - 2026-09-09

Correctness, docs and small security fixes from a full code review of
5.8.3, plus the reason in-app updates were still failing on a
long-lived box.

### In-app update died at the snapshot step

The 5.8.2/5.8.3 updater snapshots `/opt/jen` before swapping files.
`shutil.copytree` followed symlinks by default, and one old install had
a stray dangling `/opt/jen/templates/templates -> (gone)` left behind
by some ancient upgrade — so every update raised ENOENT at the snapshot
and exited with a traceback. Because that happens before the swap,
nothing was damaged; the box just stayed on its old version, and the
update overlay reported "Jen restarted but still reports vX", which was
untrue (Jen never restarted).

- The snapshot (and the rollback restore) now copy symlinks *as*
  symlinks and never follow them. A snapshot failure aborts with a
  plain "could not snapshot — aborting, /opt/jen untouched" line.
- The updater exits early with "Already running vX — nothing to do"
  when GitHub's latest is what's already installed, instead of
  re-downloading and reinstalling it.
- New admin-only `/settings/infrastructure/update-status` (a read-only
  `systemctl show jen-update.service` — no `sudo`, so no sudoers
  change). The overlay polls it and now says **"Update failed (exit N)
  … `journalctl -u jen-update.service`"** when the unit failed, and
  only falls back to "still not confirmed" after 90 s.

### Security

- **Uploaded SVGs are refused if they carry active content.** Custom
  brand icons and an SVG nav logo are served same-origin from
  `/static/` under a CSP that allows inline script, so an SVG with
  `<script>`, an `on*=` handler, a `javascript:` link, a
  `<foreignObject>`, SMIL `<set>`/`<animate>`, an XML entity or an
  external/data `href` was stored XSS by an admin against a superadmin.
  Rejected on upload with a reason; never sanitized.
- **The CSRF exemption for `Authorization: Bearer` requests is now
  scoped to `/api/v1/`.** Before, *any* route skipped the CSRF check
  the moment a request carried a Bearer header — even a bogus one —
  while the session cookie still authenticated it. Not exploitable
  cross-site (a custom header forces a CORS preflight Jen never
  answers), but "a header disables CSRF" was the wrong invariant to
  keep. UI routes now require the token regardless of headers.
- `shlex.quote` on the two remaining remote paths interpolated into
  SSH commands (`kea_authoring.read_remote_json`,
  `kea6._config_exists`). Both were already validated on save; this is
  defense-in-depth.

### Bugs

- **Servers page → Restart** only tried the `isc-kea-dhcp4-server`
  unit. Every other restart in Jen tries `kea-dhcp4-server` first (ISC's
  own packages) and falls back — this one now does too, so the button
  works on ISC-package hosts.
- `login()` carried its own inline copy of the rate-limit check that
  reported the *whole* lockout window as "minutes remaining" rather
  than the time left from the oldest attempt — the same bug 5.8.0 fixed
  on the MFA side — and left `jen.services.auth.is_locked_out()` dead.
  Login now calls the one shared implementation.
- `release.yml` archived `HEAD` rather than the tag: identical on a
  tag push, wrong for a `workflow_dispatch` with a tag input.
- `legacy/jen.py` (the retired pre-2.6.0 monolith, 6,300 lines) is
  export-ignored and no longer ships in the release tarball.
- `scheduler.py` used `datetime.utcnow()` (deprecated in 3.12).

### Docs — the threat model catches up

- `ARCHITECTURE.md` §3.1 still described the pre-5.2.6
  `/tmp/jen_update_install.sh` grant. Rewritten for what `jen-sudoers`
  actually contains and why.
- `ARCHITECTURE.md` §3.3 now states the privilege implication of the
  SSH config push plainly: the Kea-side sudoers line grants
  `/usr/bin/python3`, which is root; a compromised Jen process is root
  on every managed Kea host. A fixed-path helper is the planned fix.
- The Kea-host sudoers instructions in the Admin Guide and
  Troubleshooting were incomplete and out of date (`kea-dhcp4`, `cp`,
  `tee` are no longer run directly; only one unit name; no
  `kea-dhcp6-server`, `tail`, `apt-get`). Replaced with one complete,
  honest block, validated with `visudo -c`.
- `CLAUDE.md`: versioning clarified (layout changes migrated by the
  installer/updater are MINOR), rule 9 (Kea-side sudo changes are
  documented sudoers changes), Kea-host conventions, `|tojson` and SVG
  rules, and the local-verification gotchas moved in from private
  notes.
- The Admin Guide and Installation guide still told people to
  `tar xzf jen-v5.3.3.tar.gz` and `jen-v3.8.0.tar.gz`. Both now use a
  `jen-vX.Y.Z.tar.gz` placeholder, and `scripts/release_check.sh` scans
  every guide for stale numeric references (and no longer needs
  `grep -P`).

### Tests

Subnet-scoped API keys are now tested against every `/api/v1` list and
by-MAC route (nothing covered §3.4's scope claim before); Servers-page
restart pins both unit names; the updater has a real dangling-symlink
snapshot test; the update-status route and the SVG checker have their
own suites.

## [5.8.3] - 2026-09-09

Fixes a bug in 5.8.2's own new post-restart checks, plus two smaller
follow-ups from external review.

### The updater's health check failed on SSL installs

5.8.2 added `service_healthy()` and `_running_version()`, both probing
`http://127.0.0.1:<http_port>/`. On an SSL install that port serves only
`jen/httpredirect.py`'s **301 to `https://<host>:<https_port>/`**, and
`urllib` follows redirects by default — so the probe chased the 301 into
a TLS handshake against a certificate issued for a hostname (or
self-signed), not `127.0.0.1`, which fails validation. The result:
`service_healthy()` timed out and **a perfectly healthy HTTPS upgrade
was rolled back**; `_running_version()` silently fell back to reading the
on-disk string, defeating the point of checking the running process.

Both probes now:

- talk to the app's **real port** — HTTPS directly when
  `/etc/jen/ssl/certificate.crt` + `private.key` are present, HTTP
  otherwise — bypassing the redirect listener entirely;
- **don't follow redirects** — a 301/302/401 is itself proof the app is
  serving;
- **don't verify TLS** on the loopback call (Jen's cert legitimately
  won't match `127.0.0.1`, and this is localhost).

The old `test_redirect_counts_as_healthy` mocked `urlopen` *raising*
`HTTPError(302)`, which never happens for a real redirect — it's replaced
with an integration test that stands up a real `jen/httpredirect.py`
listener and a real HTTPS server with a deliberately wrong-CN
certificate.

### Also

- `ensure_venv()`: if `apt-get install python3-venv` fails (a box old
  enough to be missing it often has stale package indices too), run
  `apt-get update` and retry the install once more before giving up.
- Docs: `docs/manual-install.md` and `ARCHITECTURE.md` §6 no longer call
  the updater flatly "transactional" — it's staged and rollback-capable,
  with the shared-venv and `static/` caveats stated inline. `static/` is
  a merge copy holding user favicon uploads, so a rollback leaves the new
  release's JS/CSS against the old templates; separating release-owned
  assets from uploads is tracked with the 6.0.0 versioned-release-dir
  work.

## [5.8.2] - 2026-09-09

In-app updater hardening, from a real deployment failure. A long-running
box that had only ever upgraded via the in-app button (never a
post-5.7 `sudo ./install.sh`) never had `python3-venv` installed. Every
in-app update since the PEP-668 world hit `externally-managed-environment`
and quietly carried on against stale system packages; the 5.8.0→5.8.1
attempt then tried to build `/opt/jen/venv`, got a half-built venv with
no `pip` (interpreter present, `ensurepip` never ran), and — because the
old check only asked "does this Python run?" — handed that back to `pip`
and failed with `No module named pip`. The transaction correctly aborted
with `/opt/jen` untouched, but the box was stuck: it could not update
itself out of the problem.

### The updater now builds its own venv

- `ensure_venv()` checks for a venv with a **working `pip`**, not just a
  runnable interpreter. A half-built venv is wiped and rebuilt.
- If `python3 -m venv` fails for want of the OS package, the updater
  (already running as root) `apt-get install`s `python3-venv` /
  `python3-full` and retries once, then falls back to the system
  interpreter with a loud warning only if that also fails.
- A failed `pip install` now logs the actual `pip` output for **every**
  attempt it made, instead of a bare "pip install failed".

### Post-restart verification

- The health-check timeout after the restart went from 45s to 90s (a
  slow homelab box doing migrations + background-worker init + gunicorn
  spawn was racing it), and is now overridable with
  `[server] update_health_timeout` in `jen.config`.
- After the restart the updater byte-compiles the freshly-installed
  `/opt/jen/jen` with the venv interpreter and confirms the **running**
  process reports the expected version (via `/api/v1/health`), rolling
  back if either fails — both inside the existing rollback transaction.
  The journal now says "Confirmed: jen is running v5.8.2" or rolls back
  with the mismatch.

**If your box is stuck reporting an old version after an in-app update:**
`sudo ./install.sh --upgrade` from the 5.8.2 tarball rebuilds the venv
and gets you current; in-app updates work from there.

## [5.8.1] - 2026-09-09

Fixes for two regressions in 5.8.0 plus the deployment-transaction gaps
from that release's review.

### The venv wasn't actually being used (bare-metal)

`run.py` decided "am I already the venv interpreter?" with
`os.path.realpath(sys.executable) != os.path.realpath(...venv/bin/python)`.
On Linux a venv's `bin/python` is a symlink chain back to the base
interpreter, so **both sides resolve to `/usr/bin/pythonX.Y`**, the guard
was always false, and the re-exec never happened — `jen.service` kept
running the system interpreter. Since 5.8.0 installs dependencies only
into `/opt/jen/venv`, a **fresh bare-metal install would crash-loop**
(and an upgrade quietly ran unisolated on leftover system packages). The
guard is now `sys.prefix == /opt/jen/venv`. The updater and the
installer had the same realpath mistake in a couple of spots; fixed.

If a bare-metal install is somehow running without its venv (an older
box that never had `python3-venv`, a failed build), Jen now shows an
admin banner and the updater logs it: `sudo ./install.sh --repair`.

### Docker `.env` quoting

5.8.0 wrapped **every** generated `.env` value in quotes. Docker Compose
before 2.24 doesn't strip quotes from `env_file:` values, so
`JEN_DB_PASS='plainpass'` reached the container with the quotes and auth
failed — a regression for anyone on older Compose with an ordinary
password. Values are now emitted bare unless they actually contain a
`$`, whitespace, `#`, a quote or a backslash; the Docker path checks for
Compose ≥ 2.24. And the "reuse an existing `.env`" path now reads an
explicit `JEN_DATABASE_MODE=external|bundled` marker instead of sniffing
credentials — the old heuristic matched the empty `JEN_MYSQL_PASSWORD=''`
that external installs write and could start an unwanted MariaDB
container.

### Self-updater is closer to actually transactional

- **Any** failure from the file-swap onward now rolls back — an
  exception mid-copy, not just a failed post-restart health check (5.8.0
  left `/opt/jen` half-updated in that case).
- The rollback snapshot now includes the files an update replaces
  *outside* `/opt/jen` — `jen.service`, `/etc/sudoers.d/jen`, the updater
  script, `jen-update.service` — with a `daemon-reload` on restore. A
  bad `jen.service` previously survived the rollback.

### Also

- MFA: `_remaining_mfa_factor_count()` now fails **closed** — if it can't
  count the user's remaining factors, a required-MFA user isn't allowed
  to remove one.

## [5.8.0] - 2026-09-09

### Bare-metal Jen runs from its own venv

Jen's Python dependencies move off system site-packages — no more
`pip install --break-system-packages` — into a dedicated virtualenv at
`/opt/jen/venv`. `install.sh` builds it (`python3 -m venv`, `--upgrade`
on re-runs so an Ubuntu Python bump doesn't strand it), installs
`-r requirements.txt` into it, and pulls `python3-venv` via apt when
it's missing.

`jen.service` **deliberately stays** on `/usr/bin/python3 /opt/jen/run.py`:
`run.py` re-execs into `/opt/jen/venv/bin/python` at the very top of the
file, before its first dependency import. Doing it as a re-exec rather
than a unit-file change means the unit never has to move, an in-app
update from a pre-venv install can't leave systemd pointing at a venv
that doesn't exist yet, and a missing or broken venv (a fresh box, or an
OS upgrade that stranded it — `sudo ./install.sh --repair` rebuilds)
falls through to the system interpreter. `JEN_NO_VENV_REEXEC=1` opts
out. Docker is unchanged — the container is the isolation.

The venv is left `root:root`, byte-compiled at install time: the
`www-data` service account reads and executes it but can't write it, so
a compromised web process can't plant persistent code in a package Jen
loads on every restart. Only `install.sh` and the root self-updater
touch it.

### Transactional self-updater

`jen-update-root.py` went from *replace `/opt/jen`, then `pip`
non-fatally, then restart* — which silently shipped a half-updated app
if a release genuinely needed a new library — to a staged flow:

1. download + checksum-verify, extract to a staging directory
2. ensure `/opt/jen/venv` exists (create it if the install predates it)
3. `pip install` the **staged** `requirements.txt` into the venv — a
   failure here **aborts before any file in `/opt/jen` is touched**
4. compile + import the staged `jen/` package under the updated venv —
   a failure aborts, still nothing changed
5. snapshot the replace-wholesale parts of the install, swap the files
   in, restart
6. health-check (unit active + the HTTP port answering below 500); if
   the service doesn't come back healthy, **restore the snapshot and
   restart the previous version**

Dependencies and code are proven against each other before the switch.
The venv is still shared, so a rollback keeps the newer (floor-pinned,
forward-compatible) dependencies rather than doing a true point-in-time
revert — a genuinely atomic switch waits for versioned release
directories in a future major (see `docs/ARCHITECTURE.md` §6).

### Security & reliability — authentication

A round of fixes from an external review of 5.7.0, in the auth/recovery
paths:

- **Mandatory-MFA enrollment could be bypassed.** When MFA was required
  but a user hadn't set it up, login called `login_user()` *before*
  redirecting to the enrollment page and nothing kept that
  fully-authenticated session off the rest of the app. Login now holds
  the user in a pre-authenticated *pending* state — password verified,
  but not a Flask-Login session — reachable only by `/mfa/enroll`; the
  session is promoted to a real login only once a factor is enrolled and
  verified. `tests/test_mfa_enrollment_gate.py` is the integration guard.
- **Backup codes never worked.** They were generated and hashed as
  `XXXXXXXX-XXXXXXXX` but the challenge path stripped the dash before
  re-hashing, so no entered code could ever match. Entered codes are now
  canonicalised back to the stored format — with or without the dash,
  any case, stray spaces — so already-issued codes work. Redemption is a
  single atomic `UPDATE … WHERE … used=0` that must change exactly one
  row, so two requests can't both spend one code.
- **Password rehash-on-login race** (introduced in 5.7.0 with the scrypt
  move): the background thread did an unconditional
  `UPDATE users SET password`, which could clobber a password changed in
  the meantime. It's now synchronous and conditional on the hash that
  was just verified still being the stored one.
- **MFA lockout "time remaining"** could display ~900 minutes just after
  lockout (it divided elapsed time by 60 inside the subtraction). Fixed.
- **Failed-attempt recording** for both password and MFA moved from a
  detached thread to synchronous, so a burst of parallel requests can't
  each pass its rate-limit check before the earlier failures land.
- **Docker `.env` values are now quoted.** `install.sh` writes every
  generated value through an escaping helper, so a password containing
  `$`, `` ` ``, `#`, spaces or quotes is no longer mangled by Docker
  Compose's interpolation.
- **You can no longer remove your last authenticator** while MFA is
  mandatory for your account — that would lock the policy out on the
  next login, and gives a stolen session no route to disabling MFA.
  Add a second one first. (A superadmin MFA-reset for a locked-out user
  is a separate, deliberate path and is unaffected.)

### Portability

- **CI now runs the full suite against MySQL 8** as well as MariaDB —
  the README has always claimed both, only MariaDB was tested. It
  immediately caught one: `dashboard_prefs.widgets` was
  `TEXT NOT NULL DEFAULT '…'`, which MySQL 8 rejects (a literal default
  on a `TEXT` column; MariaDB allows it). The baseline schema wouldn't
  build on MySQL at all. It's now `VARCHAR(512)`; migration 19 converts
  existing installs.

### Documentation

- `docs/manual-install.md` — the full bare-metal install by hand (every
  path, owner, and the venv), for a distro `install.sh` doesn't know or
  a config-managed host. The stale "Method 4" stub in the install guide
  (still referencing the pre-2.6.0 `jen.py` monolith) now points at it.
- `tests/README.md` rewritten to actually map the suite.

## [5.7.0] - 2026-09-08

### Alert-channel tokens encrypted at rest

`alert_channels.config` — a JSON blob holding every notification
channel's delivery credentials (Telegram bot tokens, SMTP passwords,
Pushover user/API keys, ntfy tokens, and the Slack/Discord/webhook URLs
that themselves embed a secret) — was stored as plaintext. Any read of
that one column (a stray database export, a read replica, SQL injection,
a shared DB host) handed over working credentials for every channel. This
was the same exposure the v5.4.0 work closed for TOTP secrets, on the
last unprotected reversible-secret surface in `jen_db`.

- The whole `config` blob is now encrypted with the existing Fernet key
  (`jen/services/crypto.py`, key at `/etc/jen/mfa_key`, outside the
  database) — whole-blob rather than per-field, so a new channel type
  with new secret fields is covered automatically. The `v1:` token is
  stored as a JSON string literal so the column stays valid JSON
  (MariaDB enforces `json_valid()` on it).
- **Migration 18** wraps every existing plaintext blob on upgrade,
  idempotently. New saves encrypt at write time; every read goes through
  `alerts.get_channel_config()`, which decrypts, with a legacy-plaintext
  passthrough for any row the migration hasn't reached.
- A blob that can't be decrypted (a DB restored onto a new install
  without copying `/etc/jen/mfa_key`) makes that channel go quiet rather
  than crashing alert dispatch — the tokens must be re-entered, same as
  MFA secrets in that situation. The database-export screen now says so.

### New passwords hashed with scrypt

`hash_password()` moves from `pbkdf2:sha256:260000` to scrypt
(`scrypt:32768:8:1`, werkzeug's current default). scrypt is memory-hard —
~32 MB per hash — where pbkdf2 is not, which is what makes it meaningfully
harder to attack with GPUs or ASICs, while staying fast enough for
interactive login (~50–100 ms).

- Existing pbkdf2 hashes keep verifying and are transparently upgraded to
  scrypt on the user's next successful login — the same
  rehash-on-login path that already handled iteration-count bumps and the
  original SHA-256 → pbkdf2 move. No forced password resets.
- `needs_rehash()` now flags any pbkdf2 hash (and any scrypt hash at
  non-current cost parameters) for upgrade.

### Documentation

- **README:** new "How Jen talks to Kea" section (the three channels —
  Control Agent HTTP, the Kea database, SSH — and what each is for), and
  a "Jen compared to ISC Stork" table laying out the agentless-vs-agent,
  management-vs-monitoring, MySQL-vs-PostgreSQL tradeoffs so people can
  tell quickly which tool they actually want.
- **`CONTRIBUTING.md`** added: dev setup, the CI gates, and a candid list
  of what does and doesn't fit the project's direction.

## [5.6.1] - 2026-09-08

### Split the two monolith files (`settings.py`, `test_kea6.py`)

Pure refactor — no behavior change, no route or endpoint renamed.
Both reviews flagged these as the maintainability frontier, and the
next feature (Kea CA-less support) adds routes and fields to Settings,
which is much nicer on a split module than a 2,060-line one.

- **`jen/routes/settings.py` → `jen/routes/settings/`** (a package):
  `alerts`, `infrastructure`, `authoring`, `branding`, `security`,
  `updates`, each registering on the one `bp` so every endpoint stays
  `settings.<fn>` and every `url_for("settings.…")` resolves unchanged.
  `_parse_subnet_lines` / `_subnets_to_lines` are re-exported from the
  package root for their existing importers. Dropped one dead helper
  (`__ip_to_int`, defined and never called).
  `tests/test_settings_blueprint.py` freezes the full 48-endpoint set as
  a drift guard. Three sibling tests that locate route code by file path
  (`test_no_raw_exception_leaks`, `test_sudoers_command_matching`) now
  scan the package instead of the old single file.
- **`tests/test_kea6.py` → `tests/test_kea6_*.py`** by feature area
  (config, service toggle, leases/devices, reservations, subnets,
  search/metrics) plus `tests/test_kea_authoring.py` for the
  Kea-config-authoring flow. Shared `FakeSSHClient` helper moved to
  `tests/_kea6_helpers.py`.

## [5.6.0] - 2026-09-08

### Docker configuration unified on `.env`, plus a hygiene pass

Two more third-party reviews. No new application features; the
interesting security work already shipped in 5.4.x/5.5.0. Both flagged
the Docker install path as the one thing to fix before pointing new
users at it.

**Docker is now `.env` / `JEN_*` only.** The installer's Docker path
built a `jen.config`; the compose files used `env_file: .env` with the
config mount commented out; the README told you to edit `jen.config`.
Following any of the three documented paths left Jen unable to start.

- `install.sh --docker` now writes `.env` (not `jen.config`): the
  guided wizard for the Kea side, a generated MariaDB password for the
  bundled path, and the admin password you choose.
- `docker-compose.mysql.yml` wires the `jen` container to the
  `jen-mysql` container via `environment:` (`JEN_DB_HOST=jen-mysql`,
  `JEN_DB_PASS=${JEN_MYSQL_PASSWORD}`) — `.env` no longer carries (or
  drifts on) the bundled DB credentials, just `JEN_MYSQL_PASSWORD` once.
- `.env.example`, `README.md`, and `docs/docker.md` rewritten to match.
- New `tests/test_docker_config.py` fails CI if the pieces drift apart
  again.

**First-run admin password for Docker.** The bare-metal installer sets
an admin password during setup; the Docker path never did and its
summary still said `admin/admin`. New `JEN_INITIAL_ADMIN_PASSWORD` env
var: `init_jen_db()` seeds the `admin` account from it (with
`must_change_password=0` — the operator picked it) on first boot only,
then never reads it again. `install.sh` writes it into the Docker `.env`
and, on bare metal, `_set_admin_password()` now also clears
`must_change_password` (it was leaving bare-metal installs to force a
redundant change of a password the operator had just chosen).

### Hygiene pass: TLS floor, metrics token, CI matrix, docs reconciliation

- **gunicorn SSL path had no TLS-version floor.** It passed `--ciphers`
  but nothing pinned the minimum protocol, so the production path was
  weaker than run.py's werkzeug fallback (which sets `TLSv1_2`). New
  `jen/gunicorn_conf.py` with an `ssl_context` hook restores the
  `TLSv1_2` minimum; `run.py` always passes
  `--config python:jen.gunicorn_conf`.
- **`/metrics` token check hardened.** Constant-time comparison
  (`secrets.compare_digest`) instead of `==`; the `?token=` query-string
  form is dropped (it would land verbatim in gunicorn's access log,
  which 5.5.0 routes to stdout/journald) — Bearer header only; and the
  "not configured" 401 body no longer spells out which config keys to
  set.
- **`_build_config_from_env()`** now reads an existing `jen.config` with
  `interpolation=None`, matching `AppConfig` — a DB/API password
  containing a literal `%` no longer trips `ConfigParser`.
- **CI now tests Python 3.10 as well as 3.12** (matrix). The README
  claims 3.10+ / Ubuntu 22.04; with floor-pinned deps a future
  "latest compatible" package could drop 3.10 while CI stayed green.
- **CI uses `JEN_ROOT` instead of symlinking the checkout into
  `/opt/jen`.** The old `ln -sf` step and its "create_app() hardcodes
  the path" comment predated the `JEN_ROOT` override (5.3.3) — removing
  them proves the override actually works.
- **Dependabot** now watches `pip` (the stale note said Jen pins deps
  inline in install.sh — true until 5.4.1's `requirements.txt`), and its
  first round of bumps landed: gunicorn, cryptography, requests, authlib,
  werkzeug floors raised; `actions/setup-python` and
  `softprops/action-gh-release` pinned SHAs moved forward (fixes the
  Node 20 deprecation warning).
- **Docs reconciliation:** `ARCHITECTURE.md` §3.4 (API keys have been
  per-key subnet-scopable since migration 13, not global-only), §3.5/§6
  (the self-updater runs pip as of 5.5.0). README: MFA line no longer
  claims WebAuthn/passkey (the page says "coming soon"); Flask badge
  3.0 → 3.1+. `jen.service` description "Internet" → "Kea DHCP" to match
  the README.

### Ruff is now a CI gate

The whole codebase was run through `ruff format` + `ruff check --fix` —
one mechanical, zero-behavior-change pass (verified: bandit shows no
new findings, the full suite is green). The ~71 backlog findings
(compound one-liners, unsorted imports, one unused var, thirteen
ambiguous `l` names) are gone.

CI now runs `ruff check .` and `ruff format --check .` as a job, so new
lint or format regressions fail the build. `ruff` is pinned exact in
`requirements-dev.txt` — its formatter output drifts subtly between
releases, so an unpinned bump could fail `format --check` on a no-op;
Dependabot PRs the bump and we reformat in that same PR if needed.

## [5.5.0] - 2026-09-08

### gunicorn replaces the werkzeug dev server

Through 5.4.x, `run.py` *was* the server — `werkzeug.serving.make_server`
/ `app.run`, the Flask development server. `threaded=True` (5.3.3)
stopped one slow request from blocking every other user, but it was
still the dev server: no request timeouts, no graceful drain, unbounded
thread spawning. For something marketed as a management console that's
the first thing a skeptical network engineer dings.

**`run.py` is now a launcher, not a server.** It loads config and then
runs gunicorn (`jen.wsgi:application`):

- **No SSL:** `os.execvp` gunicorn on the HTTP port — the process is
  replaced, systemd owns gunicorn directly.
- **SSL:** gunicorn runs as a child (HTTPS, `--certfile/--keyfile`);
  `run.py` stays parent, serves the HTTP→HTTPS 301 redirect
  (`jen/httpredirect.py`, stdlib only) and forwards SIGTERM to gunicorn.
  A `systemctl restart jen` now **drains** in-flight requests
  (`--graceful-timeout 30`, `jen.service` `TimeoutStopSec=40`) instead
  of cutting them.

**`--workers 1 --threads N`** (N = `[server] threads` in jen.config,
default 8, editable in Settings → Infrastructure → Server Ports &
Performance; a restart applies it). Jen is I/O-bound (DB, Kea API, SSH),
so threads carry the concurrency and a single worker keeps the backup
scheduler and the alert loop single-process. Those were started by
`create_app()` before — which under gunicorn would have run them once
per worker. Now the factory only builds the app; `jen/wsgi.py` starts
the background workers once, in the sole worker. Multi-worker gunicorn
is deliberately not offered (it reopens "scheduler runs N times").

**Werkzeug fallback, safety-net only.** If gunicorn can't be imported or
launched (a bad dependency install, a non-Linux dev box), `run.py` logs
a CRITICAL and falls back to the old werkzeug path so the console
doesn't go dark. It is not a supported production path and says so on
every start.

**The self-updater now runs pip.** `jen-update-root.py` copied files but
never installed dependencies — so a file-only self-update to 5.5.0 would
land a `run.py` that expects gunicorn to be present. It now runs
`pip install -r /opt/jen/requirements.txt` after the file install,
non-fatally (logged on failure; the werkzeug fallback covers a missing
package until a `sudo ./install.sh --upgrade`). This closes the PENDING
"self-updater doesn't run pip" gap.

`gunicorn>=23.0.0` added to `requirements.txt`. New tests:
`test_run_launcher.py` (command-line construction, SSL/non-SSL
branching, thread clamping), `test_background.py` (the factory starts
nothing; `start_background_workers` is idempotent), and self-updater
pip-step coverage in `test_jen_update_root.py`.

## [5.4.1] - 2026-09-08

### One dependency list instead of four

The same ~14 runtime packages were pinned independently in `install.sh`,
`Dockerfile`, and both jobs of `.github/workflows/tests.yml`. They had
already drifted: `werkzeug` was pinned in the Dockerfile, missing from
`install.sh` (relying on flask to pull it), and unpinned in CI;
`cryptography` (added in 5.4.0) was pinned in two places and unpinned in
CI. The `Dockerfile` `LABEL version` had also sat at `5.3.3` through the
entire 5.4.0 release.

- **`requirements.txt`** at the repo root is now the single source of
  truth — floor-pinned (`>=`), the deliberate choice documented in
  `docs/ARCHITECTURE.md` §3.5 (a lockfile was considered and rejected
  for this project's solo-maintenance model; `pip-audit` in CI is the
  compensating control). `install.sh`, the Docker build, and both CI
  jobs now `pip install -r requirements.txt`. `requirements-dev.txt`
  adds the test/lint tooling.
- **`jinja2>=3.1.6`** and **`werkzeug>=3.1.7`** are now pinned
  explicitly rather than left as transitive flask dependencies, so a
  security floor (e.g. jinja2 3.1.6 for CVE-2025-27516) doesn't depend
  on flask happening to require it.
- **`tests/test_dependency_consistency.py`** fails CI if any consumer
  re-inlines a package pin, and if the version strings that must move
  together (`jen/__init__.py`, `install.sh`, `Dockerfile` LABEL, README
  badge, CHANGELOG) fall out of sync.
- `requirements.txt` now travels with each release and is copied to
  `/opt/jen/`. The in-app self-updater still does **not** run `pip` —
  a release that adds or raises a dependency floor needs a
  `sudo ./install.sh --upgrade`, noted in §3.5 and `PENDING`.

No runtime behavior change — this is a build/packaging refactor.

## [5.4.0] - 2026-09-08

### TOTP secrets are now encrypted at rest

`mfa_methods.secret` — the shared secret behind every enrolled
authenticator app — was stored as plaintext base32. Anyone able to read
that one column could generate valid second-factor codes for every user
and walk straight through MFA: a downloaded or misplaced database
export (Jen's own export UI includes this table), a read replica, a
compromised database account, SQL injection anywhere in the app, or a
shared database host. Backup codes, trusted-device tokens, and API keys
were already one-way sha256 hashes; the TOTP secret is the one value
Jen has to be able to read back (it recomputes the current code from it
every 30 seconds), so the fix is encryption with a key kept outside the
database, not a hash.

**How it works.** A new `jen/services/crypto.py` wraps each secret with
Fernet (AES-128-CBC + HMAC, from the `cryptography` library — already a
transitive dependency via paramiko, now pinned explicitly). Stored
values gain a `v1:` prefix so a future key rotation is a recognizable,
migratable format rather than an ambiguous blob. The key lives at
`/etc/jen/mfa_key` (0600), with the same two-candidate load-or-create
logic and `$JEN_ROOT` fallback that `_load_secret_key()` already uses
for the Flask session key — created on first use, not by the installer,
and preserved across upgrades because `/etc/jen` always is.

**Upgrade.** Migration 17 encrypts every existing plaintext secret in
place on the first restart after updating. It's idempotent (rows
already in `v1:` form are skipped) and shares one transaction with its
own version record, so a crash partway through recovers cleanly on the
next start. New enrolments encrypt at the point of insert;
`verify_totp()` decrypts on read, with a passthrough for any
still-plaintext value so nothing breaks in the window before migration
17 runs.

**Key loss fails closed.** If `/etc/jen/mfa_key` can't be read (a
database restored or migrated onto a different install without copying
the key across) `verify_totp()` skips the unreadable row and returns
false — the affected user falls back to their backup codes and an admin
can reset their MFA. A missing-and-unwritable key aborts startup during
migration rather than inventing an ephemeral one that would render
every stored secret permanently unreadable. Database exports now carry
`v1:` ciphertext instead of plaintext (an improvement — export files
were a leak vector), with the tradeoff that MFA secrets do not restore
onto a different install; this is called out in the export table
description and `docs/troubleshooting.md`.

16 tests added (`tests/test_mfa_encryption.py`): crypto round-trips and
failure modes, migration 17 (encrypt + idempotent re-run), the
enroll/verify wiring, legacy-plaintext compatibility, and the
fail-closed paths.

## [5.3.3] - 2026-09-08

### The privileged updater can now update itself, a migration gap closed, and Ruff added

Three items from a second round of third-party review, deliberately
combined into one release since two are small and well-scoped, and
the third (Ruff) touches the same broad surface without any
interaction risk between the three.

**The updater couldn't update itself.** `install_extracted_files()`
(the v5.2.6 rewrite) installs the application it updates — `jen/`,
`run.py`, `templates/`, `static/`, `jen.service`, `jen-sudoers` — but
never a new copy of `jen-update-root.py` itself, or of
`jen-update.service`. A fix shipped inside the updater would therefore
never reach a running instance via the in-app update button; only a
manual `sudo ./install.sh --upgrade` would ever pick it up, quietly
recreating the exact "self-update can't fix itself" maintenance trap
the v5.2.6 redesign exists to close for the application. Fixed with a
new `install_self_update_files()`: writes to a temp file in the same
destination directory, sets root:root ownership and the correct mode
(0700 for the script, 0644 for the service unit) on the temp file
*before* the atomic rename via `os.replace()`, then reloads systemd.
Safe to do while this exact script is the one currently running — the
interpreter already has the source read into memory before execution
began, so only the *next* invocation ever sees the new file. Added 7
regression tests, including the specific one requested: "a verified
release containing a newer root updater installs it root-owned and
non-writable by www-data." Caught two mistakes in my own first draft
of these tests before trusting them — one asserted a total call count
that didn't account for the service file getting its own separate
call, the second one checked the wrong path entirely, since ownership is
set on the temp file before the rename, not the final destination.

**Migration 15 didn't protect existing installations.** It added
`must_change_password` with `DEFAULT 0` — correct for new rows going
forward, but every row that already existed when it ran got treated as
"already fine," including an admin account still sitting on the
literal password `admin`. Only a genuinely fresh install was actually
protected. Couldn't be fixed by editing migration 15 itself — the
migration runner never re-invokes an already-applied migration, and
most currently-deployed installations already have it recorded as
applied. Added migration 16 instead: checks every unflagged user's
password against the literal string `"admin"` via `verify_password()`
(hashes are salted, so this can't be a direct hash comparison) and
retroactively flags any match, checking every user rather than just
the admin account. Verified the decision logic directly with real
password hashing against three simulated users before trusting it.

**Ruff added to the project for the first time.** A standalone
`ruff.toml` (deliberately not folded into a future `pyproject.toml` —
dependency management is a separate, larger piece of work this project
has intentionally deferred), scoped conservatively: pyflakes,
pycodestyle, import sorting, pyupgrade, and bugbear, excluding
`legacy/jen.py` (explicitly documented as dead reference code, never
imported or executed by the live application). First scan: 734
findings. Ran the safe, mechanical auto-fixes (493 of them — mostly
unused and unsorted imports) and verified the result rather than
trusting it: spot-checked the diff on `settings.py`, confirmed every
removed import was genuinely unused via direct search, and ran
pyflakes across all 62 touched files to catch anything the auto-fix
might have broken.

Manually reviewed and fixed the remainder individually rather than
applying further automation blindly: a bare `except:`; seven
`raise ...` statements inside exception handlers now explicitly chain
with `from e` (one of these had an `except ValueError:` that didn't
even bind the exception to a name — applying the mechanical fix
without checking would have introduced a `NameError`); three
genuinely-unused imports in `jen/__init__.py`, each confirmed unused
by direct search before removal, with the whole package re-verified to
still import and `create_app` still callable afterward; two imports in
the IPAM and network-discovery plugins moved to the top of their
files; three unused loop-control variables renamed per Ruff's own
convention; and two `zip()` calls given explicit `strict=` values —
these needed *opposite* answers, not the same fix twice.
`migrations.py`'s registry sanity check needs `strict=False` (the two
lists being compared are intentionally different lengths by exactly
one element; `strict=True` there would make the assertion always fail
and break the app at import time — confirmed by importing the module
after the change), while the extra-Kea-servers form handler in
`settings.py` needed `strict=True`, since it zips eight independently-
submitted form arrays that could legitimately mismatch in length under
a malformed or tampered POST — silently truncating to the shortest one
would misalign one server's fields with a different server's. That one wasn't a
mechanical fix alone: the surrounding route had no exception handling
at all, so `strict=True` on its own would have turned a length
mismatch into an uncaught `ValueError` and a raw 500. Added a
try/except around it with a clean error message instead. Directly
verified both the normal (matched-length) and the new protective
(mismatched-length) cases.

**Deliberately deferred, not silently decided:** 69 remaining findings
are purely stylistic — compound one-line statements (`try: x` /
`except: y` on one line) and single-letter ambiguous variable names.
Fixing these by hand wasn't the right use of manual review time, and
running Ruff's full formatter would produce a whole-codebase diff
(quote-style and spacing changes across thousands of lines) large
enough to swamp the two substantive fixes in this same release. Left
as a follow-up decision rather than made unilaterally.

Bandit's finding count dropped from 141 to 131 as a side effect of
this cleanup, not a suppressed check: several of the files touched had
a genuinely-unused `import subprocess` or `import threading` that
bandit flags on the import statement itself regardless of whether it's
used, and removing genuinely dead code removed those specific
findings along with it. Confirmed directly rather than assumed.

### A second round of review — two independent reviewers, real convergence

A second third-party review (independent of the one above) surfaced
six more items, several of which the first review's author also
flagged independently — two different reviewers arriving at the same
conclusions without coordinating is a stronger signal than either
alone.

**The global exception handler leaked raw exception text — the most
important item here.** `jen/__init__.py`'s catch-all
`@app.errorhandler(Exception)` interpolated the raw exception directly
into the user-facing error page:
`message=f"An error occurred: {e}"`. This is a real gap in the v5.2.14
"stop leaking exceptions" work: that release fixed dozens of
individual per-route `except Exception as e:` blocks, but never
touched this single global handler, which catches literally anything
unhandled anywhere in the app. Fixed to use a generic message —
matching the 404 and explicit-500 handlers immediately above it in the
same file, which were already doing this correctly — while the full
traceback still goes to the server log via the existing
`logger.exception()` call. Nothing about debugging capability changed,
only what reaches the browser.

The regression scanner from v5.2.14
(`tests/test_no_raw_exception_leaks.py`) had two gaps that let this
through: it only scanned `jen/routes/*.py`, never `jen/__init__.py` or
anything else in the package, since the bug it was designed around was
route-shaped; and its pattern list covered `flash()`/`jsonify()`/
`api_error()` calls specifically, never a bare `message=f"...{e}"`
keyword argument. Both fixed — the scanner now covers the whole `jen/`
package recursively, and the pattern list catches this shape too.
Verified the fix has real teeth the same way the original scanner was
verified: planted the exact bug that just shipped in a throwaway file
and confirmed the widened scanner catches it. The wider scan also
turned up one more real instance in `jen/routes/ddns.py` that the
original, narrower scanner had also missed.

**Werkzeug's dev server had no threading.** `run.py`'s `make_server()`
calls (both the HTTPS server and the HTTP-redirect server) and the
HTTP-only `app.run()` fallback all defaulted to handling exactly one
request at a time, globally, across every user of the app — a slow
SSH-backed config apply or a slow Kea API call blocked every single
concurrent request, including basic page loads, until it finished.
Added `threaded=True` to all three. This is not a substitute for a
real production WSGI server (gunicorn) — that's a larger, deliberate
migration queued as its own next piece of work, since it needs to
solve a real problem first: the background alert-checking thread
currently starts once, in the one process `run.py` runs; naively
adding multiple gunicorn worker *processes* would start it once per
worker, producing duplicate alerts for every single lease event. This
fix closes the acute, immediate symptom (the app appearing to hang
under even light concurrent use) without taking on that migration yet.

**Hardcoded `/opt/jen` path removed.** `jen/__init__.py`'s Flask app
factory passed `static_folder="/opt/jen/static"` and
`template_folder="/opt/jen/templates"` as literal strings, which made
a local clone-and-run hostile — nothing under `/opt/jen` exists outside
a real install — and forced CI to symlink the checkout into place to
work around it. Introduced a single `JEN_ROOT` constant in
`extensions.py`, defaulting to `/opt/jen` (so every existing production
install's behavior is completely unchanged — verified the default
resolves to the exact original hardcoded values), overridable via the
`JEN_ROOT` environment variable for local development. Every
`/opt/jen`-rooted path in the active application (`STATIC_DIR`,
`TEMPLATE_DIR`, `FAVICON_PATH`, `PLUGIN_DIR`, and several more) now derives
from it instead of repeating the literal path. `install.sh` and
`jen-update-root.py` deliberately keep their own hardcoded references
— those manage real production installs, which is a different concern
from "can this be run locally for development."

**Plugin installation gained checksum verification.** Mirrors the same
principle already applied to the self-updater in v5.2.6: HTTPS-only,
manifest ID matching, and zip-slip-safe extraction were already
present, but nothing verified the downloaded plugin zip's integrity
against anything published alongside it — a compromised
`registry.json` or a compromised plugin repository could serve
arbitrary code, executed as `www-data`, plus whatever `db_migrations`
the manifest declares. Deliberately *not* fail-closed on a missing
checksum, unlike the self-updater: the two plugins that exist today
(network-discovery, ipam) don't have one in the registry yet, and
there's no way to manufacture a trustworthy hash for zip files hosted
in separate repositories without a verified, out-of-band copy of them
— computing one from what this function just downloaded would be
circular and add no real security. A registry entry *with* a `sha256`
field that doesn't match is a hard failure; one *without* the field
logs a warning and installs anyway, as a visible, deliberate transition
state rather than a silent gap. Verified all three cases directly —
matching, mismatched, and missing. **Existing plugin maintainers: real
`sha256` values need adding to `plugins/registry.json` the next time
either plugin is released, computed against the actual current
`plugin.zip` — this can't be generated after the fact by anyone who
doesn't already have a verified-good copy.**

**`/metrics` now defaults to closed.** Previously, no configuration at
all meant the endpoint was fully open — deliberate, documented
behavior ("unauthenticated by design for scraper compatibility"), not
an oversight, but backwards from a secure-by-default posture even
though the data exposed is limited to aggregate counts, never
individual MACs, IPs, or hostnames. **This is a breaking change**: set
either `metrics_token` (recommended — token-protected access) or the
new `metrics_open = true` (restores the old fully-open behavior, for
anyone who's already decided that tradeoff is fine given their network
setup) in `jen.config`'s `[server]` section. With neither set,
`/metrics` now returns 401. Updated `docs/admin-guide.md`, which had
also drifted to claim the wrong config section name (`[jen]` instead of
the actual `[server]`) on top of describing the old default. Also
added a proper Settings UI for this (Settings → Infrastructure →
Prometheus Metrics — token field with a "Generate" button, plus an
"Allow open access" checkbox), rather than requiring a config-file
edit for something this project has consistently kept
UI-driven. No restart needed, unlike the ports card right above it in
the same page — `extensions.cfg` is read fresh on every `/metrics`
request, so the setting takes effect on the very next scrape.

**`CHANGELOG.md` trimmed from ~330KB to ~100KB.** It had become an
audit log rather than a changelog — every release since v1.0.0, all in
one file, 223 entries. Moved everything before the 5.x series (182
entries, v4.4.24 and earlier) into
`docs/release-history/CHANGELOG-archive-pre-5.0.md`. Nothing deleted,
only relocated — did this programmatically rather than by hand given
the file's size, and verified the split reconstructs the original file
byte-for-byte before writing anything, then separately verified entry
counts on both sides and spot-checked specific entries for content
integrity. The in-app "What's New" viewer only ever shows the 5 most
recent entries regardless, so this has no effect on it.

### Test fixes caught by CI before this ever got tagged

Since this release was never actually pushed or tagged, CI on the
first attempt at it caught real mistakes worth being honest about
rather than quietly folding away: four of the new updater self-update
tests either called the real `systemctl daemon-reload` (unmocked,
which fails outside a real systemd environment) or referenced a
destination directory that was never created with `.mkdir()` first —
both classes of mistake I'd actually already caught and fixed once in
ad-hoc scratch testing while writing these tests, but didn't correctly
carry into every corresponding formal test method. Separately, three
tests in `test_kea6.py`'s own Prometheus v6 metrics suite broke
outright from the `/metrics` default-closed change, and two more in
that same class were passing for the wrong reason — asserting specific
text was *absent*, which is trivially true of a 401 page too, not a
meaningful confirmation of what they claimed to test. All were missed
because the search for `/metrics` usages when making that change only
covered `test_dashboard.py`; a repo-wide search afterward found this
second file. All nine now fixed and individually re-verified directly
before repackaging, not just re-run and trusted.

A second CI run, against the same still-untagged release, caught one
more: the new `TestMetricsSettings` class assumed each test could
rely on a predictable starting state — "default closed," or "whatever
the previous test in file order left behind." `jen.config` is a real
file on disk, not reset between individual tests the way the database
fixture is, so a write from one test genuinely persists into the
next. `test_short_token_rejected` expected `/metrics` to still be
closed after its own (correctly rejected) short token, but the
previous test in file order had left `metrics_open=true` behind, so
the endpoint was actually open — an assertion of 401 got a 200
instead. Fixed by having every test in the class explicitly establish
its own starting state via a setup call first, rather than assuming
one; verified by simulating the exact five-test sequence against the
real route logic both before and after the fix, reproducing the
identical 200-instead-of-401 failure from CI on the unfixed version
before confirming the fixed version resolves it.

## [5.3.2] - 2026-09-08

### Rebrand follow-up: About page missed, dedicated navbar asset

Two gaps from v5.3.0's rebrand, both reported directly after checking
the deployed app rather than caught beforehand.

**The About page still showed the old branding** — a CSS gradient-text
"Jen" heading, the exact same pattern already replaced on the login
and MFA verification pages in v5.3.0, just missed there. Confirmed via
a repo-wide search for the specific gradient CSS this time, not just
the handful of templates checked in the original pass — login.html and
mfa_challenge.html were already clean; about.html was the only
remaining instance. Replaced with the same wide wordmark image used
elsewhere.

**Navbar logo replaced with a dedicated, hand-tuned asset.** v5.3.0
used the same wide wordmark image everywhere, relying on CSS to scale
it down to navbar size (28px tall). A purpose-built 99×32 export,
tuned specifically for legibility at that exact small size, now ships
instead — `static/icons/jen-logo-navbar.png`. The navbar's CSS height
now matches this asset's native size (32px, up from 28px).

No application behavior changed — this release is template and asset
content only, matching the scope of v5.3.0 itself.

## [5.3.1] - 2026-09-08

### Fix CI failure carried over from 5.2.14 (also present in 5.3.0)

Three tests in `tests/test_no_raw_exception_leaks.py` failed —
present in 5.2.14's own CI run, and still present in 5.3.0 since that
release never touched this test file or the routes it covers.

**Root cause, found by actually reading the failure rather than
re-running and hoping:** `jen.__init__.load_user()` (Flask-Login's own
per-request user-loading callback) does a *local*, per-call `from
jen.models.db import jen_db` — meaning it always resolves whatever the
*current* attribute on the `jen.models.db` module is, not a reference
captured once at import time. Three of this file's tests patched
`jen.routes.X.__db.jen_db` to simulate one route's own database
failure — but for any route module that imports the db layer as
`import jen.models.db as __db` (as opposed to `api.py`'s `from
jen.models.db import jen_db`, which creates an independent local
name), `__db.jen_db` **is** `jen.models.db.jen_db`, not a copy. Patching
it broke authentication itself for the duration of the mock:
`load_user()` also calls `jen_db()` on every request, before the route
body ever runs, so every request in those three tests appeared
unauthenticated and got redirected to login (302) — the route's own
exception-handling was never actually reached or exercised at all.

**A second, distinct bug found while fixing the first:** the
dashboard-stats test mocked `jen_db()`, but `api_stats()` actually
calls `__db.kea_db()` in its own logic — confirmed by reading the
route directly. That test's mock was never touching the code path it
claimed to test; the assertion would have passed regardless of whether
the underlying exception-hiding fix (from v5.2.14) worked at all. Fixed
by mocking the function the route actually calls, which also needed
none of the load_user() workaround below, since `kea_db()` is never
touched by `load_user()`.

**The fix** for the remaining two: a `side_effect` wrapper that walks the
*entire* call stack (not just the immediate caller) looking for a
frame named `load_user`, delegating to the real function when found so
authentication proceeds normally, and raising the test's exception for
any call that isn't. Walking the full stack rather than checking one level up
was necessary because `unittest.mock`'s own call machinery
(`__call__` → `_mock_call` → `_execute_mock_call` → the side_effect)
introduces several frames of its own — an initial version of this fix
checked only the immediate caller and never actually matched
`load_user` when run through a real `patch(..., side_effect=...)`,
only when called directly in isolation. Verified the corrected version
through actual `unittest.mock.patch` machinery, not just a bare
function call, before trusting it — confirming `load_user()` gets the
real result while a simulated route handler still raises.

No application behavior changed; this is a test-only fix.

## [5.3.0] - 2026-09-08

### Rebrand — new logo across the entire app

Jen's first real visual identity: a wordmark plus a standalone router-
icon mark, replacing the plain-text "Jen" and generic default icons
used everywhere until now.

**A design problem found before it shipped:** the full wordmark, which
looks good at normal sizes, was tested directly at actual favicon size
(16×16, 32×32) and turned out nearly illegible — just a green smudge,
not a recognizable mark. Rather than ship that, the red router icon
(with its radiating signal lines) was isolated from the wordmark via
color-based pixel analysis and confirmed legible at 16×16 through
direct visual inspection. App icons now consistently use this
standalone mark; the full wordmark is reserved for wide contexts
where there's room to show it properly.

**Assets replaced**, all generated from the source artwork rather than
hand-drawn: `favicon.ico` (a genuine multi-resolution ICO — verified
by parsing its byte structure directly, not just trusting the save
call, since an earlier attempt silently produced a single-size file),
`icon-192.png`, `icon-512.png`, `apple-touch-icon.png` — all using the
icon-only mark on a dark background matching the PWA manifest's own
declared `background_color` (`#0d0d0d`, chosen to match Jen's overall
dark UI theme rather than the older teal accent color). A new
`jen-logo-wide.png` (transparent background, full wordmark, trimmed to
its actual content and resized to a sensible file size) is used for
the nav bar, login page, and MFA verification page.

**Where it now appears:**
- Nav bar — this is now the default logo shown to everyone, not
  hidden behind the existing "upload a custom nav logo" admin setting.
  That setting is untouched and still works exactly as before; it now
  overrides this new default instead of overriding plain text.
- Login page and MFA verification page — both previously showed a CSS
  gradient-text "Jen" wordmark; both now show the real logo image.
- Browser tab icon, PWA home-screen icon, iOS "Add to Home Screen"
  icon — all updated to the new mark.
- README header, using the same wide wordmark asset.

No application behavior changed — this release is asset and template
content only. Verified every touched template still renders correctly
after the edits, and confirmed the PWA manifest's icon references
still resolve to real files on disk with no path or structural changes
needed.

## [5.2.14] - 2026-09-08

### SECURITY: stop leaking raw exception text across the app

Final finding from the third-party security review that also produced
v5.2.6, v5.2.7, v5.2.10, and v5.2.12: raw Python exception text —
potentially including internal file paths, database schema details,
or connection info — was shown directly to users and API clients in
roughly 60 places across 14 route files, including several introduced
in this project's own 5.2.2 bulk-action work.

**Rule applied throughout:** fix anything wrapping a database or
file-system operation, since the exception text there can reveal
internal implementation details that are actionable for nobody except
someone probing the app. Leave alone anything that's a deliberate,
already-constructed message about the user's own submitted input (a
form-validation error), or an error communicating with infrastructure
the admin themselves configured — an SSH target, a webhook/Discord/
ntfy/Telegram integration. That text is the actionable diagnostic an
admin managing their own gear actually needs; hiding it behind "check
server logs" would make the app measurably less useful without
addressing any real security concern.

Fixed: `database.py`, `devices.py`, `leases.py`, `dashboard.py`,
`mfa_routes.py`, `plugins.py` (fixed at the shared `fetch_registry()`
source rather than patching each caller separately), `reports.py`,
`reservations.py`, `search.py`, `servers.py`, `subnets.py`, `users.py`,
`settings.py`, and the REST API v1 endpoints in `api.py` (separate
from the API-key management routes already fixed in v5.2.10).

Deliberately left alone, with the specific reason documented in each
case: `parse_import_file()`'s message about a malformed uploaded file,
`normalize_duid()`'s validation error about a submitted DUID, a
`configparser` error parsing an admin's own submitted subnet textarea,
and roughly ten SSH/webhook/Telegram cases where the error text is
about infrastructure the admin configured themselves.

Caught and fixed a real mistake in this exact release before it
shipped: one edit accidentally dropped a line while restructuring an
exception handler in `api.py`, leaving an unclosed dict literal — a
genuine syntax error. Found immediately via `ast.parse()`, and rather
than trusting the one-line fix, re-verified every remaining function in
that file individually, ran a full codebase-wide AST sweep, and spot-
checked several of the more complex multi-line edits from earlier in
this same pass.

Added `tests/test_no_raw_exception_leaks.py`: a regression scanner
(same approach as v5.2.9's sudoers-matching test) that greps every
route file for the leak pattern and fails on anything not in an
explicit, individually-justified allowlist, plus spot-check tests
across a representative sample of files that mock the database layer
to raise a distinctively-marked exception and confirm that marker
never reaches the response. Verified the scanner has real teeth, not
just coincidental passing, by planting a fake leak in a throwaway file
and confirming it's caught.

## [5.2.13] - 2026-09-08

### Fix CI failure in 5.2.12's test suite

`tests/test_small_hardening_fixes.py` failed to even collect in CI:
`ModuleNotFoundError: No module named 'yaml'`.

**Cause:** the Docker healthcheck tests in that file used `import yaml`
(PyYAML) to parse `docker-compose.yml`. PyYAML isn't an actual
dependency of this project anywhere — `install.sh` never installs it,
nothing else in the codebase imports it — it only happened to be
present in the environment the test was originally written and
checked in, which is exactly why the gap wasn't caught before the
tests reached CI.

**Fix:** removed the PyYAML dependency entirely, applying the same
discipline already used for `jen/services/changelog.py` — don't reach
for a general-purpose parsing library for a narrow, well-known, fully
self-authored format. The specific line these tests need (`test:
["CMD-SHELL", "..."]`) is a single-line YAML flow sequence, which is
also valid JSON, so a targeted regex isolates it and the stdlib `json`
module parses it directly. The regex is anchored on the actual
`CMD-SHELL` content rather than a generic `test:` match, so it doesn't
accidentally pick up the separate MariaDB healthcheck present in
`docker-compose.mysql.yml`, which uses plain `CMD`.

Verified properly this time, not just re-run: uninstalled PyYAML from
the development environment entirely (not just avoided calling it) and
confirmed both that `pytest --collect-only` succeeds — the exact
failure mode from the CI log — and that the corrected parsing logic
still returns the right values from both compose files.

No application behavior changed; this is a test-only fix.

## [5.2.12] - 2026-09-08

### Two small hardening fixes: trusted-device cookie, Docker healthcheck

Fourth and fifth findings from the same third-party security review
that produced v5.2.6, v5.2.7, and v5.2.10 — bundled together since
both are small, single-file, mechanical changes with no relationship
between them and no interaction risk.

**`jen_trusted` cookie missing `Secure`.** This cookie is a long-lived
MFA bypass token (up to 10 years for "remember this device forever").
Unlike the main session cookie, which is marked `Secure` whenever SSL
is configured, this one had no `secure` flag at all — a browser could
send this specific token over plain HTTP even on an instance with
HTTPS configured, before any HTTP→HTTPS redirect takes effect. Fixed
across all four call sites (two duplicated code paths — backup-code
verification and TOTP verification — each with a "forever" and an
"N days" branch), using the same `ssl_configured()` condition the
session cookie already uses. Also removed a stale, incorrect comment
next to one of the call sites ("No max_age = session-less persistent
cookie" — the code has always explicitly set a 10-year `max_age`;
the comment was simply wrong).

**Docker Compose healthcheck used `CMD` (exec form) with `||`.**
`CMD` does not invoke a shell, so `||` was never treated as shell OR
logic — it was passed to `curl` as a literal, meaningless argument.
Verified this directly rather than assuming: ran the exact broken
argv as a single non-shell process and found curl's own handling of
multiple positional URL arguments happened to mask the bug in some
cases (occasionally still reaching a later URL in the list by
accident), which is worth being precise about — it was never the
intended "try HTTP, fall back to HTTPS" logic actually running, just
an unreliable side effect of how curl parses extra arguments. Fixed by
switching to `CMD-SHELL`, which explicitly invokes `/bin/sh -c`, in
both `docker-compose.yml` and `docker-compose.mysql.yml` (which
maintain this same healthcheck independently).

Added `tests/test_small_hardening_fixes.py`. For the cookie fix,
verified via direct source inspection that all four call sites include
the flag, correctly conditioned on `ssl_configured()` rather than
hardcoded — full HTTP-level testing would require a real enrolled TOTP
secret and a live-generated code just to reach one `set_cookie()`
call. For the healthcheck fix, went further than checking the YAML
text: spun up a real local HTTP server and ran the actual shell
command Docker would run, confirming it genuinely falls through to the
working fallback target when the first is unreachable — with a server
log line proving the fallback request was actually received, not just
that the exit code happened to be zero.

## [5.2.11] - 2026-09-08

### Fix CI failure in 5.2.10's test suite

`tests/test_api_key_authorization.py::TestLimitParameterFloor::test_zero_limit_does_not_crash`
failed in CI — a bug in the test's own fixture data, not the `limit`
floor logic it was checking.

**Cause:** `TestLimitParameterFloor`'s helper for inserting a valid API
key built the raw key from a fixed literal string, so every call
within that test class produced the exact same SHA-256 hash.
`api_keys.key_hash` has a `UNIQUE` constraint, so the second test to
call the helper failed with a duplicate-key `IntegrityError` before
the actual `limit`-clamping code under test ever ran.

**Fix:** each call now generates its own genuinely random raw key via
`secrets.token_hex()`, matching how real API keys are actually
generated elsewhere in the app. Verified directly — ran the fixed
helper's key-generation logic twice in sequence and confirmed the two
resulting hashes are always distinct, rather than just re-running the
suite and hoping.

While reviewing this, checked the rest of the same test file for the
identical class of mistake — every API-key-name and admin-username
value used across the file's remaining ~15 test methods was confirmed
genuinely unique, so this was an isolated case, not a symptom of a
wider pattern in that file.

No application behavior changed; this is a test-only fix.

## [5.2.10] - 2026-09-08

### SECURITY: API key authorization scope, plus three related fixes in the same file

Third fix from the same third-party security review that produced
v5.2.6 and v5.2.7.

**The finding:** the API key listing query loaded every key regardless
of who created it, and the revoke/delete routes checked only
`role in (superadmin, admin)` — no ownership check, no scope check. A
subnet-restricted plain admin could view metadata for, revoke, or
delete a superadmin's unrestricted API key just by knowing or guessing
its (small, sequential) id.

**Fix:** a plain admin now only ever sees, and can only ever act on,
API keys they created themselves. Superadmins continue to see and
manage everything, consistent with how superadmin access already
works everywhere else in the app. The revoke and delete routes give
the same generic "API key not found" message whether a key genuinely
doesn't exist or exists but isn't the caller's — distinguishing the
two would let someone confirm a specific key id exists even though
they can't act on it either way. Added a brief note to the API Keys
page itself for plain admins, since this is a real, visible behavior
change worth surfacing rather than a silent restriction.

**Bundled into the same pass**, since all three touch this exact file
and two of them are the exact lines being rewritten for the
authorization fix anyway:

- **Raw exception leaks** in the API key listing, create, revoke, and
  delete routes — all four previously did `flash(f"Error: {e}")`,
  putting raw exception text (potentially including schema details,
  connection info, or credentials) directly in front of the user. Now
  logged server-side with a generic message shown instead.
- **`limit` parameter floor** — the REST API's `limit` query parameter
  was capped at 1000 but had no lower bound, so `?limit=-1` reached
  MySQL as a literal negative `LIMIT`, which MySQL rejects outright
  rather than clamping. Now `max(1, min(value, 1000))`.
- **`last_used` write throttling** — `_api_auth()` wrote `last_used`
  on every single authenticated API request, unconditionally. Now
  throttled to once per 5-minute window via a single conditional
  `UPDATE ... WHERE last_used IS NULL OR last_used < NOW() - INTERVAL
  5 MINUTE` — atomic, one round trip, no separate SELECT-then-maybe-
  UPDATE that could race with itself under concurrent requests.

Added `tests/test_api_key_authorization.py` covering all of the above
— including a test that specifically reproduces the reported
vulnerability (a restricted admin attempting to revoke an
unrestricted key created by a second admin) and confirms the key
remains untouched, and DB-level tests proving the throttling SQL
correctly distinguishes "never used," "still within the window," and
"window has passed" cases.

## [5.2.9] - 2026-09-08

### Fix self-update being completely broken since v5.2.6

**Impact:** every self-update attempt has failed on every instance
running v5.2.6, v5.2.7, or v5.2.8 — not a transitional issue affecting
one upgrade, a permanent break in the feature until this fix is
applied. Reported as "Could not start the update" in the UI.

**Cause:** the v5.2.6 security rewrite's sudoers rule authorized
`/usr/bin/systemctl start jen-update.service`, but the actual code
invoked `/usr/bin/systemctl start --no-block jen-update.service` — an
extra `--no-block` flag added for a real reason (without it, the
triggering call blocks waiting for the update service to fully
complete, including its own final `systemctl restart jen` step, which
kills the exact Flask worker process that's blocked waiting) but never
reflected in the sudoers rule authorizing it. `sudo` matches commands
literally, argument-by-argument — a rule with no wildcards (deliberate,
since a wildcard here would reopen exactly the attacker-controllable-
input gap the v5.2.6 rewrite exists to close) must match byte-for-byte,
and this one didn't. Every attempt was rejected with a sudo permission
denial before ever reaching the update logic.

**Fix:** the sudoers rule now authorizes the exact command the code
actually invokes, `--no-block` included.

Added `tests/test_sudoers_command_matching.py` — parses `jen-sudoers`
and cross-checks every sudo-invoking `subprocess.run()` call in
`jen/routes/settings.py` against it via AST, failing if any invoked
command doesn't exactly match something authorized. Verified this test
actually has teeth, not just coincidental passing: ran it against the
original broken sudoers content and confirmed it correctly flags the
exact mismatch that shipped. This class of bug — an update to one side
of a two-file contract (code and the sudoers rule authorizing it)
without a matching update to the second — is now checked automatically instead of
depending on remembering to keep them in sync by hand.

**⚠️ Because self-update is what's broken, self-update cannot fix
itself.** Use the manual upgrade path for this release, with real
administrator access:

```
cd ~/jen
sudo ./install.sh --upgrade
```

This installs the corrected `jen-sudoers` file directly. After this
one update, the in-app "Update Now" button works correctly again for
every release going forward.

## [5.2.8] - 2026-09-08

### Fix CI failure in 5.2.7's test suite

Two failures in `tests/test_password_change_enforcement.py`, both bugs
in the tests rather than the application logic they were checking —
same category as the 5.2.4 fix, but for this feature's own test suite.

**`test_rejects_reusing_the_literal_default` failed:**
`force_password_change()` checked password length before checking for
the literal string `"admin"`. Since `"admin"` is only 5 characters,
the generic "must be at least 8 characters" error always fired first,
and the dedicated "not the default" check
could never actually run for the one input it exists to catch. The
security outcome was already correct either way (`"admin"` was always
rejected), but the specific, more useful error message was
unreachable. Fixed by reordering: the specific check now runs before
the generic length check.

**`test_change_password_route_clears_flag_too` failed:**
this test assumed the general `/users/change-password` route would
still work while `must_change_password` is set and clear the flag.
It doesn't — the enforcement middleware's allowlist only permits
`/force-password-change` and `/logout`, by design, since the entire
point of this feature is that the rest of the application (including
this alternate password-change route) is genuinely unavailable until
the dedicated screen is used. The test's premise was wrong, not the
middleware. Replaced it with two tests: one confirming
`/users/change-password` is correctly blocked and redirected while the
flag is set, and one verifying — via direct source inspection rather
than a fragile HTTP-level test — that `change_password()`'s own UPDATE
statement still clears the flag as a defense-in-depth measure, in case
a future change to the allowlist ever makes that route reachable
during enforcement.

No application behavior changed beyond the validation-order fix in
`force_password_change()`, which only affects which error message is
shown for one specific rejected input — the actual set of passwords
accepted or rejected is unchanged.

## [5.2.7] - 2026-09-08

### SECURITY: enforce a password change on the default admin credential

Second fix from the same third-party security review that produced
v5.2.6. A fresh install seeds an `admin`/`admin` superadmin account
with nothing enforcing that the obvious default ever actually gets
changed — the README says to change it immediately, but that was
advisory only, never enforced anywhere in the application. Given Jen
manages real DHCP infrastructure, a forgotten default credential has a
much larger blast radius than the same oversight elsewhere.

**Fix:** new `users.must_change_password` column, set on the default
admin seed and on any newly-created user account (an admin setting a
new user's initial password is the same category of concern as
the default seed itself). A new `before_request` hook makes the rest
of the application genuinely unavailable while this flag is set —
every authenticated request redirects to a forced password-change
screen — rather than just documenting that the password should be
changed. The new screen deliberately doesn't re-verify the current
password (reaching it at all already proves the user knows it — they
just logged in) and explicitly rejects setting the new password back
to `admin` or to the account's own username, closing the obvious
"change it right back" loophole.

Traced the session-cache plumbing carefully rather than assuming:
`load_user()`'s fast and slow paths both needed updating, and the
login route in `auth.py` turned out to independently build its own
session-cache dict in two separate places (a detail only found by
checking). The existing `change_password()` route already clears the
session cache on a successful change, which meant this flag correctly
propagates without needing any new cache-invalidation logic of its
own.

Added `tests/test_password_change_enforcement.py` covering the seed
and creation paths, the enforcement middleware (including that it
doesn't interfere with an in-progress MFA enrollment/verification
flow), and the new route's validation — verified the actual SQL and
validation logic directly via source inspection against the real
functions, since a fresh, all-migrations-applied test database isn't
available in every environment this was developed in.

## [5.2.6] - 2026-09-08

### SECURITY: root privilege escalation via the self-update sudoers rule

**This is the most important fix shipped in this project to date.**
Following a third-party security review, the self-updater's privilege
model has been redesigned.

**The vulnerability:** the sudoers file granted `www-data` (the Jen
web process) passwordless root access to run
`/bin/bash /tmp/jen_update_install.sh`. That exact file was written by
`www-data` itself, as part of every normal update. Since `/tmp` is
world-writable and `www-data` is the exact account permitted to write
that exact path, the real security boundary was: **gain any code
execution as `www-data` → write that file yourself → `sudo` it → root.**
Every checksum/signature validation the old `self_update()` route
performed was irrelevant to this path, because an attacker never
needed to go through that route at all — the update button's own
checks are not a barrier if you can just create the file the sudo rule
already trusts.

**The fix** moves the entire download → verify → extract → install
pipeline out of the Flask app and into a new standalone script,
`jen-update-root.py`:
- Lives outside `/opt/jen` entirely, so `install.sh`'s own
  `chown -R www-data:www-data` on the install directory can never
  re-expose it
- Owned `root:root`, mode `0700` — `www-data` cannot read or modify it
- Takes **zero arguments and accepts no input from `www-data` at all**
  — it always re-derives "the current latest release" from GitHub
  itself, independently, in the trusted execution context
- Reachable only via `sudo systemctl start jen-update.service` — a
  command with no parameters, mirroring the already-safe
  `sudo systemctl restart jen` pattern used elsewhere in this project

The practical result: even a fully-compromised `www-data` account can
now only ever trigger "install whatever GitHub currently publishes as
the latest jen-kea release" — nothing else. It cannot inject arbitrary
file content or arbitrary commands into the root execution context,
because nothing it controls ever reaches the privileged script as input.

**Also fixed in the same rewrite** (a separate issue from the same
review): the old code proceeded with an *unverified* update if a
checksum file was missing, had no matching entry, or failed to parse —
logging a warning and continuing anyway. `jen-update-root.py` fails
closed in all of those cases: no valid checksum match, no install,
full stop.

`self_update()` in `jen/routes/settings.py` is reduced from roughly
290 lines to about 70. It no longer downloads, verifies, extracts, or
copies anything — it only optionally backs up the database (unchanged
— that's Jen backing up its own data with credentials it already has,
not part of the privilege boundary) and triggers the hardened service.

**⚠️ Important — a one-time manual step is required for this specific
upgrade, for any instance whose primary deployment path is the in-app
"Update Now" button:**

Self-update always runs using the code already on disk *before* the
update runs. That means clicking "Update Now" to reach this version
will still execute the *old*, vulnerable copy logic one last time —
which has no way of knowing to install the new root-owned script or
the new systemd unit, since neither existed in any prior release. For
this one release only, run the manual upgrade path instead, with real
administrator access:

```
sudo ./install.sh --upgrade
```

This correctly installs `jen-update-root.py` and `jen-update.service`
alongside everything else. After this one transition, the in-app
"Update Now" button works normally — and correctly — for every release
after this one.

**Frontend note:** the update-progress overlay's polling logic
previously received the exact target version back from the server in
the post-update redirect (`?updated=X.Y.Z`) to know what to wait for.
The new route can't supply that anymore, since resolving "latest" now
happens entirely inside the privileged script. The redirect is now a
simple `?updating=1` flag, and the target version for display/
comparison is carried across the page reload via `sessionStorage`
instead (set right before the form submits, read back on page load).
If that value is ever unavailable, the polling logic falls back to
"Jen responded at all" as its completion signal rather than getting
permanently stuck waiting for an exact match it can't make.

Added `tests/test_jen_update_root.py` (checksum verification and file
installation, run directly against real temporary directories rather
than mocked shell-script text matching) and completely rewrote
`tests/test_self_update.py`, since every previous test in that file
verified the old route's now-removed download/copy pipeline. The new
tests confirm the route never writes to `/tmp/jen_update_install.sh`
again, never calls `requests` or `tarfile` itself, and only ever
triggers the hardened service.

## [5.2.5] - 2026-09-08

### The actual root cause of "What's New" showing old releases

v5.2.3 fixed a real bug in `parse_changelog()`'s sort order, but it
wasn't the actual cause of what was reported: "What's New" continued
showing an old 3.x-series release as the newest entry even after that
fix shipped. The real cause is more fundamental: **CHANGELOG.md was
never included in either deployment path's file list at all** — not
`self_update()`, not `install.sh`. Both treat it as source-repo
material (like docs/ or tests/), not part of "the running install," so
it has never been refreshed by any automated update, on any release,
ever. Any instance's `CHANGELOG.md` has been frozen since whichever
version was first manually installed — completely independent of the
actual application code being correctly updated release after release.

This is the **third** time this exact category of bug has hit this
project: `run.py` itself was missing from self-update's copy list
until v4.4.16; vendored static assets (`chart.umd.min.js`,
`htmx.min.js`) were missing until v5.1.6/v5.1.8; now `CHANGELOG.md`,
for the identical underlying reason — a file the running app actually
reads, living outside the `jen/`/`templates/`/`static/` scope both
deployment paths treat as "the app."

**Fixed** by adding `CHANGELOG.md` to both `install.sh` and
`self_update()`'s copy lists. Added `TestSelfUpdateCopiesChangelog` to
`tests/test_self_update.py`, matching the existing convention from the
`run.py` and static-asset fixes — capturing the real generated helper
script and asserting the actual `cp` command is present, not just that
some code path was reached.

**Important — this fix has the same bootstrapping limitation as every
prior fix to `self_update()` itself:** self-update runs using the code
*already on disk* before the update runs. Updating to this version via
the in-app "Update Now" button updates the application code (including
the fixed `self_update()` function itself) correctly, but that
specific update cycle is still driven by the *old*, un-fixed copy
logic — so `CHANGELOG.md` will not actually refresh until the *next*
update after this one. If you want "What's New" to be current
immediately rather than after your next update, copy it manually once:
`sudo cp ~/jen/CHANGELOG.md /opt/jen/CHANGELOG.md` (adjust paths to
your actual git working copy and install directory).

## [5.2.4] - 2026-09-08

### Fix CI failure in 5.2.2's own test suite (5.2.2 never actually shipped)

`tests/test_reservations.py::TestBulkReservationActions::test_bulk_delete_removes_selected_reservations`
failed in CI — a bug in that new test itself, not in
`bulk_delete_reservations()`, which was behaving correctly.

**Cause:** the actual `hosts` row for a reservation is removed by Kea
when it processes `reservation-del` — Kea owns that table, the exact
same way the pre-existing single-item `delete_reservation()` route
already works, and neither route ever issues its own `DELETE FROM
hosts`. The failing test mocked Kea's API (`result: 0` on any command)
and then asserted the `hosts` row was gone from the test database —
but a mocked Kea never touches the real table, so that assertion could
never pass regardless of whether the route's own logic was correct.
The existing `test_delete_reservation()` test already knew this and
only checks `status_code == 200` for exactly this reason; the new
bulk-delete test just didn't follow that established pattern.

**Fix:** rewrote the test to verify what's actually under Jen's
control and observable without a real Kea server — that
`bulk_delete_reservations()` sends the correct `reservation-del`
command (right subnet-id, right MAC, right identifier type) for the
selected host, and reports success. Confirmed the two remaining bulk-
action tests from 5.2.2 (Leases, Devices) don't share this flaw —
those routes mutate `lease4`/`devices` directly via Jen's own SQL with
no Kea API dependency, so asserting the row's state directly against
the test database is valid there.

This test would have failed 5.2.2's own CI too, and did — the release
was never actually confirmed green before being tagged. No application
behavior changes here; this is a test-only fix.

## [5.2.3] - 2026-09-08

### Fix "What's New" showing old releases as the newest

Reported: the About page's changelog viewer (added 5.2.1) showed an
old 3.x-series release at the top, ahead of the actual current
version.

**Cause:** `parse_changelog()` trusted the physical order release
headers appear in CHANGELOG.md, on the assumption the file is always
maintained strictly newest-entry-first. That assumption held for
every test fixture used to verify this module — all newest-first by
construction — which is exactly why it wasn't caught before shipping.
It doesn't hold against the real CHANGELOG.md, which has genuine
multi-year history well before this feature existed (the file's own
intro line references a separate "3.x line" with its own
release-history docs this module never had visibility into) —
something in that older history isn't strictly ordered the way every
entry written during this project has been.

**Fix:** rather than track down the exact historical formatting quirk
responsible, in a file this module can't fully see, entries are now
explicitly sorted by parsed semantic version (descending) after
parsing, instead of trusting file order at all. Numeric comparison,
not lexical — `5.2.10` correctly sorts after `5.2.9`, which plain
string comparison would get backwards. A version string that doesn't
parse cleanly falls back to sorting as the lowest priority rather than
crashing the whole page.

Added `TestVersionSortKey` and three new tests in `TestParseChangelog`
that deliberately build changelog fixtures *out of order* — proving
the fix holds regardless of file order, rather than only checking
against already-sorted input like every existing test here did.

The reports/analytics expansion originally planned for this release
(device churn, busiest-hours, manufacturer breakdown) is real, larger
scope than fit alongside this fix — moved to its own release rather
than shipped half-finished.

## [5.2.2] - 2026-09-08

### Bulk actions for Leases and Devices — and a real bug found along the way

Third release of the 5.2.x series. Set out to extend Reservations'
existing bulk-action pattern to Leases and Devices — turned out
Reservations' bulk actions didn't actually work either.

**Found: Reservations' bulk delete/export were completely unreachable
from the UI.** The JS (`toggleAll`/`updateCount`/`confirmBulk`) already
existed in `reservations.html`, and both backend routes
(`bulk_delete_reservations`, `bulk_export_reservations`) were fully
built and correct — but there was no checkbox, no select-all control,
no action bar, and no `<form>` anywhere in the template to actually
connect them. The exact same "half-wired feature" pattern as the
subnet-notes bug found earlier in this project. The original JS was
also written assuming a single dispatcher endpoint with an `action`
field, which never matched how the two real backend routes actually
work — so even with the markup in place, the wiring itself needed
correcting, not just completing.

- **Reservations** — added the missing markup (checkboxes, select-all,
  action bar, form) and fixed the JS to target each action's real
  endpoint directly. Checkboxes and "Export Selected" are visible to
  any logged-in user (matching `bulk_export_reservations`'s existing
  `@login_required`-only gate); "Delete Selected" is admin/superadmin
  only.
- **Leases** — new `/leases/bulk-release` route and matching UI,
  scoped to active (non-expired), non-reserved leases only — matching
  exactly where the single-lease "Release lease" action already lives.
  Releasing a reserved lease's active binding doesn't accomplish much
  since Kea just reissues the same reservation on renewal; the route
  re-checks this server-side even though the template only ever offers
  a checkbox for non-reserved rows.
- **Devices** — new `/devices/bulk-delete` route and matching UI. Pure
  Jen-side inventory cleanup — no Kea API or lease-table interaction at
  all, so there's no external system to fail against beyond the same
  subnet-access guard the single-device delete route already applies.

All three bulk routes: per-item subnet-access check (a bulk action
can't reach a subnet a restricted admin couldn't touch one at a time),
a single summary flash rather than one per item, and an audit log
entry. Fixed the empty-state `colspan` on Leases and Devices to be
dynamically correct now that column count varies by role and view
state, rather than the previous hardcoded (and already slightly
imprecise) values.

Added real test coverage for all three bulk routes plus the previously
untested Reservations bulk actions — including confirming the
subnet-restriction guard actually holds, that a reserved lease can't
be released via a hand-crafted bulk request even though the UI never
offers it a checkbox, and that the correct markup is now genuinely
present in each rendered page rather than just asserting the JS
functions exist.

## [5.2.1] - 2026-09-07

### In-app changelog viewer + PWA installability

Second release of the 5.2.x series — two small, independent additions
bundled together since neither touches existing data or behavior.

**In-app "What's New" viewer** — Jen has always maintained a genuinely
good CHANGELOG.md, but nothing surfaced it in the app itself. Added:

- **`jen/services/changelog.py`** — a small, purpose-built parser for
  CHANGELOG.md's own consistent format (release headers, subheadings,
  prose, bullet lists with `**bold**`, `*italic*`, `` `code` ``, and
  `[links](url)`). Deliberately not a general markdown library — this
  parses our own file with a format we fully control, not arbitrary
  third-party markdown, so a full parser would be a new dependency and
  a larger, harder-to-audit HTML-output surface for a task this
  constrained. All text is HTML-escaped before any formatting markup
  is reintroduced, verified against actual injection attempts (a
  `<script>` tag and a quote-breakout in a link URL), not just assumed
  safe because the source file is our own.
- Reads the real CHANGELOG.md shipped with the running instance at
  request time, not a bundled/hardcoded copy — the same "don't let two
  sources of truth drift apart" principle behind config drift
  detection (5.2.0) itself.
- Surfaced on the About page: newest release shown expanded, earlier
  ones collapsed behind a "Show details" toggle.

**PWA installability** — Jen was already thoroughly mobile-responsive
but had no web manifest, so it couldn't be installed to a phone home
screen as a standalone app.

- New on-brand icon set (192×192, 512×512, iOS touch icon), generated
  to match the existing teal/blue "Jen" wordmark gradient.
- `static/manifest.webmanifest` plus the corresponding manifest link
  and Apple-specific meta tags in `base.html`.
- **Deliberately no service worker.** This app shows live Kea/lease
  status; a service worker's caching could serve a stale "Kea: Online"
  page while Kea is actually down, which is actively misleading for a
  monitoring tool, not just a UX nitpick. Manual "Add to Home Screen"
  works fully without one; only the fully-automatic install banner
  some browsers proactively show may not appear.

Added `tests/test_changelog.py` (parser correctness and injection
resistance, plus route-level coverage for `/about`, which had none
before this) and `tests/test_pwa_manifest.py` (manifest validity, every
referenced icon file actually existing on disk, and an explicit guard
that fails if a service worker registration is ever added later).

## [5.2.0] - 2026-09-07

### Config drift detection

New feature (first of the 5.2.x series). Jen's own subnet id → name/
CIDR mapping (`extensions.SUBNET_MAP`/`SUBNET6_MAP`, sourced from
Jen's `[subnets]` config file) is not derived from Kea's live config
at all — it's a separate, manually-maintained list kept in sync only
by whoever remembers to update it. This is exactly what caused a real
bug found in practice: selecting "IoT" in a subnet filter silently
returned Production's data, because Jen's stored id for "IoT" no
longer matched what Kea's live config actually assigned that id to.
There was no way to know this had happened until it produced a
confusing symptom.

- **`jen/services/config_drift.py`** — compares Jen's stored subnet
  map against a live `config-get` for both IPv4 and IPv6 (when
  configured), surfacing three distinct problems: a subnet Jen has
  that Kea's live config no longer does, a subnet Kea has that Jen
  never named, and — the critical case, the exact failure mode behind
  the real bug — both sides agreeing a subnet id exists but
  disagreeing on which network it actually is. The core comparison is
  a pure function with no I/O, so it's fully and directly testable
  against hand-built maps; a live-fetch failure is treated as
  "couldn't check right now," never as "Kea has zero subnets" (which
  would otherwise flood false positives during any transient Kea
  outage).

- **Automatic, continuous checking** — wired into the existing
  `check_alerts()` background loop, using the same detected-once/
  resolved-once alerting pattern already used for `kea_down`/`kea_up`
  and `utilization_high`/`utilization_ok` (two new alert types,
  `config_drift_detected` and `config_drift_resolved`), so it doesn't
  spam every 30-second cycle while an issue persists, and lets you
  know when it's fixed too. Respects per-channel subnet scoping like
  every other subnet-specific alert.

- **Manual on-demand check** — Settings → Infrastructure → "Config
  Drift Check" card, matching the existing "Kea Package Status" card's
  pattern, for checking right now without waiting for or digging
  through alert history.

Added `tests/test_config_drift.py`, weighted heavily toward the pure
comparison logic since that's where the feature's actual value lives —
covers the no-drift case, all three issue types individually and in
combination, and the "Kea unreachable must skip rather than report
false drift" case explicitly.

## [5.1.21] - 2026-09-06

### Fix false "kea-dhcp4/kea-dhcp6 not installed" report on a genuinely-running server

Settings → Infrastructure → "Check Installation" (Kea Package Status)
could report both binaries as not installed on a server that was
demonstrably running Kea fine — Control Agent connected, actively
serving DHCP.

**Cause:** the check ran `which kea-dhcp4 kea-dhcp6` over SSH, which
only searches `$PATH`. Paramiko's `exec_command()` runs a
non-interactive, non-login shell by default, and depending on the
target's sshd/PAM configuration, that session's `$PATH` can easily
exclude `/usr/sbin` — exactly where the official
`kea-dhcp4-server`/`kea-dhcp6-server` `.deb` packages install these
binaries (standard Debian policy for system-administration daemons).
A genuinely-installed, genuinely-running server got reported as "not
installed" purely because the check was searching a `$PATH` that never
included the directory the binary actually lives in.

The existing tests for this function never caught it because they only
exercised output *parsing* against a canned stdout string (literally
hardcoding `/usr/sbin/kea-dhcp4` as the fixture text) — never the real
command's actual `$PATH`-dependent behavior against a live, restricted
SSH session. Verified the fix directly: ran both the old and new
commands under a deliberately restricted `$PATH` missing `/usr/sbin`,
confirming the old command fails to find a binary that's genuinely
there while the new one correctly finds it.

**Fix:** now checks `command -v` (kept as the first, cheapest check —
still catches non-standard install locations) OR'd with explicit
`test -x` checks against the standard install directories
(`/usr/sbin`, the real-world location; `/usr/local/sbin`, for a
build-from-source install), so a restricted non-login `$PATH` can no
longer produce a false negative for a binary that demonstrably exists.

Updated the existing tests' canned output to match the new detection
markers, and added a new test that checks the actual SSH command sent
includes the `/usr/sbin/` fallback — confirming the fix mechanism is
present, not just that output parsing still works (which is exactly
what the previous tests already covered without ever catching this).

## [5.1.20] - 2026-09-06

### The action-menu clipping fix, actually fixed this time

v5.1.18's fix for `.action-menu-dropdown` getting trapped in a scroll
box on short/filtered tables did nothing. Confirmed still fully
reproducible on v5.1.19 exactly as originally reported.

**What went wrong:** the CSS overflow "computed-value fixup" rule (one
axis explicitly non-`visible` forces the other axis to behave as
non-`visible` too) operates on the *computed* value, not on whether it
was authored explicitly or left as the default. `overflow-x: auto;
overflow-y: visible;` computes identically to `overflow-x: auto;`
alone — there is no way to fix this by setting overflow properties on
the same element. v5.1.18 shipped a no-op, and its regression test
only checked that the literal string `overflow-y: visible` appeared in
the CSS text, never actual browser clipping behavior, so it passed a
fix that changed nothing.

**The actual fix:** `.action-menu-dropdown` is now repositioned via JS
to `position: fixed` (viewport-relative — genuinely escapes ancestor
overflow clipping, confirmed no ancestor here sets transform/filter/
perspective/will-change:transform, any of which would defeat this)
computed from the trigger button's own `getBoundingClientRect()`, only
while open. Includes a flip-upward fallback when there isn't enough
room below the button (exactly the short-table case reported), closes
on scroll rather than trying to track a moving trigger, and
repositions (without closing) on window resize.

Reverted the ineffective `overflow-y: visible` from `.table-wrap`.

**Verified properly this time**, not just asserted:
- Extracted and syntax-checked the actual shipped JS with Node
- Ran the real positioning math against four scenarios (normal case,
  flip-upward, edge-clamping, and the exact short-viewport/short-table
  case from the report) — all correct
- Ran the actual functions (not a reimplementation) against a real
  jsdom-simulated DOM: confirmed the dropdown genuinely switches to
  `position: fixed` with correct coordinates on open, and all inline
  overrides clear correctly on close

Rewrote `tests/test_table_wrap_overflow.py` (the previous version
tested for the ineffective CSS property) to check for the actual fix
mechanism, and to explicitly guard against the ineffective
`overflow-y: visible` ever being reintroduced and mistaken for
sufficient again. This project has no browser-automation test
infrastructure, so these are structural checks (the right function
exists, calls the right APIs, is wired to the right events) — a real
limitation, not a substitute for confirming this by hand after
deploying it.

Also: swept every comment touched in this release for accidental
word-collisions with existing tests' `assert <word> not in resp.data`
checks (the exact class of self-inflicted CI failure fixed in 5.1.19)
before shipping, rather than after.

## [5.1.19] - 2026-09-06

### Fix CI test failure from v5.1.18's own explanatory CSS comment

`test_kea6.py::TestReservationsV6View::test_v6_view_search_filters_by_hostname`
started failing in CI after v5.1.18 shipped — not a regression in any
actual functionality. That test inserts two IPv6 reservations, one
hostnamed "findme" and one hostnamed "other", searches for "findme",
and asserts the string "other" doesn't appear anywhere in the full
page response — a reasonable way to confirm the non-matching
reservation was correctly excluded from the results.

v5.1.18's fix for the `.table-wrap` overflow bug added a detailed
explanatory comment directly in `base.html`'s `<style>` block,
including the sentence "...one axis is explicitly non-visible and
**the other** is left as the visible default...". Since `base.html` is
the shared page shell rendered on every full-page response, that
comment text — containing the substring "other" — showed up in this
test's response body too, tripping the assertion. The actual
reservation filtering was, and remains, completely correct; only one
reservation was ever rendered in the results table. This was a
collision between an explanatory comment's prose and a test's
substring check, not a functional bug.

Fixed by rewording the comment (no technical meaning changed) to avoid
the literal substring. Swept every other `assert <word> not in
resp.data`-style test in the suite against `base.html` specifically,
since it's the only template rendered on every full page — found four
other superficial matches (`page-header`, `btn-act-edit`,
`btn-act-pin`, `btn-act-del`), all of which are pre-existing CSS class
*definitions* that were already in `base.html` before this session and
only matter in practice for full-page responses; the tests checking
for their absence specifically target HTMX partial responses, which
never include `base.html`'s `<style>` block at all — confirmed no
actual collision there.

No functional changes — comment wording only.

## [5.1.18] - 2026-09-03

### Fix action-menu dropdown getting trapped in a scroll box on filtered/short tables

App-wide UI bug: `.table-wrap` (the container wrapping every list-page
table — Leases, Reservations, Devices, both v4 and v6 variants, Users,
API Keys, Audit Log, Plugins, Search Results, Saved Searches, Alert
Settings, MFA Trusted Devices, the Dashboard's recent-leases widget —
16 templates in total) only ever set `overflow-x: auto`, leaving
`overflow-y` implicit. Per the CSS spec's overflow computed-value
fixup rule, when one axis is explicitly non-`visible` and the other is
left as the default `visible`, browsers force **both** axes to behave
as `auto` — so this container was silently clipping vertical overflow
too, not just the horizontal overflow it was actually meant for.

The visible symptom: `.action-menu-dropdown` (the "⋯" menu) is an
absolutely-positioned child that needs to overflow below the table
when a row near the bottom opens it. With a short, heavily-filtered
result set — one or two rows — there's no natural extra table height
to absorb that overflow, so the dropdown got trapped inside a forced,
tiny scroll region instead of floating naturally above the page,
exactly matching the report: filter down to a couple of devices, open
the "⋯" menu, and end up scrolling inside a cramped box just to click
an item.

Fixed with a single shared CSS rule change (`overflow-y: visible` set
explicitly rather than left implicit) in `base.html` — since every
affected page shares this one container class, this one-line fix
resolves it everywhere at once rather than needing 16 separate
per-template patches. Confirmed no `.table-wrap` usage anywhere
intentionally relied on vertical scrolling (no paired `max-height`
found), and confirmed the dropdown itself has no nested overflow
clipping of its own that would undo the fix one level down.

Added `tests/test_table_wrap_overflow.py`, which parses the actual CSS
rule text (not just a substring match) so a future edit that drops the
explicit `overflow-y: visible` — reintroducing the fixup-rule bug —
fails CI immediately instead of shipping invisibly again.

## [5.1.17] - 2026-09-02

### Decouple Kea health checking from the 30-second monitoring cycle

Investigated a report of a Kea server reboot that Jen never showed as
down. Traced the up/down detection logic exhaustively — the state
machine itself is correct (verified: it alerts immediately if Kea is
already down at Jen's very first check, doesn't false-alarm on a
healthy start, and fires clean down→up/up→down transitions with no
edge case found). The real problem is architectural, not a logic bug:

Every check in `check_alerts()` — Kea health, HA state, lease
tracking, utilization, stale reservations, snapshots, the daily
summary — shared one single 30-second heartbeat. A reboot that's
actually down for less than ~30 seconds (entirely plausible for a
fast VM or a lightweight OS) can fall completely between two polls
and never register as down at all, purely by timing luck. Polling
can't guarantee catching every outage shorter than its own interval,
but coupling a cheap, fast-changing check (is the API up right now?)
to the same cadence as much heavier, far-less time-sensitive work was
making that blind spot needlessly wide.

Kea/HA health is now checked every ~5 seconds (6 times within the
same overall ~30-second cycle the heavier work still runs on) —
shrinking the blind spot from ~30 seconds to ~5 without changing how
often utilization scans, snapshots, or the daily summary run. Also
simplified `last_kea_status` from an awkward bool-or-dict dual-typed
variable to a plain dict throughout, removing a redundant duplicate
`kea_is_up()` call that only fired on Jen's very first-ever health
check.

No behavior change to alert content, thresholds, or any other alert
type — purely a timing fix for how quickly a real outage gets caught.

## [5.1.16] - 2026-09-02

### Per-channel subnet scoping, reserved-lease recurrence control, Telegram rate-limit hardening

Three additions, all in the notification system, following a request
to review the whole alerting pipeline end to end:

- **Per-channel subnet scoping** — each alert channel can now be
  limited to specific subnets for subnet-specific alerts (new lease,
  new device, reserved device online, utilization, pool exhaustion,
  stale reservation). Kea up/down, HA failover, and the daily summary
  are never subnet-scoped, since they aren't tied to one specific
  subnet. New `alert_channels.subnet_scope` column (migration 14),
  same NULL-means-unrestricted convention as `users.subnet_access` and
  `api_keys.subnet_access` — every existing channel keeps alerting on
  everything by default. Unlike those two, a malformed scope value
  fails *open* here (sends anyway), not closed — this is a
  notification preference, not an access boundary, and going silent
  on every alert because of a JSON typo is worse than occasionally
  over-notifying.

- **Reserved-lease notification recurrence is now an explicit choice**
  — a new "Reserved Device Notifications" setting (global, Settings →
  Alerts) lets you pick "every time it comes online" (the v5.1.13
  behavior, and the default) or "only the first time ever" (the
  original, narrower behavior from before 5.1.13, now offered
  as a documented option instead of something that could only happen
  by accident).

- **Telegram rate-limit handling** — Telegram's Bot API returns HTTP
  429 with a `retry_after` value when you exceed roughly one message
  per second to the same chat, with no handling for that previously. A
  burst of several devices reconnecting within the same 30-second poll
  cycle (e.g. after an outage) sends that many `sendMessage` calls
  back-to-back with no delay between them — enough to trip this limit
  and permanently drop whichever messages got rate-limited, no retry,
  nothing to show for it beyond a generic `failed` row in `alert_log`.
  One retry, honoring Telegram's own requested wait (capped at 10s so
  a single alert can't stall the whole poll cycle), covers the
  ordinary burst case.

Also re-confirmed by tracing the code directly: `new_reserved_lease`
was NOT still firing only once — that was fixed in 5.1.13 and remains
correct. If reserved-device alerts still aren't showing up after this
release, the next thing to check is which version is actually running
live, given how much churn this alert type has had across 5.1.11–13.

## [5.1.15] - 2026-08-31

### Fix silent per-message alert failures caused by unescaped device hostnames

Root cause of "some notifications never go out" (as distinct from "no
notifications go out," already fixed in 5.1.14, and "this specific
alert type never fires," already fixed in 5.1.11–5.1.13): a device's
DHCP hostname (option 12) is fully attacker/device-controlled — any
client on the network can set it to anything, including raw `&`, `<`,
`>`. Telegram (`parse_mode=HTML`) and Pushover (`html=1`) both strictly
validate the outgoing message as HTML and reject the **entire send**
if it doesn't parse. An ordinary, not-even-malicious hostname like
`AT&T-Hotspot` was enough to silently kill every `new_lease`/
`new_device`/`new_reserved_lease` alert for that one device, every
single time its lease went active, while every other device on the
network kept alerting fine. No retry, nothing surfaced anywhere except
a `failed` row in `alert_log` that nobody's watching in real time —
exactly the "some, not all, and seemingly random" pattern reported.

Fixed by HTML-escaping the untrusted value (`hostname`) at each call
site in `check_alerts()`, via a new `safe_text()` helper — deliberately
**not** applied generically to every kwarg inside `render_template_str`,
since `daily_summary`'s `summary` kwarg is pre-built HTML from Jen
itself (deliberate `<b>` tags); blanket-escaping every kwarg would have
turned that into visible `&lt;b&gt;` text instead of fixing anything.
Slack/webhook/ntfy/Discord — which strip HTML tags via regex rather
than validating them — now also unescape the stripped text afterward,
so a hostname's escaped entities render as the actual characters for
recipients that don't parse HTML at all, rather than showing literal
`&amp;` in the message.

Added `tests/test_alerts.py::TestUntrustedHostnameHtmlEscaping`,
including a regression test asserting `daily_summary`'s own markup
survives the fix untouched.

## [5.1.14] - 2026-08-31

### The real root cause of "subnet filters don't apply": htmx was never actually vendored

`static/js/htmx.min.js` — the JS library every `hx-get`/`hx-trigger`/
`hx-target`/`hx-push-url` attribute in the entire app depends on — was
a 42-byte placeholder comment (`// HTMX 1.9.12 - replace with actual
file`), not the real library. Confirmed present as far back as v5.1.9,
the earliest version audited, so this predates every fix in this
series and has nothing to do with any of them.

This is the actual explanation for every "I select a subnet and it
doesn't filter" report investigated across 5.1.9–5.1.13: no JS ever
ran to intercept the selection and fire the AJAX request. The
`<select>` element visually kept showing whatever the user picked —
that's native browser behavior, unrelated to JS — while the request
that was supposed to apply the filter simply never happened. On pages
with a real `<button type="submit">` on a plain `method="GET"` form,
the browser's own non-JS fallback could still produce a real
navigation; on the live-filter (`change`-triggered) path relied on
elsewhere, nothing fired at all. The three v5.1.12 subnet-filter
consistency fixes (existence/access validation across Leases, Devices,
Reservations) were real and correct fixes for what they addressed, but
they could never have been the actual cause of what was being
reported, because the request carrying the filter value often never
reached the server in the first place.

Fixed by replacing the placeholder with the genuine htmx 1.9.12
minified build (verified against npm's published shasum before use).

**Added `tests/test_htmx_vendoring.py`** to close the gap that let
this ship silently for so long: checks the vendored file is
appropriately sized and contains real htmx content, not just a
same-named stub. This mirrors a check that already exists for
Chart.js (`test_reports.py`) — that fix's own docstring named
htmx.min.js as following the same vendoring convention, but the
equivalent verification for htmx itself was never actually written
until now. No test in this suite loads a real browser or JS engine —
the existing htmx-behavior tests only exercise the server's response
to a simulated `HX-Request` header — so nothing here previously could
have caught a client-side asset being silently wrong.

## [5.1.13] - 2026-08-31

### Fix new_reserved_lease firing logic (was shipped incorrect under the 5.1.12 label)

`new_reserved_lease` (added below in 5.1.12) shipped with the wrong
firing semantics: it fired only once per MAC, ever — the same
"genuinely never seen before" logic `new_device` uses. For a device
that's already been reserved and seen for a while (the normal case),
that means it would never fire again, no matter how many times that
device's lease actually goes active — moving subnets, coming back
online after being off. That's exactly backwards from what the alert
type exists for.

Fixed by making reservation status a tag on the *same* freshness check
`new_lease` already uses (was this IP active as of the last 30-second
poll), instead of a reason to run a separate one-time check. A reserved
lease going newly active now fires `new_reserved_lease` every time,
not just the first time in Jen's history; a mere renewal of an
already-active reserved lease still stays silent, exactly as before.

This also simplified the implementation — one query instead of two, no
separate reservation lookup needed per cycle.

**Note on versioning:** the incorrect version of this logic was
mistakenly repackaged and re-presented under the "5.1.12" label after
an initial correction attempt, meaning two different code payloads
briefly existed under the same version string. If you deployed
anything calling itself 5.1.12, please redeploy this release
regardless of when you pulled it, to be certain you're running the
corrected logic. Version numbers should never be reused once a build
has been shared — this was a process mistake worth naming plainly.

## [5.1.12] - 2026-08-27

### New alert type, and consistency fixes for subnet filtering across Leases/Devices/Reservations

- **New `new_reserved_lease` alert type** (`jen/services/alerts.py`) —
  `new_lease`/`new_device` are built from a query that deliberately
  excluded any lease matching a reservation entirely, to avoid
  re-alerting on every renewal of every statically-reserved device.
  That also meant a reserved device's lease going newly active — moving
  subnets, coming back online after being off — was invisible, not just
  on its first-ever appearance but every single time. Reservation status
  is now a tag on the exact same freshness check `new_lease` already
  uses (an IP not seen active last cycle), rather than a reason to skip
  that check altogether — so a reserved device's lease going active
  fires `new_reserved_lease` every time it happens, while a mere
  renewal of an already-active reserved lease still stays silent, same
  as it always has for the dynamic pool. Selectable per-channel and has
  its own editable template, same as every other alert type.

- **Subnet-filter consistency across Leases/Devices/Reservations**
  (`jen/routes/leases.py`, `devices.py`, `reservations.py`) — auditing
  all three pages side by side surfaced two one-directional gaps:
  - The v4 Leases filter already verified a submitted subnet id actually
    exists in `SUBNET_MAP` before using it, falling back to "all"
    otherwise. Devices and Reservations were missing that same guard —
    a stale or mistyped subnet id (e.g. left over after a Kea-side
    subnet renumbering) would filter directly on whatever the id
    happened to currently mean, with no indication the requested
    subnet didn't match what was returned. All three v4 views now
    apply the same existence check consistently.
  - Conversely, all three IPv6 views checked `SUBNET6_MAP` membership
    but never the user's own subnet access — a subnet-restricted user
    could view any v6 subnet's leases/devices/reservations by id
    regardless of their own restrictions. Now enforced consistently
    with the same paired-v4-subnet access rule global search already
    uses (an unpaired v6 subnet has no v4 side to inherit access from,
    so it's restricted to unrestricted/superadmin users).

Neither of these subnet-filter fixes changes behavior for an
unrestricted (superadmin, or admin with no subnet_access set) user
selecting a subnet id that legitimately exists — only for ids that
don't exist at all, or that a restricted user shouldn't be able to see.
If a page's dropdown shows a subnet by name and filtering by it still
returns another subnet's data, that id exists in Jen's own `[subnets]`
config but no longer matches what Kea's live config actually assigns
that id to — worth checking directly, since neither of these fixes
can correct a genuine mismatch between Jen's config and Kea's own.

## [5.1.11] - 2026-08-23

### Security/reliability: session-cache staleness, per-key API scoping, alert-template resilience

Three fixes from a continued audit pass, following up on v5.1.9/v5.1.10:

- **Stale session cache on revoked access** (`jen/__init__.py`, `users.py`) —
  `load_user()`'s session-cache fast path trusted `session['_user_cache']`
  (role, subnet access, session timeout) indefinitely once set at login,
  with no way for the server to invalidate one specific already-open
  session. An admin demoting a user, restricting their subnets,
  shortening their timeout, or deleting their account outright had no
  effect on that user's current session until it happened to expire on
  its own — using the OLD, possibly-longer cached timeout. Added
  `users.token_version` (migration 12), bumped on every such change.
  `load_user()` now does one cheap indexed `SELECT token_version` before
  trusting the cache: match → serve from cache as before (same
  performance profile for the unchanged case); mismatch → full refetch
  and cache refresh; no row at all (deleted account) → cache dropped and
  the user is logged out immediately. Also removed two `_g._route_start`
  lines in `load_user()` — confirmed dead, set but never read anywhere.

- **API keys had no scope of their own** (`jen/routes/api.py`,
  `templates/api_keys.html`) — every `/api/v1/*` endpoint returned data
  for ALL subnets for any valid key, regardless of who created it or
  what subnets *they* could see. Since subnet-restricted admins (not just
  viewers) can create API keys, a restricted admin could mint a key with
  more access than their own account has. Added `api_keys.subnet_access`
  (migration 13, NULL = unrestricted, same convention as
  `users.subnet_access`) — a key's scope is now chosen explicitly at
  creation time, independent of the creating user, and is clamped
  server-side to never exceed what the creating user can themselves see
  (checked against a hand-crafted request too, not just the form). All
  six `/api/v1/*` read endpoints now filter/deny by the key's own scope;
  a lease/device outside scope 404s the same way a nonexistent one would.

- **`render_template_str` (alerts.py)** — previously only caught
  `KeyError` from a malformed admin-authored alert template. Any other
  `str.format()` failure (`IndexError`, `ValueError`, `AttributeError`)
  propagated out of `send_alert()`; because `check_alerts()`'s
  `kea_down`/`kea_up`/`new_lease`/`new_device`/`ha_failover` calls aren't
  individually wrapped, that exception skipped every remaining check for
  the rest of that 30-second cycle — utilization, stale-reservation,
  snapshot, daily summary — and repeated on every subsequent cycle for as
  long as the bad template existed, with only a log line to show for it.
  Now falls back to the raw template on any formatting failure.

No functional changes to any endpoint's read-only nature; API responses
for existing unrestricted keys are unaffected (NULL scope = all subnets,
same as before this release).

## [5.1.10] - 2026-08-23

### Security: fixed stored XSS in the dashboard device widget, wired up subnet notes

Found during a follow-up audit of the frontend/HTMX layer requested after
v5.1.9:

- **Stored XSS in "Top Active Devices"** (`dashboard.html`) — the
  `loadTopDevices()` widget built its table with string-concatenated
  `innerHTML`, including the device's DHCP-reported hostname with no
  escaping. A DHCP client's hostname option is attacker-controlled — any
  device on the network can set it to arbitrary text — so a malicious
  hostname rendered as live HTML/JS in the browser of any logged-in user
  who viewed the dashboard, including superadmins. Added a shared
  `escapeHtml()` helper in `base.html` and applied it to every
  device-supplied field in that widget (name, hostname, IP, subnet,
  manufacturer). Every other place hostname is displayed already goes
  through server-side Jinja autoescaping (or the `hostname` filter) and
  was unaffected.
- **Subnet notes feature completed** (`subnets.html`) — the notes
  editor JS (`editNote`/`saveNote`/`cancelNote`) and its backend route
  (`/subnets/save-note`) already existed and worked, but the template
  never rendered the `note-display-*`/`note-edit-*`/`note-text-*`
  elements the JS depended on, so the feature was unreachable. Added the
  missing markup to each subnet card (admin/superadmin only, matching
  the existing edit/delete controls), and escaped saved notes on the
  client side with the same `escapeHtml()` helper as a second line of
  defense — the initial page-load render already went through Jinja
  autoescaping.

No Python changed — templates only. No functional changes to any
existing route or permission model.

## [5.1.9] - 2026-08-18

### Security: hardened self-update extraction and SSH host-key verification

Found via a security-scanning pass (bandit + hand-tracing of every
flagged path, plus a hadolint check on the Dockerfile):

- **Self-update tarball extraction** (`settings.py`) — the member
  filter for the downloaded release tarball only checked the name
  (`startswith("jen/")`, no `..`), not the member *type*. A symlink or
  hardlink member could pass that filter and, once extracted, point
  outside the temp directory. The filter now also requires
  `m.isfile() or m.isdir()` and rejects absolute paths, so only plain
  files and directories are ever extracted.
- **SSH known-hosts loading** (`auth.py`) — `paramiko_load_known_hosts()`
  previously logged a warning and continued if the known-hosts file
  couldn't be loaded (corruption, permissions, disk error). Combined
  with `AutoAddPolicy()`, that meant a load failure silently disabled
  host-key verification — every host would be re-trusted as if seen for
  the first time. It now raises instead, so the failure surfaces as a
  real connection error through the existing SSH try/except in every
  caller, rather than a log line nobody sees.
- **Dockerfile** — added `--no-cache-dir` to the pip install step
  (hadolint DL3042).

No functional or UI changes. 616/617 tests passing — the one failure
(`test_ipam_manifest_applies_correctly`) fails only in a full-suite run
and passes cleanly in isolation, pointing to shared-DB-state/test-order
leakage in `test_plugin_migrations.py` rather than anything touched by
this release (neither changed file goes near plugin migrations). Not
independently confirmed against unmodified v5.1.8 — worth a look, but
not blocking this release.

## [5.1.8] - 2026-08-17

### Fix: static-asset deploy fix was overwriting custom favicons

Both the `install.sh` fix (v5.1.5) and the self-update fix (v5.1.6)
for the Reports/Chart.js deployment gap blanket-copied the whole
`static/` tree from the release tarball onto the live install. That
was correct for vendored assets like `chart.umd.min.js` and
`htmx.min.js`, but wrong for `favicon.ico`: it's shipped in the
tarball as the stock default, but it's *also* the exact path
Settings → System writes a user-uploaded favicon to
(`extensions.FAVICON_PATH`). Every update — manual `install.sh
--upgrade` or the self-update button — was silently overwriting a
real custom favicon with the stock one, a real regression a user hit
directly.

### What changed for users

- A custom favicon uploaded via Settings → System now survives every
  future update. If yours was already overwritten by v5.1.5–v5.1.7,
  you'll need to re-upload it once after this update; from here
  forward it won't happen again.
- Fresh installs, and installs that never had a custom favicon,
  continue to get the shipped default exactly as before.

### What changed under the hood

- `install.sh` and `jen/routes/settings.py::self_update()`: both now
  back up any existing `static/favicon.ico` before the recursive
  `static/` copy runs, then restore that backup afterward — so
  whatever was there before (default or custom) survives untouched,
  and the shipped default is only ever installed when nothing exists
  yet at all. Same semantics `nav_logo` and `static/icons/custom/`
  already get, just applied to a file that (unlike those two) actually
  ships in the tarball too.
- Verified two ways: a direct simulation of the exact command sequence
  against a real temp directory (not just checking the generated
  script's text) for both the "custom favicon survives an update" and
  "fresh install still gets the default" cases, plus text-level checks
  confirming the backup happens before the static/ copy and the
  restore happens after it, so the ordering can't silently regress.
- 4 new tests in `tests/test_self_update.py` for the self-update code
  path specifically; the `install.sh` side was verified by direct
  bash-script simulation (not covered by the Python test suite, since
  `install.sh` does real systemd/apt/sudoers operations that aren't
  meaningfully unit-testable) — same verification approach used for
  the v5.1.5 `install.sh` fix.

## [5.1.7] - 2026-08-17

### Unblocking the v5.1.6 self-update fix (no functional changes)

v5.1.6 fixed self_update()'s static-asset copy logic — but that fix
could never take effect on the update that installed it, because
self_update() always runs using the code already on disk *before* the
update starts, not the new code inside the tarball being installed.
Anyone updating from v5.1.5 to v5.1.6 via the button ran v5.1.5's old,
still-broken copy logic to do it, so chart.umd.min.js still never got
installed even though v5.1.6's tarball genuinely contained it — and
the update button won't offer anything once you're already on the
latest tag, so there was no way to retrigger it without a new version
existing to update to.

This release is purely a version bump for that reason. No code
changed. Once this is live as the latest release, clicking Update
runs v5.1.6's already-correct copy logic (now running on the box
doing the updating) against this tarball, which finally installs
`static/js/chart.umd.min.js` correctly.

### What changed for users

- Reports charts should finally render after this update, if you
  updated to v5.1.6 via the self-update button rather than a manual
  `install.sh --upgrade` (which wasn't affected by this particular
  bootstrap gap, since it always re-derives its file list from
  whatever's in the currently-extracted tarball rather than from
  already-running code).

## [5.1.6] - 2026-08-17

### The self-update button had its own, separate static-assets gap

v5.1.5 fixed `install.sh` so a manual `install.sh --upgrade` correctly
deploys vendored static assets like `chart.umd.min.js`. That fix never
touched the in-app self-update button (Settings → Infrastructure →
Update), because it's a completely independent code path — its own
hand-maintained list of what to copy, generated into a helper script
and run via sudo, living entirely in `jen/routes/settings.py`. That
list had a comment explicitly excluding "other static/ subfolders
(nav_logo, favicon, generated JS, etc.)" — treating vendored release
assets the same as genuine user uploads. The Reports page stayed
broken for anyone using the self-update button specifically, on every
release, regardless of what v5.1.5 fixed elsewhere.

### What changed for users

- Reports charts actually render after clicking Update in Settings →
  Infrastructure, not just after a manual `install.sh --upgrade`.
- `favicon.ico` and `htmx.min.js` also get updated on self-update now,
  for the same reason.

### What changed under the hood

- `jen/routes/settings.py::self_update()`: replaced the
  `static/icons/brands/*.svg`-only copy command with a recursive copy
  of the whole extracted `static/` directory into the install dir,
  mirroring the v5.1.5 `install.sh` fix. `static/icons/custom/` (user
  uploads) is gitignored and never present in the release tarball, so
  this copy cannot reach it — confirmed by a real test asserting
  `icons/custom` never appears anywhere in the generated helper
  script.
- 3 new tests using the existing real-tarball-and-captured-helper-
  script pattern from the v4.4.16 `run.py` regression test: the
  recursive static copy command is present, it never references
  `icons/custom` or `rm -rf`s anything under `static/`, and
  self-update still succeeds against a tarball with no `static/`
  directory at all (older/malformed release, shouldn't crash).

## [5.1.5] - 2026-08-17

### install.sh wasn't actually deploying the Reports fix

v5.1.4 vendored Chart.js locally to fix the Reports page, but the fix
didn't actually take effect on deployment: `install.sh` copies files
into the live install directory using a hand-maintained per-file list
(it only knew about `htmx.min.js` and `icons/brands/*.svg` by exact
name), and `chart.umd.min.js` was never added to that list. The
browser requested `/static/js/chart.umd.min.js`, got a 404, and the
`<script>` tag failed to load with no visible error — so the symptom
looked identical to the original CDN bug even though that part of the
fix was correct.

### What changed for users

- Reports charts actually render now after upgrading. Confirmed by
  simulating both a fresh install and an upgrade of a pre-5.1.4
  install against a realistic directory layout before shipping this.
- `favicon.ico` gets installed too — it had the exact same gap
  (missing from every install, not just this release, simply less
  noticeable than a broken feature page).
- `install.sh` no longer reaches out to `unpkg.com` over the network
  at install time to fetch htmx as a fallback — everything it needs is
  already bundled in the package tarball, so there's no reason for
  install-time internet access at all.

### What changed under the hood

- `install.sh`: replaced the hand-maintained per-file copy list
  (`icons/brands/*.svg`, `htmx.min.js` with a `curl` fallback to
  `unpkg.com`) with a single generic `cp -r "$SCRIPT_DIR/static/."
  "$INSTALL_DIR/static/"`, so any file added to `static/` in the
  future is installed automatically without needing a matching
  `install.sh` change. `static/icons/custom/` (user-uploaded device
  icons) is gitignored and never present in the source tree, so this
  copy cannot touch it — verified directly by simulating an upgrade
  with a fake pre-existing custom icon in place and confirming it
  survived.

## [5.1.4] - 2026-08-17

### Reservation active/inactive status, Reports fix, unified action menus

Three related changes: the Reservations page now shows whether each
reserved IP is actually in use right now; the Reports page's charts,
which were silently failing to render, are fixed; and every page with
a row of action icons (edit/reserve/delete and similar) now uses one
consistent "⋯" action-menu component instead of the old fixed icon
row, whose width and icon set used to shift depending on which
actions applied to a given row.

### What changed for users

- **Reservations**: a new Status column — **● Active** (the reserved
  IP currently has a live, non-expired lease bound to it), **○
  Inactive** (no current lease at that address), or **⚠️ Conflict**
  (the address is currently leased, but to a different MAC than the
  reservation itself). A new Status filter (All / Active only /
  Inactive only) alongside the existing subnet and search filters.
- **Reports**: charts render again. Root cause was Chart.js loading
  from an external CDN at runtime with no error shown on failure —
  fixed by vendoring it locally, matching the same convention already
  used for htmx.
- **Unified row actions**: Devices, Leases, Reservations, Database
  (backups), Settings → Alerts, and Settings → API Keys all now show a
  single "⋯" button per row that opens a dropdown of the actions that
  apply to that row. Rows that used to lose an icon or shift width
  depending on state — a device that already has a reservation, a
  lease already tied to a reservation, an API key that's already
  revoked — now show an explicit, always-present entry for that state
  (e.g. "Reservation exists", grayed out) instead of silently omitting
  the icon. A handful of other pages (Infrastructure's extra-server
  rows, the nav logo remover, plugin uninstall, saved-search delete,
  custom icon delete) keep a single button rather than a dropdown,
  since they have one incidental action next to a primary labeled
  button and no shifting-row problem to fix — those were simply
  re-skinned with the same icon set for visual consistency.
- Icons switched from emoji to small inline SVGs everywhere — no
  external icon font, no CDN dependency.

### What changed under the hood

- `jen/routes/reservations.py`: the v4 reservation query gained a
  `LEFT JOIN lease4` (matched on address, restricted to `state=0 AND
  expire > NOW()`) to compute active/conflict status per row, plus an
  `EXISTS`/`NOT EXISTS` clause for the status filter.
- `static/js/chart.umd.min.js` (new) — Chart.js 4.4.1, vendored.
  `templates/reports.html` now loads it locally instead of from
  cdnjs.cloudflare.com.
- `templates/_icon_sprite.html` (new) — hand-authored inline SVG macros
  (edit, trash, pin, dots, download, test, pause).
- `templates/base.html` — new `.action-menu` CSS component (same
  checkbox-toggle mechanism already used for the nav avatar dropdown,
  so open/close works without JS; a small script handles outside-click
  close, Escape, single-menu-open, and closing the menu when an item
  inside it is clicked).
- `_device_rows.html`, `_lease_rows.html`, `_reservation_row.html`,
  `database.html`, `settings_alerts.html`, `api_keys.html` rewritten
  to use the new pattern.
- 30 new tests: 8 for reservation status (active/inactive/conflict,
  expired/released leases not counting as active, filter correctness),
  7 for the Reports fix (no CDN reference remains, the vendored file
  loads and is served, real `lease_history` data renders correctly),
  and 15 across the action-menu conversions (Devices, Leases, and the
  Settings pages), specifically covering the conditional-item-count
  cases — a reserved device, a lease with a reservation, a revoked API
  key — that the redesign exists to fix.

## [5.1.2] - 2026-08-17

### Kea package detection and one-click install

A missing `kea-dhcp4`/`kea-dhcp6` binary previously surfaced as a raw
Python traceback in the config-authoring and subnet-edit preview
panels — genuinely broken output, not just unpolished. Fixed, and
turned into a real capability: Jen can now tell you whether the Kea
packages are actually installed and install them for you.

### What changed for users

- Settings → Infrastructure has a new "Kea Package Status" card
  (superadmin only) — "Check Installation" reports whether
  `kea-dhcp4-server`/`kea-dhcp6-server` are present on each configured
  server, with an inline "Install" button for anything missing.
- The "Author a starting config" wizard now catches a missing binary
  during Preview & Validate and offers to install it right there,
  re-running validation automatically afterward.
- The same clean handling was applied to the existing v4/v6 subnet-edit
  preview and apply flows, which had the identical latent bug.

### What changed under the hood

- `jen/services/kea_authoring.py`: `detect_installed_kea_services()`
  (checks both protocols together via `which`) and
  `install_kea_service()` (`apt-get update && apt-get install -y
  kea-{service}-server` over SSH, targeting Jen's documented Ubuntu
  24.04 platform).
- All three script generators that shell out to `kea-dhcp4/6 -t`
  (`kea_authoring.py`, `kea6.py`'s subnet patch script, and
  `subnets.py`'s v4 equivalent) now catch `FileNotFoundError` around
  the `subprocess.run()` call and emit a clean `missingbinary:<name>`
  sentinel instead of letting the traceback reach the browser.
- Two new routes: `POST /settings/infrastructure/check-kea-binaries`
  and `POST /settings/infrastructure/install-kea-binary/<service>`,
  both superadmin-gated.
- 20 new tests, including one that confirms all three generated remote
  scripts remain valid Python after the fix, and one reproducing the
  exact reported bug (missing binary during config authoring) to
  confirm the response is now structured JSON, never a traceback.

## [5.1.1] - 2026-08-17

### Fix: "Author a starting config" required subnets that had no way to be added

The wizard shipped in 5.1.0 required at least one subnet to already
exist in Jen for the target protocol before it would even render the
form — but authoring a config from scratch is exactly the situation
where nothing exists there yet, and there was no UI path to add a v6
subnet ahead of time. The only way through it was hand-editing
`jen.config` directly.

Subnets are now defined inline in the wizard itself (one per line,
`id = name, cidr[, paired_v4_subnet_id]` — the same syntax
`jen.config`'s own `[subnets]`/`[subnets6]` sections already use, and
pre-filled from any subnets Jen already knows about). On a successful
write, those subnets are saved into Jen's own config automatically, so
they show up on the Subnets page from then on without a separate step.

## [5.1.0] - 2026-08-17

### Author a starting kea-dhcp4.conf / kea-dhcp6.conf

Settings → Infrastructure now has an "Author a starting config" flow
for either protocol, for the case where Jen is managing a Kea install
that doesn't have a config file yet — most commonly, adding IPv6 to an
existing IPv4 deployment.

### What changed for users

- New buttons on the Kea API and Kea6 API cards in Settings →
  Infrastructure: "Author a starting kea-dhcp4.conf" / "kea-dhcp6.conf"
  (superadmin only).
- If the other protocol's config already exists on the target server,
  interfaces and database connection settings are pulled from it
  automatically rather than asked for — enabling IPv6 alongside a
  working IPv4 setup reuses what's already there. Live interface
  detection over SSH is the fallback only when neither protocol has a
  config yet.
- The Control Agent's own config is read to find the correct
  control-socket path for the new service, so the generated file is
  actually reachable through the same CA Jen already talks to.
- Subnets to include come directly from Jen's own configured subnet
  list, with a full-CIDR default pool narrowed later via the existing
  Subnets → Edit flow.
- Same Preview & Validate pattern as subnet editing: the generated
  config and each server's `kea-dhcp4/6 -t` result are shown before
  anything is written. Refuses to overwrite an existing file unless
  explicitly told to, and backs up first when it does.
- The IPv6 toggle's old "create it manually first" message now links
  directly to this flow instead.
- Deliberately excluded: HA peer configuration (never generated), and
  hooks beyond `host_cmds`/`lease_cmds` (the two Jen's own commands
  actually depend on) — not a guess at what a broader setup might want.

### What changed under the hood

- **`jen/services/kea_authoring.py`** (new) — shared between both
  protocols: `detect_sibling_config()` (reads the other protocol's real
  config, never surfaces its database password), `autodetect_interfaces()`
  (SSH-based fallback), `detect_ca_socket_path()`, `build_new_kea_config()`,
  and `render_author_config_script()` (same dry-run-then-apply contract
  as every other config-writing path in this project).
- **New routes** in `jen/routes/settings.py`:
  `GET /settings/infrastructure/author-kea/<service>`,
  `POST .../preview`, `POST .../<service>` — superadmin-gated.
- **`templates/author_kea_config.html`** (new).
- 41 new tests, including confirming the dry-run preview path sends
  exactly one SSH command per server (never a write), that a real v4
  config's database password never leaks through sibling detection,
  and that every combination of the generated remote script (dry-run/
  apply × overwrite/no-overwrite) is valid Python.

## [5.0.0] - 2026-08-16

### IPv6 (DHCPv6) support

The largest single change in Jen's history — full IPv6 visibility
across every major page, plus write support for reservations and
subnet editing, built alongside Jen's existing IPv4 management rather
than replacing any of it. Ships as `5.0.0`, not a `4.5.x` patch series,
to signal the scale honestly rather than bury it.

**Off by default, on every install — new and existing.** Nothing about
this release changes behavior for a v4-only setup: `ipv6_enabled`
defaults to `false`, `[kea6]`/`[kea6_db]`/`[subnets6]` are optional
`jen.config` sections that don't need to exist, and every v6 code path
checks the flag before doing anything. This is the single most heavily
tested property of this release — see `docs/ARCHITECTURE.md` §5 for the
full design writeup, including what's deliberately deferred and why.

### What changed for users

- **Settings → Infrastructure**: a new "Kea6 Control Agent API"
  section with the "Enable IPv6 support" toggle (superadmin only).
  Flipping it doesn't just change what Jen displays — it SSHes to every
  configured Kea server, confirms `kea-dhcp6.conf` actually exists, and
  starts/stops `kea-dhcp6-server` for real.
- **Leases, Devices, Reservations pages**: a new `IPv4 | IPv6`
  segmented control, entirely absent (not just disabled) when no IPv6
  subnets are configured. The Devices view groups leases by DUID so a
  single device's address and delegated-prefix leases show as one row,
  and shows a manufacturer icon when the DUID embeds a recoverable MAC
  (DUID-LL/DUID-LLT) — never a guessed one otherwise.
- **Subnets page**: v6 subnets tagged and shown either as a second
  detail block on a paired v4 card (via an optional config-driven
  `paired_subnet4_id`) or as their own card. Admins get a real "Edit"
  flow — address pool, preferred/valid lifetime, T1/T2, DNS — with the
  same dry-run Preview & Validate safety net v4.4.24 established:
  `kea-dhcp6 -t` runs against every configured server before Apply is
  even clickable, and the live config is never touched by the preview.
- **Reservations page**: admins can add or delete a v6 reservation
  (address, delegated prefix, or both on the same DUID) directly
  through Kea's own API — no manual JSON editing.
- **Dashboard**: a genuine IPv6 summary card (active leases,
  reservations) when enabled; an explicit "(IPv4 only)" label on the
  existing totals widget when it isn't — never a silently-incomplete
  number either way.
- **Global search** now covers IPv6 leases and reservations, respecting
  the same paired-subnet access rule as everywhere else: a subnet-
  restricted user sees v6 results only for subnets paired with a v4
  subnet they already have access to.
- **`/metrics`** gains `jen_ipv6_enabled`, `jen_subnet6_active_leases`
  (labeled by IA_NA/IA_PD), `jen_subnet6_reserved_hosts`, and
  `jen_kea6_up` — separate metric names, not folded into the existing
  v4 gauges.
- **IPAM Lite and Network Discovery plugins** now show an in-app note
  (only when IPv6 is enabled) and document in their own READMEs that
  they remain IPv4-only for this release — a full-address-space view
  doesn't have a sane equivalent for a `/64`.

### What changed under the hood

- **`jen/services/kea6.py`** (new) — the entire v6 service layer: Kea
  API command wrappers, the read layer (`list_lease6()`,
  `get_ipv6_reservations()`, `list_lease6_devices()`), the write layer
  (`add_v6_reservation()`/`delete_v6_reservation()`,
  `build_subnet6_patch_script()`), and the SSH-based service-state
  orchestration for the enable/disable toggle. `lease6`/`hosts`/
  `ipv6_reservations` column shapes confirmed directly against Kea's
  real `dhcpdb_create.mysql`, not assumed from the v4 schema — notably
  `lease6.address` is `VARCHAR(39)`, not the `INET_ATON` integer v4
  uses.
- **`jen/models/db.py`** — `kea6_db()`/`get_kea6_db()`, which reuse the
  existing `kea_db` connection pool when `[kea6_db]` targets the same
  database as `[kea_db]` (the common case) rather than always opening a
  redundant second pool.
- **`jen/models/migrations.py`** — migration 11, `lease6_history`.
  Deliberately a separate table from `lease_history`, not columns
  bolted on: NA/PD counts aren't comparable quantities, and a `/64` has
  no finite "percent used" the way a v4 `/24` does. Applies
  automatically on next restart like every other migration in this
  project's history — no manual step.
- **`jen.config`** — new optional `[kea6]`, `[kea6_db]`, `[subnets6]`
  sections. Every `[kea6]`/`[kea6_db]` value falls back to its v4
  counterpart when absent. `[subnets6]` entries accept an optional
  third field, `paired_v4_subnet_id`, for the Subnets page pairing.
- **Test suite**: `tests/test_kea6.py`, ~150 tests covering every layer
  above — config fallback, the DUID/MAC extraction edge cases (DUID-LL,
  DUID-LLT, DUID-EN, DUID-UUID), the one-to-many reservation shape, the
  toggle's all-or-nothing success semantics, and — critically — that
  the subnet-edit preview endpoint never sends more than one SSH
  command (the dry-run test), never a second apply/restart call.
- Found and fixed a real pre-existing test-isolation bug along the way:
  `tests/conftest.py`'s `_patch_extensions()` predated the `KEA6_*`
  extensions fields and never reset them, which silently corrupted
  global state for any test running after one that called
  `AppConfig.apply()`/`reload()` — invisible until this release's DB
  connection-pooling logic started comparing `KEA6_DB_HOST` against
  `KEA_DB_HOST`.
