# Upgrading from 5.66.0

Everything below changed since v5.66.0 — the last stable release before
this one — that you'd actually notice or need to know about when you
upgrade. Run `sudo ./install.sh` on the new tarball (or use the in-app
updater) the normal way; nothing here needs a manual step beyond what's
called out explicitly. See `docs/runbooks.md` for step-by-step
procedures, and `CHANGELOG.md` if you want the full detail behind any
item below. The previous page, covering everything since 5.56.3 through
the 5.66.0 baseline, is archived at
[`docs/release-history/upgrading-5.56.3-to-5.66.0.md`](release-history/upgrading-5.56.3-to-5.66.0.md).

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
companions directly — doing so skips the matching `/setup` step, same as
every other answers-file key already skips its own prompt. None of this
affects an existing install or an upgrade — it only changes what a fresh
install's terminal session asks (5.67.0-beta.3).

## jen.config tightens to 0600

The config file holding every DB password, API credential and DDNS
token this install has moves from `0640` to `0600` — owner and group
have been the same service user since v5.10.4, so the group-read bit
never actually granted anyone anything. This happens automatically on
your next config save (Settings, or the next `install.sh` run); nothing
for you to do (5.67.0-beta.1).

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
this fix, a box stuck on one of the affected betas needs the one line
it would have run itself: `sudo systemctl start jen-update.service`.
See `docs/troubleshooting.md` for the full detail. Nothing else about
an affected install was wrong, and Docker/dev checkouts were never
affected (5.67.0-beta.6).
