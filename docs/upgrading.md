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

If you run the wizard by hand and a Kea API or database test fails,
you're now offered retry / edit / continue instead of a bare warning
that just carries on. A value you never actually change from its
placeholder default is written to `jen.config` as empty rather than
as the placeholder itself — Jen's own Health and Getting started pages
already read an empty key as "not configured" and say so. When the
Kea API test passes, its own subnet list is offered for confirmation
instead of asking you to retype it; when the Jen database is local
and root can already connect, you're offered to create it (the SQL
shown first either way). None of this affects an existing install or
an upgrade — it's the fresh-install wizard only (5.67.0-beta.1).

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
