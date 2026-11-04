# Upgrading from 5.70.0

Everything below changed since v5.70.0 — the last stable release before
this one — that you'd actually notice or need to know about when you
upgrade. Run `sudo ./install.sh` on the new tarball (or use the in-app
updater) the normal way; nothing here needs a manual step beyond what's
called out explicitly. See `docs/runbooks.md` for step-by-step
procedures, and `CHANGELOG.md` if you want the full detail behind any
item below. The previous page, covering everything since 5.69.0 through
the 5.70.0 baseline, is archived at
[`docs/release-history/upgrading-5.69.0-to-5.70.0.md`](release-history/upgrading-5.69.0-to-5.70.0.md).

## Changes can go over Kea's own API; no existing server changes by itself

One step (7.0.0-beta.1). There is no Jen 6: the number is 7 because this release changes what Jen needs on a Kea host (a change can reach a server through the daemon's own API instead of an SSH file replacement), and 6 was skipped on purpose. **No existing server gains a write path on upgrade; switch a server to the API transport from its card** (Settings → Kea → *How changes reach each Kea server*). It adds no migration and needs no manual step: the upgrade writes nothing to your configuration, a server that wrote over SSH before still does, and a server that was only read (no SSH host) is still only read.

**What you will see.** The Servers page shows one word per server beside its role: `API`, `API, unauthenticated`, `file` or `off`. A server with an SSH host and no setting reads `file`; one with no SSH host reads `off`. Settings → Kea has a card per server with **Check API configuration**, the three-way switch and, where SSH is set up, **Allow the daemon to write its file** and **Take the write right back**. Config history labels three new kinds of row (`rollback`, `switch` and `pending`). The Doctor names a transport value that is not spelled exactly `api`, `file` or `off` (a mistake reads as `off`).

**A server added after the upgrade starts on the API** and writes nothing until you have run **Check API configuration** on its card, read the facts it shows and allowed changes over the API. The check shows how the endpoint is authenticated (a password, Jen's client certificate, or nothing) and whether it is reached over TLS; where SSH is set up, whether the daemon's account may write its file, whether the file carries an include and whether the file and the daemon agree.

**What changes when you switch a server to the API.** Kea writes its file in its own form: comments and key order are not kept (a 1,932-byte file became 4,769), and the switch is the one moment they are lost. A change is live at once with no restart, guarded by the daemon's configuration digest. Kea writes the file in place, so a crash in the middle of a write leaves a file the daemon cannot start on; where there is no SSH you repair it by hand from Config history. A refused `config-write` is undone by Jen, remembered on the card and blocks further changes to that server until you fix it. One Jen instance per daemon is the supported configuration: inside the two round trips of a change, a second client's `config-set` is overwritten without a trace.

**The Kea host helper has a new build (19).** It adds the three ops behind the card's grant buttons, keeps verifying after a restore of investigation logging, and never makes a backup group-writable. Press **Update helper** on a host only if you want the grant; the legacy `python3` path has no engine for these ops.

**Recovery bundles.** A recovery bundle exported on 5.x restores on 7.0 (the major-version check accepts it). Export a fresh bundle after upgrading.

**What stays on the file path in this beta.** Control-socket changes and investigation logging (the host restores the marker from the file), the first file Author Kea Config writes, dhcp6 and D2. A restore or an import applied to an API server goes over the API with no restart.
