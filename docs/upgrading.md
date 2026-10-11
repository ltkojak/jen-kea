# Upgrading from 5.68.0

Everything below changed since v5.68.0 — the last stable release before
this one — that you'd actually notice or need to know about when you
upgrade. Run `sudo ./install.sh` on the new tarball (or use the in-app
updater) the normal way; nothing here needs a manual step beyond what's
called out explicitly. See `docs/runbooks.md` for step-by-step
procedures, and `CHANGELOG.md` if you want the full detail behind any
item below. The previous page, covering everything since 5.67.0 through
the 5.68.0 baseline, is archived at
[`docs/release-history/upgrading-5.67.0-to-5.68.0.md`](release-history/upgrading-5.67.0-to-5.68.0.md).

## The Kea host helper bounds what it does as root: press Update helper again

One step (5.69.0-beta.1). If you use investigation logging, press **Settings → Kea → SSH → Update helper** on every Kea host (build 18; Jen refuses to turn logging on below it, with
nothing changed, and says so). Hosts that do not use investigation logging can take the update at their next convenience: it adds no operation and changes no sudoers line.

**A control socket's credential files must meet one rule.** The helper asks the running Kea what its logger is through the control socket in the config, and it reads that socket's
`user-file` and `password-file` only when the config's `directory` is `/etc/kea` itself and each file is a regular file directly in it with exactly one link, owned by root or by Kea's own
account, and writable by neither group nor everyone (`sudo chown root:root /etc/kea/<file>` and `sudo chmod 640 /etc/kea/<file>` if yours are not). A unix control socket is used only under
`/run/kea`, `/var/run/kea` or `/tmp`. A config that points anywhere else is not followed: the helper falls back to Kea's own log or a fresh process to confirm a restore, and Health says which
of these it could not do beside a restore that also failed (`socket_note`). Nothing breaks if your files already meet the rule.

**A config anyone could read is tightened when Jen next writes it.** The next time Jen applies a change to a Kea config whose mode is 0644 or 0664 (it carries the database password), the
helper writes the replacement `root:<the daemon's group>` 0640, `root:root` 0600 for a daemon that runs as root; a config that is already stricter keeps its owner and mode. Where the helper
cannot see a Kea unit of either name the packages use, the existing owner and mode are kept.

A restore that cannot be held up: the timer's unit now stops after two minutes, the restore waits at most a minute for the helper's lock (now in `/var/lib/jen-kea-helper/locks`, with the old
one beside the config still taken for this one build) and fails that minute's tick loudly if it cannot, and a restart is recorded on disk before it is issued. A symlink at a config, log or
TLS path is refused (`symlink` in the helper's reply) instead of followed.
