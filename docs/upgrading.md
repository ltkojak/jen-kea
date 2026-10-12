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

## Access control and secrets: the database cards are the superadmin's, and a password change signs out the account's older sessions

One step (5.69.0-beta.2), and nothing to do for it: this release closes the places where a role or a subnet scope was weaker than the page said. What you will notice:

**The database cards, the Kea6 card and the restart are the superadmin's, with a fresh password.** Where Jen's own database, Kea's database and Kea's IPv6 database point, and the **Restart Jen** button, now need a superadmin who confirmed their password in the last ten minutes (Jen asks for it the first time). An admin still sees where each database points, and the restart banner tells them a superadmin restarts Jen. An admin who changed these before has to ask a superadmin now. Creating a subnet needs access to every subnet: an admin limited to some subnets gets a sentence saying so.

**DDNS: scoped users get the Status tab alone.** A user whose account is limited to some subnets sees the dhcp4 to D2 table on the DDNS page and nothing more: no log tail, no Mode and Log card, no hostname lookup, and no Verify tab (it resolves any name or address through the Jen host). Viewers see Status only, as before. Everyone else keeps every tab.

**`[ddns] log_path` must be a `.log` file under `/var/log`.** The Settings form refuses anything else, and so does the legacy read over SSH (the Kea host helper already did). If you hand-edited the path in `jen.config` to a file that does not end in `.log`, move the log or rename the setting's target. A blank field in the DDNS form now clears its setting, and the API token is kept unless you tick **Remove the saved API token**.

**The MFA policy only gets stricter for an admin.** An admin may raise it (Optional, Required for Admins, Required for All Users) and keep it, never lower it; stepping down, including to Off, is the superadmin's, and the page greys out the options an admin may not pick.

**The API answers a hidden object like a missing one.** With a key limited to some subnets, `DELETE /api/v1/reservations/<id>` and `PATCH /api/v1/devices/<mac>` for an object outside those subnets now return the same 404 as an id or MAC that does not exist, where they returned 403. A script that treated 403 as "not allowed" should treat 404 the same way. The pages say "not found" the same way for a lease, reservation, device or subnet a restricted admin cannot see.

**One sign-out after a password change.** When a password is changed, the account's older sessions, in any browser, end at their next request and sign in again; the session that made the change stays. Sessions that are open when you upgrade are not signed out.

**IPv6 pages follow the IPv6 switch.** With IPv6 switched off, `?view=v6` shows the IPv4 page and the IPv6 add and edit routes answer 404, even when the config has a `[subnets6]` section.

## Data, the clock and alerts: database sessions run in UTC, one migration, and a few alerts can repeat once

One step (5.69.0-beta.3), and nothing to do for it. What you will notice:

**Every database connection runs in UTC.** Jen now sets `time_zone = '+00:00'` on each connection it opens, to its own database and to Kea's, so `NOW()` in a query and the time Jen's Python code reads are one clock whatever zone the database host is in. Your server's own zone is not touched, and rows written earlier keep the clock they were written with. On a database host that was east or west of UTC you may see Health's "Lease snapshots current" row, the once-a-day backup and the capacity forecast's day settle onto the right hour; the daily summary time is UTC (HH:MM, and the form refuses anything else, such as `7am`).

**Migration 35 runs by itself.** It removes the old `telegram_token`, `telegram_chat_id` and `telegram_enabled` rows from the settings table, a plaintext bot token the removed save-telegram page used to write. Your alert channels (where the token is stored encrypted) are not touched; a database that never had the rows changes nothing, and an interrupted run finishes on the next start.

**A few alerts can repeat once.** Stale-reservation, configuration-drift and Kea-down messages kept what they had said in memory, so a restart said it again; from this release the fact is stored, and the first sweep after the upgrade can send, one time, a message that the earlier version had already sent. After that a restart sends nothing, a message no channel took is retried with a back-off, and a recovery is sent only for a warning that was delivered.

**A subnet that left Kea's config ends its alert.** A subnet still listed in Jen but gone from Kea's config (or left with no pool) used to keep its utilization or exhaustion warning for ever; Jen now sends one recovery that names it, and clears it.

**Reservations and plugins.** A CSV import stores a hardware address as a hardware address. Reservations an earlier import created were stored as a DUID, which may never have matched a client: check any you imported by CSV and re-create the ones that do not take effect. The import also names a bad row by its line and refuses an address outside the subnet. The Plugins page shows "Failed to load" for a plugin whose start-up raised, with the exception class only.

## The interface: pages you may see differently, nothing to do

One step (5.69.0-beta.4), and nothing to do for it. What you will notice:

**A viewer sees fewer buttons.** Controls that led a viewer to an "Admin access required" page are no longer shown: the stale-after-days setting on Devices, the options and classes links on a subnet card, the Settings links on Servers and the dashboard's Alert Summary, and the Getting Started widget. A scoped admin is no longer offered Add Subnet. Nothing a viewer could do before is removed; only the dead ends are.

**Names.** The navigation entry is "Kea servers", and the database pages say "Kea reservations". The pages no longer name the release that introduced a feature.

**The Saved-filters dropdown on Leases and Reservations works again**, and its Save Filter button with it.

**Keyboard and screen readers.** The shortcuts window and the confirmation window take focus when they open, keep it inside until they close and give it back.

## The loose ends: seven plugin updates and a safer SSH key button, nothing to do

One step (5.69.0-beta.5), and nothing to do for it. What you will notice:

**Seven plugin updates are offered** under Settings → Plugins (the copies that ship with Jen are already the new versions; a box that installed a plugin from the registry is offered the update). They fix small things: a database error on a plugin page is a sentence, a viewer is no longer shown buttons the page then refuses, and every row that names a client has the Investigate action.

**Regenerate SSH key** (Settings → Kea) now works over an existing key, asks you to confirm your password again first, and keeps the old pair beside the new one as `<key>.prev`. Add the new public key to each Kea server's `authorized_keys`, then delete the `.prev` files.

**A password in a DNS-sync URL is refused**: put the credential in the password field. A target saved earlier with `user:pass@` in its URL keeps working, and shows without the password; remove and re-add it to drop the stored copy.

**An unknown `?subnet=` on the API is a 400** where it used to return everything the key may see. If a script passes a subnet name or id that does not exist, it now learns that.
