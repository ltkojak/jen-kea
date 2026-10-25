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

**`[ddns] log_path` must be a `.log` file under `/var/log`.** The Settings form refuses anything else, and so does the legacy read over SSH (the Kea host helper already did). If you hand-edited the path in `jen.config` to a file that does not end in `.log`, move the log or rename the setting's target. A blank field in the DDNS form now clears its setting, and the API token is kept for the provider it was typed for unless you tick **Remove the saved API token** (a change of provider removes it).

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

## Where Kea's log is: a logger that writes to the journal, and a new field

One step (5.69.0-beta.6), and nothing has to be done for it. What you may notice:

**Tools → Doctor can say that Kea's log is not written to a file.** Jen reads Kea's own log for the Problems inbox, for Trace and Explain, and the Kea host reads it to prove that investigation logging was put back. They all need a file the helper may read, a `*.log` under `/var/log`. If the `kea-dhcp4` logger writes to `stdout` it writes to the system journal and none of them can see it: the Problems inbox stays empty, which looks exactly like a quiet network. Doctor now shows a warning for it, and the Health Center row "Problems inbox sweep" names the file it looked for instead of sending you to check SSH. To fix it, give the logger a file output in `kea-dhcp4.conf` and reload Kea:

```
"output-options": [{"output": "/var/log/kea/kea-dhcp4.log", "flush": true, "maxsize": 10485760, "maxver": 4}]
```

That is a file under `/var/log/kea`, flushed as it is written, rotated at 10 MB with four old files kept. Leave out any `pattern` (or use Kea's default, which starts with the date and time): Jen's line parser needs the timestamp, and Doctor warns about a pattern that has none.

**Settings → Kea → SSH has a Kea log path field.** It is the `[kea] dhcp4_log_path` key, which used to be edited by hand. Jen reads the file the logger's own `output-options` name first and uses this path only when the logger names none. Blank is `/var/log/kea/kea-dhcp4.log`. It must be a `*.log` file under `/var/log`, the same rule the Kea host applies.

**The Utilization History chart shows its window.** The 24-hour, 7-day and 30-day views are scaled to the data's own range and the label under each subnet says which window it is, the range it covered and, on a box that has been collecting snapshots for less than the window, how many days of data there are.

## The DDNS card moved to Settings → Kea

One step (5.69.0-beta.7), and nothing has to be done for it. What you will notice:

**The DDNS settings are one section under Settings → Kea.** The D2 control-socket card and the DNS provider card (it was "DDNS & DNS Provider" under Alerts & Integrations) sit together under a DDNS heading, with a DDNS chip in the page's contents list. A bookmark to the old place forwards to the new one. Neither card was ever an alert; both are how Jen reaches the DDNS pipeline on the Kea side. The pipeline itself is still operated under Network → DDNS.

**The wording says who writes DNS.** Jen writes no DNS records. D2 does when dhcp4 sends updates, or a hook script of your own does if you load one through `libdhcp_run_script.so`. The DNS provider is where Jen looks names up, so the card is now "DNS provider (lookups)" and the no-provider choice is "None (no lookups)".

**A box with no DNS provider set reads "Not configured".** A missing `[ddns] dns_provider` used to read as Technitium, so a fresh install showed "Provider (technitium)" on the DDNS Status tab and tailed a log that did not exist. The default is now none. A box that has the key set is not affected, and neither is a hand-written section that has an `api_url` or `api_token` and no `dns_provider` key: it still reads as Technitium. If you relied on the old default with nothing else set, choose Technitium under Settings → Kea → DDNS.

**A hook script beside D2 is warned about.** If a `libdhcp_run_script.so` hook is loaded and dhcp4 also sends updates to D2, Doctor, the DDNS Status tab and the Naming tab say that every lease may be written twice. Nothing is blocked. The admin guide has a walk-through, "Moving from a hook script to D2".

## A provider switch asks for its credential; a replaced Kea host starts afresh

One step (5.69.0-beta.8), and nothing has to be done for it. What you may notice:

**Changing the DNS provider asks for the new provider's token or password.** Under Settings → Kea → DDNS, a saved token is kept only for the provider it was typed for. If you switch from Technitium to Pi-hole (or any change of provider) and leave the token box empty, the saved token is removed rather than reused, and the page says to enter the new provider's own. Saving the same provider again with the box empty still keeps its token, and so does a file that has an address or a token and no provider key. The provider blocks no longer show one provider's address inside another's block.

**A Kea host that is replaced under the same server entry starts its Problems progress afresh.** The Problems inbox remembers how far it has read each server's log. When a server's SSH host, SSH user or config path changes, that memory is cleared before the next read, so the new host's problems are counted from its own log instead of being skipped behind the old host's position. The rows already in the inbox stay, and renaming a server changes nothing.

**The DDNS Status tab has a hook mode.** If a `libdhcp_run_script.so` hook is loaded and D2 is off, the Mode row says what it writes is outside Jen's view instead of "Not configured", and an explicit `[ddns] mode = none` is honoured.

## A changed endpoint asks for its password; a replaced Kea host's earlier problems read "earlier host"

One step (5.69.0-beta.9). It adds one database migration (36) that runs by itself on the first start; nothing else has to be done. What you may notice:

**A form that keeps a blank password asks for it when the address changes.** On the Kea API, Kea6, D2, additional-server, Kea database and Jen database forms, a saved password is kept only while the address (or database host) names the same place: the same scheme, host and port. Change the address and leave the password box empty and the form refuses, with a sentence saying so, and saves nothing; type the password and it saves. Saving with the same address, or with the address spelled differently (a different case, a trailing slash, an explicit default port), still keeps the password. On a Kea6 or D2 form, ticking Inherit still removes the saved password. Adding a new additional server takes the primary's password only when its own box says so (the next section). For the DNS provider under Settings → Kea → DDNS the saved token is removed, with a warning, when the provider or its address changes.

**Migration 36 adds a generation to the Problems inbox.** The column `client_problems.generation` (every existing row is generation 0) becomes part of the table's unique key. No row is removed or changed.

**A Kea host that is replaced under the same server entry is a new generation.** When a server's SSH host, SSH user or config path changes, the Problems inbox closes that server's open rows and starts the new host's from its own log; the earlier rows stay, marked "(earlier host)" beside the server name on the Problems page, and the dashboard no longer counts them. The earlier host's alert state no longer silences or repeats for the new host. Renaming a server changes nothing.

## Kea connection settings are a superadmin's; the share box; "earlier host - resolved"

One step (5.69.0-beta.10). It adds no migration and needs no action. What you may notice:

**Where Jen reaches Kea is a superadmin's setting.** The Kea API address, user and password and the connection mode, the SSH host, user and config path, the additional servers and the D2 control socket belong to a superadmin, and saving any of them asks for the superadmin's password if it has not been confirmed in the last ten minutes. An admin still sees each of those cards, as facts (the address, the user, whether a password is saved, the helper table and its Check button) with a line saying only a superadmin changes them, and still changes the HA mode, the primary's name, the DNS provider and the whole day-to-day DHCP estate. The rule is held where Jen's configuration is written, so a plugin or a hand-made request meets it too; `install.sh --configure` and API keys are not signed-in sessions and are not asked. The Kea log path sits on the SSH card and moves with it. An admin's Probe still tests a daemon on the host Jen already reaches, and a probe of an address on a different host is a superadmin's.

**Kea6 and D2 take one answer for a password.** Ticking Inherit and typing a password in the same save is refused with a sentence asking you to choose one, and nothing is saved.

**A new additional server takes the primary's password only if you tick the box.** The new-row form has "Share the primary's API password (an HA peer of the same Kea)". Without it, a server you give no password has none of its own, and from 5.69.0-beta.11 it is sent nothing with the primary's password unless it is on the primary's own host (the next section). Moving a saved server to a new address with the password box empty is refused, whichever password it would have used.

**The Problems page says when an earlier host was closed.** A row from a replaced Kea host reads "(earlier host · resolved 2026-10-14 09:30 UTC)" beside the server name. The kind counts and the dashboard count only what is open now.

## A password is used at its own host; the upgrade copies the primary's into each additional server once

One step (5.69.0-beta.11). It adds no migration. What you may notice:

**Each endpoint that borrowed a password across hosts keeps a copy of it, made once.** Until now an additional server with no password of its own was reached with the primary's, whatever host it was on - and Kea6, D2, the Kea6 database and a server's IPv6 and D2 endpoints borrowed the same way. On the FIRST start of this release (and only then: from 5.69.0-beta.12 the install remembers it in `jen.config` itself, so a server you later leave without a password is never filled in at a restart) Jen writes the password each such endpoint was using into its section as its own, marks it `<key>_shared = 1`, writes one audit row per endpoint (`CONFIG_MIGRATION`: "kea_server_N: the parent's api_pass materialised; it no longer follows the parent's") and one line in the log. Your peers and daemons are reached with the same password they were yesterday. What changes: a later change of the parent's password is no longer copied to them - each one's is its own from now on. Servers & HA shows "shared copy" beside such a password and offers **Copy the primary's again** when you want it to follow once more. One on the same host as its parent needs no copy and keeps following it.

**An endpoint on a different host needs its own password.** Kea6, D2 and the Kea6 database use the Kea API's (or Kea's database's) password only when they are on the same host as it - another port of that host is the same Kea. One on a different host with no password of its own is sent nothing with that password: the Health Center row "Every endpoint has a credential" and Tools → Doctor name it, and Settings → Kea is where you set its own. A Kea with no authentication takes the "No password" box on those forms (and on an additional-server row), which saves an explicit blank: nothing is withheld and nothing is sent. An absent password is "inherit, if the host is the same".

**A saved password does not follow an endpoint to a new host, and is not typed twice by accident.** Changing a host or address and leaving the password box empty is refused; so is saving the same password for two endpoints on different hosts unless you typed it in that save. The Kea API, Kea6, D2, additional-server, Kea database and Jen database forms, the setup wizard and the direct-socket pages all follow it.

**The setup wizard's DHCPv6 check asks for the password of a socket on a different host.** In direct mode the Found step probes the DHCPv6 socket you type with the Kea API's password only when it is on the same host; otherwise it shows a password field for it and sends nothing without one. The check and "Manage IPv6 in Jen" ask for your password again if it has been more than ten minutes, and enabling IPv6 saves the socket and the subnets together or not at all.

## The conversion marker moves into jen.config; a first address asks for the password; "No password" everywhere

One step (5.69.0-beta.12). It adds no migration and needs no action. What you may notice:

**`jen.config` gets a new section.** `[jen] credential_model = explicit` says every endpoint's password in the file is its own or deliberately absent. A new install is created with it; an existing install gets it on the first start of this release, in the same write as the copies of borrowed passwords (the copies now include the user the endpoint was sending), so the two exist together or not at all. An install that already converted under 5.69.0-beta.11 gets the key without a second round of copies. A file without the key is treated as one that has not been converted, whatever database it is used with: restoring an older `jen.config` converts it again, with its audit rows. If the file cannot be written, Jen logs one error naming it and tries again at the next start.

**A saved password that had no address asks to be typed when it is given one.** Changing an address and leaving the password box empty was already refused when the endpoint had an address before; it is now refused for an endpoint that had none (a Kea6 or D2 password saved with no address, then given its first one). Typing the password in the same save passes, a new additional server passes because its password is typed, and switching the connection mode between Control Agent and direct is not refused for the daemons whose address it only re-derives (the next section says what it still asks).

**"No password" wherever a password is.** The setup wizard's DHCPv6 step has a box for a control socket with no authentication and a username field for a socket on a different host; each additional-server row has a box beside its IPv6 password and, for a server with a D2 address, beside the D2 socket. A blank password still keeps the saved one; an endpoint on a different host needs its own password, or this box.

**The username follows the password.** A daemon on the same host as the Kea API uses its username unless it has its own; one on a different host uses it too when it has a password of its own, and has none when it has no password. Nothing is sent without a credential it may use: Health Center's "Every endpoint has a credential" names what is missing.

## No authentication sends no header; the marker's value; a probed pair is kept; the installer asks too

One step (5.69.0-beta.13). It adds no migration and needs no action. What you may notice:

**An endpoint with no authentication sends no header.** A Kea6, D2 or additional-server endpoint saved with "No password" used to send an empty Basic header carrying the Kea API's username when it was on the same host. It now sends no username and no Authorization header at all. A username you type beside "No password" is yours and is sent; a database keeps its username beside a blank password.

**The credential-model marker has two values.** `[jen] credential_model` is `explicit` when Jen wrote it. Any text that is not `explicit` (a typo, an empty value) is named by Tools → Doctor and by Health Center's "Every endpoint has a credential" row as `credential-model-invalid`: Jen converts nothing until you set it to `explicit` (every password in the file is its own) or remove the line (convert a legacy file). An install that converted under 5.69.0-beta.11 is marked converted only when its file has nothing left to convert; a restored older file with a passwordless peer on a different host is converted, with its audit rows.

**A socket set up by IP keeps the credentials it answered with.** On a server Jen reaches by name, setting up a DHCPv6 or D2 control socket by IP address used to leave that endpoint without a password, because the two spellings of the host are compared as written. The pair that answered the probe is now written as the endpoint's own. The form's default for the username and password is what Jen would send to that address: the server's own pair on the same spelling of the host, nothing on a different one, so type them. If Jen cannot write its own settings after the Kea host has changed, the socket is put back and the daemon restarted, with the reason shown. "Remove socket" for kea-dhcp4 is checked before anything is sent to the Kea host.

**The connection-mode switch asks more.** Switching between Control Agent and direct is not refused for a daemon whose address is the Control Agent's. A daemon you give an address of its own in the same save, or a Control Agent on a new host, asks for the daemon's password like any move.

**"Copy the primary's again" works on a copy only.** A server whose password is its own is told so; type a new one on its row to change it. A Kea6 database host written blank means no Kea6 database: Jen opens no connection to the machine it runs on, and Health names it.

**`install.sh --configure` asks the question Settings asks.** An answer that would send a saved password to a new host is refused, with the sentence, before anything is written. Give that endpoint a new password in the wizard or its answers file, or move it under Settings → Kea.

## Remove socket asks only what it can; a URL with a backslash is refused; shared copies are shown

One step (5.69.0-beta.14). It adds no migration and there is nothing for you to do. What you may notice:

**"Remove socket" no longer carries a password to a host it was not typed for.** The button has no password field, so it now types an endpoint only when that endpoint's saved password has already gone to the Kea box the button acts on. A Kea6 or D2 address that points at a different host, a primary that was moved to a different host after its socket was set up, or a daemon whose password has no address are refused before anything is sent to the Kea host, and the page says where to type the password (Settings → Kea) instead.

**Switching the connection mode asks about a password that had no address.** A daemon with a saved password and no address, given the Control Agent's address by the switch, is being given its first one and asks for the password like any first address. A daemon that had an address on the Control Agent's host is not asked again.

**A password value changes only when it is typed.** A write that copies a saved password into a different endpoint is refused. Every Settings form and the setup wizard already type what they save, so nothing you do changes.

**Shared copies are shown on every card.** The IPv6 and D2 passwords of an additional server, and the Kea6, D2 and Kea6-database passwords, say "shared copy" when they are a marked copy of the Kea API's or the server's password, and typing a password again makes it its own.

**A URL with a backslash or a control character is not an API address.** The Kea API, Kea6, D2 and additional-server address fields refuse it, because the two programs that read an address disagree about which host it names.

## Switching back asks for the Control Agent's password; a dot is a different name

One step (5.69.0-beta.15). It adds no migration and there is nothing for you to do. What you may notice:

**"Switch back to the Control Agent" has a password field.** It shows the address the Control Agent will be reached at, a user field, a password field, a "No password" box and, when Jen saved the Control Agent's own user and password while setting the socket up, a box to restore them. Jen does not guess which password belongs at which address: type the Control Agent's, tick No password, or tick the restore box. Pressing the button with none of them is refused, before anything is sent to the Kea host, when the Control Agent is at a different address from the socket.

**The Control Agent's own user and password are remembered at setup.** Setting up a kea-dhcp4 socket saves the primary's previous user and password beside its previous address; the switch-back can put them back. A socket set up by an earlier release has the address but no saved pair, so type the password the first time.

**A daemon that loses a credential is named.** If switching back changes the spelling of the primary's address, a Kea6 or D2 socket that inherited the primary's user and password on the same host has none afterwards; the message names it and says to type its password under Settings → Kea.

**A dot at the end of a host name is part of the name.** `kea-a.` and `kea-a` are two names for the purposes of deciding which saved password may go where. An address containing a no-break space, a zero-width character or any control character is refused, and so is a host name that is not plain ASCII letters, digits, dots, hyphens and underscores (internationalised names that survive unchanged are still accepted).

## "No password" means no user

One step (5.69.0-beta.16). It adds no migration and there is nothing for you to do. What you may notice:

**"No password" on the Remove forms now removes the user as well.** A socket you declare unauthenticated is reached with no credentials at all, instead of a header that carried the socket's username with an empty password. If a Kea6 or D2 socket was sending the Kea API's user because it had none of its own, it keeps sending that user and the message says so.

**A user typed beside "No password" or beside the restore box is refused.** Those two answers set the user themselves; choose one for the user, and nothing is sent to the Kea host.

**A same-host switch-back says what happened to the saved pair.** If the Control Agent is at the same address as the socket and you typed nothing, the saved user and password are discarded and the message says so and how to restore them next time.

**A restored password keeps its "shared copy" mark, and the Remove button appears for a Kea6 or D2 socket that is still configured while the connection mode is Control Agent.** An address in jen.config that ends in a no-break space or a control character is refused when it is read; the Settings forms trim the ends of what you type before they save it.

## A removal asks for the Control Agent address when none is saved

One step (5.69.0-beta.17). It adds no migration. What you may notice:

**"Switch back to the Control Agent" asks for the Control Agent's address when Jen has none saved.** If the address Jen remembered is missing, or is the socket's own, and no server besides this one keeps its own socket, the form shows an address field. Jen asks that address who it is before the socket is removed: it must answer as a Control Agent. Without an address the removal is refused and nothing is changed. A saved address is checked the same way before it is restored.

**A failed save after a socket change puts the daemon's sockets back as they were.** If Jen changes a Kea host's control socket and then cannot save its own settings, the daemon's whole list of control sockets is restored, including a socket the change had replaced, and the daemon is restarted. The message names a socket by type, address and port only, and says where its authentication settings are kept (Settings → Kea → Config History).

**A daemon with more than one http or https control socket is refused.** Jen manages one; remove the extras by hand first.

**Switching back restores what the Control Agent had, including nothing.** A user or password the Control Agent did not have is removed again, so a server that inherited the primary's password inherits it again.

## A failed probe puts the daemon's sockets and certificate back; an unproved recovery shows on Servers

One step (5.69.0-beta.18). It adds no migration and there is nothing for you to do. What you may notice:

**A failed probe puts the daemon's sockets and certificate back.** If "Set up direct socket" replaces a socket and the new one does not answer from the Jen host, the daemon's whole list of control sockets is put back as it was (and for https, the certificate it had), the daemon is restarted, and the message names the socket you had and the one that did not answer. A first socket is still left in place so you can fix the firewall and run it again; Servers and Health show it as waiting until a probe of it succeeds.

**An unproved recovery shows on Servers until it is acknowledged.** When Jen cannot prove it put a Kea host back (for example the earlier certificate was installed by hand, or a restart did not verify), a notice on Servers and a row in Health name the server and the service. It goes away when a later operation on that server probes the endpoint and gets its answer, or when a superadmin presses Acknowledge. Checking the daemon yourself first is what the notice is for.

**Jen keeps the server key it installs.** From the next https change on, the key Jen puts on a Kea host is also kept, private, beside the certificate copy on the Jen host (`kea-servers`), so a failed change can put the previous certificate back. A certificate installed before this release, or by hand, has no earlier copy: if a change to it fails the sockets come back and the notice says the certificate could not be.

**The Remove form always shows the Control Agent address field.** It says whether leaving it blank uses the saved address, and which; when Jen has none saved, a switch-back needs one. The address you type, or the saved one, is asked who it is before the socket is removed, and a switch-back is refused when a second server record names the very socket being removed.

## An https setup stops when Jen cannot keep its own copy; a recovery is undone only when the endpoint answered

One step (5.69.0-beta.19). It adds no migration and there is nothing for you to do. What you may notice:

**An https setup stops when Jen cannot keep its own copy of the certificate.** "Set up direct socket" for https now saves its own copy of the new certificate and of the one the host has before anything is installed on the Kea host. If Jen cannot write them (its SSL directory is full or read-only) the setup stops with the host untouched. If the host takes the new certificate and Jen then cannot make its copy live, the certificate the host had is installed again and the socket change never starts. A socket that is already in the daemon's config is only checked again; no new certificate is written under it. If the socket answers with a certificate that is not the one Jen holds, the setup says so, and the way to fix it is to remove the socket and set it up again.

**A CA rotation is all or nothing.** Rotate keeps the new CA beside the live one, pushes a certificate to each server, restarts it and checks it with the new CA, and only then makes the new CA live. Any failure puts every server it touched back on the CA Jen still trusts, restarts it and checks that it answers; the message lists which servers are back and which need you.

**A recovery is called undone only when the endpoint answered.** After a failed change Jen restores the sockets and the certificate, restarts the daemon, and then asks the address it uses for that daemon who it is, with the credentials and certificates it has saved. If that does not answer, Servers and Health show the server as unreachable after the recovery instead of saying the change was undone. A previous certificate that is back on the host but whose Jen-side copy could not be refreshed is shown the same way; remove the socket and set it up again once Jen's SSL directory is writable.

**Incidents on Servers do not get lost.** Two changes that fail at the same moment on two servers now both stay on the Servers page; the note that holds them is updated as one step. Eight kinds of notice exist; an http socket that answers does not clear a certificate notice, and neither does a run that left the certificate alone.

## A rotation refuses when Jen has no record of an https endpoint's certificate; a recovery record that cannot be read is set aside, never overwritten

One step (5.69.0-beta.20). It adds no migration and there is nothing for you to do. What you may notice:

**Rotate Kea CA lists the endpoints it will re-issue, and refuses when Jen has lost track of one.** The list is every https endpoint Jen dials, for each server and each of kea-dhcp4, kea-dhcp6 and the DDNS daemon, not the certificate files in Jen's `kea-servers` folder. If Jen has no complete record of the certificate for one of them (the copy or its key is missing, damaged, does not belong together, or was issued by an earlier Jen CA), or cannot read the folder, Rotate stops before it changes anything and names the server, the daemon and the address. Remove the direct socket and set it up again so Jen issues and keeps a certificate for it, then rotate. An endpoint whose certificate was issued by your own CA is named and left alone.

**Jen says "unknown" when it cannot be sure which certificate a host holds.** If a rollback puts the previous certificate back on a Kea host and Jen cannot write its own copy, the pair Jen records is the pair the host was given. If even that cannot be written, a notice on Servers says Jen cannot record which certificate the host holds, and Jen installs nothing on a guess until the SSL folder is writable and the socket is set up again.

**A recovery record that cannot be read is set aside by a superadmin.** If the stored note of unproved recoveries is damaged, Jen refuses to write a new note over it and Health shows the check as unknown. Servers then offers a superadmin "Set aside and clear": the damaged text is kept in a setting of its own, the note is cleared, and the audit row records its length. The same message appears if you press Acknowledge or Dismiss while the note is damaged.

**A cut connection while Jen reads a daemon's config is a message, not an error page.** Both direct-socket forms now stop with "Jen could not reach the host to read the config; nothing was changed". A new first socket that answers with a certificate Jen does not hold is reported as one problem with one fix: remove the socket and set it up again.

## Rotate decides who is on Jen's CA by certificate; a URL with a user name is refused

One step (5.69.0-beta.21). It adds no migration. What you may notice:

**Rotate Kea CA decides which endpoints depend on Jen's CA by looking at certificates, one endpoint at a time.** An endpoint Jen holds a certificate copy for is re-issued when Jen's CA issued that copy, and left alone (and named) when your own CA did. An endpoint Jen holds no copy for is judged by the CA bundle Jen verifies against, compared by certificate and not by file name: a bundle that holds only Jen's CA, or Jen's CA together with a different CA, or a file Jen cannot read, makes Rotate stop and say so before it changes anything. If you point Jen at a copy of its CA, or at a bundle that contains it, and Jen has issued certificates to https endpoints, Rotate stops and names the file: it cannot rewrite your copy, so Jen would no longer trust the endpoints it had just re-issued. Point the CA bundle under Settings → Kea at Jen's own CA file (`kea-ca.crt` in Jen's SSL folder) or at a link to it, then rotate. With no CA bundle and certificate checking switched off, Jen cannot tell whose endpoint an unrecorded socket is, and Rotate stops for the same reason.

**A Kea address with a user name or password in it is refused on save.** `https://user:password@host:8004` is rejected on every form and in the setup wizard; type the user and password in their own fields. If an address in `jen.config` already carries one, Jen keeps working with it exactly as before, logs one warning per setting at start (never the value), and Health's credential check names the endpoint and says to move the user name and password to their own fields. The Settings → Kea fields no longer show the user name or password inside an address, so saving that page with such an address removes it from the address: type the pair in the user and password fields first.

**Addresses in messages show only the scheme, host and port.** That includes the dashboard, Health and the Doctor page, which could print the full address a connection error named.

**A recovery record Jen cannot recognise is kept.** Servers now says when an entry of the stored recovery record is not an incident Jen wrote, and a successful change no longer deletes it. A superadmin can set the record aside from the same page, as before.

## A client certificate that is a copy of Jen's own is refused; a user name in a URL was never sent

One step (5.69.0-beta.22). It adds no migration and there is nothing for you to do. What you may notice:

**Rotate Kea CA and the https setup look at the client certificate Jen presents, as well as the CA bundle.** If the client certificate and key under Settings → Kea are a copy of Jen's own pair (a file at a different path with the same certificate, or one Jen's CA issued), or are a pair Jen's CA did not issue, or cannot be loaded as a pair, and Jen has issued a certificate to an https endpoint, Rotate stops before it changes anything and names the file: after a rotation the copy would no longer be the certificate the daemons accept. The https setup stops for the same reasons. Point the client certificate and key at Jen's own files (`jen-kea-client.pem` and `jen-kea-client.key` in Jen's SSL folder), at a link to them, or clear the fields. The Settings → Kea form refuses a copy of Jen's pair when you save it; your own certificate authority's pair is still accepted there.

**A user name or password written inside a Kea API URL was never sent.** Jen has always sent the user and password fields, and the HTTP library ignores a user name in the address whenever those are given. Saving Settings → Kea with an address that carries one therefore removes text that never authenticated, and nothing about how Jen authenticates changes. Messages that name an address show only its scheme, host and port. The DNS provider's address is the one place where a user name in the URL was sent: its lookups carry no separate pair, so a provider behind a proxy that asked for one will refuse them after a save removes it, and the save says so.

**Settings → Kea shows the DNS provider's address without a user name or password,** and the installer's configure step prints a warning naming the section and key of any Kea or DNS address that still carries one.

## A rotation proves the new client certificate first; a damaged CA refuses https setup and is replaced only by an acknowledged Rotate

One step (5.69.0-beta.23). It adds no migration and there is nothing for you to do. What you may notice:

**Rotate Kea CA refuses when an endpoint depends on Jen's current client certificate.** Before it installs anything, Rotate tries the current and the new client certificate against every https endpoint Jen does not manage. If one accepts the current certificate and refuses the new one, its trust anchor for client certificates is Jen's current CA, and Rotate stops and names it. Use the new "Prepare only" button on Settings → Kea first: it writes the new CA beside the current one without changing any server and shows its fingerprint and path. Add that certificate to the endpoint's trust anchor beside the current one, then rotate; the rotation reuses the prepared CA. "Discard prepared CA" removes it. An endpoint that does not answer Jen's current certificate at all also stops the rotation, because Jen cannot tell whether it depends on it.

**A damaged CA refuses https setup and is replaced only by an acknowledged Rotate.** If `kea-ca.crt` or `kea-ca.key` is missing, unreadable, damaged, or the two do not belong together, or the CA's files are gone while Jen's client certificate or its server copies remain, Health fails and names the damage, an https setup is refused before anything is changed on a Kea host, and Jen's files are left exactly as they are (nothing creates a new CA under your existing sockets). Restore the files from a backup, or use "Replace the damaged CA" on Settings → Kea. That asks you to confirm that the current CA cannot sign, so a server that fails part-way cannot be put back and would need its socket set up again.

**A client pair whose key is not the certificate's is re-issued.** Health now checks that Jen's client certificate and key belong together, were issued by the current CA, carry the client-authentication usage and are inside their validity. A damaged pair shows as a failure; setting up an https socket re-issues it from the same CA, so every daemon that trusts the CA keeps trusting it, and says so. The pair it replaced is kept beside it as `.prev`.

**A rotation also refuses, before it touches any host, when one of Jen's own CA or client files, or its previous-copy name, is a directory or a link.** Remove or replace the item named in the message.

## A failed CA replacement is repeated with the acknowledgement; Prepare works while the CA is damaged

One step (5.69.0-beta.24). It adds no migration and there is nothing for you to do. What you may notice:

**A replacement of a damaged CA that stops part-way says what happened.** If "Replace the damaged CA" stops (a server refuses the new certificate, does not restart, or does not answer), the message counts the daemons left in a state that needs it repeated and names each: a daemon that took the new CA's certificate and will not answer Jen until the replacement is repeated, a daemon whose host refused the certificate (what it holds is unknown, usually unchanged), and the daemons nothing reached. Each daemon left behind is recorded on Servers. Jen's CA is still damaged, so the action is to run "Replace the damaged CA" again with the acknowledgement ticked; an https setup stays refused until the CA is replaced. The message no longer tells you to restore `.prev` copies or to set each socket up again.

**"Prepare only" works while the CA is damaged.** It writes a new CA beside the damaged one and changes nothing on any server, so a daemon that depends on Jen's CA can have its trust anchor updated first. It refuses only when there is no CA at all, and then points you to the https setup, which creates one.

**Replacing a damaged CA checks that Jen can write its certificate folder.** A folder Jen can neither read nor write now stops the replacement before any server is touched; it used to stop after the first server had taken its new certificate. A folder Jen cannot list but can write is still accepted.

**Every message about a damaged CA names the same two actions:** restore the CA files from a backup, or replace the CA with the acknowledgement ticked. Where Jen cannot tell whose CA an https endpoint is on while its own CA is damaged, the message says to point the CA bundle under Settings → Kea at Jen's own CA file, `kea-ca.crt` in Jen's SSL folder.

## A CA that cannot sign is damaged, not replaced; a rotation proves it can keep its certificate records

One step (5.69.0-beta.25). It adds no migration and there is nothing for you to do. What you may notice:

**A CA that is not a certificate-signing authority is damaged.** Jen now checks the CA at `kea-ca.crt` and `kea-ca.key` for what it is for, not only that the two files load and belong together. It must be marked as a CA, must be allowed to sign certificates if it carries a key-usage restriction, must be inside its validity dates, must be self-signed with a signature Jen can verify, and must use an EC or RSA key. A CA that fails any of these - expired, not yet valid, not marked as a CA, a key usage without certificate signing - is treated like a missing file: Health fails and names the check, an https setup is refused before anything is changed, and the files are left exactly as they are (nothing creates a new CA under your existing sockets). Restore the CA files from a backup, or use "Replace the damaged CA" with the acknowledgement. An expired CA used to show Health's expiry row with a normal Rotate; it now needs that acknowledged replacement, because it can no longer sign. A CA you made yourself with `openssl req -x509` and placed at Jen's paths is accepted when it carries no key-usage extension at all (that means unrestricted); one signed with SHA-1 is reported as a self-signature Jen cannot verify.

**A prepared CA that cannot sign is never used.** "Prepare only" and Rotate judge the prepared CA by the same checks. One that fails is discarded with the reason and the rotation continues with a fresh CA, so it never reaches a Kea host.

**Rotate and the https setup prove that Jen can keep its certificate records before they change anything.** Jen creates its certificate folder if it is missing and writes and removes a small test file in it. If it cannot (a read-only SSL folder, a full or unavailable disk), Rotate, including the replacement of a damaged CA, and the https setup stop before any server is touched and name the problem. A refusal leaves no folder behind. Rotate checks once more immediately before it changes the first server.

## A recovery beside a daemon that trusts the damaged CA: Prepare, install, rotate again

One step (5.69.0-beta.26). It adds no migration and there is nothing for you to do. What you may notice:

**Replacing a damaged CA no longer stops at a daemon that cannot answer the old certificate.** When Jen's CA is damaged because it expired, is not marked as a CA, or is not valid yet, a Kea control socket that Jen does not manage and that trusts that CA for client certificates turns Jen's current client certificate away, because the CA can no longer vouch for it. Before, "Replace the damaged CA" stopped there with "it has to answer before a rotation can be proved safe" and no way forward. Now Jen tries the new client certificate on that socket as well. If the socket accepts it, the replacement goes on. If it does not accept it yet, the message says so and names the steps: use "Prepare only", install the prepared CA certificate in that daemon's trust anchor for client certificates (beside the old one), then replace the damaged CA again with the acknowledgement. A daemon that cannot be reached, or whose own certificate Jen cannot verify, keeps its earlier message, and a normal rotation behaves as before.

**A rotation that fails because Jen's CA became unusable says what the CA is now.** If the CA stops being usable while a rotation is running and no replacement step was attempted, the message names the damage and says to replace the CA with the acknowledgement (or restore the files from a backup), instead of describing a step that did not happen. The message about a daemon that could not be put back names the same action.

**A file you keep in the certificate folder is left alone.** Jen's test file there is the one named `.write-probe-<number>-<16 hex digits>`, and a leftover is removed only when it is over a minute old. A file of yours with a similar name, such as `.write-probe-notes`, is never removed.

## A CA a real verifier rejects is damaged; two records for one daemon refuse a rotation

One step (5.69.0-beta.27). It adds no migration and there is nothing for you to do. What you may notice:

**Jen now asks a real certificate verifier whether the CA works.** Besides the earlier checks, Jen issues a throwaway server certificate and a throwaway client certificate from the CA, in memory, and verifies each with the same chain verification a TLS peer performs. A CA that fails either - for example one whose Extended Key Usage leaves out `serverAuth` or `clientAuth` - is shown as damaged: Health fails and prints the verifier's own reason, an https setup is refused before anything is sent to a host, and the files are left alone. A CA with no Key Usage extension, or whose Basic Constraints or Extended Key Usage is not marked critical, is accepted. A CA that is name-constrained away from one Kea host's address is refused when Jen issues that host's certificate, before anything is installed, and the message names the address. Where `openssl` is installed, Health also runs `openssl verify` on the same throwaway certificates and reports a disagreement; that never blocks anything. Jen's verifier is stricter than OpenSSL for a DNS name constraint written with a leading dot, for a directory-name constraint, and for a key that is not P-256, P-384, P-521 or RSA of 2048 bits or more; the admin guide lists them.

**Two server records for one daemon refuse a rotation.** If two Kea server records share one SSH host and one service, Rotate stops before anything changes and names both; remove one, or point it at its own host. The dhcp4 and dhcp6 daemons on one host are two daemons and stay separate. After the last server is changed, Rotate checks every server once more with the new certificates before it replaces the CA, and rolls back if one no longer answers.

## The daemon's own library judges your CA; a CA that cannot issue for an address is healthy and told so; stale certificate records can be forgotten

One step (5.69.0-beta.28). It adds no migration and there is nothing for you to do. What you may notice:

**Where `openssl` is installed on the Jen host, it judges the Kea CA at the gate.** Jen already asked a certificate verifier whether the CA works; it now also runs `openssl verify -purpose sslserver` and `-purpose sslclient` on the same throwaway certificates, because `openssl` is what the Kea daemon itself uses. A CA it rejects is shown as damaged, with its own line as the reason. If `openssl` is missing, broken or slow, it gives no opinion and Jen's own verifier decides, as before. Two CA shapes that Jen used to call healthy while the daemon rejected every certificate issued from them are damaged now: an Extended Key Usage that is `anyExtendedKeyUsage` alone, and a self-issued CA whose Authority Key Identifier names a key that is not its own. A CA you placed at Jen's paths that was working is not affected unless it has one of those shapes. The admin guide lists the shapes Jen's verifier is stricter about than `openssl`.

**A CA that cannot issue for one address is healthy, and the setup says so.** If the CA's name constraints do not permit the address or host name of a Kea server, the https setup now says "Jen's CA is healthy, but it cannot issue a certificate the verifier accepts for ...", names the address that failed (the bind address, or the SSH host's name), changes nothing on the host and does not ask for the damaged-CA acknowledgement. Change the address, or replace the CA with Rotate Kea CA. A host name that a certificate cannot carry (an underscore, a trailing dot) is refused when you save an https address in direct mode.

**Stale certificate records can be forgotten.** A certificate Jen kept for a socket that is no longer https is a record of nothing. The Kea mTLS row in Health no longer counts it as a valid or an expiring certificate; it says "stale record for ..." and what to do. Removing the socket now drops its record, and a superadmin can press **Forget stale records** on the Kea CA card (a local change that asks no host anything).

**An https setup on a second record for one daemon is refused.** If a second server record has the same SSH host and already holds a Jen-issued certificate for the same service, the setup stops before anything changes and names it. The dhcp4 and dhcp6 daemons on one host are two daemons.

Small things: a rotation prepared with **Prepare only** no longer leaves a `.prev` copy of the new key beside it; folders Jen creates under its SSL folder are private (0700); and the Kea CA card says "expiry unreadable" instead of "None day(s)" when a certificate's expiry cannot be read.
