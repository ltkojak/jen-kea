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
