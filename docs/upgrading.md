# Upgrading from 7.1.0

Everything below changed since v7.1.0 — the last stable release before
this one — that you'd actually notice or need to know about when you
upgrade. Run `sudo ./install.sh` on the new tarball (or use the in-app
updater) the normal way; nothing here needs a manual step beyond what's
called out explicitly. See `docs/runbooks.md` for step-by-step
procedures, and `CHANGELOG.md` if you want the full detail behind any
item below. The previous page, covering everything since 7.0.0 through
the 7.1.0 baseline, is archived at
[`docs/release-history/upgrading-7.0.0-to-7.1.0.md`](release-history/upgrading-7.0.0-to-7.1.0.md).

## 7.2.0-beta.7: Kea logging from Jen, Edit Subnet without timers, and the fixes of the pass on 7.2.0-beta.6

One step (7.2.0-beta.7). No migration, no helper build and no new setting. Nothing to do; these behave differently and are worth knowing.

**Kea logging.** Settings → Kea has a new card, Kea logging. Nothing changes until you save it. If Health says the Problems inbox sweep cannot read Kea's log, open the card and choose "A file Jen can read" or "The system journal and a file": Kea then writes `/var/log/kea/kea-dhcp4.log` itself and rotates it at the size you set. Jen checks that Kea really writes to the file and puts the previous logging back when it does not. To go back, choose "The system journal (Kea's default)". On a server in File over SSH mode the change restarts Kea, as every change there does; in Live API mode Kea applies it at once. The card is refused while investigation logging is on for that server. The audit log records a change as `KEA_LOG_OUTPUT`.

**Words a script may match.** A refusal names the page's fixed address only: "Superadmin access required for /database/backup/download." where 7.2.0-beta.6 printed the whole path asked for. The HA action's refusal reads the same way. The sweep row of Health's JSON says "choose a file under Settings → Kea → Kea logging" and its `fix_url` is `/settings/kea#kea-logging`.

**Health's JSON for a viewer or an admin.** `fix_url`, `fix_hint`, `link` and `link_label` are empty for a row whose page the signed-in role may not open. A superadmin's rows are unchanged.

**Reserved.** A lease is marked Reserved, and counted, when a reservation with an IPv4 subnet exists for its hardware address (a global reservation included). A DHCPv6-only reservation for the same address no longer marks it.

**Users.** A form post to Edit User with no `role` field keeps the account's role (it was read as Viewer). An account whose stored subnet list cannot be read is shown with no subnets.

**The top row.** On a wide monitor the top row and the section tabs are in the same place on every page; on the four list pages only the table under them is wider. In a narrow window with many favorites, the favorites at the right end leave the top row when it does not fit; each is still in the menu it came from.

**Presence 1.2.10.** A device whose own probe could not be sent is not counted as missed on that pass. A log line says how many addresses could not be asked.

**IPAM Lite 1.8.6.** A long host or device name on a subnet's page is cut to its cell, with the whole name in a tooltip; a device's maker is on the same line as its name.

## 7.2.0-beta.6: the look over every page, seven plugin updates, and an API key or account that is never wider than the boxes ticked

One step (7.2.0-beta.6). No migration, no helper build and no new setting. Nothing to do; these behave differently and are worth knowing.

**API keys and accounts: the subnet boxes.** An unrestricted API key is created only when All Subnets is ticked and no subnet is. With nothing ticked, or with All Subnets ticked beside a subnet, the form is refused with a sentence and no key is created; before this release nothing ticked made an unrestricted key. Add User and Edit User follow the same rule, and their subnet lists are checkboxes now. A script that posts either form with no `subnet_ids` field and expected an unrestricted key or account has to send `subnet_ids=all`. This corrects the note under 7.2.0-beta.5 below ("A key is created with the access it always was"): with the page's script not running, a subnet ticked beside All Subnets made an unrestricted key. A key or an account that exists is not changed by the upgrade: look over API Keys and Users for one that is wider than you meant. An alert channel's subnet list is unchanged: nothing selected there still means every subnet.

**Words a script may match.** A refusal names the page: "Admin access required for /settings/kea." where it was "Admin access required.". The role is written Superadmin. The audit log's details say "signed in" and "signed out" where they said "logged in" and "logged out"; the action names `LOGIN` and `LOGOUT` are unchanged, and rows already written keep their words. The Health JSON answers gain two fields per check, `link` and `link_label`.

**Where things moved.** About is in the Account menu on every window width. The palette button's menu is named Display; its times section reads Display Times with Local Browser Time and UTC Time, the install's default theme is listed once as "(default)", and a Table Rows section offers Compact. Subnets is a list of rows that open in place; Expand All opens every row. The pages of a Settings group are tabs on every page of the group. The Devices setting "stale after N days" sits beside the filter bar. Settings, System lists plugins by name with a link to the Plugin Manager, which holds the descriptions. A page that does not exist is answered inside Jen with its navigation, still with status 404.

**Dashboard and Health.** The dashboard shows a Needs attention card when a Kea server is down, a Health check fails or a pool is near its end; the card asks Health when the dashboard opens and every five minutes after. Health lists failures and warnings first and folds the checks that do not apply behind one line. Getting Started no longer ticks a step whose check Health shows as a warning.

**Colors.** Muted text is lighter in Dark and darker in Light and Retro; the warning color of Phosphor and of Ember is no longer the accent color; a button's text is black or white by what reads on its color. A custom palette keeps the colors you chose; the text on its main button is chosen the same way.

**Alert email.** The plain-text part and the subject show what was typed (`Lab & <one>`) where they showed `Lab &amp; &lt;one&gt;`. A mail filter written against the escaped form has to be changed.

**Docker.** The image installs `iproute2`. Rebuild or pull the image for Wake & Actions to tell whether Jen is in a wake's subnet: on an image built before this release Wake & Actions 1.2.1 gives no warning on Docker's default network, where 1.2.0's warning was true. See "Wake-on-LAN" in `docs/docker.md`.

**Presence 1.2.9.** On a pass where the probe could not be sent, or the Jen host's neighbor table could not be read after it, no device is counted as missed. While the probe cannot be sent at all, the neighbor pass calls no device offline. Sinks are called destinations, under Publish To.

**Wake & Actions 1.2.1.** On a host with no `ip` command a wake no longer carries the warning that Jen has no address in the subnet; the audit detail says `on_link=unknown`. A wake for a subnet Jen is not configured for answers "Wake packet sent on Jen's own network only". Favorites are called saved hosts on the page; the routes and the audit actions of 1.2.0 are unchanged. A search of the audit log: rows written before 1.2.0 keep the old action names, so `WOL_` finds both and `FAVORITE` finds only rows written since.

**IPAM Lite 1.8.5.** On an unmanaged subnet a save is refused with "Could not read IPAM's own entries" when that table cannot be read (1.8.4 did so on a Kea subnet only). Eight buttons are renamed to say what they do.

**DNS Sync 1.1.6.** What it writes records to is called a DNS server. The default text of the sync-failed alert changes to "DNS Sync: the sync to DNS server name (kind) failed: error"; a template you edited is kept. Route paths, table names and audit action names are unchanged.

**Network Discovery 1.3.7, Host Watchdog 1.1.5, Switch Port Locator 1.1.6.** The page only: a Getting started card where a table was empty, and Scan Now and View Results in each Network Discovery card's header.

## 7.2.0-beta.5: Presence and Wake in the desktop navigation, four plugin updates and page fixes

One step (7.2.0-beta.5). No migration and no helper build. Nothing to do; these behave differently and are worth knowing.

**Navigation.** Presence and Wake are now tabs of the Management section, on a desktop and in the phone's More menu (they were under Plugins there). The button that adds the page being shown to the top row stays in view on a window narrower than the section's tabs.

**Wake & Actions 1.2.0.** A wake aimed at a subnet the Jen host has no address in now answers with a warning that the packet arrives only if a router forwards directed broadcasts; the packet is sent as before. Under Docker's default network a wake does not reach the LAN: see "Wake-on-LAN" in `docs/docker.md`. A script that reads the Audit log: the actions `WOL_ADD_FAVOURITE` and `WOL_DELETE_FAVOURITE` are written as `WOL_ADD_FAVORITE` and `WOL_DELETE_FAVORITE` from this release on (rows already written keep the old name), and the detail of `WOL_SENT` is now `via=... subnet_id=... on_link=...`. The API's answer to a wake gains `on_link` and `targets`, and answers 503 when the saved wake settings could not be read.

**Presence 1.2.8.** While Kea's lease database cannot be read, no tracked device is counted as missed, so none is published offline for that reason; a device that left in that time is called offline once the leases can be read again.

**IPAM Lite 1.8.4.** A conflict alert is now delivered on Telegram and Pushover whatever the device's hostname or the subnet's name contains. When IPAM's own table cannot be read, the subnet page says so and shows no Next free button.

**Network Discovery 1.3.6.** A scan that cannot read Jen's devices or the Jen host's neighbor table ends as an error before nmap runs.

**Health.** The check "DEBUG logging left on" is titled "No DEBUG logging left on". Its id in the JSON answer, `debug_logging_left_on`, is unchanged.

**API keys.** Subnet access is a list of checkboxes. A key is created with the access it always was while the page's script runs; without it a subnet ticked beside All Subnets made an unrestricted key, which 7.2.0-beta.6 refuses (see above).

## 7.2.0-beta.4: five plugin updates

One step (7.2.0-beta.4). No migration and no helper build. Nothing to do; five things behave differently and are worth knowing.

**Host Watchdog 1.1.4.** A target on the 5-minute interval is now checked on every tick; before, a host that did not answer was checked every ten minutes and called down after twenty. A probe that could not be made (no `ping` on the Jen host, or `ping` reporting an error of its own) shows *could not probe* under the target and is no longer counted as a failure. If the Jen host itself loses its route to a target's network, that target shows *could not probe* and is not announced as down.

**Network Discovery 1.3.5.** A scan that cannot read Kea's leases, Kea's configuration, the known-hosts list, IPAM Lite, Jen's devices or the neighbor table now ends as an error that names what it could not read, and sends no Rogue Device alert. Before, such a scan stored leased hosts, the gateway or known hosts as unknown and alerted for them. While Kea's API does not answer, scans end in that error. A host you marked known before its MAC was visible now shows as known on every page.

**IPAM Lite 1.8.3.** When Kea's leases cannot be read, a save, a range action and an import are refused with one sentence, the JSON API answers 503 and the subnet page shows a notice and no Next free button; before, an address a lease held could be handed out or marked static. The conflict check no longer announces every standing conflict again after one run with the Kea database away. A link to an address in a collapsed run opens 256 addresses around it; the rest stays collapsed and opens 256 at a time.

**Presence 1.2.7.** Only if more than 64 tracked devices on the Jen host's own networks are unseen at once: every unseen device is now asked in turn, 64 a pass. Before, the same 64 were asked every pass and the others were published offline. A device that has left is called offline later when many devices are unseen at once.

**DNS Sync 1.1.5.** Preview shows the address of each record it will remove, and lists an AdGuard Home rewrite that is switched off on the server on its own. Also worth knowing since 1.1.4: after a restore of Jen's database from an older backup, records Jen made since that backup stay on the DNS server for good. Compare Preview's "Already on the server, left alone" with the server and remove what is stale.

## 7.2.0-beta.3: a restore of the accounts keeps API keys and sign-in factors, and two plugin fixes

One step (7.2.0-beta.3). No migration and no helper build.

**If you ran a replace restore of `users` on 7.2.0-beta.2** from a file that does not carry the tables that hang on the accounts (an export made with only `users` ticked is one), that restore deleted every API key, MFA method, backup code, trusted device and passkey. This release does not bring them back. Check Settings → API keys, and have each person look at their MFA; the page of that restore listed what it removed.

**Databases → Import, replace mode.** When a restore replaces the accounts from a file that lacks one of those tables, the rows of every account that is the same before and after are now kept. An account is the same when its id has the username it had. For an account that is gone, or an id that now has a different username, the MFA methods, passkeys, saved searches, dashboard and navigation choices are removed with it, and an API key it created is kept. The page says which tables changed and by how many rows. Merge mode changes nothing.

**DNS Sync 1.1.4.** A record that is already on your DNS server with the name and address Jen wants, and that Jen did not create, is left alone and listed in Preview under "Already on the server, left alone". Before, Jen could take such a record into its ledger and delete it later (AdGuard Home), or report an error on every sync (Pi-hole).

**Presence 1.2.6.** For a tracked device on a network the Jen host is on, Jen now sends one small UDP datagram to the device (port 9) when its five-minute check did not see it, and reads the answer nine seconds later. Before, a phone at home could be published offline after fifteen minutes and stay that way. If you filter traffic leaving the Jen host, this is new traffic to the devices you track.

## 7.2.0-beta.2: fixes to the navigation of beta.1, to restores and to the support bundle

One step (7.2.0-beta.2). No migration and no helper build. Nothing to do.

**A favorite in the top row** is drawn like the items beside it: muted until it is the page you are on or the pointer is over it.

**Customize navigation** offers Reset to default whenever anything is saved, and says how many saved pages cannot be shown now (a plugin that is off, a page your account no longer opens). Those pages come back with the plugin; Reset removes them.

**Databases → Import, replace mode.** When a restore replaces the accounts from a file that does not carry one of the tables that hang on them (an export made before 7.2.0 has no saved navigation), that table is emptied and the page says how many rows were removed. Before, each saved navigation stayed on its user id and was shown to whoever held that id after the restore. Merge mode removes nothing.

**A restore whose plugin commit was not confirmed** now goes on to the plugins after it, and the audit log records `DB_IMPORT_FAILED` for it. A Kea data migration that fails and cannot remove what it copied says so; it used to say the target was rolled back.

**The support bundle** masks the query values and the fragment of an address, as Config history does. Before, `api_url = https://host:8000/?token=...` kept its token in the bundle. If you sent a bundle from a box whose `jen.config` or Kea addresses carry a secret in a query string, treat that secret as shared.

**For plugin authors:** `jen.plugin_api.safe_text(value)` escapes one value before it goes into an alert.

## 7.2.0-beta.1: your own navigation, and a sign-in page that was open too long

One step (7.2.0-beta.1). It adds one migration (40, a new table `user_nav`; it runs by itself and touches no existing row) and no helper build. Nothing to do.

**Favorites in the top row.** Each person can keep up to five pages after About in the top row. The button at the right end of a section's tabs, **Add to top row**, adds the page you are on; **Customize navigation** in your account menu edits the list. The five fixed items stay where they are.

**The phone's bottom bar is yours to choose.** On the same page, pick up to four pages for the bar; More stays the last button. Until you choose, the bar is the one it was.

**These choices are per account.** They are stored in Jen's database, follow you to every browser, and are in a Jen database export and backup (table `user_nav`). A favorite never gives access: a page your role or subnet access does not allow is not shown.

**Signing in from a page that was open for hours** no longer ends on a 403 page with no form. The sign-in page comes back with one sentence, "This sign-in page was open too long. Sign in again.", your username kept, and signing in from it works. The sign-in page also tells the browser not to keep a copy of it, so a restored tab or the back button asks for a fresh one.
