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
