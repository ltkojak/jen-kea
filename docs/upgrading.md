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

## 7.2.0-beta.1: your own navigation, and a sign-in page that was open too long

One step (7.2.0-beta.1). It adds one migration (40, a new table `user_nav`; it runs by itself and touches no existing row) and no helper build. Nothing to do.

**Favorites in the top row.** Each person can keep up to five pages after About in the top row. The button at the right end of a section's tabs, **Add to top row**, adds the page you are on; **Customize navigation** in your account menu edits the list. The five fixed items stay where they are.

**The phone's bottom bar is yours to choose.** On the same page, pick up to four pages for the bar; More stays the last button. Until you choose, the bar is the one it was.

**These choices are per account.** They are stored in Jen's database, follow you to every browser, and are in a Jen database export and backup (table `user_nav`). A favorite never gives access: a page your role or subnet access does not allow is not shown.

**Signing in from a page that was open for hours** no longer ends on a 403 page with no form. The sign-in page comes back with one sentence, "This sign-in page was open too long. Sign in again.", your username kept, and signing in from it works. The sign-in page also tells the browser not to keep a copy of it, so a restored tab or the back button asks for a fresh one.
