# Upgrading from 7.2.0

Everything below changed since v7.2.0 — the last stable release before
this one — that you'd actually notice or need to know about when you
upgrade. Run `sudo ./install.sh` on the new tarball (or use the in-app
updater) the normal way; nothing here needs a manual step beyond what's
called out explicitly. See `docs/runbooks.md` for step-by-step
procedures, and `CHANGELOG.md` if you want the full detail behind any
item below. The previous page, covering everything since 7.1.0 through
the 7.2.0 baseline, is archived at
[`docs/release-history/upgrading-7.1.0-to-7.2.0.md`](release-history/upgrading-7.1.0-to-7.2.0.md).

## 7.2.1: a log output change is proven by a line Jen asks for, a lost commit is never a rollback, and the fixes registered at 7.2.0

One step (7.2.1). It adds no migration, no helper build and no sudoers line, and there is nothing for you to do. What you may notice:

**A line from Jen in Kea's log after you change where Kea writes it.** Settings → Kea → Kea logging now proves a change by asking the running kea-dhcp4 to write one line that carries a value made for that change. At severity INFO or DEBUG the line is `COMMAND_RECEIVED Received command 'jen-log-proof-...'`. At WARN or ERROR it is one ERROR line, `DHCP4_PARSER_FAIL ... jen-log-proof-...`, from a configuration test that Kea refuses and does not apply. If you alert on ERROR lines in Kea's log, expect one for each such change.

**At severity FATAL or NONE a change to a file that already exists is put back** unless the logger already named that file and the change takes no output away. Kea writes nothing Jen can ask for at those levels. Choose a file name that does not exist yet, or set the severity to ERROR or lower first.

**The SSH card saves again** on a box whose stored Kea log path is outside `/var/log` while the page hides that field. The stored value is left as it was; correct it in the field when the page shows it, or under `[kea]` in `jen.config`.

**Linking a restricted account to single sign-on** now tells you, before and after, that the identity provider sets its subnets from the next sign-in: the subnets its groups map to, and every subnet when no Subnet Mapping is set. Set the mapping first if the account must stay restricted.

**Migrate, import and restore say what is known.** A migration whose commit was not confirmed says the outcome is not known and no longer says the target was rolled back; look at the target before you migrate again. Every failed migration is in the audit log as `DB_MIGRATE_FAILED`. An import in which one part failed is `DB_IMPORT_FAILED`. After a failed Replace, a snapshot that could be put back only in part is reported as not put back and is kept.

**The support bundle** masks the query values and the fragment of every address, also inside a sentence.

**If a script reads Jen's output:** seven `fix_hint` texts in Health's JSON are sentences now; the `SAVE_INFRA` audit detail may end `log_path=kept`; the `LINK_SSO` detail is longer for a restricted account; the sentences of a log output change that was put back begin "Kea accepted the change on ... but Jen could not prove that it writes to ...".
