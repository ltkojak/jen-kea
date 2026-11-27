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

## 7.2.2: the Kea logging card on a busy server, and with logger entries of their own

One step (7.2.2). It adds no migration, no helper build and no sudoers line, and there is nothing for you to do. What you may notice:

**A change of where Kea writes its log works again on a busy server.** In 7.2.1 a server that wrote more than about 150 log lines a second had every change to a file put back. Jen now looks for the line it asked for in the last 1000 lines of the file, not the last 60.

**A logger entry of its own for `kea-dhcp4.commands` or `kea-dhcp4.dhcp4`** no longer gets a working change put back. When the configuration has an entry for the commands logger, the line Jen asks for at INFO and DEBUG is one ERROR line, `DHCP4_PARSER_FAIL ... jen-log-proof-...`, from a configuration test Kea refuses and does not apply. It is the check, and nothing is wrong. When both loggers have entries, choose a file name that does not exist yet: Kea creates it, and that is the proof.

**The message of a change that was put back** now tells a daemon that did not answer from a line that was not found, and says how much of the file Jen read.

**If a script reads Jen's output:** the second sentence of a log output change that was put back reads "... and did not find that line in the last 1000 lines of the file, on any of 5 reads. ..." or "... and kea-dhcp4 did not answer on any of 5 tries, so nothing could be proven. ..."; the `KEA_LOG_OUTPUT` audit detail may end "(proven by the file Kea created: a logger entry of its own)" or "(not checked: a logger entry of its own)".

## 7.2.1: a log output change is proven by a line Jen asks for, a lost commit is never a rollback, and the fixes registered at 7.2.0

One step (7.2.1). It adds no migration, no helper build and no sudoers line, and there is nothing for you to do. What you may notice:

**A line from Jen in Kea's log after you change where Kea writes it.** Settings → Kea → Kea logging now proves a change by asking the running kea-dhcp4 to write one line that carries a value made for that change. At severity INFO or DEBUG the line is `COMMAND_RECEIVED Received command 'jen-log-proof-...'`. At WARN or ERROR it is one ERROR line, `DHCP4_PARSER_FAIL ... jen-log-proof-...`, from a configuration test that Kea refuses and does not apply. If you alert on ERROR lines in Kea's log, expect one for each such change.

**At severity FATAL or NONE a change to a file that already exists is put back** unless the logger already named that file and the change takes no output away. Kea writes nothing Jen can ask for at those levels. Choose a file name that does not exist yet, or set the severity to ERROR or lower first.

**The SSH card saves again** on a box whose stored Kea log path is outside `/var/log` while the page hides that field. The stored value is left as it was; correct it in the field when the page shows it, or under `[kea]` in `jen.config`.

**Linking a restricted account to single sign-on** now tells you, before and after, that the identity provider sets its subnets from the next sign-in: the subnets its groups map to, and every subnet when no Subnet Mapping is set. Set the mapping first if the account must stay restricted.

**Migrate, import and restore say what is known.** A migration whose commit was not confirmed says the outcome is not known and no longer says the target was rolled back; look at the target before you migrate again. Every failed migration is in the audit log as `DB_MIGRATE_FAILED`. An import in which one part failed is `DB_IMPORT_FAILED`. After a failed Replace, a snapshot that could be put back only in part is reported as not put back and is kept.

**The support bundle** masks the query values and the fragment of every address, also inside a sentence.

**If a script reads Jen's output:** seven `fix_hint` texts in Health's JSON are sentences now; the `SAVE_INFRA` audit detail may end `log_path=kept`; the `LINK_SSO` detail is longer for a restricted account; the sentences of a log output change that was put back begin "Kea accepted the change on ... but Jen could not prove that it writes to ...".
