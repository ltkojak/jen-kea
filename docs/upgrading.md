# Upgrading from 7.0.0

Everything below changed since v7.0.0 — the last stable release before
this one — that you'd actually notice or need to know about when you
upgrade. Run `sudo ./install.sh` on the new tarball (or use the in-app
updater) the normal way; nothing here needs a manual step beyond what's
called out explicitly. See `docs/runbooks.md` for step-by-step
procedures, and `CHANGELOG.md` if you want the full detail behind any
item below. The previous page, covering everything since 5.70.0 through
the 7.0.0 baseline, is archived at
[`docs/release-history/upgrading-5.70.0-to-7.0.0.md`](release-history/upgrading-5.70.0-to-7.0.0.md).

## 7.1.0-beta.11: an upload leaves no private key beside the certificate

One step (7.1.0-beta.11). It adds no migration and no helper build.

**One thing to do.** If you ever uploaded a file that holds a private key in the *certificate* or *CA bundle* field under Settings → Security (a combined PEM, for example), upload the certificate once more after this upgrade. The upload now cleans the copies beside the certificate files (the ones that end in `.prev`) and removes a `ca_bundle.crt` it did not write. That key was readable by any local account on the Jen box: replace the key and its certificate when you can.

**Databases → Import** says "the outcome is not known" when the database did not confirm the commit, on the page and in the audit log, and tells you to look at the data before importing again. It used to log that import as rolled back. An import that fails before its commit is recorded as "rolled back; nothing was changed".

**Alerts.** A Kea `ha-heartbeat` answer of a shape Kea does not send is logged and skipped; it used to end the whole alert cycle on every pass.

## 7.1.0-beta.10: an uploaded certificate is written as Jen read it

One step (7.1.0-beta.10). It adds no migration and no helper build.

**One thing to check.** If you ever uploaded a file that holds a private key in the *certificate* or *CA bundle* field under Settings → Security (a combined PEM, for example), that key is in `certificate.crt`, `ca_bundle.crt` or `combined.crt` under `/etc/jen/ssl`, which any local account on the Jen box can read. Jen now writes only the certificates to those three files. On 7.1.0-beta.10 itself, uploading again leaves the key in the `.prev` copies beside them: see 7.1.0-beta.11 above.

**Settings → Security: the certificate upload** writes the certificates it read, each as a plain PEM block, and nothing else of the pasted text. A CA bundle with a space, a tab or a word before a `-----BEGIN CERTIFICATE-----` line used to be accepted and then not served.

**Settings → Kea and the support bundle.** The sentence that says where a server's file and its running daemon differ masks what Config history masks: a query value, what follows a `#`, and the password of an address that is not http(s). A sentence stored by an earlier release shows the place and no values until the readiness check runs again.

## 7.1.0-beta.9: everything after the `#` of an address is masked

One step (7.1.0-beta.9). It adds no migration and no helper build, and there is nothing to do.

**Config history and the Kea configurations in the support bundle** show nothing after the `#` of an address, and mask a query token that has no parameter name. The anchor of a link to a manual is shown as `#********`, and so is any text joined to it with no space. (The readiness sentence in the bundle's `servers.json` was not covered until 7.1.0-beta.10.)

**Alerts.** A failure inside the HA failover check is logged as an error and no longer stops the rest of the alert cycle.

**Settings → Security.** Removing the certificate when none is installed does nothing; it used to restart Jen.

## 7.1.0-beta.8: the HA failover alert works again

One step (7.1.0-beta.8). It adds no migration and no helper build, and there is nothing to do.

**The HA failover alert announced nothing in 7.1.0-beta.7,** on every installation with two or more Kea servers. If you ran that beta, a failover in that time was not announced. It works again from this release; the first check records each server's state.

**Settings → Security: the certificate upload** refuses a certificate block under any PEM label but `CERTIFICATE`, with the command that converts it.

**Config history and the support bundle** mask a token written after `#` in an address when it is written as `name=value`. (7.1.0-beta.9 masks everything after the `#`.)

## 7.1.0-beta.7: Config history shows what changed again

One step (7.1.0-beta.7). It adds no migration and no helper build, and there is nothing to do.

**Config history and the support bundle.** 7.1.0-beta.6 could replace the rest of a value by one mask after the first `?` or `#` of an address in it, so two revisions could look the same. Only the user and password of an address and the values of its query are masked now.

**Settings → Security: the certificate upload.** A chain whose intermediate names a different signing key than the CA this box trusts is refused, as it was before 7.1.0-beta.6. An OpenSSL `TRUSTED CERTIFICATE` block is refused with the command that converts it.

**The HA failover alert.** A failover seen while Jen's database is away is announced when it is back.

**Settings → Databases.** The Export and Recovery tabs render when Jen's database is away. Every way an import ends leaves an audit row.

## 7.1.0-beta.6: a by-hand upgrade moves the Python dependencies

One step (7.1.0-beta.6). It adds no migration and no helper build, and there is nothing to do.

**`sudo ./install.sh` now upgrades the Python dependencies.** It used to leave an installed dependency where it was as long as it satisfied its floor, so a box that was only ever upgraded by hand kept the versions of its first install. On this upgrade those move to current releases, which the in-app updater has always done. Without a route to the package index the step keeps the installed versions and prints a warning; the upgrade still completes. `--repair` runs the same step; `--configure` does not touch the dependencies.

**Settings → Security: the certificate upload.** A root that was renewed with a new serial number no longer refuses a good chain when the box still holds the earlier copy. An intermediate that does not say it is a CA is refused. More than twenty certificates, or more than a million characters, is refused before anything is read. Removing the certificate also removes the `.prev` copies.

**Settings → Databases → Import.** A Kea file is restored whole or not at all: a table that cannot be read stops the import and everything is rolled back. A mode the page does not offer is refused.

**Config history and the support bundle** mask every value of an address's query, not only a parameter named like a secret. Names are kept.

**The HA failover alert** is retried until a channel takes it and is not lost across a restart of Jen. The first check after this upgrade records each server's state and announces nothing.

## 7.1.0-beta.5: what the box's CA store says is evidence about the box

One step (7.1.0-beta.5). It adds no migration and no helper build, and there is nothing to do.

**Settings → Security: a renewed private root.** 7.1.0-beta.4 refused a good chain when the box's own CA store still held the expired copy of a root that was renewed with the same key. It is accepted now. When the CA was issued again with a NEW key and the box holds only the old one, the upload is refused with a sentence that names the certificate; add the new root to the upload, or to the box's CA store (`update-ca-certificates`).

**A wrong intermediate is refused also when the certificates carry key identifiers,** which every real CA's do.

**An upload of more than twenty certificates is refused.** Upload the certificate and the chain above it, not a bundle of CAs.

**Investigation logging on a server whose Write mode is the API.** Turn on is also refused when the daemon does not answer the question; try again when Kea's API answers. Turn off is never refused.

## 7.1.0-beta.4: the certificate upload is judged by what signed what

One step (7.1.0-beta.4). It adds no migration and no helper build. One thing to do, on Ubuntu 22.04 only:

**On Ubuntu 22.04, upgrade once with `sudo ./install.sh`.** The Restart button, Update Now and plugin installs from the page did not work on 22.04 in any release from 5.17.0 to 7.1.0-beta.2: its systemd refuses `sudo` inside Jen's unit. From 7.1.0-beta.3 on they need no `sudo`, so after this one upgrade by hand they work. Ubuntu 24.04 was never affected.

**Settings → Security: a CA bundle with an old and a new root is accepted in any order.** 7.1.0-beta.3 could refuse it depending on the order of the paste. When the only root in the upload has expired, the refusal names that certificate; take it out of the file when your clients hold a newer one.

**A `fullchain.pem` from a public CA has its intermediate checked against the CA certificates Jen's box trusts.** A damaged intermediate is refused. For a private CA, paste the root with the chain so the whole chain can be checked.

**Investigation logging on a server whose Write mode is the API.** Turn on is refused when the daemon runs a change its file does not carry, or when an earlier change on that server is unresolved or its record cannot be read; the page says which, and what to do. It used to go ahead, and the daemon lost that change. Turn off is never refused.

**Settings → Databases → Import refuses a table the file does not carry,** and restores nothing when no table is ticked, whichever release drew the page.

## 7.1.0-beta.3: Jen's own box has no sudoers entry

One step (7.1.0-beta.3). It adds no migration and no helper build, and there is nothing for you to do. What you may notice:

**`/etc/sudoers.d/jen` is gone.** Jen used it to restart itself and to start an update or a plugin install. It now restarts by stopping its own process, which systemd starts again, and it asks for an update or a plugin install by leaving an empty request file in `/run/jen` that two new systemd path units watch (`jen-update.path`, `jen-plugin-install.path`). `sudo ./install.sh` installs the units and removes the file in one step. A box updated with **Update Now** converts itself at the restart that ends the update. Docker installs never had the file and are unchanged.

**Health has a new line, "Update and plugin triggers".** It warns when a path unit is not watching. `sudo ./install.sh` repairs that.

**If you kept your own edits in `/etc/sudoers.d/jen`,** move them to a file of your own before upgrading. The upgrade removes that file.

**Settings → Security judges every certificate on the path from yours to the top of the upload.** 7.1.0-beta.2 judged the certificate and the one above it. A `fullchain.pem` of three certificates whose top one has expired was still accepted; it is refused now. A certificate whose only stated purpose is "any" is refused with the sentence that says it was not issued for a server.

**Settings → Databases → Import: untick every table and nothing is restored.** It used to restore every table in the file.

**Settings → Kea shows "expired N days ago"** beside a server certificate that has expired, where it showed a negative number.

## 7.1.0-beta.2: the certificate upload judges the whole chain; a Kea host without the helper takes a config again

One step (7.1.0-beta.2). It adds no migration, no helper build and no sudoers line, and there is nothing for you to do. What you may notice:

**Settings → Security refuses a certificate chain a browser would refuse.** The upload now runs a TLS handshake against the material before it installs it. A `fullchain.pem` whose intermediate has expired is refused with "certificate has expired" and nothing is changed. A self-signed certificate and a certificate uploaded without its chain are accepted as before.

**A Kea server without `jen-kea-helper` can be configured again.** Config tests and config pushes over the legacy path failed for every real config since 5.1.0. They work now. Installing the helper is still the recommended setup.

**An e-mail alert channel may ask for its password once.** Only a channel stored before 1.4.5 that has no STARTTLS setting, and only when you untick STARTTLS on it.

**Settings → Databases → Export: untick everything and both cards refuse.** The Jen card used to export every table in that case.

**A direct-socket setup that failed and could not be undone says STATE NOT KNOWN** for a single server too, as it did for several.

## 7.1.0-beta.1: the Kea export picks tables; the bundled IPAM Lite draws an address map

One step (7.1.0-beta.1). It adds no migration, no helper build and no sudoers line, and there is nothing for you to do. What you may notice:

**Settings → Databases → Export, the Kea card, has tick boxes.** An All box and one box per table, like the Jen card. The four reservation tables are ticked when the page opens; tick `lease4` as well to put a lease snapshot in the same file. A file with any set of tables imports as before. Backups still save reservations only, and the migration page still offers its three groups.

**IPAM Lite 1.8.2 is bundled.** A subnet's page shows an address map above its table: one cell per address with its last octet, a heading at each /24, the DHCP pool tinted. Click a cell to find its row.

## 7.0.1: an ntfy token stays with its topic, the certificate upload refuses what a browser refuses, an SMTP host is a host alone

One step (7.0.1). It adds no migration, no helper build and no sudoers line, and there is nothing for you to do. What you may notice:

**Editing an ntfy channel's topic asks for the access token again.** The token is kept on a blank field only while the channel posts to the same address, and the topic is the last part of that address. A topic you type is letters, digits, hyphens and underscores, 64 characters at most. A topic that is already saved keeps working.

**The certificate upload refuses a certificate no browser would accept.** Settings → Security now refuses a certificate that has expired or is not valid yet, a CA's own certificate uploaded as the server's, and a certificate issued for a client only, each with its reason and with nothing changed. A self-signed certificate is accepted as before.

**An SMTP host is a host name or an IP address alone.** A host typed with a port (`mail.example:25`) is refused; the port has its own field. An IPv6 address is typed without brackets. If a channel was saved with a port in its host by an earlier release, edit it once: enter the host alone and the password again.

**Turning STARTTLS or its verification on keeps the stored password.** Only a weaker wire, a different server, port or user name asks for the password again.

**The single sign-on Redirect URI is checked.** It is an `http://` or `https://` address with no user name, password, query or fragment. Blank still means auto-detected.

**After a failed control-socket change whose rollback also failed, Jen leaves the certificate alone.** When the Kea host could not be read back, the page says STATE NOT KNOWN and Servers shows an incident; nothing is reinstalled on the host until you restore the last good config from Config history.

**Config history masks more.** The password inside an address of any scheme (`ldap://`, `postgresql://` and so on) and the value of a query parameter named like a secret (`?token=`) are masked in the diff and the masked download.

**Smaller things.** The Write mode card prints its times as `2026-11-12 14:05 UTC`. An expired HTTPS certificate's alert says "expired N day(s) ago". Getting started loads when the backups folder cannot be listed and says so.
