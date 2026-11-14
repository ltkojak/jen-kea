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

## 7.1.0-beta.3: Jen's own box has no sudoers entry

One step (7.1.0-beta.3). It adds no migration and no helper build, and there is nothing for you to do. What you may notice:

**`/etc/sudoers.d/jen` is gone.** Jen used it to restart itself and to start an update or a plugin install. It now restarts by stopping its own process, which systemd starts again, and it asks for an update or a plugin install by leaving an empty request file in `/run/jen` that two new systemd path units watch (`jen-update.path`, `jen-plugin-install.path`). `sudo ./install.sh` installs the units and removes the file in one step. A box updated with **Update Now** converts itself at the restart that ends the update. Docker installs never had the file and are unchanged.

**Health has a new line, "Update and plugin triggers".** It warns when a path unit is not watching. `sudo ./install.sh` repairs that.

**If you kept your own edits in `/etc/sudoers.d/jen`,** move them to a file of your own before upgrading. The upgrade removes that file.

**Settings → Security judges every certificate of a chain.** 7.1.0-beta.2 judged the certificate and the one above it. A `fullchain.pem` of three certificates whose top one has expired was still accepted; it is refused now. A certificate whose only stated purpose is "any" is refused with the sentence that says it was not issued for a server.

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
