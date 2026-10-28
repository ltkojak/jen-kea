# Upgrading from 5.69.0

Everything below changed since v5.69.0 — the last stable release before
this one — that you'd actually notice or need to know about when you
upgrade. Run `sudo ./install.sh` on the new tarball (or use the in-app
updater) the normal way; nothing here needs a manual step beyond what's
called out explicitly. See `docs/runbooks.md` for step-by-step
procedures, and `CHANGELOG.md` if you want the full detail behind any
item below. The previous page, covering everything since 5.68.0 through
the 5.69.0 baseline, is archived at
[`docs/release-history/upgrading-5.68.0-to-5.69.0.md`](release-history/upgrading-5.68.0-to-5.69.0.md).

## A rotation's earlier notes finish first; a certificate that names nothing is refused; saving ports or Jen's certificate needs a superadmin

One step (5.69.2). It adds no migration and needs no action beyond what you may notice below.

**Saving the server's ports, threads or Jen's own SSL certificate now needs a superadmin whose password was confirmed in the last ten minutes.** Every restart of Jen is behind one gate: *Save ports*,
*Upload certificate* and *Remove certificate* restart Jen like the Restart button does, and until now an admin could press them without the step-up. An admin sees the refusal and asks a superadmin.

**A rotation will not start while an earlier rotation's note is unfinished.** A rotation leaves a note on Servers for every record it does not rotate. If the database refused the note that finishes one,
the next Rotate finishes it from Jen's files first, and refuses - changing nothing - when it cannot ("the bookkeeping of an earlier rotation for *server* is not finished"); **Forget stale records** finishes
it as well. A note is never overwritten by a later rotation, and it has no Acknowledge button: it is Jen's own bookkeeping.

**A Jen-signed certificate that names no address and no machine is refused.** A record whose certificate has no DNS or IP name (hand-placed or damaged files; Jen's own issuer always writes the bind address)
proves nothing about which daemon it was installed on, so Rotate, the recovery, the setup and the rollback refuse it: remove the direct socket and set it up again, or restore the certificate Jen issued.

**The address Jen dials may be any name the certificate carries.** 5.69.1 required it to be the certificate's first name, which refused a record whose address was changed to the machine's DNS name (the
certificate's second name) although a TLS client accepts it. The address is now judged the way a TLS client judges it; the SSH host Jen logs into must still be the certificate's last name.

**A second record on one daemon refuses a rotation too, parked ones included.** The setup already refused to run while another record shared a daemon (even one that is not dialled over https now); the
rotation now asks the same question, because its install would overwrite the certificate that record holds. The sentence names the action: remove one of the two records or re-point it at its own host.

**A saved SSH host stays valid only on its own record.** A scoped IPv6 SSH host saved before 5.69.1 is still accepted where it is saved (in any spelling that names the same address) and refused anywhere else.

## The SSH host must be the name the certificate was installed on; a scoped IPv6 SSH host is refused; a rotation writes its notes first

One step (5.69.1). It adds no migration and there is nothing for you to do. What you may notice:

**Rotate compares each name with its own role.** The certificate Jen issues for a daemon carries two names in a fixed order: the address the daemon serves, then the machine Jen installed it on (the SSH
host). A rotation, a recovery and the rollback require the SSH host Jen logs into to be the last (5.69.2: the address Jen dials may be any name the certificate carries - a TLS client accepts every one). A name that only appears in the other role does not
count as the SSH host, so a server whose SSH host was changed to the daemon's address (the same machine, written differently) is refused with the sentence "its certificate names *name* as the machine it was
installed on; this record's SSH host is now *host*": remove the direct socket and set it up again, or restore the previous SSH host. Nothing is installed or restarted by a refused rotation.

**A recovery judges the whole record.** When Jen's CA is damaged and you rotate with the acknowledgement, a server's record is judged by the certificate that represents what its host holds: the
current copy, or the previous pair when the current copy is missing, unreadable or marked as not the host's. A record with files and no certificate that says which machine they belong to is refused
instead of being made a target; remove the direct socket and set it up again, or restore the previous host. A server with no files at all is still given a fresh pair by the recovery.

**A rotation writes its notes first.** Before it changes anything, a rotation writes a note on Servers for every record it will not rotate (a parked server, left-over files, a record you forgot) and reads
it back; if the database cannot take the note, the rotation does not start. After the new CA is in place each note is finished from Jen's files. If the database refuses a final note the rotation still
completes, the note stays as "a rotation's bookkeeping is unfinished", and the next Rotate (or Forget stale records) finishes it from Jen's files; Health only names it.

**The setup checks for a parked twin and for its own record.** Setting up https for a server now stops, before anything is installed, when another server record with the same SSH host still holds a
Jen certificate for that daemon even if that record is not dialled over https now. It also stops when its own existing record names a different machine than the SSH host now set: remove the direct
socket first (a removal on a host whose config has no socket left now sets the record aside), then set it up there.

**A scoped IPv6 address is not accepted as an SSH host.** A certificate cannot carry an interface scope, so `fe80::1%eth0` would never match the certificate Jen issues for `fe80::1`. Saving a NEW such host
is refused with that reason; use a name. A host already saved with a scope stays valid as it is saved, and is compared without the scope against its certificate.
