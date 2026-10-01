# Runbooks

Step-by-step procedures for the operations described elsewhere in the
docs (the admin guide, [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](../SECURITY.md)) but never
written out as a numbered list an operator can just follow. One section
per runbook; each stands alone — you shouldn't need to also go read the
CHANGELOG to carry it out.

## 1. Rotating the helper signing key

The permanent trust root for both Jen's own self-update and every Kea
host's signed helper update is one ed25519 key pair. The private half
exists only as the `RELEASE_SIGNING_KEY` GitHub Actions secret; the
public half is embedded, byte-identical, in three places — `RELEASE_SIGNERS`
in `jen-update-root.py`, the same-named constant in `jen-kea-helper`, and
again in `jen/services/kea_host.py` (this repo's own tests diff all three
against each other, so they can't drift silently). Rotating the key means
there's always at least one release where both the old and new key verify
— never a single release that only the new key can install.

1. **Generate a new ed25519 key pair** somewhere offline — never on a
   machine that will ever hold the old private key, and never anywhere
   the old key already lives:
   ```bash
   ssh-keygen -t ed25519 -C release@jen -f new-jen-release-key -N ''
   ```
   `new-jen-release-key.pub` is the new public half; `new-jen-release-key`
   (no `.pub`) is the new private half — this is what eventually replaces
   the `RELEASE_SIGNING_KEY` secret's contents.
2. **Add the new public key as a second `RELEASE_SIGNERS` line** in all
   three places in the same commit (`jen-update-root.py`,
   `jen-kea-helper`, `jen/services/kea_host.py`) — additive, the old line
   stays. `RELEASE_SIGNERS` is a multi-line "allowed signers" body, one
   key per line, same format as the existing entry:
   `release@jen ssh-ed25519 <base64-key>`.
3. **On any Kea host that needs to trust the new key before the next Jen
   release reaches it** (rare — normally every host just picks the new
   trust up the next time Jen itself updates and re-ships the helper),
   add the same new public line to
   `/etc/jen-kea-helper/allowed_signers` on that host by hand: a
   root-owned file, mode without group or world write, at most 8 KiB.
   It's additive too — the helper always also trusts its own embedded
   key regardless of what's in this file.
4. **Ship one release signed with the OLD key** that carries both lines
   in the three files above. This is the release every host upgrades
   into before the switch — it proves both keys verify at once.
5. **Switch the `RELEASE_SIGNING_KEY` secret** (GitHub repo settings →
   Secrets and variables → Actions) to the new private key
   (`new-jen-release-key`'s contents). Every release from here on is
   signed with the new key.
6. **Ship the next release.** It's signed with the new key; every host
   that upgraded in step 4 already trusts it (both lines are still
   there). A host that hasn't upgraded yet still trusts its own old
   embedded key for anything it does locally, but can no longer install
   a release signed only with the new one until it upgrades past step 4's
   release first.
7. **Drop the old key's line** from all three files, one release after
   that — the release after next. From here on only the new key verifies
   anything.
8. **Destroy the old private key material** once step 7 has shipped and
   nothing depends on the old line anymore.

**How to check which key a Kea host currently trusts.**
`sudo -n /usr/local/sbin/jen-kea-helper version` reports the host's
`helper_version`/`helper_build` — cross-reference that against
`CHANGELOG.md` to know which Jen release (and therefore which embedded
key) it's running. `sudo cat /etc/jen-kea-helper/allowed_signers` (if the
file exists at all) shows any additional key granted there by hand. Between
the two you know exactly what that host will accept a signed update from.

## 2. "We signed the wrong bytes" — recovering from a build with a bad candidate

The release job runs a real `ssh-keygen -Y verify` against the tarball's
own `RELEASE_SIGNERS` before it ever publishes (`.github/workflows/release.yml`),
so a release with a genuinely mismatched signature can't reach GitHub in
the first place — but a release can still ship a helper that's simply
*wrong* (a bug in the build, a bad edit that slipped through review) while
being correctly and validly signed. The published `jen-kea-helper` is what
it is; you can't un-ship it.

**The fix is never re-signing the same `HELPER_VERSION`/`HELPER_BUILD`
pair with corrected bytes.** `jen-kea-helper`'s own `update` op refuses a
candidate whose version and build are not strictly newer than what a host
already reports — a same-numbered "corrected" candidate is refused as
`not-newer` on every host that already has the broken one, and a host
that hasn't updated yet has no way to tell the broken build and the fixed
one apart (they'd claim the identical version *and* build). It would also
mean two different byte sequences have both, at different times, carried
a valid signature under the identical `(HELPER_VERSION, HELPER_BUILD)`
pair — exactly the ambiguity the whole build-number scheme exists to rule
out.

1. **Fix the bug** in `jen-kea-helper`.
2. **Bump `HELPER_BUILD`** by at least 1 (never reuse or decrease it,
   even across a version bump). Leave `HELPER_VERSION` exactly where it
   was if the protocol itself didn't change — this is precisely the
   helper-only-fix case `HELPER_BUILD` was added for (v5.66.0-beta.2,
   Q104 item c): a host stuck on the broken build reads it as a genuine,
   newer build worth taking, not as "already up to date."
3. **Update the pin file**, `tests/kea_helper_build.json` — both the
   `build` number and the `sha256` of the corrected file. Run
   `py -m pytest --noconftest tests/test_kea_helper.py -k TestBuildBumpReminder -q`
   locally; it fails on purpose if the pin and the real file disagree,
   as a reminder that this step is not optional.
4. **Ship a normal release** from there — the usual beta-first process.
   Every host, whether it already took the broken build or never saw it
   at all, ends up on the corrected one because it's strictly newer by
   build number.

There's no separate "hotfix" procedure beyond this: bump the build,
update the pin, release.

## 3. Installing the Kea host helper by hand, including offline

Settings → Kea → SSH's **Install helper** / **Update helper** button is
the normal path. The procedures below are for the two cases it can't
cover: a host with no legacy grant and no sudoers file yet (first
install, before the button has anything to work with) and a Kea host
with no route to the internet at all.

### Online — the verified one-liner

This is the exact command Jen itself shows in every flash that offers a
by-hand fallback (v5.66.0-beta.2, Q104 item b) — copy it from there
rather than retyping it, since it embeds the release version and the
signing key inline. It also runs the downloaded candidate's own
`version` op and checks it reports exactly the version/build this
release ships (v5.66.0-beta.7, Q109 — the same self-check the automatic
signed-update path already runs before installing anything), so `7` and
`9` below are this release's own `HELPER_VERSION`/`HELPER_BUILD`, not
placeholders to fill in. Run it as a user with `sudo` on the Kea host:

```bash
d="$(mktemp -d)" && cd "$d" && curl -fsSLO https://github.com/ltkojak/jen-kea/releases/download/vX.Y.Z/jen-kea-helper && curl -fsSLO https://github.com/ltkojak/jen-kea/releases/download/vX.Y.Z/jen-kea-helper.sig && printf '%s\n' 'release@jen ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXk5NbQwUy85pHCzLfOwPisL0JGLCOrHuRjRZSf25vD' > allowed_signers && ssh-keygen -Y verify -f allowed_signers -I release@jen -n jen-kea-helper -s jen-kea-helper.sig < jen-kea-helper && /usr/bin/python3 -I jen-kea-helper version </dev/null | /usr/bin/python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get("ok") is True and d.get("helper_version")==7 and d.get("helper_build")==9 else 1)' && sudo install -o root -g root -m 0755 jen-kea-helper /usr/local/sbin/jen-kea-helper
```

It downloads both the helper and its signature from this release's own
GitHub asset, verifies the signature locally with `ssh-keygen -Y verify`
against the same embedded key Jen carries, and only installs the file if
that verification AND the self-check both pass — a corrupted download or
a tampered mirror makes `ssh-keygen` exit non-zero, and a candidate that
doesn't self-report what it just verified as makes the self-check exit
non-zero; the `&&` chain means nothing gets installed either way.
**Never install a copy that fails this verification, by hand or
otherwise** — if the check fails, the problem is the download or the
release, not something to work around.

Then add the sudoers line, if this is a fresh install with no grant yet:

```bash
printf '%s\n' '# Jen (DHCP console) — SSH user "youruser". The helper op allowlist is the control; see docs/ARCHITECTURE.md §3.3' 'youruser ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper' | sudo tee /etc/sudoers.d/jen-kea-helper >/dev/null && sudo chmod 440 /etc/sudoers.d/jen-kea-helper && sudo visudo -c -f /etc/sudoers.d/jen-kea-helper
```

### Offline — a Kea host with no route to GitHub

Fetch `jen-kea-helper` and `jen-kea-helper.sig` on any machine that does
have a route — they're the same two release assets the online one-liner
above downloads (a tarball install already has both files sitting side
by side in the extracted `jen/` directory, so an operator working from a
tarball has them already, with no fetch needed at all). Copy both onto
the Kea host by whatever transport you trust — `scp`, a USB drive — then
run the same verify-then-install steps locally, in the directory holding
both files:

```bash
printf '%s\n' 'release@jen ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXk5NbQwUy85pHCzLfOwPisL0JGLCOrHuRjRZSf25vD' > allowed_signers && ssh-keygen -Y verify -f allowed_signers -I release@jen -n jen-kea-helper -s jen-kea-helper.sig < jen-kea-helper && /usr/bin/python3 -I jen-kea-helper version </dev/null | /usr/bin/python3 -c 'import json,sys;d=json.load(sys.stdin);sys.exit(0 if d.get("ok") is True and d.get("helper_version")==7 and d.get("helper_build")==9 else 1)' && sudo install -o root -g root -m 0755 jen-kea-helper /usr/local/sbin/jen-kea-helper
```

Never skip the verify step just because you trust the transport — it's
exactly what catches a corrupted or partial copy before it's installed
as root. Then add the sudoers line the same way as the online case above.

## 4. Restoring a JENREC2 recovery bundle onto a scratch VM

A recovery bundle (Settings → Databases → Recovery, `jen-recovery-*.tar.enc`)
is only as good as a restore drill actually proving it works. Do this on
a throwaway VM, never against a live box, before you need it for real.

0. **Before you start: size.** The Jen database export inside the bundle
   is written straight to disk, one row at a time (v5.66.0-beta.4, Q106) —
   building it never needs much memory, however large `audit_log` has
   grown. Restoring it is a different story: `jen.tools.restore` still
   decompresses and parses the whole export as one JSON document (a
   streaming importer is a bigger change, out of scope here), and the
   recovery manifest records exactly how big that document is
   (`jen_db_uncompressed_bytes`) so `jen.tools.restore` can check, BEFORE
   it stops or touches anything, that the box has enough free memory —
   measured (`tests/test_dbexport_streaming.py::TestRestoreMemoryFactor`,
   driving the real import path under `tracemalloc` over three synthetic
   `audit_log` sizes), not guessed: peak/uncompressed came out around
   **6.1× at 2,000 rows (737 KB), 3.4× at 20,000 rows (7.4 MB), and 3.0×
   at 100,000 rows (37 MB)** — the ratio actually falls as the export
   grows (fixed per-call overhead amortizing), so the guard uses the
   worst of those three, with headroom, as a flat **7×**
   (`jen.tools.restore.RESTORE_MEMORY_FACTOR`).

   **v5.66.0-beta.6 (Q108) — the check weighs whichever side is bigger,
   not just the incoming bundle.** A small bundle restored onto a box
   whose CURRENT database is large still has to hold that current
   database's own export in memory — for the pre-restore snapshot taken
   just before the bundle is applied, and again for a rollback if
   anything afterward goes wrong — so `jen.tools.restore` now measures the
   existing database's real size too (a real export to a throwaway file
   in the snapshot directory, deleted right after — costs time and disk
   there, never memory) and refuses if `max(incoming, existing) × 7`
   would exceed what's available, naming whichever side was the actual
   problem. The same step also confirms the snapshot directory has room
   for the snapshot itself (twice the existing database's compressed
   size) before anything is touched. If a restore refuses on either
   check, the message names the actual figures; the ways to shrink
   either side are the same as before — lower Settings → System → Audit
   Log Retention before the next export/backup, or check **"Without
   audit history"** on the recovery bundle form (`audit_log` is the one
   table this leaves out — export it separately from Settings →
   Databases → Export if you need it after all) — or restore onto a box
   with more RAM or free disk. The check never suggests adding swap: it
   measures real, currently-available memory, and swap isn't that.
1. **Provision a scratch VM** and run a normal `sudo ./install.sh` on it
   — this sets up the venv, the systemd unit, and sudoers; the restore
   below layers *state* onto that working install, it does not set one
   up.
2. **Snapshot the VM** (or otherwise make sure you can revert it)
   immediately after the base install, before touching the bundle at
   all — the whole point of a scratch VM is that a bad restore costs you
   nothing to undo.
3. **Copy the bundle onto the VM** and run:
   ```bash
   sudo ./install.sh --restore /path/to/jen-recovery-*.tar.enc
   ```
   You're prompted for the passphrase on the TTY — it's never accepted as
   a command-line argument or an environment variable, since both are
   visible to any other process on the box via `/proc` or `ps`.
4. **Apply.** `--restore` stops the running Jen service, writes
   `/etc/jen` and the content directory, imports the database, starts
   Jen back up, and waits for it to answer healthy before printing a
   checklist of anything a human still has to do by hand (anything the
   bundle format itself can't restore — a Kea host's own config isn't
   pushed anywhere; the bundled copy is a reference file only).
5. **Health check.** The restore's own health wait polls the
   unauthenticated `/api/v1/health` endpoint until it answers HTTP 200
   with a JSON body carrying `jen_version` — nothing about Kea, since
   that endpoint was trimmed to just that one field (v5.65.12-beta.1,
   Q101). If the restore reports Jen came back healthy, this is what it
   checked.
6. **Leave it up.** Don't tear the VM down right after — log into the
   restored Jen, confirm the data you expected is actually there (users,
   subnets, whatever the bundle should have carried), and leave the box
   running for a while. A restore that "completed successfully" but
   silently left something out is a real failure mode a health check
   alone won't catch. If any bundled plugin (DNS Sync, IPAM, Network
   Discovery, Presence, Switchport, Watchdog, Wake-on-LAN) was installed
   on the box the bundle came from, check **Settings → Plugins** and that
   plugin's own page too (v5.66.0-beta.5 — its data tables are in the
   bundle now, not just its enabled/disabled row; a bundle made before
   this release never had them to restore in the first place, so this
   check only proves anything on a bundle taken after upgrading).

**What a wrong passphrase looks like, verified against the real
`jen.tools.restore`:**
```
Recovery bundle passphrase:
error: wrong passphrase, or the bundle is corrupted or was tampered with
```

**What a truncated or corrupted bundle file looks like — the identical
message:**
```
Recovery bundle passphrase:
error: wrong passphrase, or the bundle is corrupted or was tampered with
```

This is deliberate, not a bug: a wrong passphrase, a bundle cut short in
transit, and a bundle someone tampered with all produce the exact same
refusal, on purpose — telling them apart would hand an attacker trying to
brute-force the passphrase a way to know when they'd gotten close.
Neither case gets a more specific message, and there isn't a more
specific one to ask for.

If either message shows up on a genuinely correct passphrase and an
intact file, re-copy the bundle (transfer corruption is the most common
real cause) before assuming the bundle itself is bad.

## 5. Moving an existing install's data directory

`install.sh --app-dir/--config-dir/--data-dir` (`docs/installation.md`
Method 1c) only ever apply at **fresh install time** — an existing
install's layout, once recorded in `/etc/jen-layout.conf`, is
authoritative, and a later run that passes one of those flags with a
different value is refused outright (`docs/ARCHITECTURE.md` §3.1 and
§6.1 explain why the file is trusted the way it is). Relocating an
existing install is this runbook, done by hand, while Jen is stopped.

Step 4 below (re-rendering the unit) runs the SAME `jen-update-root.py
--check-layout` every other privileged run does (`docs/installation.md`
Method 1c's "A dedicated directory" and "ancestor" subsections) against
the new location: its own existing ancestors must be root-owned and
not group/other-writable (the one-line fix is named in the refusal if
not), and it's recognized as genuinely Jen's own by the
`.jen-directory` marker. `cp -a SOURCE/. DEST/` (step 2 below) copies
that marker along with everything else, since it's a dot-prefixed file
inside the directory being copied — nothing extra to do for it, but
don't swap it for a `cp -a SOURCE DEST` (no trailing `/.`) or an rsync
invocation that excludes dotfiles, or the new location arrives
unmarked and the next upgrade has to recognize it by content instead
(still fine — see `docs/ARCHITECTURE.md` §6.1 — just slower to reason
about if something looks wrong).

The steps below move the **data directory** (`/var/lib/jen` by default —
uploads, database backups, registry-installed plugins) onto a new
volume, the case an operator actually hits in practice (a disk running
low, moving onto NFS/NAS, a dataset with its own snapshot policy).
Moving `app_dir` or `config_dir` instead is the same shape — stop Jen,
move the directory, edit the one line in `/etc/jen-layout.conf`, render
+ verify the unit, start Jen — substituting that directory and that
layout key throughout.

1. **Stop Jen** so nothing writes to the data directory mid-move:
   ```bash
   sudo systemctl stop jen
   ```
2. **Copy the data to its new home**, preserving ownership and
   permissions, before touching anything the running config points at:
   ```bash
   sudo mkdir -p /srv/jen/data
   sudo cp -a /var/lib/jen/. /srv/jen/data/
   ```
   Verify the copy — `diff -rq /var/lib/jen /srv/jen/data` should report
   nothing — before the next step makes the old location's continued
   existence irrelevant.
3. **Edit `/etc/jen-layout.conf`** (create it, root:root 0644, if this
   install predates it and has never had one — absent has always meant
   "the historical defaults," so the file may simply not exist yet):
   ```ini
   [layout]
   app_dir = /opt/jen
   config_dir = /etc/jen
   data_dir = /srv/jen/data
   ```
   Keep `app_dir`/`config_dir` at whatever this install already uses —
   only change the one key you're actually moving.
4. **Re-render `jen.service`** so its `ReadWritePaths=` and
   `Environment=JEN_CONTENT_DIR=` lines agree with the new location, and
   verify the result before trusting it:
   ```bash
   sudo ./install.sh --repair
   sudo systemctl daemon-reload
   ```
   `--repair` reinstalls files and re-renders the unit from the layout
   you just edited without touching `jen.config` or re-asking any
   configuration question; it runs `systemd-analyze verify` on the
   rendered unit itself and refuses to proceed if that fails.
5. **Start Jen and confirm it's reading the new location:**
   ```bash
   sudo systemctl start jen
   systemctl show jen -p Environment | tr ' ' '\n' | grep JEN_CONTENT_DIR
   ```
   should print `Environment=JEN_CONTENT_DIR=/srv/jen/data`. Log in, check
   an uploaded icon or the branding logo still renders, and confirm a new
   database backup (Settings → Databases → Backup) lands in
   `/srv/jen/data/backups/`.
6. **Remove the old copy** only once you've confirmed the above — not
   before:
   ```bash
   sudo rm -rf /var/lib/jen
   ```
