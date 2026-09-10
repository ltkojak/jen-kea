# Changelog

*Detailed per-series notes for the 3.x line live in [docs/release-history/](docs/release-history/).*

## [5.11.0] - 2026-09-10

The privilege boundary on the Kea hosts.

### `jen-kea-helper` — one sudoers line instead of root

Until now, everything Jen did on a Kea host — editing a subnet, authoring
a config, restarting a daemon, reading the DDNS log, installing a Kea
package — was done by generating a Python script on the Jen host, piping
it over SSH, and running it as root. The documented Kea-side sudoers grant
was therefore `NOPASSWD: /usr/bin/python3`, which **is** root: a
compromised Jen process was root on every Kea box it managed. This was the
largest unaddressed item in the threat model (`docs/ARCHITECTURE.md`
§3.3).

`jen-kea-helper` replaces that with a small, fixed-function, root-owned
script at `/usr/local/sbin/jen-kea-helper` behind **one** sudoers line:

```
youruser ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper
```

Jen calls it as `sudo -n jen-kea-helper <op>` with a JSON request on
stdin and gets a JSON reply. It exposes a closed set of operations
(`read-config`, `test-config`, `apply-config`, `service`, `tail-log`,
`install-package`), validates every path itself (Kea configs must sit in
`/etc/kea` or `/usr/local/etc/kea`; logs must resolve under `/var/log`),
and **never executes anything it is handed** — stdin is data only. There
is deliberately no self-update operation.

**Install it** from **Settings → Kea → SSH** (one click per host, while
the old grant is still present), or by hand — see the Admin Guide → Kea
host helper. The page shows `v1` for each host once it is reachable.

### The legacy path stays, banner-warned

A Kea host that does not have the helper yet falls back to the old
`sudo python3` path automatically. Jen shows an admin banner naming every
such host and flashes a warning on each use. **The fallback is not
removed** — a host still on it keeps working. Once every host shows the
helper you can delete `/etc/sudoers.d/jen` (the `python3 = root` grant).

### Config editing moved into Jen

As a by-product, the seven near-identical remote-script builders are gone.
Subnet add / delete / edit (v4 and v6) now read the config, mutate it in
pure Python (`jen/services/kea_config_edit.py`), and push the result back
through the helper. The Servers-page restart button and the DDNS log read
no longer shell out to `ssh` directly.

### Also

- Removed a stale committed symlink (`templates/templates`, from v4.4.10)
  that shipped in every release tarball and made a plain `tar xzf` fail.
- `.gitattributes` pins LF on the shipped scripts so a Windows checkout
  can't break a `#!` line.

## [5.10.4] - 2026-09-10

A patch for four small things, two of which have been quietly broken
since 5.9.0.

### The in-app updater refreshes the page again

Trigger an update from Settings and Jen tells you "this page will
refresh automatically once Jen is back." It hasn't, since 5.9.0 — and
not because of the virtualenv work, which is where the finger has been
pointed. The 5.9.0 Settings reorganisation moved the update overlay and
its restart-poller onto the System page, but the update trigger kept
redirecting to the Kea page, which has neither. So the update ran to
completion and the browser just sat there until you reloaded by hand.
The trigger now sends you to the page that actually carries the
overlay. The overlay's own "give up and tell the operator" timers were
also too short — 60 and 90 seconds against a server-side health window
that alone is 90 seconds — and now allow three minutes.

### A fresh install could not save its own settings

`install.sh` wrote `/etc/jen/jen.config` owned by `root`, in a step
that runs *after* the one that hands the application tree to the
service user. On a fresh 5.9.0–5.10.3 install that left the file
root-owned, and the running service — which rewrites it on every
Settings save — got permission denied every time, until the next
`sudo ./install.sh --upgrade` happened to fix the ownership as a side
effect. The installer now assigns it to the service user, and Jen
writes the file atomically (to a sibling temp file, then an atomic
rename), which only needs write access to the directory. **An
already-affected box heals itself on the first successful Settings save
after upgrading to 5.10.4** — no manual `chown` needed. The atomic
write also means an interrupted save can no longer truncate the config
to nothing.

### /about and the API docs stop showing deployment detail to viewers

The About page listed the HTTP and HTTPS ports, the on-disk config and
application paths, and the Kea SSH host to every signed-in user; the
API documentation page pre-filled its examples from a list of every
active API key's name and prefix, even though the key-management page
itself is admin-only. Both are now limited to admins and superadmins.
(The About page also now actually fills in the port and SSH-host rows,
which it never did — admins were looking at blank cells.)

### The login-attempt table is pruned hourly, not per attempt

Every failed login ran a "delete rows older than 24 hours" sweep of
the rate-limit table. The row insert that the lockout logic depends on
is still synchronous; the cleanup now runs at most once an hour.

## [5.10.3] - 2026-09-09

5.10.2 made single-server direct mode correct. This makes the
**multi-server** case correct too, and stops accepting mTLS material it
can't actually use. All bug fixes and validation on features that already
shipped — no new config keys, no manual upgrade steps.

### A standby's IPv6 endpoint is its own

In `ca` mode, an HA standby with no `api6_url` was sending **every DHCPv6
command to the primary**, with the primary's credentials. Jen's endpoint
resolution consulted the `[kea6]` globals before falling back to the
server's own `api_url` — and those globals are the *primary's* `[kea6]`
values, which in `ca` mode are just the primary's `[kea] api_url`. Server
status, config-drift checks, v6 subnet reads and v6 reservation writes
all pass a real server, so all of them were affected.

A server's v6 endpoint is now that server's: its `api6_url` /
`api6_user` / `api6_pass`, else (in `ca` mode) its own `api_url` and
credentials. `[kea6]` is the primary's per-daemon override and reaches
the primary the same way it always did.

### Reordering servers no longer swaps their passwords

Settings → Kea → Additional Servers rebuilds every `[kea_server_N]`
section on save. It used to carry a blank password field, and any
hand-added key like `ssh_key`, forward from **whatever section number the
row landed on** — so reordering two rows quietly gave each server the
other's `api_pass`, `api6_pass` and `ssh_key`, and deleting the first of
two handed the survivor the deleted server's password. 5.10.2 documented
the `ssh_key` half as a positional limitation; the password half was a
credential swap.

Each row now carries its original section number, and preservation
follows the server. Sections are also renumbered contiguously: a row with
a blank API URL used to leave a gap, and Jen stops reading
`[kea_server_N]` at the first gap — so every server after a blank row was
invisible.

### Authoring binds each server's own address

"Author a starting config" detected one bind address on the first Kea
server and wrote it into every target server's control socket. An HA pair
has two management IPs, so the second server was told to bind an address
it doesn't have — which pushes you toward `0.0.0.0` just to make the
error go away. There is now one bind picker per server, offering that
server's own detected addresses and defaulting to the address Jen dials
for it. A server with no bind address chosen fails only itself.

Relatedly: in direct mode for DHCPv6 with no v6 socket configured, the
form used to claim the endpoint was plain HTTP on an empty host and only
told you the truth when you hit Preview. It now leads with what's missing.

### The client certificate is checked before it's saved

`api_client_cert` / `api_client_key` were only checked for *existence* —
and existence is a `stat`, which says nothing about whether the files
parse, whether the key matches the certificate, or whether the Jen
service user can read the key at all. A `root:root 600` key passed
validation and then failed every single Kea request. Jen now loads the
pair (and `api_ca`) the way the HTTP client will, as the service user,
and refuses to save material it couldn't use.

### Probe any server, either daemon

Probe always used the primary's URL and credentials, so there was no way
to test a standby. It now takes a server and `dhcp4`/`dhcp6` and resolves
the endpoint the same way the live transport does — the URL and
credentials Jen will actually dial for that daemon on that server. With
no selection it behaves exactly as before.

### Quieter logs with TLS verification off

With `api_tls_verify = false`, urllib3 emitted an `InsecureRequestWarning`
on *every* request, and the dashboard polls. Jen now says it once, as a
log warning naming the setting.

### Not in this release

Per-server client certificates (one `[kea]` pair still covers every
server); replacing the remote `sudo python3` config-push path with a
fixed-function helper; plugin-registry checksums.

## [5.10.2] - 2026-09-09

The Kea 3 direct-control-socket work from 5.10.0/5.10.1 got the transport
right; this release finishes the edges around it — TLS, config lifecycle,
and authoring defaults — from an external review. All of it is optional
and backward-compatible; a `ca`-mode install is unaffected.

### HTTPS direct sockets actually work

5.10.1's "Author a starting config" always emitted an `http` control
socket, even when Jen's own `api_url` was `https://` — so Jen dialled
HTTPS and Kea listened plain HTTP, and they couldn't talk. And Kea's
per-daemon `https` socket defaults `cert-required` to **true** (mutual
TLS), which the admin-guide's HTTPS instructions didn't account for.

- New `[kea] api_client_cert` / `api_client_key` — a client-certificate
  PEM and key on the Jen host, passed to every Kea request. Set both or
  neither; Jen checks each file exists on save. Kea can now demand a
  client cert (its default) and Jen can satisfy it.
- The authoring wizard is scheme-aware: an `https://` endpoint produces a
  `socket-type: https` entry with `trust-anchor` / `cert-file` /
  `key-file`, and `cert-required` is set to `true` only when Jen actually
  has a client certificate configured — never authored as `true` into a
  file Jen then can't connect to.
- The admin-guide's "Direct control sockets" section is rewritten
  secure-first: HTTPS-with-mTLS on a management address is the headline
  example, with a `cert-required: false` variant and a plain-HTTP warning
  box, plus a minimal private-CA `openssl` recipe.

### The authored socket is the endpoint Jen will dial

The generated config is now built **per target server**, from each
server's own `api_url` and credentials via the same endpoint resolution
the live transport uses — not once from the primary's globals. An
HA standby with its own port/credentials gets a config Jen can reach.

- Direct-mode API URLs must include an explicit port (`http://kea:8004`,
  not `http://kea`). A daemon control socket is never on 80/443, and a
  portless URL had Jen dial `:80` while authoring emitted `:8000`. The
  Kea page warns about any portless URL after a mode switch.
- The stale dhcp4 fallback port (`8000`, the old Control Agent port) is
  gone — there's no fallback; a missing port is an error.

### No more 0.0.0.0 by default

5.10.1 hard-coded the authored control socket to bind `0.0.0.0` (every
interface) with no way to choose — a "secure enough on a trusted LAN"
default, not a secure one. The authoring form now offers a **bind
address** picker over the Kea host's detected management IPs, preselecting
the one Jen connects to; `0.0.0.0` is present but flagged "not
recommended" and never the default. A plain-`http` endpoint shows a
"credentials in the clear" warning.

### Config that stays configured

- **Clearing a `[kea6]` override now works.** Blanking a Kea6 API/DB text
  field removes the key so Jen genuinely inherits the v4 value — before
  this a blank field wrote nothing and a stale `…:8006` override could
  survive a `direct → ca` switch and get a CA-shaped payload aimed at the
  v6 daemon's port. Passwords are kept unless you tick a new "Inherit"
  box.
- **Additional Servers no longer drops `api6_url`.** The editor rebuilt
  each `[kea_server_N]` from a fixed field list, so a per-server v6
  endpoint (or a hand-added `ssh_key`) vanished on any unrelated save.
  The form now carries `api6_url` / `api6_user` / `api6_pass`, and keys
  it doesn't manage are preserved.
- Per-server `api6_user` / `api6_pass` now make the full trip from config
  through to the transport.

### Preview no longer shows passwords

The "Preview & Validate" step returned the whole generated config as
JSON, lease-database and control-socket passwords included, into the
browser DOM. Passwords are now redacted (`********`) in that payload; the
real values still reach the remote `kea-dhcpX -t` check.

### Probe a specific URL

The Probe button on Settings → Kea takes an optional URL — it probes just
that endpoint (direct-style, no port-8004 guessing) and, when it answers,
recommends setting it as the API URL. The scheme is never downgraded.

### Not in this release

Per-server or `[kea6]`-specific client certificates (one global
`[kea]` pair for now); replacing the remote `sudo python3` config-push
path with a fixed-function helper (a larger change, tracked separately);
plugin-registry checksums.

## [5.10.1] - 2026-09-09

Completes the Kea 3 work from 5.10.0: **"Author a starting config" now
produces a config Jen can actually reach in `direct` mode.**

5.10.0 added `connection_mode = direct` (talk to each Kea daemon's own
HTTP control socket, since Kea 3.2 removed the Control Agent) but left one
gap: a config generated by Settings → Kea → "Author a starting
kea-dhcpX.conf" still emitted only a Unix `control-socket`. On a fresh Kea
that started with that config, Jen — connecting over HTTP from another
host — had nothing to talk to, and the operator had to hand-add the
`http` socket.

Now, when `connection_mode = direct`, a generated config gets a
`control-sockets` **list**: the Unix socket (kept for `kea-shell` and some
hooks) plus an `http` entry —

- **address** `0.0.0.0` so the Jen host can reach it,
- **port** parsed from `[kea] api_url` (or `[kea6] api_url` for dhcp6),
- **basic auth** from `api_user` / `api_pass`.

The authoring form shows exactly what the `http` socket will be before
you generate, and refuses if the API username/password aren't set (they'd
otherwise become empty basic-auth credentials on a socket bound to all
interfaces). In `ca` mode the generated config is unchanged — the
singular `control-socket` map, exactly as before.

Also: the suggested Unix socket path when no Control Agent config is
found now follows ISC's convention (`/run/kea/kea4-ctrl-socket` /
`kea6-ctrl-socket`).

## [5.10.0] - 2026-09-09

Kea 3 removed the Control Agent. Jen learns to talk to Kea without it.

### Why this matters

ISC deprecated `kea-ctrl-agent` in **Kea 3.0** (it still runs, but logs a
warning at startup) and **removed it entirely in Kea 3.2**. Every release
of Jen before this one could only reach Kea's command API *through* that
Control Agent, so a site that upgrades Kea to 3.2 would find Jen's status
panels, config-drift check, HA state and lease stats all going dark at
once — nothing on the command channel would answer.

Since Kea 2.7.2 each daemon (`kea-dhcp4`, `kea-dhcp6`, `kea-dhcp-ddns`)
exposes its own HTTP control socket. This release adds a second
connection mode that talks to those directly.

### `[kea] connection_mode`

A new, optional config key with two values:

- **`ca`** — the default, and byte-for-byte identical to every prior
  release: one endpoint, commands routed by a `"service"` field. An
  existing `jen.config` with no `connection_mode` line behaves exactly as
  it did before upgrading.
- **`direct`** — Jen posts straight to each daemon's own control socket.
  `[kea] api_url` is the `kea-dhcp4` socket; `[kea6] api_url` is the
  `kea-dhcp6` socket, and in this mode there is **no fallback** from v6 to
  the v4 URL (a `kea-dhcp4` daemon can't answer DHCPv6 commands) — if
  IPv6 is on and `[kea6] api_url` is unset, v6 API calls return a clear
  error instead of being misrouted. The `"service"` field is omitted from
  the payload, which is the portable choice across Kea 3.0.x and 3.2+.

Two more optional `[kea]` keys cover a TLS control socket: `api_ca` (a CA
bundle path on the Jen host that pins verification) and `api_tls_verify`
(default `true`). They only take effect for an `https://` URL, so adding
them changes nothing for a plaintext socket. Client-certificate auth
(`cert-required`) is not yet supported — a follow-up.

This is a backward-compatible, opt-in config addition, so a `sudo
./install.sh` upgrade stays fully automatic with no manual steps —
hence MINOR, not MAJOR. A site staying on Kea 3.0/3.1 with the Control
Agent needs to do nothing.

### Settings → Kea

- A **Connection Mode** selector on the Kea card. The URL field's label
  and help text follow the mode; the IPv6 card's label becomes
  "kea-dhcp6 control socket URL" in direct mode and warns inline when
  IPv6 is enabled with no v6 socket configured.
- **CA bundle path** and **Verify TLS** inputs for an HTTPS socket.
- A **Probe** button. It tries the configured endpoint in the configured
  mode, then a direct socket on the same host at port 8004, and reports
  the running Kea version, which mode answered, and a recommendation
  keyed on the version — "the Control Agent is deprecated, switch to
  direct" for 3.0–3.1 on `ca`, "the Control Agent is gone, you must
  switch" for 3.2+ on `ca`.
- The Kea page shows the same warning as a banner when `ca` mode is
  configured against a reachable Kea ≥ 3.0, and the Settings landing tile
  carries a one-line hint.
- `save-kea` now validates the mode, the URL scheme, and that a given CA
  bundle path actually exists on the Jen host.

### Docs

The Admin Guide gains a **"Direct control sockets"** section: the
`control-sockets` JSON to add to each daemon (keeping the existing `unix`
entry alongside the new `http` one), the 8004/8006 port convention, basic
auth, the TLS knobs, and a warning never to point Jen at an HA peer port
(Kea 3.2's HA hook defaults `restrict-commands` to true). `ARCHITECTURE.md`
and the README requirements list are updated for both paths.

### Not in this release

Authoring a fresh Kea config with the `http` control socket already in it
(so a brand-new Kea is reachable in direct mode without hand-editing) is
deferred to **5.10.1**. Until then, a config generated by "Author a
starting config" needs the `http` `control-sockets` entry added by hand —
the Admin Guide section walks through it.

## [5.9.1] - 2026-09-09

Follow-ups from the 5.9.0 review, plus the capitalisation nit.

### A bad certificate upload can no longer take Jen down

The certificate upload checked its inputs textually — "contains `BEGIN
CERTIFICATE`", "contains `PRIVATE KEY`" — and then overwrote the live
files and restarted. A perfectly valid certificate paired with the wrong
private key passed, gunicorn refused the pair at startup, and systemd's
`Restart=always` spun the console into an outage until someone SSHed in.

- **Upload validates first.** The pair (and the CA bundle, if given) is
  loaded with the same `ssl` API gunicorn uses, on temp files, before
  anything under `/etc/jen/ssl` changes. A mismatched key or a truncated
  PEM is refused with the reason and "Nothing was changed." Writes are
  atomic (`os.replace`) and the previous cert/key are kept beside the new
  ones as `.prev`.
- **Startup never crash-loops on a bad pair.** `run.py` loads the on-disk
  pair before launching HTTPS; if it can't, it logs CRITICAL, comes up
  **HTTP-only** so the console stays reachable to fix it, and sets
  `JEN_SSL_DISABLED=1` so the HTTPS redirect, the Secure cookie flag and
  the settings badges all agree that plain HTTP is what's being served.

### HTTP → HTTPS redirect

- **Query strings are preserved.** The redirect used `request.path`, so
  `/settings/databases?tab=backups` over HTTP landed on
  `/settings/databases` — noticeable now that Settings tabs are `?tab=`.
- **The Host header is validated** before it becomes a `Location`: a plain
  hostname, IPv4 or bracketed IPv6 (port stripped), anything else gets a
  400. Applies to both the in-app redirect and the standalone HTTP
  listener (`jen/httpredirect.py`). Low risk in practice — a browser sends
  the URL's own host — but there was no reason to build a redirect from
  an unchecked header.

### Updater

- **The running-process version is authoritative.** After the restart the
  updater must read the installed version back from `/api/v1/health`
  (retried a few times while the app warms up). The on-disk `JEN_VERSION`
  is no longer accepted as "confirmed running" — it only proves the copy
  succeeded, which is not the question.
- **Pruning keeps what recovery might need.** Stale `.rollback-*`
  snapshots are still pruned, but the newest always survives, and a
  snapshot the CRITICAL path marks with `.keep` is never auto-pruned —
  clicking Update again after a failed rollback must not delete the one
  intact copy of the previous release.

### Also

- ShellCheck runs in CI (`-S error` to start) on `install.sh`,
  `uninstall.sh` and `scripts/release_check.sh`.
- Sub-tab and jump-list labels are Title Case ("Updates & System",
  "Plugin Manager", "Audit Log", "Alert Log", "Ports & Threads", …).
- README still pointed IPv6 at "Settings → Infrastructure"; it's Settings
  → Kea.

## [5.9.0] - 2026-09-09

Settings, reorganised. Plus three small hardenings of the in-app
updater from watching a real box go through the 5.8.4 update.

### Settings is seven groups, not nine tabs and a junk drawer

The old Settings area had grown by accretion: an Infrastructure tab
with fourteen cards, a System tab with nine, the same Ports card on
both, SSH split across two tabs, branding in three places, and Jen
updates, plugin updates and Kea package installs each somewhere
different. Users, the audit log, API keys and API docs lived under
Settings because there was nowhere else. On a phone the nine-tab strip
overflowed and a fourteen-card page was a long blind scroll.

It's now organised by what you're trying to do:

| Group | What's there |
|---|---|
| **Kea** | Control Agent (v4 + v6), SSH — host, user, path *and* the key, one card — servers & HA, package status, config drift |
| **Databases** | Jen / Kea connection settings, plus the export, import, backups, schedule and migrate tools as tabs (superadmin) |
| **Access & Security** | MFA policy, session timeout, rate limiting, SSL certificate; Users, API Keys and API Docs as sub-tabs |
| **Alerts & Integrations** | Thresholds, channels, templates, DDNS/DNS provider, Prometheus |
| **Appearance** | Logo, nav colour, favicon, brand icons |
| **System** | Jen updates and the plugin summary in one place, ports & threads (one card), restart, audit retention |
| **Logs** | Audit log and the alert delivery log |

- `/settings` is a **landing page** — a grid of the groups with a live
  hint on each (Kea reachable, certificate expiry, users, enabled
  channels, backups, pending restart). On a phone that grid *is* the
  Settings navigation; group pages get an "All settings" link back and a
  jump list of their cards.
- **Database left the top nav.** The top bar is the same for admin and
  superadmin: Dashboard · Management · Network · Settings · About.
  Superadmin-only tools are gated per card, not by hiding menus.
- The navigation is defined **once**, in `jen/routes/settings/nav.py`,
  and `base.html` renders the top links, the mobile drawer and every
  section strip from it. Before, each was a hand-maintained list of
  endpoint names repeated three times and they had drifted.
- Section strips scroll horizontally on narrow screens instead of
  wrapping.

**Nothing changed for forms, bookmarks or the updater:** every POST
endpoint URL is unchanged; the old page URLs (`/settings/infrastructure`,
`/settings/icons`, `/database`, `/users`, `/audit`) redirect permanently
to their new homes, query strings intact. `tests/test_settings_ia.py`
pins all of that — every old URL's redirect, every group's active state,
and that every literal form action in the settings templates still
resolves.

### Updater

- **The health probe is baselined before the swap.** The updater now
  probes the currently-running Jen first; if it can't see a known-good
  app it aborts with `/opt/jen` untouched and says why, instead of
  installing a release and then rolling it back on a false negative —
  which is exactly what the 5.8.2 updater did to a healthy 5.8.4 on an
  SSL box.
- Stale `.rollback-*` snapshots from earlier failed runs are pruned at
  the start of each run (one box had four).
- The CRITICAL "rollback restart also unhealthy" line now names the
  probe URL and says plainly that if `systemctl is-active jen` reports
  active, the probe is what's wrong, not the restored app.

## [5.8.4] - 2026-09-09

Correctness, docs and small security fixes from a full code review of
5.8.3, plus the reason in-app updates were still failing on a
long-lived box.

### In-app update died at the snapshot step

The 5.8.2/5.8.3 updater snapshots `/opt/jen` before swapping files.
`shutil.copytree` followed symlinks by default, and one old install had
a stray dangling `/opt/jen/templates/templates -> (gone)` left behind
by some ancient upgrade — so every update raised ENOENT at the snapshot
and exited with a traceback. Because that happens before the swap,
nothing was damaged; the box just stayed on its old version, and the
update overlay reported "Jen restarted but still reports vX", which was
untrue (Jen never restarted).

- The snapshot (and the rollback restore) now copy symlinks *as*
  symlinks and never follow them. A snapshot failure aborts with a
  plain "could not snapshot — aborting, /opt/jen untouched" line.
- The updater exits early with "Already running vX — nothing to do"
  when GitHub's latest is what's already installed, instead of
  re-downloading and reinstalling it.
- New admin-only `/settings/infrastructure/update-status` (a read-only
  `systemctl show jen-update.service` — no `sudo`, so no sudoers
  change). The overlay polls it and now says **"Update failed (exit N)
  … `journalctl -u jen-update.service`"** when the unit failed, and
  only falls back to "still not confirmed" after 90 s.

### Security

- **Uploaded SVGs are refused if they carry active content.** Custom
  brand icons and an SVG nav logo are served same-origin from
  `/static/` under a CSP that allows inline script, so an SVG with
  `<script>`, an `on*=` handler, a `javascript:` link, a
  `<foreignObject>`, SMIL `<set>`/`<animate>`, an XML entity or an
  external/data `href` was stored XSS by an admin against a superadmin.
  Rejected on upload with a reason; never sanitized.
- **The CSRF exemption for `Authorization: Bearer` requests is now
  scoped to `/api/v1/`.** Before, *any* route skipped the CSRF check
  the moment a request carried a Bearer header — even a bogus one —
  while the session cookie still authenticated it. Not exploitable
  cross-site (a custom header forces a CORS preflight Jen never
  answers), but "a header disables CSRF" was the wrong invariant to
  keep. UI routes now require the token regardless of headers.
- `shlex.quote` on the two remaining remote paths interpolated into
  SSH commands (`kea_authoring.read_remote_json`,
  `kea6._config_exists`). Both were already validated on save; this is
  defense-in-depth.

### Bugs

- **Servers page → Restart** only tried the `isc-kea-dhcp4-server`
  unit. Every other restart in Jen tries `kea-dhcp4-server` first (ISC's
  own packages) and falls back — this one now does too, so the button
  works on ISC-package hosts.
- `login()` carried its own inline copy of the rate-limit check that
  reported the *whole* lockout window as "minutes remaining" rather
  than the time left from the oldest attempt — the same bug 5.8.0 fixed
  on the MFA side — and left `jen.services.auth.is_locked_out()` dead.
  Login now calls the one shared implementation.
- `release.yml` archived `HEAD` rather than the tag: identical on a
  tag push, wrong for a `workflow_dispatch` with a tag input.
- `legacy/jen.py` (the retired pre-2.6.0 monolith, 6,300 lines) is
  export-ignored and no longer ships in the release tarball.
- `scheduler.py` used `datetime.utcnow()` (deprecated in 3.12).

### Docs — the threat model catches up

- `ARCHITECTURE.md` §3.1 still described the pre-5.2.6
  `/tmp/jen_update_install.sh` grant. Rewritten for what `jen-sudoers`
  actually contains and why.
- `ARCHITECTURE.md` §3.3 now states the privilege implication of the
  SSH config push plainly: the Kea-side sudoers line grants
  `/usr/bin/python3`, which is root; a compromised Jen process is root
  on every managed Kea host. A fixed-path helper is the planned fix.
- The Kea-host sudoers instructions in the Admin Guide and
  Troubleshooting were incomplete and out of date (`kea-dhcp4`, `cp`,
  `tee` are no longer run directly; only one unit name; no
  `kea-dhcp6-server`, `tail`, `apt-get`). Replaced with one complete,
  honest block, validated with `visudo -c`.
- `CLAUDE.md`: versioning clarified (layout changes migrated by the
  installer/updater are MINOR), rule 9 (Kea-side sudo changes are
  documented sudoers changes), Kea-host conventions, `|tojson` and SVG
  rules, and the local-verification gotchas moved in from private
  notes.
- The Admin Guide and Installation guide still told people to
  `tar xzf jen-v5.3.3.tar.gz` and `jen-v3.8.0.tar.gz`. Both now use a
  `jen-vX.Y.Z.tar.gz` placeholder, and `scripts/release_check.sh` scans
  every guide for stale numeric references (and no longer needs
  `grep -P`).

### Tests

Subnet-scoped API keys are now tested against every `/api/v1` list and
by-MAC route (nothing covered §3.4's scope claim before); Servers-page
restart pins both unit names; the updater has a real dangling-symlink
snapshot test; the update-status route and the SVG checker have their
own suites.

## [5.8.3] - 2026-09-09

Fixes a bug in 5.8.2's own new post-restart checks, plus two smaller
follow-ups from external review.

### The updater's health check failed on SSL installs

5.8.2 added `service_healthy()` and `_running_version()`, both probing
`http://127.0.0.1:<http_port>/`. On an SSL install that port serves only
`jen/httpredirect.py`'s **301 to `https://<host>:<https_port>/`**, and
`urllib` follows redirects by default — so the probe chased the 301 into
a TLS handshake against a certificate issued for a hostname (or
self-signed), not `127.0.0.1`, which fails validation. The result:
`service_healthy()` timed out and **a perfectly healthy HTTPS upgrade
was rolled back**; `_running_version()` silently fell back to reading the
on-disk string, defeating the point of checking the running process.

Both probes now:

- talk to the app's **real port** — HTTPS directly when
  `/etc/jen/ssl/certificate.crt` + `private.key` are present, HTTP
  otherwise — bypassing the redirect listener entirely;
- **don't follow redirects** — a 301/302/401 is itself proof the app is
  serving;
- **don't verify TLS** on the loopback call (Jen's cert legitimately
  won't match `127.0.0.1`, and this is localhost).

The old `test_redirect_counts_as_healthy` mocked `urlopen` *raising*
`HTTPError(302)`, which never happens for a real redirect — it's replaced
with an integration test that stands up a real `jen/httpredirect.py`
listener and a real HTTPS server with a deliberately wrong-CN
certificate.

### Also

- `ensure_venv()`: if `apt-get install python3-venv` fails (a box old
  enough to be missing it often has stale package indices too), run
  `apt-get update` and retry the install once more before giving up.
- Docs: `docs/manual-install.md` and `ARCHITECTURE.md` §6 no longer call
  the updater flatly "transactional" — it's staged and rollback-capable,
  with the shared-venv and `static/` caveats stated inline. `static/` is
  a merge copy holding user favicon uploads, so a rollback leaves the new
  release's JS/CSS against the old templates; separating release-owned
  assets from uploads is tracked with the 6.0.0 versioned-release-dir
  work.

## [5.8.2] - 2026-09-09

In-app updater hardening, from a real deployment failure. A long-running
box that had only ever upgraded via the in-app button (never a
post-5.7 `sudo ./install.sh`) never had `python3-venv` installed. Every
in-app update since the PEP-668 world hit `externally-managed-environment`
and quietly carried on against stale system packages; the 5.8.0→5.8.1
attempt then tried to build `/opt/jen/venv`, got a half-built venv with
no `pip` (interpreter present, `ensurepip` never ran), and — because the
old check only asked "does this Python run?" — handed that back to `pip`
and failed with `No module named pip`. The transaction correctly aborted
with `/opt/jen` untouched, but the box was stuck: it could not update
itself out of the problem.

### The updater now builds its own venv

- `ensure_venv()` checks for a venv with a **working `pip`**, not just a
  runnable interpreter. A half-built venv is wiped and rebuilt.
- If `python3 -m venv` fails for want of the OS package, the updater
  (already running as root) `apt-get install`s `python3-venv` /
  `python3-full` and retries once, then falls back to the system
  interpreter with a loud warning only if that also fails.
- A failed `pip install` now logs the actual `pip` output for **every**
  attempt it made, instead of a bare "pip install failed".

### Post-restart verification

- The health-check timeout after the restart went from 45s to 90s (a
  slow homelab box doing migrations + background-worker init + gunicorn
  spawn was racing it), and is now overridable with
  `[server] update_health_timeout` in `jen.config`.
- After the restart the updater byte-compiles the freshly-installed
  `/opt/jen/jen` with the venv interpreter and confirms the **running**
  process reports the expected version (via `/api/v1/health`), rolling
  back if either fails — both inside the existing rollback transaction.
  The journal now says "Confirmed: jen is running v5.8.2" or rolls back
  with the mismatch.

**If your box is stuck reporting an old version after an in-app update:**
`sudo ./install.sh --upgrade` from the 5.8.2 tarball rebuilds the venv
and gets you current; in-app updates work from there.

## [5.8.1] - 2026-09-09

Fixes for two regressions in 5.8.0 plus the deployment-transaction gaps
from that release's review.

### The venv wasn't actually being used (bare-metal)

`run.py` decided "am I already the venv interpreter?" with
`os.path.realpath(sys.executable) != os.path.realpath(...venv/bin/python)`.
On Linux a venv's `bin/python` is a symlink chain back to the base
interpreter, so **both sides resolve to `/usr/bin/pythonX.Y`**, the guard
was always false, and the re-exec never happened — `jen.service` kept
running the system interpreter. Since 5.8.0 installs dependencies only
into `/opt/jen/venv`, a **fresh bare-metal install would crash-loop**
(and an upgrade quietly ran unisolated on leftover system packages). The
guard is now `sys.prefix == /opt/jen/venv`. The updater and the
installer had the same realpath mistake in a couple of spots; fixed.

If a bare-metal install is somehow running without its venv (an older
box that never had `python3-venv`, a failed build), Jen now shows an
admin banner and the updater logs it: `sudo ./install.sh --repair`.

### Docker `.env` quoting

5.8.0 wrapped **every** generated `.env` value in quotes. Docker Compose
before 2.24 doesn't strip quotes from `env_file:` values, so
`JEN_DB_PASS='plainpass'` reached the container with the quotes and auth
failed — a regression for anyone on older Compose with an ordinary
password. Values are now emitted bare unless they actually contain a
`$`, whitespace, `#`, a quote or a backslash; the Docker path checks for
Compose ≥ 2.24. And the "reuse an existing `.env`" path now reads an
explicit `JEN_DATABASE_MODE=external|bundled` marker instead of sniffing
credentials — the old heuristic matched the empty `JEN_MYSQL_PASSWORD=''`
that external installs write and could start an unwanted MariaDB
container.

### Self-updater is closer to actually transactional

- **Any** failure from the file-swap onward now rolls back — an
  exception mid-copy, not just a failed post-restart health check (5.8.0
  left `/opt/jen` half-updated in that case).
- The rollback snapshot now includes the files an update replaces
  *outside* `/opt/jen` — `jen.service`, `/etc/sudoers.d/jen`, the updater
  script, `jen-update.service` — with a `daemon-reload` on restore. A
  bad `jen.service` previously survived the rollback.

### Also

- MFA: `_remaining_mfa_factor_count()` now fails **closed** — if it can't
  count the user's remaining factors, a required-MFA user isn't allowed
  to remove one.

## [5.8.0] - 2026-09-09

### Bare-metal Jen runs from its own venv

Jen's Python dependencies move off system site-packages — no more
`pip install --break-system-packages` — into a dedicated virtualenv at
`/opt/jen/venv`. `install.sh` builds it (`python3 -m venv`, `--upgrade`
on re-runs so an Ubuntu Python bump doesn't strand it), installs
`-r requirements.txt` into it, and pulls `python3-venv` via apt when
it's missing.

`jen.service` **deliberately stays** on `/usr/bin/python3 /opt/jen/run.py`:
`run.py` re-execs into `/opt/jen/venv/bin/python` at the very top of the
file, before its first dependency import. Doing it as a re-exec rather
than a unit-file change means the unit never has to move, an in-app
update from a pre-venv install can't leave systemd pointing at a venv
that doesn't exist yet, and a missing or broken venv (a fresh box, or an
OS upgrade that stranded it — `sudo ./install.sh --repair` rebuilds)
falls through to the system interpreter. `JEN_NO_VENV_REEXEC=1` opts
out. Docker is unchanged — the container is the isolation.

The venv is left `root:root`, byte-compiled at install time: the
`www-data` service account reads and executes it but can't write it, so
a compromised web process can't plant persistent code in a package Jen
loads on every restart. Only `install.sh` and the root self-updater
touch it.

### Transactional self-updater

`jen-update-root.py` went from *replace `/opt/jen`, then `pip`
non-fatally, then restart* — which silently shipped a half-updated app
if a release genuinely needed a new library — to a staged flow:

1. download + checksum-verify, extract to a staging directory
2. ensure `/opt/jen/venv` exists (create it if the install predates it)
3. `pip install` the **staged** `requirements.txt` into the venv — a
   failure here **aborts before any file in `/opt/jen` is touched**
4. compile + import the staged `jen/` package under the updated venv —
   a failure aborts, still nothing changed
5. snapshot the replace-wholesale parts of the install, swap the files
   in, restart
6. health-check (unit active + the HTTP port answering below 500); if
   the service doesn't come back healthy, **restore the snapshot and
   restart the previous version**

Dependencies and code are proven against each other before the switch.
The venv is still shared, so a rollback keeps the newer (floor-pinned,
forward-compatible) dependencies rather than doing a true point-in-time
revert — a genuinely atomic switch waits for versioned release
directories in a future major (see `docs/ARCHITECTURE.md` §6).

### Security & reliability — authentication

A round of fixes from an external review of 5.7.0, in the auth/recovery
paths:

- **Mandatory-MFA enrollment could be bypassed.** When MFA was required
  but a user hadn't set it up, login called `login_user()` *before*
  redirecting to the enrollment page and nothing kept that
  fully-authenticated session off the rest of the app. Login now holds
  the user in a pre-authenticated *pending* state — password verified,
  but not a Flask-Login session — reachable only by `/mfa/enroll`; the
  session is promoted to a real login only once a factor is enrolled and
  verified. `tests/test_mfa_enrollment_gate.py` is the integration guard.
- **Backup codes never worked.** They were generated and hashed as
  `XXXXXXXX-XXXXXXXX` but the challenge path stripped the dash before
  re-hashing, so no entered code could ever match. Entered codes are now
  canonicalised back to the stored format — with or without the dash,
  any case, stray spaces — so already-issued codes work. Redemption is a
  single atomic `UPDATE … WHERE … used=0` that must change exactly one
  row, so two requests can't both spend one code.
- **Password rehash-on-login race** (introduced in 5.7.0 with the scrypt
  move): the background thread did an unconditional
  `UPDATE users SET password`, which could clobber a password changed in
  the meantime. It's now synchronous and conditional on the hash that
  was just verified still being the stored one.
- **MFA lockout "time remaining"** could display ~900 minutes just after
  lockout (it divided elapsed time by 60 inside the subtraction). Fixed.
- **Failed-attempt recording** for both password and MFA moved from a
  detached thread to synchronous, so a burst of parallel requests can't
  each pass its rate-limit check before the earlier failures land.
- **Docker `.env` values are now quoted.** `install.sh` writes every
  generated value through an escaping helper, so a password containing
  `$`, `` ` ``, `#`, spaces or quotes is no longer mangled by Docker
  Compose's interpolation.
- **You can no longer remove your last authenticator** while MFA is
  mandatory for your account — that would lock the policy out on the
  next login, and gives a stolen session no route to disabling MFA.
  Add a second one first. (A superadmin MFA-reset for a locked-out user
  is a separate, deliberate path and is unaffected.)

### Portability

- **CI now runs the full suite against MySQL 8** as well as MariaDB —
  the README has always claimed both, only MariaDB was tested. It
  immediately caught one: `dashboard_prefs.widgets` was
  `TEXT NOT NULL DEFAULT '…'`, which MySQL 8 rejects (a literal default
  on a `TEXT` column; MariaDB allows it). The baseline schema wouldn't
  build on MySQL at all. It's now `VARCHAR(512)`; migration 19 converts
  existing installs.

### Documentation

- `docs/manual-install.md` — the full bare-metal install by hand (every
  path, owner, and the venv), for a distro `install.sh` doesn't know or
  a config-managed host. The stale "Method 4" stub in the install guide
  (still referencing the pre-2.6.0 `jen.py` monolith) now points at it.
- `tests/README.md` rewritten to actually map the suite.

## [5.7.0] - 2026-09-08

### Alert-channel tokens encrypted at rest

`alert_channels.config` — a JSON blob holding every notification
channel's delivery credentials (Telegram bot tokens, SMTP passwords,
Pushover user/API keys, ntfy tokens, and the Slack/Discord/webhook URLs
that themselves embed a secret) — was stored as plaintext. Any read of
that one column (a stray database export, a read replica, SQL injection,
a shared DB host) handed over working credentials for every channel. This
was the same exposure the v5.4.0 work closed for TOTP secrets, on the
last unprotected reversible-secret surface in `jen_db`.

- The whole `config` blob is now encrypted with the existing Fernet key
  (`jen/services/crypto.py`, key at `/etc/jen/mfa_key`, outside the
  database) — whole-blob rather than per-field, so a new channel type
  with new secret fields is covered automatically. The `v1:` token is
  stored as a JSON string literal so the column stays valid JSON
  (MariaDB enforces `json_valid()` on it).
- **Migration 18** wraps every existing plaintext blob on upgrade,
  idempotently. New saves encrypt at write time; every read goes through
  `alerts.get_channel_config()`, which decrypts, with a legacy-plaintext
  passthrough for any row the migration hasn't reached.
- A blob that can't be decrypted (a DB restored onto a new install
  without copying `/etc/jen/mfa_key`) makes that channel go quiet rather
  than crashing alert dispatch — the tokens must be re-entered, same as
  MFA secrets in that situation. The database-export screen now says so.

### New passwords hashed with scrypt

`hash_password()` moves from `pbkdf2:sha256:260000` to scrypt
(`scrypt:32768:8:1`, werkzeug's current default). scrypt is memory-hard —
~32 MB per hash — where pbkdf2 is not, which is what makes it meaningfully
harder to attack with GPUs or ASICs, while staying fast enough for
interactive login (~50–100 ms).

- Existing pbkdf2 hashes keep verifying and are transparently upgraded to
  scrypt on the user's next successful login — the same
  rehash-on-login path that already handled iteration-count bumps and the
  original SHA-256 → pbkdf2 move. No forced password resets.
- `needs_rehash()` now flags any pbkdf2 hash (and any scrypt hash at
  non-current cost parameters) for upgrade.

### Documentation

- **README:** new "How Jen talks to Kea" section (the three channels —
  Control Agent HTTP, the Kea database, SSH — and what each is for), and
  a "Jen compared to ISC Stork" table laying out the agentless-vs-agent,
  management-vs-monitoring, MySQL-vs-PostgreSQL tradeoffs so people can
  tell quickly which tool they actually want.
- **`CONTRIBUTING.md`** added: dev setup, the CI gates, and a candid list
  of what does and doesn't fit the project's direction.

## [5.6.1] - 2026-09-08

### Split the two monolith files (`settings.py`, `test_kea6.py`)

Pure refactor — no behaviour change, no route or endpoint renamed.
Both reviews flagged these as the maintainability frontier, and the
next feature (Kea CA-less support) adds routes and fields to Settings,
which is much nicer on a split module than a 2,060-line one.

- **`jen/routes/settings.py` → `jen/routes/settings/`** (a package):
  `alerts`, `infrastructure`, `authoring`, `branding`, `security`,
  `updates`, each registering on the one `bp` so every endpoint stays
  `settings.<fn>` and every `url_for("settings.…")` resolves unchanged.
  `_parse_subnet_lines` / `_subnets_to_lines` are re-exported from the
  package root for their existing importers. Dropped one dead helper
  (`__ip_to_int`, defined and never called).
  `tests/test_settings_blueprint.py` freezes the full 48-endpoint set as
  a drift guard. Three sibling tests that locate route code by file path
  (`test_no_raw_exception_leaks`, `test_sudoers_command_matching`) now
  scan the package instead of the old single file.
- **`tests/test_kea6.py` → `tests/test_kea6_*.py`** by feature area
  (config, service toggle, leases/devices, reservations, subnets,
  search/metrics) plus `tests/test_kea_authoring.py` for the
  Kea-config-authoring flow. Shared `FakeSSHClient` helper moved to
  `tests/_kea6_helpers.py`.

## [5.6.0] - 2026-09-08

### Docker configuration unified on `.env`, plus a hygiene pass

Two more third-party reviews. No new application features; the
interesting security work already shipped in 5.4.x/5.5.0. Both flagged
the Docker install path as the one thing to fix before pointing new
users at it.

**Docker is now `.env` / `JEN_*` only.** The installer's Docker path
built a `jen.config`; the compose files used `env_file: .env` with the
config mount commented out; the README told you to edit `jen.config`.
Following any of the three documented paths left Jen unable to start.

- `install.sh --docker` now writes `.env` (not `jen.config`): the
  guided wizard for the Kea side, a generated MariaDB password for the
  bundled path, and the admin password you choose.
- `docker-compose.mysql.yml` wires the `jen` container to the
  `jen-mysql` container via `environment:` (`JEN_DB_HOST=jen-mysql`,
  `JEN_DB_PASS=${JEN_MYSQL_PASSWORD}`) — `.env` no longer carries (or
  drifts on) the bundled DB credentials, just `JEN_MYSQL_PASSWORD` once.
- `.env.example`, `README.md`, and `docs/docker.md` rewritten to match.
- New `tests/test_docker_config.py` fails CI if the pieces drift apart
  again.

**First-run admin password for Docker.** The bare-metal installer sets
an admin password during setup; the Docker path never did and its
summary still said `admin/admin`. New `JEN_INITIAL_ADMIN_PASSWORD` env
var: `init_jen_db()` seeds the `admin` account from it (with
`must_change_password=0` — the operator picked it) on first boot only,
then never reads it again. `install.sh` writes it into the Docker `.env`
and, on bare metal, `_set_admin_password()` now also clears
`must_change_password` (it was leaving bare-metal installs to force a
redundant change of a password the operator had just chosen).

### Hygiene pass: TLS floor, metrics token, CI matrix, docs reconciliation

- **gunicorn SSL path had no TLS-version floor.** It passed `--ciphers`
  but nothing pinned the minimum protocol, so the production path was
  weaker than run.py's werkzeug fallback (which sets `TLSv1_2`). New
  `jen/gunicorn_conf.py` with an `ssl_context` hook restores the
  `TLSv1_2` minimum; `run.py` always passes
  `--config python:jen.gunicorn_conf`.
- **`/metrics` token check hardened.** Constant-time comparison
  (`secrets.compare_digest`) instead of `==`; the `?token=` query-string
  form is dropped (it would land verbatim in gunicorn's access log,
  which 5.5.0 routes to stdout/journald) — Bearer header only; and the
  "not configured" 401 body no longer spells out which config keys to
  set.
- **`_build_config_from_env()`** now reads an existing `jen.config` with
  `interpolation=None`, matching `AppConfig` — a DB/API password
  containing a literal `%` no longer trips `ConfigParser`.
- **CI now tests Python 3.10 as well as 3.12** (matrix). The README
  claims 3.10+ / Ubuntu 22.04; with floor-pinned deps a future
  "latest compatible" package could drop 3.10 while CI stayed green.
- **CI uses `JEN_ROOT` instead of symlinking the checkout into
  `/opt/jen`.** The old `ln -sf` step and its "create_app() hardcodes
  the path" comment predated the `JEN_ROOT` override (5.3.3) — removing
  them proves the override actually works.
- **Dependabot** now watches `pip` (the stale note said Jen pins deps
  inline in install.sh — true until 5.4.1's `requirements.txt`), and its
  first round of bumps landed: gunicorn, cryptography, requests, authlib,
  werkzeug floors raised; `actions/setup-python` and
  `softprops/action-gh-release` pinned SHAs moved forward (fixes the
  Node 20 deprecation warning).
- **Docs reconciliation:** `ARCHITECTURE.md` §3.4 (API keys have been
  per-key subnet-scopable since migration 13, not global-only), §3.5/§6
  (the self-updater runs pip as of 5.5.0). README: MFA line no longer
  claims WebAuthn/passkey (the page says "coming soon"); Flask badge
  3.0 → 3.1+. `jen.service` description "Internet" → "Kea DHCP" to match
  the README.

### Ruff is now a CI gate

The whole codebase was run through `ruff format` + `ruff check --fix` —
one mechanical, zero-behaviour-change pass (verified: bandit shows no
new findings, the full suite is green). The ~71 backlog findings
(compound one-liners, unsorted imports, one unused var, thirteen
ambiguous `l` names) are gone.

CI now runs `ruff check .` and `ruff format --check .` as a job, so new
lint or format regressions fail the build. `ruff` is pinned exact in
`requirements-dev.txt` — its formatter output drifts subtly between
releases, so an unpinned bump could fail `format --check` on a no-op;
Dependabot PRs the bump and we reformat in that same PR if needed.

## [5.5.0] - 2026-09-08

### gunicorn replaces the werkzeug dev server

Through 5.4.x, `run.py` *was* the server — `werkzeug.serving.make_server`
/ `app.run`, the Flask development server. `threaded=True` (5.3.3)
stopped one slow request from blocking every other user, but it was
still the dev server: no request timeouts, no graceful drain, unbounded
thread spawning. For something marketed as a management console that's
the first thing a skeptical network engineer dings.

**`run.py` is now a launcher, not a server.** It loads config and then
runs gunicorn (`jen.wsgi:application`):

- **No SSL:** `os.execvp` gunicorn on the HTTP port — the process is
  replaced, systemd owns gunicorn directly.
- **SSL:** gunicorn runs as a child (HTTPS, `--certfile/--keyfile`);
  `run.py` stays parent, serves the HTTP→HTTPS 301 redirect
  (`jen/httpredirect.py`, stdlib only) and forwards SIGTERM to gunicorn.
  A `systemctl restart jen` now **drains** in-flight requests
  (`--graceful-timeout 30`, `jen.service` `TimeoutStopSec=40`) instead
  of cutting them.

**`--workers 1 --threads N`** (N = `[server] threads` in jen.config,
default 8, editable in Settings → Infrastructure → Server Ports &
Performance; a restart applies it). Jen is I/O-bound (DB, Kea API, SSH),
so threads carry the concurrency and a single worker keeps the backup
scheduler and the alert loop single-process. Those were started by
`create_app()` before — which under gunicorn would have run them once
per worker. Now the factory only builds the app; `jen/wsgi.py` starts
the background workers once, in the sole worker. Multi-worker gunicorn
is deliberately not offered (it reopens "scheduler runs N times").

**Werkzeug fallback, safety-net only.** If gunicorn can't be imported or
launched (a bad dependency install, a non-Linux dev box), `run.py` logs
a CRITICAL and falls back to the old werkzeug path so the console
doesn't go dark. It is not a supported production path and says so on
every start.

**The self-updater now runs pip.** `jen-update-root.py` copied files but
never installed dependencies — so a file-only self-update to 5.5.0 would
land a `run.py` that expects gunicorn to be present. It now runs
`pip install -r /opt/jen/requirements.txt` after the file install,
non-fatally (logged on failure; the werkzeug fallback covers a missing
package until a `sudo ./install.sh --upgrade`). This closes the PENDING
"self-updater doesn't run pip" gap.

`gunicorn>=23.0.0` added to `requirements.txt`. New tests:
`test_run_launcher.py` (command-line construction, SSL/non-SSL
branching, thread clamping), `test_background.py` (the factory starts
nothing; `start_background_workers` is idempotent), and self-updater
pip-step coverage in `test_jen_update_root.py`.

## [5.4.1] - 2026-09-08

### One dependency list instead of four

The same ~14 runtime packages were pinned independently in `install.sh`,
`Dockerfile`, and both jobs of `.github/workflows/tests.yml`. They had
already drifted: `werkzeug` was pinned in the Dockerfile, missing from
`install.sh` (relying on flask to pull it), and unpinned in CI;
`cryptography` (added in 5.4.0) was pinned in two places and unpinned in
CI. The `Dockerfile` `LABEL version` had also sat at `5.3.3` through the
entire 5.4.0 release.

- **`requirements.txt`** at the repo root is now the single source of
  truth — floor-pinned (`>=`), the deliberate choice documented in
  `docs/ARCHITECTURE.md` §3.5 (a lockfile was considered and rejected
  for this project's solo-maintenance model; `pip-audit` in CI is the
  compensating control). `install.sh`, the Docker build, and both CI
  jobs now `pip install -r requirements.txt`. `requirements-dev.txt`
  adds the test/lint tooling.
- **`jinja2>=3.1.6`** and **`werkzeug>=3.1.7`** are now pinned
  explicitly rather than left as transitive flask dependencies, so a
  security floor (e.g. jinja2 3.1.6 for CVE-2025-27516) doesn't depend
  on flask happening to require it.
- **`tests/test_dependency_consistency.py`** fails CI if any consumer
  re-inlines a package pin, and if the version strings that must move
  together (`jen/__init__.py`, `install.sh`, `Dockerfile` LABEL, README
  badge, CHANGELOG) fall out of sync.
- `requirements.txt` now travels with each release and is copied to
  `/opt/jen/`. The in-app self-updater still does **not** run `pip` —
  a release that adds or raises a dependency floor needs a
  `sudo ./install.sh --upgrade`, noted in §3.5 and `PENDING`.

No runtime behavior change — this is a build/packaging refactor.

## [5.4.0] - 2026-09-08

### TOTP secrets are now encrypted at rest

`mfa_methods.secret` — the shared secret behind every enrolled
authenticator app — was stored as plaintext base32. Anyone able to read
that one column could generate valid second-factor codes for every user
and walk straight through MFA: a downloaded or misplaced database
export (Jen's own export UI includes this table), a read replica, a
compromised database account, SQL injection anywhere in the app, or a
shared database host. Backup codes, trusted-device tokens, and API keys
were already one-way sha256 hashes; the TOTP secret is the one value
Jen has to be able to read back (it recomputes the current code from it
every 30 seconds), so the fix is encryption with a key kept outside the
database, not a hash.

**How it works.** A new `jen/services/crypto.py` wraps each secret with
Fernet (AES-128-CBC + HMAC, from the `cryptography` library — already a
transitive dependency via paramiko, now pinned explicitly). Stored
values gain a `v1:` prefix so a future key rotation is a recognisable,
migratable format rather than an ambiguous blob. The key lives at
`/etc/jen/mfa_key` (0600), with the same two-candidate load-or-create
logic and `$JEN_ROOT` fallback that `_load_secret_key()` already uses
for the Flask session key — created on first use, not by the installer,
and preserved across upgrades because `/etc/jen` always is.

**Upgrade.** Migration 17 encrypts every existing plaintext secret in
place on the first restart after updating. It's idempotent (rows
already in `v1:` form are skipped) and shares one transaction with its
own version record, so a crash partway through recovers cleanly on the
next start. New enrolments encrypt at the point of insert;
`verify_totp()` decrypts on read, with a passthrough for any
still-plaintext value so nothing breaks in the window before migration
17 runs.

**Key loss fails closed.** If `/etc/jen/mfa_key` can't be read (a
database restored or migrated onto a different install without copying
the key across) `verify_totp()` skips the unreadable row and returns
false — the affected user falls back to their backup codes and an admin
can reset their MFA. A missing-and-unwritable key aborts startup during
migration rather than inventing an ephemeral one that would render
every stored secret permanently unreadable. Database exports now carry
`v1:` ciphertext instead of plaintext (an improvement — export files
were a leak vector), with the tradeoff that MFA secrets do not restore
onto a different install; this is called out in the export table
description and `docs/troubleshooting.md`.

16 tests added (`tests/test_mfa_encryption.py`): crypto round-trips and
failure modes, migration 17 (encrypt + idempotent re-run), the
enrol/verify wiring, legacy-plaintext compatibility, and the
fail-closed paths.

## [5.3.3] - 2026-09-08

### The privileged updater can now update itself, a migration gap closed, and Ruff added

Three items from a second round of third-party review, deliberately
combined into one release since two are small and well-scoped, and
the third (Ruff) touches the same broad surface without any
interaction risk between the three.

**The updater couldn't update itself.** `install_extracted_files()`
(the v5.2.6 rewrite) installs the application it updates — `jen/`,
`run.py`, `templates/`, `static/`, `jen.service`, `jen-sudoers` — but
never a new copy of `jen-update-root.py` itself, or of
`jen-update.service`. A fix shipped inside the updater would therefore
never reach a running instance via the in-app update button; only a
manual `sudo ./install.sh --upgrade` would ever pick it up, quietly
recreating the exact "self-update can't fix itself" maintenance trap
the v5.2.6 redesign exists to close for the application. Fixed with a
new `install_self_update_files()`: writes to a temp file in the same
destination directory, sets root:root ownership and the correct mode
(0700 for the script, 0644 for the service unit) on the temp file
*before* the atomic rename via `os.replace()`, then reloads systemd.
Safe to do while this exact script is the one currently running — the
interpreter already has the source read into memory before execution
began, so only the *next* invocation ever sees the new file. Added 7
regression tests, including the specific one requested: "a verified
release containing a newer root updater installs it root-owned and
non-writable by www-data." Caught two mistakes in my own first draft
of these tests before trusting them — one asserted a total call count
that didn't account for the service file getting its own separate
call, the second one checked the wrong path entirely, since ownership is
set on the temp file before the rename, not the final destination.

**Migration 15 didn't protect existing installations.** It added
`must_change_password` with `DEFAULT 0` — correct for new rows going
forward, but every row that already existed when it ran got treated as
"already fine," including an admin account still sitting on the
literal password `admin`. Only a genuinely fresh install was actually
protected. Couldn't be fixed by editing migration 15 itself — the
migration runner never re-invokes an already-applied migration, and
most currently-deployed installations already have it recorded as
applied. Added migration 16 instead: checks every unflagged user's
password against the literal string `"admin"` via `verify_password()`
(hashes are salted, so this can't be a direct hash comparison) and
retroactively flags any match, checking every user rather than just
the admin account. Verified the decision logic directly with real
password hashing against three simulated users before trusting it.

**Ruff added to the project for the first time.** A standalone
`ruff.toml` (deliberately not folded into a future `pyproject.toml` —
dependency management is a separate, larger piece of work this project
has intentionally deferred), scoped conservatively: pyflakes,
pycodestyle, import sorting, pyupgrade, and bugbear, excluding
`legacy/jen.py` (explicitly documented as dead reference code, never
imported or executed by the live application). First scan: 734
findings. Ran the safe, mechanical auto-fixes (493 of them — mostly
unused and unsorted imports) and verified the result rather than
trusting it: spot-checked the diff on `settings.py`, confirmed every
removed import was genuinely unused via direct search, and ran
pyflakes across all 62 touched files to catch anything the auto-fix
might have broken.

Manually reviewed and fixed the remainder individually rather than
applying further automation blindly: a bare `except:`; seven
`raise ...` statements inside exception handlers now explicitly chain
with `from e` (one of these had an `except ValueError:` that didn't
even bind the exception to a name — applying the mechanical fix
without checking would have introduced a `NameError`); three
genuinely-unused imports in `jen/__init__.py`, each confirmed unused
by direct search before removal, with the whole package re-verified to
still import and `create_app` still callable afterward; two imports in
the IPAM and network-discovery plugins moved to the top of their
files; three unused loop-control variables renamed per Ruff's own
convention; and two `zip()` calls given explicit `strict=` values —
these needed *opposite* answers, not the same fix twice.
`migrations.py`'s registry sanity check needs `strict=False` (the two
lists being compared are intentionally different lengths by exactly
one element; `strict=True` there would make the assertion always fail
and break the app at import time — confirmed by importing the module
after the change), while the extra-Kea-servers form handler in
`settings.py` needed `strict=True`, since it zips eight independently-
submitted form arrays that could legitimately mismatch in length under
a malformed or tampered POST — silently truncating to the shortest one
would misalign one server's fields with a different server's. That one wasn't a
mechanical fix alone: the surrounding route had no exception handling
at all, so `strict=True` on its own would have turned a length
mismatch into an uncaught `ValueError` and a raw 500. Added a
try/except around it with a clean error message instead. Directly
verified both the normal (matched-length) and the new protective
(mismatched-length) cases.

**Deliberately deferred, not silently decided:** 69 remaining findings
are purely stylistic — compound one-line statements (`try: x` /
`except: y` on one line) and single-letter ambiguous variable names.
Fixing these by hand wasn't the right use of manual review time, and
running Ruff's full formatter would produce a whole-codebase diff
(quote-style and spacing changes across thousands of lines) large
enough to swamp the two substantive fixes in this same release. Left
as a follow-up decision rather than made unilaterally.

Bandit's finding count dropped from 141 to 131 as a side effect of
this cleanup, not a suppressed check: several of the files touched had
a genuinely-unused `import subprocess` or `import threading` that
bandit flags on the import statement itself regardless of whether it's
used, and removing genuinely dead code removed those specific
findings along with it. Confirmed directly rather than assumed.

### A second round of review — two independent reviewers, real convergence

A second third-party review (independent of the one above) surfaced
six more items, several of which the first review's author also
flagged independently — two different reviewers arriving at the same
conclusions without coordinating is a stronger signal than either
alone.

**The global exception handler leaked raw exception text — the most
important item here.** `jen/__init__.py`'s catch-all
`@app.errorhandler(Exception)` interpolated the raw exception directly
into the user-facing error page:
`message=f"An error occurred: {e}"`. This is a real gap in the v5.2.14
"stop leaking exceptions" work: that release fixed dozens of
individual per-route `except Exception as e:` blocks, but never
touched this single global handler, which catches literally anything
unhandled anywhere in the app. Fixed to use a generic message —
matching the 404 and explicit-500 handlers immediately above it in the
same file, which were already doing this correctly — while the full
traceback still goes to the server log via the existing
`logger.exception()` call. Nothing about debugging capability changed,
only what reaches the browser.

The regression scanner from v5.2.14
(`tests/test_no_raw_exception_leaks.py`) had two gaps that let this
through: it only scanned `jen/routes/*.py`, never `jen/__init__.py` or
anything else in the package, since the bug it was designed around was
route-shaped; and its pattern list covered `flash()`/`jsonify()`/
`api_error()` calls specifically, never a bare `message=f"...{e}"`
keyword argument. Both fixed — the scanner now covers the whole `jen/`
package recursively, and the pattern list catches this shape too.
Verified the fix has real teeth the same way the original scanner was
verified: planted the exact bug that just shipped in a throwaway file
and confirmed the widened scanner catches it. The wider scan also
turned up one more real instance in `jen/routes/ddns.py` that the
original, narrower scanner had also missed.

**Werkzeug's dev server had no threading.** `run.py`'s `make_server()`
calls (both the HTTPS server and the HTTP-redirect server) and the
HTTP-only `app.run()` fallback all defaulted to handling exactly one
request at a time, globally, across every user of the app — a slow
SSH-backed config apply or a slow Kea API call blocked every single
concurrent request, including basic page loads, until it finished.
Added `threaded=True` to all three. This is not a substitute for a
real production WSGI server (gunicorn) — that's a larger, deliberate
migration queued as its own next piece of work, since it needs to
solve a real problem first: the background alert-checking thread
currently starts once, in the one process `run.py` runs; naively
adding multiple gunicorn worker *processes* would start it once per
worker, producing duplicate alerts for every single lease event. This
fix closes the acute, immediate symptom (the app appearing to hang
under even light concurrent use) without taking on that migration yet.

**Hardcoded `/opt/jen` path removed.** `jen/__init__.py`'s Flask app
factory passed `static_folder="/opt/jen/static"` and
`template_folder="/opt/jen/templates"` as literal strings, which made
a local clone-and-run hostile — nothing under `/opt/jen` exists outside
a real install — and forced CI to symlink the checkout into place to
work around it. Introduced a single `JEN_ROOT` constant in
`extensions.py`, defaulting to `/opt/jen` (so every existing production
install's behavior is completely unchanged — verified the default
resolves to the exact original hardcoded values), overridable via the
`JEN_ROOT` environment variable for local development. Every
`/opt/jen`-rooted path in the active application (`STATIC_DIR`,
`TEMPLATE_DIR`, `FAVICON_PATH`, `PLUGIN_DIR`, and several more) now derives
from it instead of repeating the literal path. `install.sh` and
`jen-update-root.py` deliberately keep their own hardcoded references
— those manage real production installs, which is a different concern
from "can this be run locally for development."

**Plugin installation gained checksum verification.** Mirrors the same
principle already applied to the self-updater in v5.2.6: HTTPS-only,
manifest ID matching, and zip-slip-safe extraction were already
present, but nothing verified the downloaded plugin zip's integrity
against anything published alongside it — a compromised
`registry.json` or a compromised plugin repository could serve
arbitrary code, executed as `www-data`, plus whatever `db_migrations`
the manifest declares. Deliberately *not* fail-closed on a missing
checksum, unlike the self-updater: the two plugins that exist today
(network-discovery, ipam) don't have one in the registry yet, and
there's no way to manufacture a trustworthy hash for zip files hosted
in separate repositories without a verified, out-of-band copy of them
— computing one from what this function just downloaded would be
circular and add no real security. A registry entry *with* a `sha256`
field that doesn't match is a hard failure; one *without* the field
logs a warning and installs anyway, as a visible, deliberate transition
state rather than a silent gap. Verified all three cases directly —
matching, mismatched, and missing. **Existing plugin maintainers: real
`sha256` values need adding to `plugins/registry.json` the next time
either plugin is released, computed against the actual current
`plugin.zip` — this can't be generated after the fact by anyone who
doesn't already have a verified-good copy.**

**`/metrics` now defaults to closed.** Previously, no configuration at
all meant the endpoint was fully open — deliberate, documented
behavior ("unauthenticated by design for scraper compatibility"), not
an oversight, but backwards from a secure-by-default posture even
though the data exposed is limited to aggregate counts, never
individual MACs, IPs, or hostnames. **This is a breaking change**: set
either `metrics_token` (recommended — token-protected access) or the
new `metrics_open = true` (restores the old fully-open behavior, for
anyone who's already decided that tradeoff is fine given their network
setup) in `jen.config`'s `[server]` section. With neither set,
`/metrics` now returns 401. Updated `docs/admin-guide.md`, which had
also drifted to claim the wrong config section name (`[jen]` instead of
the actual `[server]`) on top of describing the old default. Also
added a proper Settings UI for this (Settings → Infrastructure →
Prometheus Metrics — token field with a "Generate" button, plus an
"Allow open access" checkbox), rather than requiring a config-file
edit for something this project has consistently kept
UI-driven. No restart needed, unlike the ports card right above it in
the same page — `extensions.cfg` is read fresh on every `/metrics`
request, so the setting takes effect on the very next scrape.

**`CHANGELOG.md` trimmed from ~330KB to ~100KB.** It had become an
audit log rather than a changelog — every release since v1.0.0, all in
one file, 223 entries. Moved everything before the 5.x series (182
entries, v4.4.24 and earlier) into
`docs/release-history/CHANGELOG-archive-pre-5.0.md`. Nothing deleted,
only relocated — did this programmatically rather than by hand given
the file's size, and verified the split reconstructs the original file
byte-for-byte before writing anything, then separately verified entry
counts on both sides and spot-checked specific entries for content
integrity. The in-app "What's New" viewer only ever shows the 5 most
recent entries regardless, so this has no effect on it.

### Test fixes caught by CI before this ever got tagged

Since this release was never actually pushed or tagged, CI on the
first attempt at it caught real mistakes worth being honest about
rather than quietly folding away: four of the new updater self-update
tests either called the real `systemctl daemon-reload` (unmocked,
which fails outside a real systemd environment) or referenced a
destination directory that was never created with `.mkdir()` first —
both classes of mistake I'd actually already caught and fixed once in
ad-hoc scratch testing while writing these tests, but didn't correctly
carry into every corresponding formal test method. Separately, three
tests in `test_kea6.py`'s own Prometheus v6 metrics suite broke
outright from the `/metrics` default-closed change, and two more in
that same class were passing for the wrong reason — asserting specific
text was *absent*, which is trivially true of a 401 page too, not a
meaningful confirmation of what they claimed to test. All were missed
because the search for `/metrics` usages when making that change only
covered `test_dashboard.py`; a repo-wide search afterward found this
second file. All nine now fixed and individually re-verified directly
before repackaging, not just re-run and trusted.

A second CI run, against the same still-untagged release, caught one
more: the new `TestMetricsSettings` class assumed each test could
rely on a predictable starting state — "default closed," or "whatever
the previous test in file order left behind." `jen.config` is a real
file on disk, not reset between individual tests the way the database
fixture is, so a write from one test genuinely persists into the
next. `test_short_token_rejected` expected `/metrics` to still be
closed after its own (correctly rejected) short token, but the
previous test in file order had left `metrics_open=true` behind, so
the endpoint was actually open — an assertion of 401 got a 200
instead. Fixed by having every test in the class explicitly establish
its own starting state via a setup call first, rather than assuming
one; verified by simulating the exact five-test sequence against the
real route logic both before and after the fix, reproducing the
identical 200-instead-of-401 failure from CI on the unfixed version
before confirming the fixed version resolves it.

## [5.3.2] - 2026-09-08

### Rebrand follow-up: About page missed, dedicated navbar asset

Two gaps from v5.3.0's rebrand, both reported directly after checking
the deployed app rather than caught beforehand.

**The About page still showed the old branding** — a CSS gradient-text
"Jen" heading, the exact same pattern already replaced on the login
and MFA verification pages in v5.3.0, just missed there. Confirmed via
a repo-wide search for the specific gradient CSS this time, not just
the handful of templates checked in the original pass — login.html and
mfa_challenge.html were already clean; about.html was the only
remaining instance. Replaced with the same wide wordmark image used
elsewhere.

**Navbar logo replaced with a dedicated, hand-tuned asset.** v5.3.0
used the same wide wordmark image everywhere, relying on CSS to scale
it down to navbar size (28px tall). A purpose-built 99×32 export,
tuned specifically for legibility at that exact small size, now ships
instead — `static/icons/jen-logo-navbar.png`. The navbar's CSS height
now matches this asset's native size (32px, up from 28px).

No application behavior changed — this release is template and asset
content only, matching the scope of v5.3.0 itself.

## [5.3.1] - 2026-09-08

### Fix CI failure carried over from 5.2.14 (also present in 5.3.0)

Three tests in `tests/test_no_raw_exception_leaks.py` failed —
present in 5.2.14's own CI run, and still present in 5.3.0 since that
release never touched this test file or the routes it covers.

**Root cause, found by actually reading the failure rather than
re-running and hoping:** `jen.__init__.load_user()` (Flask-Login's own
per-request user-loading callback) does a *local*, per-call `from
jen.models.db import jen_db` — meaning it always resolves whatever the
*current* attribute on the `jen.models.db` module is, not a reference
captured once at import time. Three of this file's tests patched
`jen.routes.X.__db.jen_db` to simulate one route's own database
failure — but for any route module that imports the db layer as
`import jen.models.db as __db` (as opposed to `api.py`'s `from
jen.models.db import jen_db`, which creates an independent local
name), `__db.jen_db` **is** `jen.models.db.jen_db`, not a copy. Patching
it broke authentication itself for the duration of the mock:
`load_user()` also calls `jen_db()` on every request, before the route
body ever runs, so every request in those three tests appeared
unauthenticated and got redirected to login (302) — the route's own
exception-handling was never actually reached or exercised at all.

**A second, distinct bug found while fixing the first:** the
dashboard-stats test mocked `jen_db()`, but `api_stats()` actually
calls `__db.kea_db()` in its own logic — confirmed by reading the
route directly. That test's mock was never touching the code path it
claimed to test; the assertion would have passed regardless of whether
the underlying exception-hiding fix (from v5.2.14) worked at all. Fixed
by mocking the function the route actually calls, which also needed
none of the load_user() workaround below, since `kea_db()` is never
touched by `load_user()`.

**The fix** for the remaining two: a `side_effect` wrapper that walks the
*entire* call stack (not just the immediate caller) looking for a
frame named `load_user`, delegating to the real function when found so
authentication proceeds normally, and raising the test's exception for
any call that isn't. Walking the full stack rather than checking one level up
was necessary because `unittest.mock`'s own call machinery
(`__call__` → `_mock_call` → `_execute_mock_call` → the side_effect)
introduces several frames of its own — an initial version of this fix
checked only the immediate caller and never actually matched
`load_user` when run through a real `patch(..., side_effect=...)`,
only when called directly in isolation. Verified the corrected version
through actual `unittest.mock.patch` machinery, not just a bare
function call, before trusting it — confirming `load_user()` gets the
real result while a simulated route handler still raises.

No application behavior changed; this is a test-only fix.

## [5.3.0] - 2026-09-08

### Rebrand — new logo across the entire app

Jen's first real visual identity: a wordmark plus a standalone router-
icon mark, replacing the plain-text "Jen" and generic default icons
used everywhere until now.

**A design problem found before it shipped:** the full wordmark, which
looks good at normal sizes, was tested directly at actual favicon size
(16×16, 32×32) and turned out nearly illegible — just a green smudge,
not a recognizable mark. Rather than ship that, the red router icon
(with its radiating signal lines) was isolated from the wordmark via
color-based pixel analysis and confirmed legible at 16×16 through
direct visual inspection. App icons now consistently use this
standalone mark; the full wordmark is reserved for wide contexts
where there's room to show it properly.

**Assets replaced**, all generated from the source artwork rather than
hand-drawn: `favicon.ico` (a genuine multi-resolution ICO — verified
by parsing its byte structure directly, not just trusting the save
call, since an earlier attempt silently produced a single-size file),
`icon-192.png`, `icon-512.png`, `apple-touch-icon.png` — all using the
icon-only mark on a dark background matching the PWA manifest's own
declared `background_color` (`#0d0d0d`, chosen to match Jen's overall
dark UI theme rather than the older teal accent color). A new
`jen-logo-wide.png` (transparent background, full wordmark, trimmed to
its actual content and resized to a sensible file size) is used for
the nav bar, login page, and MFA verification page.

**Where it now appears:**
- Nav bar — this is now the default logo shown to everyone, not
  hidden behind the existing "upload a custom nav logo" admin setting.
  That setting is untouched and still works exactly as before; it now
  overrides this new default instead of overriding plain text.
- Login page and MFA verification page — both previously showed a CSS
  gradient-text "Jen" wordmark; both now show the real logo image.
- Browser tab icon, PWA home-screen icon, iOS "Add to Home Screen"
  icon — all updated to the new mark.
- README header, using the same wide wordmark asset.

No application behavior changed — this release is asset and template
content only. Verified every touched template still renders correctly
after the edits, and confirmed the PWA manifest's icon references
still resolve to real files on disk with no path or structural changes
needed.

## [5.2.14] - 2026-09-08

### SECURITY: stop leaking raw exception text across the app

Final finding from the third-party security review that also produced
v5.2.6, v5.2.7, v5.2.10, and v5.2.12: raw Python exception text —
potentially including internal file paths, database schema details,
or connection info — was shown directly to users and API clients in
roughly 60 places across 14 route files, including several introduced
in this project's own 5.2.2 bulk-action work.

**Rule applied throughout:** fix anything wrapping a database or
file-system operation, since the exception text there can reveal
internal implementation details that are actionable for nobody except
someone probing the app. Leave alone anything that's a deliberate,
already-constructed message about the user's own submitted input (a
form-validation error), or an error communicating with infrastructure
the admin themselves configured — an SSH target, a webhook/Discord/
ntfy/Telegram integration. That text is the actionable diagnostic an
admin managing their own gear actually needs; hiding it behind "check
server logs" would make the app measurably less useful without
addressing any real security concern.

Fixed: `database.py`, `devices.py`, `leases.py`, `dashboard.py`,
`mfa_routes.py`, `plugins.py` (fixed at the shared `fetch_registry()`
source rather than patching each caller separately), `reports.py`,
`reservations.py`, `search.py`, `servers.py`, `subnets.py`, `users.py`,
`settings.py`, and the REST API v1 endpoints in `api.py` (separate
from the API-key management routes already fixed in v5.2.10).

Deliberately left alone, with the specific reason documented in each
case: `parse_import_file()`'s message about a malformed uploaded file,
`normalize_duid()`'s validation error about a submitted DUID, a
`configparser` error parsing an admin's own submitted subnet textarea,
and roughly ten SSH/webhook/Telegram cases where the error text is
about infrastructure the admin configured themselves.

Caught and fixed a real mistake in this exact release before it
shipped: one edit accidentally dropped a line while restructuring an
exception handler in `api.py`, leaving an unclosed dict literal — a
genuine syntax error. Found immediately via `ast.parse()`, and rather
than trusting the one-line fix, re-verified every remaining function in
that file individually, ran a full codebase-wide AST sweep, and spot-
checked several of the more complex multi-line edits from earlier in
this same pass.

Added `tests/test_no_raw_exception_leaks.py`: a regression scanner
(same approach as v5.2.9's sudoers-matching test) that greps every
route file for the leak pattern and fails on anything not in an
explicit, individually-justified allowlist, plus spot-check tests
across a representative sample of files that mock the database layer
to raise a distinctively-marked exception and confirm that marker
never reaches the response. Verified the scanner has real teeth, not
just coincidental passing, by planting a fake leak in a throwaway file
and confirming it's caught.

## [5.2.13] - 2026-09-08

### Fix CI failure in 5.2.12's test suite

`tests/test_small_hardening_fixes.py` failed to even collect in CI:
`ModuleNotFoundError: No module named 'yaml'`.

**Cause:** the Docker healthcheck tests in that file used `import yaml`
(PyYAML) to parse `docker-compose.yml`. PyYAML isn't an actual
dependency of this project anywhere — `install.sh` never installs it,
nothing else in the codebase imports it — it only happened to be
present in the environment the test was originally written and
checked in, which is exactly why the gap wasn't caught before the
tests reached CI.

**Fix:** removed the PyYAML dependency entirely, applying the same
discipline already used for `jen/services/changelog.py` — don't reach
for a general-purpose parsing library for a narrow, well-known, fully
self-authored format. The specific line these tests need (`test:
["CMD-SHELL", "..."]`) is a single-line YAML flow sequence, which is
also valid JSON, so a targeted regex isolates it and the stdlib `json`
module parses it directly. The regex is anchored on the actual
`CMD-SHELL` content rather than a generic `test:` match, so it doesn't
accidentally pick up the separate MariaDB healthcheck present in
`docker-compose.mysql.yml`, which uses plain `CMD`.

Verified properly this time, not just re-run: uninstalled PyYAML from
the development environment entirely (not just avoided calling it) and
confirmed both that `pytest --collect-only` succeeds — the exact
failure mode from the CI log — and that the corrected parsing logic
still returns the right values from both compose files.

No application behavior changed; this is a test-only fix.

## [5.2.12] - 2026-09-08

### Two small hardening fixes: trusted-device cookie, Docker healthcheck

Fourth and fifth findings from the same third-party security review
that produced v5.2.6, v5.2.7, and v5.2.10 — bundled together since
both are small, single-file, mechanical changes with no relationship
between them and no interaction risk.

**`jen_trusted` cookie missing `Secure`.** This cookie is a long-lived
MFA bypass token (up to 10 years for "remember this device forever").
Unlike the main session cookie, which is marked `Secure` whenever SSL
is configured, this one had no `secure` flag at all — a browser could
send this specific token over plain HTTP even on an instance with
HTTPS configured, before any HTTP→HTTPS redirect takes effect. Fixed
across all four call sites (two duplicated code paths — backup-code
verification and TOTP verification — each with a "forever" and an
"N days" branch), using the same `ssl_configured()` condition the
session cookie already uses. Also removed a stale, incorrect comment
next to one of the call sites ("No max_age = session-less persistent
cookie" — the code has always explicitly set a 10-year `max_age`;
the comment was simply wrong).

**Docker Compose healthcheck used `CMD` (exec form) with `||`.**
`CMD` does not invoke a shell, so `||` was never treated as shell OR
logic — it was passed to `curl` as a literal, meaningless argument.
Verified this directly rather than assuming: ran the exact broken
argv as a single non-shell process and found curl's own handling of
multiple positional URL arguments happened to mask the bug in some
cases (occasionally still reaching a later URL in the list by
accident), which is worth being precise about — it was never the
intended "try HTTP, fall back to HTTPS" logic actually running, just
an unreliable side effect of how curl parses extra arguments. Fixed by
switching to `CMD-SHELL`, which explicitly invokes `/bin/sh -c`, in
both `docker-compose.yml` and `docker-compose.mysql.yml` (which
maintain this same healthcheck independently).

Added `tests/test_small_hardening_fixes.py`. For the cookie fix,
verified via direct source inspection that all four call sites include
the flag, correctly conditioned on `ssl_configured()` rather than
hardcoded — full HTTP-level testing would require a real enrolled TOTP
secret and a live-generated code just to reach one `set_cookie()`
call. For the healthcheck fix, went further than checking the YAML
text: spun up a real local HTTP server and ran the actual shell
command Docker would run, confirming it genuinely falls through to the
working fallback target when the first is unreachable — with a server
log line proving the fallback request was actually received, not just
that the exit code happened to be zero.

## [5.2.11] - 2026-09-08

### Fix CI failure in 5.2.10's test suite

`tests/test_api_key_authorization.py::TestLimitParameterFloor::test_zero_limit_does_not_crash`
failed in CI — a bug in the test's own fixture data, not the `limit`
floor logic it was checking.

**Cause:** `TestLimitParameterFloor`'s helper for inserting a valid API
key built the raw key from a fixed literal string, so every call
within that test class produced the exact same SHA-256 hash.
`api_keys.key_hash` has a `UNIQUE` constraint, so the second test to
call the helper failed with a duplicate-key `IntegrityError` before
the actual `limit`-clamping code under test ever ran.

**Fix:** each call now generates its own genuinely random raw key via
`secrets.token_hex()`, matching how real API keys are actually
generated elsewhere in the app. Verified directly — ran the fixed
helper's key-generation logic twice in sequence and confirmed the two
resulting hashes are always distinct, rather than just re-running the
suite and hoping.

While reviewing this, checked the rest of the same test file for the
identical class of mistake — every API-key-name and admin-username
value used across the file's remaining ~15 test methods was confirmed
genuinely unique, so this was an isolated case, not a symptom of a
wider pattern in that file.

No application behavior changed; this is a test-only fix.

## [5.2.10] - 2026-09-08

### SECURITY: API key authorization scope, plus three related fixes in the same file

Third fix from the same third-party security review that produced
v5.2.6 and v5.2.7.

**The finding:** the API key listing query loaded every key regardless
of who created it, and the revoke/delete routes checked only
`role in (superadmin, admin)` — no ownership check, no scope check. A
subnet-restricted plain admin could view metadata for, revoke, or
delete a superadmin's unrestricted API key just by knowing or guessing
its (small, sequential) id.

**Fix:** a plain admin now only ever sees, and can only ever act on,
API keys they created themselves. Superadmins continue to see and
manage everything, consistent with how superadmin access already
works everywhere else in the app. The revoke and delete routes give
the same generic "API key not found" message whether a key genuinely
doesn't exist or exists but isn't the caller's — distinguishing the
two would let someone confirm a specific key id exists even though
they can't act on it either way. Added a brief note to the API Keys
page itself for plain admins, since this is a real, visible behavior
change worth surfacing rather than a silent restriction.

**Bundled into the same pass**, since all three touch this exact file
and two of them are the exact lines being rewritten for the
authorization fix anyway:

- **Raw exception leaks** in the API key listing, create, revoke, and
  delete routes — all four previously did `flash(f"Error: {e}")`,
  putting raw exception text (potentially including schema details,
  connection info, or credentials) directly in front of the user. Now
  logged server-side with a generic message shown instead.
- **`limit` parameter floor** — the REST API's `limit` query parameter
  was capped at 1000 but had no lower bound, so `?limit=-1` reached
  MySQL as a literal negative `LIMIT`, which MySQL rejects outright
  rather than clamping. Now `max(1, min(value, 1000))`.
- **`last_used` write throttling** — `_api_auth()` wrote `last_used`
  on every single authenticated API request, unconditionally. Now
  throttled to once per 5-minute window via a single conditional
  `UPDATE ... WHERE last_used IS NULL OR last_used < NOW() - INTERVAL
  5 MINUTE` — atomic, one round trip, no separate SELECT-then-maybe-
  UPDATE that could race with itself under concurrent requests.

Added `tests/test_api_key_authorization.py` covering all of the above
— including a test that specifically reproduces the reported
vulnerability (a restricted admin attempting to revoke an
unrestricted key created by a second admin) and confirms the key
remains untouched, and DB-level tests proving the throttling SQL
correctly distinguishes "never used," "still within the window," and
"window has passed" cases.

## [5.2.9] - 2026-09-08

### Fix self-update being completely broken since v5.2.6

**Impact:** every self-update attempt has failed on every instance
running v5.2.6, v5.2.7, or v5.2.8 — not a transitional issue affecting
one upgrade, a permanent break in the feature until this fix is
applied. Reported as "Could not start the update" in the UI.

**Cause:** the v5.2.6 security rewrite's sudoers rule authorized
`/usr/bin/systemctl start jen-update.service`, but the actual code
invoked `/usr/bin/systemctl start --no-block jen-update.service` — an
extra `--no-block` flag added for a real reason (without it, the
triggering call blocks waiting for the update service to fully
complete, including its own final `systemctl restart jen` step, which
kills the exact Flask worker process that's blocked waiting) but never
reflected in the sudoers rule authorizing it. `sudo` matches commands
literally, argument-by-argument — a rule with no wildcards (deliberate,
since a wildcard here would reopen exactly the attacker-controllable-
input gap the v5.2.6 rewrite exists to close) must match byte-for-byte,
and this one didn't. Every attempt was rejected with a sudo permission
denial before ever reaching the update logic.

**Fix:** the sudoers rule now authorizes the exact command the code
actually invokes, `--no-block` included.

Added `tests/test_sudoers_command_matching.py` — parses `jen-sudoers`
and cross-checks every sudo-invoking `subprocess.run()` call in
`jen/routes/settings.py` against it via AST, failing if any invoked
command doesn't exactly match something authorized. Verified this test
actually has teeth, not just coincidental passing: ran it against the
original broken sudoers content and confirmed it correctly flags the
exact mismatch that shipped. This class of bug — an update to one side
of a two-file contract (code and the sudoers rule authorizing it)
without a matching update to the second — is now checked automatically instead of
depending on remembering to keep them in sync by hand.

**⚠️ Because self-update is what's broken, self-update cannot fix
itself.** Use the manual upgrade path for this release, with real
administrator access:

```
cd ~/jen
sudo ./install.sh --upgrade
```

This installs the corrected `jen-sudoers` file directly. After this
one update, the in-app "Update Now" button works correctly again for
every release going forward.

## [5.2.8] - 2026-09-08

### Fix CI failure in 5.2.7's test suite

Two failures in `tests/test_password_change_enforcement.py`, both bugs
in the tests rather than the application logic they were checking —
same category as the 5.2.4 fix, but for this feature's own test suite.

**`test_rejects_reusing_the_literal_default` failed:**
`force_password_change()` checked password length before checking for
the literal string `"admin"`. Since `"admin"` is only 5 characters,
the generic "must be at least 8 characters" error always fired first,
and the dedicated "not the default" check
could never actually run for the one input it exists to catch. The
security outcome was already correct either way (`"admin"` was always
rejected), but the specific, more useful error message was
unreachable. Fixed by reordering: the specific check now runs before
the generic length check.

**`test_change_password_route_clears_flag_too` failed:**
this test assumed the general `/users/change-password` route would
still work while `must_change_password` is set and clear the flag.
It doesn't — the enforcement middleware's allowlist only permits
`/force-password-change` and `/logout`, by design, since the entire
point of this feature is that the rest of the application (including
this alternate password-change route) is genuinely unavailable until
the dedicated screen is used. The test's premise was wrong, not the
middleware. Replaced it with two tests: one confirming
`/users/change-password` is correctly blocked and redirected while the
flag is set, and one verifying — via direct source inspection rather
than a fragile HTTP-level test — that `change_password()`'s own UPDATE
statement still clears the flag as a defense-in-depth measure, in case
a future change to the allowlist ever makes that route reachable
during enforcement.

No application behavior changed beyond the validation-order fix in
`force_password_change()`, which only affects which error message is
shown for one specific rejected input — the actual set of passwords
accepted or rejected is unchanged.

## [5.2.7] - 2026-09-08

### SECURITY: enforce a password change on the default admin credential

Second fix from the same third-party security review that produced
v5.2.6. A fresh install seeds an `admin`/`admin` superadmin account
with nothing enforcing that the obvious default ever actually gets
changed — the README says to change it immediately, but that was
advisory only, never enforced anywhere in the application. Given Jen
manages real DHCP infrastructure, a forgotten default credential has a
much larger blast radius than the same oversight elsewhere.

**Fix:** new `users.must_change_password` column, set on the default
admin seed and on any newly-created user account (an admin setting a
new user's initial password is the same category of concern as
the default seed itself). A new `before_request` hook makes the rest
of the application genuinely unavailable while this flag is set —
every authenticated request redirects to a forced password-change
screen — rather than just documenting that the password should be
changed. The new screen deliberately doesn't re-verify the current
password (reaching it at all already proves the user knows it — they
just logged in) and explicitly rejects setting the new password back
to `admin` or to the account's own username, closing the obvious
"change it right back" loophole.

Traced the session-cache plumbing carefully rather than assuming:
`load_user()`'s fast and slow paths both needed updating, and the
login route in `auth.py` turned out to independently build its own
session-cache dict in two separate places (a detail only found by
checking). The existing `change_password()` route already clears the
session cache on a successful change, which meant this flag correctly
propagates without needing any new cache-invalidation logic of its
own.

Added `tests/test_password_change_enforcement.py` covering the seed
and creation paths, the enforcement middleware (including that it
doesn't interfere with an in-progress MFA enrollment/verification
flow), and the new route's validation — verified the actual SQL and
validation logic directly via source inspection against the real
functions, since a fresh, all-migrations-applied test database isn't
available in every environment this was developed in.

## [5.2.6] - 2026-09-08

### SECURITY: root privilege escalation via the self-update sudoers rule

**This is the most important fix shipped in this project to date.**
Following a third-party security review, the self-updater's privilege
model has been redesigned.

**The vulnerability:** the sudoers file granted `www-data` (the Jen
web process) passwordless root access to run
`/bin/bash /tmp/jen_update_install.sh`. That exact file was written by
`www-data` itself, as part of every normal update. Since `/tmp` is
world-writable and `www-data` is the exact account permitted to write
that exact path, the real security boundary was: **gain any code
execution as `www-data` → write that file yourself → `sudo` it → root.**
Every checksum/signature validation the old `self_update()` route
performed was irrelevant to this path, because an attacker never
needed to go through that route at all — the update button's own
checks are not a barrier if you can just create the file the sudo rule
already trusts.

**The fix** moves the entire download → verify → extract → install
pipeline out of the Flask app and into a new standalone script,
`jen-update-root.py`:
- Lives outside `/opt/jen` entirely, so `install.sh`'s own
  `chown -R www-data:www-data` on the install directory can never
  re-expose it
- Owned `root:root`, mode `0700` — `www-data` cannot read or modify it
- Takes **zero arguments and accepts no input from `www-data` at all**
  — it always re-derives "the current latest release" from GitHub
  itself, independently, in the trusted execution context
- Reachable only via `sudo systemctl start jen-update.service` — a
  command with no parameters, mirroring the already-safe
  `sudo systemctl restart jen` pattern used elsewhere in this project

The practical result: even a fully-compromised `www-data` account can
now only ever trigger "install whatever GitHub currently publishes as
the latest jen-kea release" — nothing else. It cannot inject arbitrary
file content or arbitrary commands into the root execution context,
because nothing it controls ever reaches the privileged script as input.

**Also fixed in the same rewrite** (a separate issue from the same
review): the old code proceeded with an *unverified* update if a
checksum file was missing, had no matching entry, or failed to parse —
logging a warning and continuing anyway. `jen-update-root.py` fails
closed in all of those cases: no valid checksum match, no install,
full stop.

`self_update()` in `jen/routes/settings.py` is reduced from roughly
290 lines to about 70. It no longer downloads, verifies, extracts, or
copies anything — it only optionally backs up the database (unchanged
— that's Jen backing up its own data with credentials it already has,
not part of the privilege boundary) and triggers the hardened service.

**⚠️ Important — a one-time manual step is required for this specific
upgrade, for any instance whose primary deployment path is the in-app
"Update Now" button:**

Self-update always runs using the code already on disk *before* the
update runs. That means clicking "Update Now" to reach this version
will still execute the *old*, vulnerable copy logic one last time —
which has no way of knowing to install the new root-owned script or
the new systemd unit, since neither existed in any prior release. For
this one release only, run the manual upgrade path instead, with real
administrator access:

```
sudo ./install.sh --upgrade
```

This correctly installs `jen-update-root.py` and `jen-update.service`
alongside everything else. After this one transition, the in-app
"Update Now" button works normally — and correctly — for every release
after this one.

**Frontend note:** the update-progress overlay's polling logic
previously received the exact target version back from the server in
the post-update redirect (`?updated=X.Y.Z`) to know what to wait for.
The new route can't supply that anymore, since resolving "latest" now
happens entirely inside the privileged script. The redirect is now a
simple `?updating=1` flag, and the target version for display/
comparison is carried across the page reload via `sessionStorage`
instead (set right before the form submits, read back on page load).
If that value is ever unavailable, the polling logic falls back to
"Jen responded at all" as its completion signal rather than getting
permanently stuck waiting for an exact match it can't make.

Added `tests/test_jen_update_root.py` (checksum verification and file
installation, run directly against real temporary directories rather
than mocked shell-script text matching) and completely rewrote
`tests/test_self_update.py`, since every previous test in that file
verified the old route's now-removed download/copy pipeline. The new
tests confirm the route never writes to `/tmp/jen_update_install.sh`
again, never calls `requests` or `tarfile` itself, and only ever
triggers the hardened service.

## [5.2.5] - 2026-09-08

### The actual root cause of "What's New" showing old releases

v5.2.3 fixed a real bug in `parse_changelog()`'s sort order, but it
wasn't the actual cause of what was reported: "What's New" continued
showing an old 3.x-series release as the newest entry even after that
fix shipped. The real cause is more fundamental: **CHANGELOG.md was
never included in either deployment path's file list at all** — not
`self_update()`, not `install.sh`. Both treat it as source-repo
material (like docs/ or tests/), not part of "the running install," so
it has never been refreshed by any automated update, on any release,
ever. Any instance's `CHANGELOG.md` has been frozen since whichever
version was first manually installed — completely independent of the
actual application code being correctly updated release after release.

This is the **third** time this exact category of bug has hit this
project: `run.py` itself was missing from self-update's copy list
until v4.4.16; vendored static assets (`chart.umd.min.js`,
`htmx.min.js`) were missing until v5.1.6/v5.1.8; now `CHANGELOG.md`,
for the identical underlying reason — a file the running app actually
reads, living outside the `jen/`/`templates/`/`static/` scope both
deployment paths treat as "the app."

**Fixed** by adding `CHANGELOG.md` to both `install.sh` and
`self_update()`'s copy lists. Added `TestSelfUpdateCopiesChangelog` to
`tests/test_self_update.py`, matching the existing convention from the
`run.py` and static-asset fixes — capturing the real generated helper
script and asserting the actual `cp` command is present, not just that
some code path was reached.

**Important — this fix has the same bootstrapping limitation as every
prior fix to `self_update()` itself:** self-update runs using the code
*already on disk* before the update runs. Updating to this version via
the in-app "Update Now" button updates the application code (including
the fixed `self_update()` function itself) correctly, but that
specific update cycle is still driven by the *old*, un-fixed copy
logic — so `CHANGELOG.md` will not actually refresh until the *next*
update after this one. If you want "What's New" to be current
immediately rather than after your next update, copy it manually once:
`sudo cp ~/jen/CHANGELOG.md /opt/jen/CHANGELOG.md` (adjust paths to
your actual git working copy and install directory).

## [5.2.4] - 2026-09-08

### Fix CI failure in 5.2.2's own test suite (5.2.2 never actually shipped)

`tests/test_reservations.py::TestBulkReservationActions::test_bulk_delete_removes_selected_reservations`
failed in CI — a bug in that new test itself, not in
`bulk_delete_reservations()`, which was behaving correctly.

**Cause:** the actual `hosts` row for a reservation is removed by Kea
when it processes `reservation-del` — Kea owns that table, the exact
same way the pre-existing single-item `delete_reservation()` route
already works, and neither route ever issues its own `DELETE FROM
hosts`. The failing test mocked Kea's API (`result: 0` on any command)
and then asserted the `hosts` row was gone from the test database —
but a mocked Kea never touches the real table, so that assertion could
never pass regardless of whether the route's own logic was correct.
The existing `test_delete_reservation()` test already knew this and
only checks `status_code == 200` for exactly this reason; the new
bulk-delete test just didn't follow that established pattern.

**Fix:** rewrote the test to verify what's actually under Jen's
control and observable without a real Kea server — that
`bulk_delete_reservations()` sends the correct `reservation-del`
command (right subnet-id, right MAC, right identifier type) for the
selected host, and reports success. Confirmed the two remaining bulk-
action tests from 5.2.2 (Leases, Devices) don't share this flaw —
those routes mutate `lease4`/`devices` directly via Jen's own SQL with
no Kea API dependency, so asserting the row's state directly against
the test database is valid there.

This test would have failed 5.2.2's own CI too, and did — the release
was never actually confirmed green before being tagged. No application
behavior changes here; this is a test-only fix.

## [5.2.3] - 2026-09-08

### Fix "What's New" showing old releases as the newest

Reported: the About page's changelog viewer (added 5.2.1) showed an
old 3.x-series release at the top, ahead of the actual current
version.

**Cause:** `parse_changelog()` trusted the physical order release
headers appear in CHANGELOG.md, on the assumption the file is always
maintained strictly newest-entry-first. That assumption held for
every test fixture used to verify this module — all newest-first by
construction — which is exactly why it wasn't caught before shipping.
It doesn't hold against the real CHANGELOG.md, which has genuine
multi-year history well before this feature existed (the file's own
intro line references a separate "3.x line" with its own
release-history docs this module never had visibility into) —
something in that older history isn't strictly ordered the way every
entry written during this project has been.

**Fix:** rather than track down the exact historical formatting quirk
responsible, in a file this module can't fully see, entries are now
explicitly sorted by parsed semantic version (descending) after
parsing, instead of trusting file order at all. Numeric comparison,
not lexical — `5.2.10` correctly sorts after `5.2.9`, which plain
string comparison would get backwards. A version string that doesn't
parse cleanly falls back to sorting as the lowest priority rather than
crashing the whole page.

Added `TestVersionSortKey` and three new tests in `TestParseChangelog`
that deliberately build changelog fixtures *out of order* — proving
the fix holds regardless of file order, rather than only checking
against already-sorted input like every existing test here did.

The reports/analytics expansion originally planned for this release
(device churn, busiest-hours, manufacturer breakdown) is real, larger
scope than fit alongside this fix — moved to its own release rather
than shipped half-finished.

## [5.2.2] - 2026-09-08

### Bulk actions for Leases and Devices — and a real bug found along the way

Third release of the 5.2.x series. Set out to extend Reservations'
existing bulk-action pattern to Leases and Devices — turned out
Reservations' bulk actions didn't actually work either.

**Found: Reservations' bulk delete/export were completely unreachable
from the UI.** The JS (`toggleAll`/`updateCount`/`confirmBulk`) already
existed in `reservations.html`, and both backend routes
(`bulk_delete_reservations`, `bulk_export_reservations`) were fully
built and correct — but there was no checkbox, no select-all control,
no action bar, and no `<form>` anywhere in the template to actually
connect them. The exact same "half-wired feature" pattern as the
subnet-notes bug found earlier in this project. The original JS was
also written assuming a single dispatcher endpoint with an `action`
field, which never matched how the two real backend routes actually
work — so even with the markup in place, the wiring itself needed
correcting, not just completing.

- **Reservations** — added the missing markup (checkboxes, select-all,
  action bar, form) and fixed the JS to target each action's real
  endpoint directly. Checkboxes and "Export Selected" are visible to
  any logged-in user (matching `bulk_export_reservations`'s existing
  `@login_required`-only gate); "Delete Selected" is admin/superadmin
  only.
- **Leases** — new `/leases/bulk-release` route and matching UI,
  scoped to active (non-expired), non-reserved leases only — matching
  exactly where the single-lease "Release lease" action already lives.
  Releasing a reserved lease's active binding doesn't accomplish much
  since Kea just reissues the same reservation on renewal; the route
  re-checks this server-side even though the template only ever offers
  a checkbox for non-reserved rows.
- **Devices** — new `/devices/bulk-delete` route and matching UI. Pure
  Jen-side inventory cleanup — no Kea API or lease-table interaction at
  all, so there's no external system to fail against beyond the same
  subnet-access guard the single-device delete route already applies.

All three bulk routes: per-item subnet-access check (a bulk action
can't reach a subnet a restricted admin couldn't touch one at a time),
a single summary flash rather than one per item, and an audit log
entry. Fixed the empty-state `colspan` on Leases and Devices to be
dynamically correct now that column count varies by role and view
state, rather than the previous hardcoded (and already slightly
imprecise) values.

Added real test coverage for all three bulk routes plus the previously
untested Reservations bulk actions — including confirming the
subnet-restriction guard actually holds, that a reserved lease can't
be released via a hand-crafted bulk request even though the UI never
offers it a checkbox, and that the correct markup is now genuinely
present in each rendered page rather than just asserting the JS
functions exist.

## [5.2.1] - 2026-09-07

### In-app changelog viewer + PWA installability

Second release of the 5.2.x series — two small, independent additions
bundled together since neither touches existing data or behavior.

**In-app "What's New" viewer** — Jen has always maintained a genuinely
good CHANGELOG.md, but nothing surfaced it in the app itself. Added:

- **`jen/services/changelog.py`** — a small, purpose-built parser for
  CHANGELOG.md's own consistent format (release headers, subheadings,
  prose, bullet lists with `**bold**`, `*italic*`, `` `code` ``, and
  `[links](url)`). Deliberately not a general markdown library — this
  parses our own file with a format we fully control, not arbitrary
  third-party markdown, so a full parser would be a new dependency and
  a larger, harder-to-audit HTML-output surface for a task this
  constrained. All text is HTML-escaped before any formatting markup
  is reintroduced, verified against actual injection attempts (a
  `<script>` tag and a quote-breakout in a link URL), not just assumed
  safe because the source file is our own.
- Reads the real CHANGELOG.md shipped with the running instance at
  request time, not a bundled/hardcoded copy — the same "don't let two
  sources of truth drift apart" principle behind config drift
  detection (5.2.0) itself.
- Surfaced on the About page: newest release shown expanded, earlier
  ones collapsed behind a "Show details" toggle.

**PWA installability** — Jen was already thoroughly mobile-responsive
but had no web manifest, so it couldn't be installed to a phone home
screen as a standalone app.

- New on-brand icon set (192×192, 512×512, iOS touch icon), generated
  to match the existing teal/blue "Jen" wordmark gradient.
- `static/manifest.webmanifest` plus the corresponding manifest link
  and Apple-specific meta tags in `base.html`.
- **Deliberately no service worker.** This app shows live Kea/lease
  status; a service worker's caching could serve a stale "Kea: Online"
  page while Kea is actually down, which is actively misleading for a
  monitoring tool, not just a UX nitpick. Manual "Add to Home Screen"
  works fully without one; only the fully-automatic install banner
  some browsers proactively show may not appear.

Added `tests/test_changelog.py` (parser correctness and injection
resistance, plus route-level coverage for `/about`, which had none
before this) and `tests/test_pwa_manifest.py` (manifest validity, every
referenced icon file actually existing on disk, and an explicit guard
that fails if a service worker registration is ever added later).

## [5.2.0] - 2026-09-07

### Config drift detection

New feature (first of the 5.2.x series). Jen's own subnet id → name/
CIDR mapping (`extensions.SUBNET_MAP`/`SUBNET6_MAP`, sourced from
Jen's `[subnets]` config file) is not derived from Kea's live config
at all — it's a separate, manually-maintained list kept in sync only
by whoever remembers to update it. This is exactly what caused a real
bug found in practice: selecting "IoT" in a subnet filter silently
returned Production's data, because Jen's stored id for "IoT" no
longer matched what Kea's live config actually assigned that id to.
There was no way to know this had happened until it produced a
confusing symptom.

- **`jen/services/config_drift.py`** — compares Jen's stored subnet
  map against a live `config-get` for both IPv4 and IPv6 (when
  configured), surfacing three distinct problems: a subnet Jen has
  that Kea's live config no longer does, a subnet Kea has that Jen
  never named, and — the critical case, the exact failure mode behind
  the real bug — both sides agreeing a subnet id exists but
  disagreeing on which network it actually is. The core comparison is
  a pure function with no I/O, so it's fully and directly testable
  against hand-built maps; a live-fetch failure is treated as
  "couldn't check right now," never as "Kea has zero subnets" (which
  would otherwise flood false positives during any transient Kea
  outage).

- **Automatic, continuous checking** — wired into the existing
  `check_alerts()` background loop, using the same detected-once/
  resolved-once alerting pattern already used for `kea_down`/`kea_up`
  and `utilization_high`/`utilization_ok` (two new alert types,
  `config_drift_detected` and `config_drift_resolved`), so it doesn't
  spam every 30-second cycle while an issue persists, and lets you
  know when it's fixed too. Respects per-channel subnet scoping like
  every other subnet-specific alert.

- **Manual on-demand check** — Settings → Infrastructure → "Config
  Drift Check" card, matching the existing "Kea Package Status" card's
  pattern, for checking right now without waiting for or digging
  through alert history.

Added `tests/test_config_drift.py`, weighted heavily toward the pure
comparison logic since that's where the feature's actual value lives —
covers the no-drift case, all three issue types individually and in
combination, and the "Kea unreachable must skip rather than report
false drift" case explicitly.

## [5.1.21] - 2026-09-06

### Fix false "kea-dhcp4/kea-dhcp6 not installed" report on a genuinely-running server

Settings → Infrastructure → "Check Installation" (Kea Package Status)
could report both binaries as not installed on a server that was
demonstrably running Kea fine — Control Agent connected, actively
serving DHCP.

**Cause:** the check ran `which kea-dhcp4 kea-dhcp6` over SSH, which
only searches `$PATH`. Paramiko's `exec_command()` runs a
non-interactive, non-login shell by default, and depending on the
target's sshd/PAM configuration, that session's `$PATH` can easily
exclude `/usr/sbin` — exactly where the official
`kea-dhcp4-server`/`kea-dhcp6-server` `.deb` packages install these
binaries (standard Debian policy for system-administration daemons).
A genuinely-installed, genuinely-running server got reported as "not
installed" purely because the check was searching a `$PATH` that never
included the directory the binary actually lives in.

The existing tests for this function never caught it because they only
exercised output *parsing* against a canned stdout string (literally
hardcoding `/usr/sbin/kea-dhcp4` as the fixture text) — never the real
command's actual `$PATH`-dependent behavior against a live, restricted
SSH session. Verified the fix directly: ran both the old and new
commands under a deliberately restricted `$PATH` missing `/usr/sbin`,
confirming the old command fails to find a binary that's genuinely
there while the new one correctly finds it.

**Fix:** now checks `command -v` (kept as the first, cheapest check —
still catches non-standard install locations) OR'd with explicit
`test -x` checks against the standard install directories
(`/usr/sbin`, the real-world location; `/usr/local/sbin`, for a
build-from-source install), so a restricted non-login `$PATH` can no
longer produce a false negative for a binary that demonstrably exists.

Updated the existing tests' canned output to match the new detection
markers, and added a new test that checks the actual SSH command sent
includes the `/usr/sbin/` fallback — confirming the fix mechanism is
present, not just that output parsing still works (which is exactly
what the previous tests already covered without ever catching this).

## [5.1.20] - 2026-09-06

### The action-menu clipping fix, actually fixed this time

v5.1.18's fix for `.action-menu-dropdown` getting trapped in a scroll
box on short/filtered tables did nothing. Confirmed still fully
reproducible on v5.1.19 exactly as originally reported.

**What went wrong:** the CSS overflow "computed-value fixup" rule (one
axis explicitly non-`visible` forces the other axis to behave as
non-`visible` too) operates on the *computed* value, not on whether it
was authored explicitly or left as the default. `overflow-x: auto;
overflow-y: visible;` computes identically to `overflow-x: auto;`
alone — there is no way to fix this by setting overflow properties on
the same element. v5.1.18 shipped a no-op, and its regression test
only checked that the literal string `overflow-y: visible` appeared in
the CSS text, never actual browser clipping behavior, so it passed a
fix that changed nothing.

**The actual fix:** `.action-menu-dropdown` is now repositioned via JS
to `position: fixed` (viewport-relative — genuinely escapes ancestor
overflow clipping, confirmed no ancestor here sets transform/filter/
perspective/will-change:transform, any of which would defeat this)
computed from the trigger button's own `getBoundingClientRect()`, only
while open. Includes a flip-upward fallback when there isn't enough
room below the button (exactly the short-table case reported), closes
on scroll rather than trying to track a moving trigger, and
repositions (without closing) on window resize.

Reverted the ineffective `overflow-y: visible` from `.table-wrap`.

**Verified properly this time**, not just asserted:
- Extracted and syntax-checked the actual shipped JS with Node
- Ran the real positioning math against four scenarios (normal case,
  flip-upward, edge-clamping, and the exact short-viewport/short-table
  case from the report) — all correct
- Ran the actual functions (not a reimplementation) against a real
  jsdom-simulated DOM: confirmed the dropdown genuinely switches to
  `position: fixed` with correct coordinates on open, and all inline
  overrides clear correctly on close

Rewrote `tests/test_table_wrap_overflow.py` (the previous version
tested for the ineffective CSS property) to check for the actual fix
mechanism, and to explicitly guard against the ineffective
`overflow-y: visible` ever being reintroduced and mistaken for
sufficient again. This project has no browser-automation test
infrastructure, so these are structural checks (the right function
exists, calls the right APIs, is wired to the right events) — a real
limitation, not a substitute for confirming this by hand after
deploying it.

Also: swept every comment touched in this release for accidental
word-collisions with existing tests' `assert <word> not in resp.data`
checks (the exact class of self-inflicted CI failure fixed in 5.1.19)
before shipping, rather than after.

## [5.1.19] - 2026-09-06

### Fix CI test failure from v5.1.18's own explanatory CSS comment

`test_kea6.py::TestReservationsV6View::test_v6_view_search_filters_by_hostname`
started failing in CI after v5.1.18 shipped — not a regression in any
actual functionality. That test inserts two IPv6 reservations, one
hostnamed "findme" and one hostnamed "other", searches for "findme",
and asserts the string "other" doesn't appear anywhere in the full
page response — a reasonable way to confirm the non-matching
reservation was correctly excluded from the results.

v5.1.18's fix for the `.table-wrap` overflow bug added a detailed
explanatory comment directly in `base.html`'s `<style>` block,
including the sentence "...one axis is explicitly non-visible and
**the other** is left as the visible default...". Since `base.html` is
the shared page shell rendered on every full-page response, that
comment text — containing the substring "other" — showed up in this
test's response body too, tripping the assertion. The actual
reservation filtering was, and remains, completely correct; only one
reservation was ever rendered in the results table. This was a
collision between an explanatory comment's prose and a test's
substring check, not a functional bug.

Fixed by rewording the comment (no technical meaning changed) to avoid
the literal substring. Swept every other `assert <word> not in
resp.data`-style test in the suite against `base.html` specifically,
since it's the only template rendered on every full page — found four
other superficial matches (`page-header`, `btn-act-edit`,
`btn-act-pin`, `btn-act-del`), all of which are pre-existing CSS class
*definitions* that were already in `base.html` before this session and
only matter in practice for full-page responses; the tests checking
for their absence specifically target HTMX partial responses, which
never include `base.html`'s `<style>` block at all — confirmed no
actual collision there.

No functional changes — comment wording only.

## [5.1.18] - 2026-09-03

### Fix action-menu dropdown getting trapped in a scroll box on filtered/short tables

App-wide UI bug: `.table-wrap` (the container wrapping every list-page
table — Leases, Reservations, Devices, both v4 and v6 variants, Users,
API Keys, Audit Log, Plugins, Search Results, Saved Searches, Alert
Settings, MFA Trusted Devices, the Dashboard's recent-leases widget —
16 templates in total) only ever set `overflow-x: auto`, leaving
`overflow-y` implicit. Per the CSS spec's overflow computed-value
fixup rule, when one axis is explicitly non-`visible` and the other is
left as the default `visible`, browsers force **both** axes to behave
as `auto` — so this container was silently clipping vertical overflow
too, not just the horizontal overflow it was actually meant for.

The visible symptom: `.action-menu-dropdown` (the "⋯" menu) is an
absolutely-positioned child that needs to overflow below the table
when a row near the bottom opens it. With a short, heavily-filtered
result set — one or two rows — there's no natural extra table height
to absorb that overflow, so the dropdown got trapped inside a forced,
tiny scroll region instead of floating naturally above the page,
exactly matching the report: filter down to a couple of devices, open
the "⋯" menu, and end up scrolling inside a cramped box just to click
an item.

Fixed with a single shared CSS rule change (`overflow-y: visible` set
explicitly rather than left implicit) in `base.html` — since every
affected page shares this one container class, this one-line fix
resolves it everywhere at once rather than needing 16 separate
per-template patches. Confirmed no `.table-wrap` usage anywhere
intentionally relied on vertical scrolling (no paired `max-height`
found), and confirmed the dropdown itself has no nested overflow
clipping of its own that would undo the fix one level down.

Added `tests/test_table_wrap_overflow.py`, which parses the actual CSS
rule text (not just a substring match) so a future edit that drops the
explicit `overflow-y: visible` — reintroducing the fixup-rule bug —
fails CI immediately instead of shipping invisibly again.

## [5.1.17] - 2026-09-02

### Decouple Kea health checking from the 30-second monitoring cycle

Investigated a report of a Kea server reboot that Jen never showed as
down. Traced the up/down detection logic exhaustively — the state
machine itself is correct (verified: it alerts immediately if Kea is
already down at Jen's very first check, doesn't false-alarm on a
healthy start, and fires clean down→up/up→down transitions with no
edge case found). The real problem is architectural, not a logic bug:

Every check in `check_alerts()` — Kea health, HA state, lease
tracking, utilization, stale reservations, snapshots, the daily
summary — shared one single 30-second heartbeat. A reboot that's
actually down for less than ~30 seconds (entirely plausible for a
fast VM or a lightweight OS) can fall completely between two polls
and never register as down at all, purely by timing luck. Polling
can't guarantee catching every outage shorter than its own interval,
but coupling a cheap, fast-changing check (is the API up right now?)
to the same cadence as much heavier, far-less time-sensitive work was
making that blind spot needlessly wide.

Kea/HA health is now checked every ~5 seconds (6 times within the
same overall ~30-second cycle the heavier work still runs on) —
shrinking the blind spot from ~30 seconds to ~5 without changing how
often utilization scans, snapshots, or the daily summary run. Also
simplified `last_kea_status` from an awkward bool-or-dict dual-typed
variable to a plain dict throughout, removing a redundant duplicate
`kea_is_up()` call that only fired on Jen's very first-ever health
check.

No behavior change to alert content, thresholds, or any other alert
type — purely a timing fix for how quickly a real outage gets caught.

## [5.1.16] - 2026-09-02

### Per-channel subnet scoping, reserved-lease recurrence control, Telegram rate-limit hardening

Three additions, all in the notification system, following a request
to review the whole alerting pipeline end to end:

- **Per-channel subnet scoping** — each alert channel can now be
  limited to specific subnets for subnet-specific alerts (new lease,
  new device, reserved device online, utilization, pool exhaustion,
  stale reservation). Kea up/down, HA failover, and the daily summary
  are never subnet-scoped, since they aren't tied to one specific
  subnet. New `alert_channels.subnet_scope` column (migration 14),
  same NULL-means-unrestricted convention as `users.subnet_access` and
  `api_keys.subnet_access` — every existing channel keeps alerting on
  everything by default. Unlike those two, a malformed scope value
  fails *open* here (sends anyway), not closed — this is a
  notification preference, not an access boundary, and going silent
  on every alert because of a JSON typo is worse than occasionally
  over-notifying.

- **Reserved-lease notification recurrence is now an explicit choice**
  — a new "Reserved Device Notifications" setting (global, Settings →
  Alerts) lets you pick "every time it comes online" (the v5.1.13
  behavior, and the default) or "only the first time ever" (the
  original, narrower behavior from before 5.1.13, now offered
  as a documented option instead of something that could only happen
  by accident).

- **Telegram rate-limit handling** — Telegram's Bot API returns HTTP
  429 with a `retry_after` value when you exceed roughly one message
  per second to the same chat, with no handling for that previously. A
  burst of several devices reconnecting within the same 30-second poll
  cycle (e.g. after an outage) sends that many `sendMessage` calls
  back-to-back with no delay between them — enough to trip this limit
  and permanently drop whichever messages got rate-limited, no retry,
  nothing to show for it beyond a generic `failed` row in `alert_log`.
  One retry, honoring Telegram's own requested wait (capped at 10s so
  a single alert can't stall the whole poll cycle), covers the
  ordinary burst case.

Also re-confirmed by tracing the code directly: `new_reserved_lease`
was NOT still firing only once — that was fixed in 5.1.13 and remains
correct. If reserved-device alerts still aren't showing up after this
release, the next thing to check is which version is actually running
live, given how much churn this alert type has had across 5.1.11–13.

## [5.1.15] - 2026-08-31

### Fix silent per-message alert failures caused by unescaped device hostnames

Root cause of "some notifications never go out" (as distinct from "no
notifications go out," already fixed in 5.1.14, and "this specific
alert type never fires," already fixed in 5.1.11–5.1.13): a device's
DHCP hostname (option 12) is fully attacker/device-controlled — any
client on the network can set it to anything, including raw `&`, `<`,
`>`. Telegram (`parse_mode=HTML`) and Pushover (`html=1`) both strictly
validate the outgoing message as HTML and reject the **entire send**
if it doesn't parse. An ordinary, not-even-malicious hostname like
`AT&T-Hotspot` was enough to silently kill every `new_lease`/
`new_device`/`new_reserved_lease` alert for that one device, every
single time its lease went active, while every other device on the
network kept alerting fine. No retry, nothing surfaced anywhere except
a `failed` row in `alert_log` that nobody's watching in real time —
exactly the "some, not all, and seemingly random" pattern reported.

Fixed by HTML-escaping the untrusted value (`hostname`) at each call
site in `check_alerts()`, via a new `safe_text()` helper — deliberately
**not** applied generically to every kwarg inside `render_template_str`,
since `daily_summary`'s `summary` kwarg is pre-built HTML from Jen
itself (deliberate `<b>` tags); blanket-escaping every kwarg would have
turned that into visible `&lt;b&gt;` text instead of fixing anything.
Slack/webhook/ntfy/Discord — which strip HTML tags via regex rather
than validating them — now also unescape the stripped text afterward,
so a hostname's escaped entities render as the actual characters for
recipients that don't parse HTML at all, rather than showing literal
`&amp;` in the message.

Added `tests/test_alerts.py::TestUntrustedHostnameHtmlEscaping`,
including a regression test asserting `daily_summary`'s own markup
survives the fix untouched.

## [5.1.14] - 2026-08-31

### The real root cause of "subnet filters don't apply": htmx was never actually vendored

`static/js/htmx.min.js` — the JS library every `hx-get`/`hx-trigger`/
`hx-target`/`hx-push-url` attribute in the entire app depends on — was
a 42-byte placeholder comment (`// HTMX 1.9.12 - replace with actual
file`), not the real library. Confirmed present as far back as v5.1.9,
the earliest version audited, so this predates every fix in this
series and has nothing to do with any of them.

This is the actual explanation for every "I select a subnet and it
doesn't filter" report investigated across 5.1.9–5.1.13: no JS ever
ran to intercept the selection and fire the AJAX request. The
`<select>` element visually kept showing whatever the user picked —
that's native browser behavior, unrelated to JS — while the request
that was supposed to apply the filter simply never happened. On pages
with a real `<button type="submit">` on a plain `method="GET"` form,
the browser's own non-JS fallback could still produce a real
navigation; on the live-filter (`change`-triggered) path relied on
elsewhere, nothing fired at all. The three v5.1.12 subnet-filter
consistency fixes (existence/access validation across Leases, Devices,
Reservations) were real and correct fixes for what they addressed, but
they could never have been the actual cause of what was being
reported, because the request carrying the filter value often never
reached the server in the first place.

Fixed by replacing the placeholder with the genuine htmx 1.9.12
minified build (verified against npm's published shasum before use).

**Added `tests/test_htmx_vendoring.py`** to close the gap that let
this ship silently for so long: checks the vendored file is
appropriately sized and contains real htmx content, not just a
same-named stub. This mirrors a check that already exists for
Chart.js (`test_reports.py`) — that fix's own docstring named
htmx.min.js as following the same vendoring convention, but the
equivalent verification for htmx itself was never actually written
until now. No test in this suite loads a real browser or JS engine —
the existing htmx-behavior tests only exercise the server's response
to a simulated `HX-Request` header — so nothing here previously could
have caught a client-side asset being silently wrong.

## [5.1.13] - 2026-08-31

### Fix new_reserved_lease firing logic (was shipped incorrect under the 5.1.12 label)

`new_reserved_lease` (added below in 5.1.12) shipped with the wrong
firing semantics: it fired only once per MAC, ever — the same
"genuinely never seen before" logic `new_device` uses. For a device
that's already been reserved and seen for a while (the normal case),
that means it would never fire again, no matter how many times that
device's lease actually goes active — moving subnets, coming back
online after being off. That's exactly backwards from what the alert
type exists for.

Fixed by making reservation status a tag on the *same* freshness check
`new_lease` already uses (was this IP active as of the last 30-second
poll), instead of a reason to run a separate one-time check. A reserved
lease going newly active now fires `new_reserved_lease` every time,
not just the first time in Jen's history; a mere renewal of an
already-active reserved lease still stays silent, exactly as before.

This also simplified the implementation — one query instead of two, no
separate reservation lookup needed per cycle.

**Note on versioning:** the incorrect version of this logic was
mistakenly repackaged and re-presented under the "5.1.12" label after
an initial correction attempt, meaning two different code payloads
briefly existed under the same version string. If you deployed
anything calling itself 5.1.12, please redeploy this release
regardless of when you pulled it, to be certain you're running the
corrected logic. Version numbers should never be reused once a build
has been shared — this was a process mistake worth naming plainly.

## [5.1.12] - 2026-08-27

### New alert type, and consistency fixes for subnet filtering across Leases/Devices/Reservations

- **New `new_reserved_lease` alert type** (`jen/services/alerts.py`) —
  `new_lease`/`new_device` are built from a query that deliberately
  excluded any lease matching a reservation entirely, to avoid
  re-alerting on every renewal of every statically-reserved device.
  That also meant a reserved device's lease going newly active — moving
  subnets, coming back online after being off — was invisible, not just
  on its first-ever appearance but every single time. Reservation status
  is now a tag on the exact same freshness check `new_lease` already
  uses (an IP not seen active last cycle), rather than a reason to skip
  that check altogether — so a reserved device's lease going active
  fires `new_reserved_lease` every time it happens, while a mere
  renewal of an already-active reserved lease still stays silent, same
  as it always has for the dynamic pool. Selectable per-channel and has
  its own editable template, same as every other alert type.

- **Subnet-filter consistency across Leases/Devices/Reservations**
  (`jen/routes/leases.py`, `devices.py`, `reservations.py`) — auditing
  all three pages side by side surfaced two one-directional gaps:
  - The v4 Leases filter already verified a submitted subnet id actually
    exists in `SUBNET_MAP` before using it, falling back to "all"
    otherwise. Devices and Reservations were missing that same guard —
    a stale or mistyped subnet id (e.g. left over after a Kea-side
    subnet renumbering) would filter directly on whatever the id
    happened to currently mean, with no indication the requested
    subnet didn't match what was returned. All three v4 views now
    apply the same existence check consistently.
  - Conversely, all three IPv6 views checked `SUBNET6_MAP` membership
    but never the user's own subnet access — a subnet-restricted user
    could view any v6 subnet's leases/devices/reservations by id
    regardless of their own restrictions. Now enforced consistently
    with the same paired-v4-subnet access rule global search already
    uses (an unpaired v6 subnet has no v4 side to inherit access from,
    so it's restricted to unrestricted/superadmin users).

Neither of these subnet-filter fixes changes behavior for an
unrestricted (superadmin, or admin with no subnet_access set) user
selecting a subnet id that legitimately exists — only for ids that
don't exist at all, or that a restricted user shouldn't be able to see.
If a page's dropdown shows a subnet by name and filtering by it still
returns another subnet's data, that id exists in Jen's own `[subnets]`
config but no longer matches what Kea's live config actually assigns
that id to — worth checking directly, since neither of these fixes
can correct a genuine mismatch between Jen's config and Kea's own.

## [5.1.11] - 2026-08-23

### Security/reliability: session-cache staleness, per-key API scoping, alert-template resilience

Three fixes from a continued audit pass, following up on v5.1.9/v5.1.10:

- **Stale session cache on revoked access** (`jen/__init__.py`, `users.py`) —
  `load_user()`'s session-cache fast path trusted `session['_user_cache']`
  (role, subnet access, session timeout) indefinitely once set at login,
  with no way for the server to invalidate one specific already-open
  session. An admin demoting a user, restricting their subnets,
  shortening their timeout, or deleting their account outright had no
  effect on that user's current session until it happened to expire on
  its own — using the OLD, possibly-longer cached timeout. Added
  `users.token_version` (migration 12), bumped on every such change.
  `load_user()` now does one cheap indexed `SELECT token_version` before
  trusting the cache: match → serve from cache as before (same
  performance profile for the unchanged case); mismatch → full refetch
  and cache refresh; no row at all (deleted account) → cache dropped and
  the user is logged out immediately. Also removed two `_g._route_start`
  lines in `load_user()` — confirmed dead, set but never read anywhere.

- **API keys had no scope of their own** (`jen/routes/api.py`,
  `templates/api_keys.html`) — every `/api/v1/*` endpoint returned data
  for ALL subnets for any valid key, regardless of who created it or
  what subnets *they* could see. Since subnet-restricted admins (not just
  viewers) can create API keys, a restricted admin could mint a key with
  more access than their own account has. Added `api_keys.subnet_access`
  (migration 13, NULL = unrestricted, same convention as
  `users.subnet_access`) — a key's scope is now chosen explicitly at
  creation time, independent of the creating user, and is clamped
  server-side to never exceed what the creating user can themselves see
  (checked against a hand-crafted request too, not just the form). All
  six `/api/v1/*` read endpoints now filter/deny by the key's own scope;
  a lease/device outside scope 404s the same way a nonexistent one would.

- **`render_template_str` (alerts.py)** — previously only caught
  `KeyError` from a malformed admin-authored alert template. Any other
  `str.format()` failure (`IndexError`, `ValueError`, `AttributeError`)
  propagated out of `send_alert()`; because `check_alerts()`'s
  `kea_down`/`kea_up`/`new_lease`/`new_device`/`ha_failover` calls aren't
  individually wrapped, that exception skipped every remaining check for
  the rest of that 30-second cycle — utilization, stale-reservation,
  snapshot, daily summary — and repeated on every subsequent cycle for as
  long as the bad template existed, with only a log line to show for it.
  Now falls back to the raw template on any formatting failure.

No functional changes to any endpoint's read-only nature; API responses
for existing unrestricted keys are unaffected (NULL scope = all subnets,
same as before this release).

## [5.1.10] - 2026-08-23

### Security: fixed stored XSS in the dashboard device widget, wired up subnet notes

Found during a follow-up audit of the frontend/HTMX layer requested after
v5.1.9:

- **Stored XSS in "Top Active Devices"** (`dashboard.html`) — the
  `loadTopDevices()` widget built its table with string-concatenated
  `innerHTML`, including the device's DHCP-reported hostname with no
  escaping. A DHCP client's hostname option is attacker-controlled — any
  device on the network can set it to arbitrary text — so a malicious
  hostname rendered as live HTML/JS in the browser of any logged-in user
  who viewed the dashboard, including superadmins. Added a shared
  `escapeHtml()` helper in `base.html` and applied it to every
  device-supplied field in that widget (name, hostname, IP, subnet,
  manufacturer). Every other place hostname is displayed already goes
  through server-side Jinja autoescaping (or the `hostname` filter) and
  was unaffected.
- **Subnet notes feature completed** (`subnets.html`) — the notes
  editor JS (`editNote`/`saveNote`/`cancelNote`) and its backend route
  (`/subnets/save-note`) already existed and worked, but the template
  never rendered the `note-display-*`/`note-edit-*`/`note-text-*`
  elements the JS depended on, so the feature was unreachable. Added the
  missing markup to each subnet card (admin/superadmin only, matching
  the existing edit/delete controls), and escaped saved notes on the
  client side with the same `escapeHtml()` helper as a second line of
  defense — the initial page-load render already went through Jinja
  autoescaping.

No Python changed — templates only. No functional changes to any
existing route or permission model.

## [5.1.9] - 2026-08-18

### Security: hardened self-update extraction and SSH host-key verification

Found via a security-scanning pass (bandit + hand-tracing of every
flagged path, plus a hadolint check on the Dockerfile):

- **Self-update tarball extraction** (`settings.py`) — the member
  filter for the downloaded release tarball only checked the name
  (`startswith("jen/")`, no `..`), not the member *type*. A symlink or
  hardlink member could pass that filter and, once extracted, point
  outside the temp directory. The filter now also requires
  `m.isfile() or m.isdir()` and rejects absolute paths, so only plain
  files and directories are ever extracted.
- **SSH known-hosts loading** (`auth.py`) — `paramiko_load_known_hosts()`
  previously logged a warning and continued if the known-hosts file
  couldn't be loaded (corruption, permissions, disk error). Combined
  with `AutoAddPolicy()`, that meant a load failure silently disabled
  host-key verification — every host would be re-trusted as if seen for
  the first time. It now raises instead, so the failure surfaces as a
  real connection error through the existing SSH try/except in every
  caller, rather than a log line nobody sees.
- **Dockerfile** — added `--no-cache-dir` to the pip install step
  (hadolint DL3042).

No functional or UI changes. 616/617 tests passing — the one failure
(`test_ipam_manifest_applies_correctly`) fails only in a full-suite run
and passes cleanly in isolation, pointing to shared-DB-state/test-order
leakage in `test_plugin_migrations.py` rather than anything touched by
this release (neither changed file goes near plugin migrations). Not
independently confirmed against unmodified v5.1.8 — worth a look, but
not blocking this release.

## [5.1.8] - 2026-08-17

### Fix: static-asset deploy fix was overwriting custom favicons

Both the `install.sh` fix (v5.1.5) and the self-update fix (v5.1.6)
for the Reports/Chart.js deployment gap blanket-copied the whole
`static/` tree from the release tarball onto the live install. That
was correct for vendored assets like `chart.umd.min.js` and
`htmx.min.js`, but wrong for `favicon.ico`: it's shipped in the
tarball as the stock default, but it's *also* the exact path
Settings → System writes a user-uploaded favicon to
(`extensions.FAVICON_PATH`). Every update — manual `install.sh
--upgrade` or the self-update button — was silently overwriting a
real custom favicon with the stock one, a real regression a user hit
directly.

### What changed for users

- A custom favicon uploaded via Settings → System now survives every
  future update. If yours was already overwritten by v5.1.5–v5.1.7,
  you'll need to re-upload it once after this update; from here
  forward it won't happen again.
- Fresh installs, and installs that never had a custom favicon,
  continue to get the shipped default exactly as before.

### What changed under the hood

- `install.sh` and `jen/routes/settings.py::self_update()`: both now
  back up any existing `static/favicon.ico` before the recursive
  `static/` copy runs, then restore that backup afterward — so
  whatever was there before (default or custom) survives untouched,
  and the shipped default is only ever installed when nothing exists
  yet at all. Same semantics `nav_logo` and `static/icons/custom/`
  already get, just applied to a file that (unlike those two) actually
  ships in the tarball too.
- Verified two ways: a direct simulation of the exact command sequence
  against a real temp directory (not just checking the generated
  script's text) for both the "custom favicon survives an update" and
  "fresh install still gets the default" cases, plus text-level checks
  confirming the backup happens before the static/ copy and the
  restore happens after it, so the ordering can't silently regress.
- 4 new tests in `tests/test_self_update.py` for the self-update code
  path specifically; the `install.sh` side was verified by direct
  bash-script simulation (not covered by the Python test suite, since
  `install.sh` does real systemd/apt/sudoers operations that aren't
  meaningfully unit-testable) — same verification approach used for
  the v5.1.5 `install.sh` fix.

## [5.1.7] - 2026-08-17

### Unblocking the v5.1.6 self-update fix (no functional changes)

v5.1.6 fixed self_update()'s static-asset copy logic — but that fix
could never take effect on the update that installed it, because
self_update() always runs using the code already on disk *before* the
update starts, not the new code inside the tarball being installed.
Anyone updating from v5.1.5 to v5.1.6 via the button ran v5.1.5's old,
still-broken copy logic to do it, so chart.umd.min.js still never got
installed even though v5.1.6's tarball genuinely contained it — and
the update button won't offer anything once you're already on the
latest tag, so there was no way to retrigger it without a new version
existing to update to.

This release is purely a version bump for that reason. No code
changed. Once this is live as the latest release, clicking Update
runs v5.1.6's already-correct copy logic (now running on the box
doing the updating) against this tarball, which finally installs
`static/js/chart.umd.min.js` correctly.

### What changed for users

- Reports charts should finally render after this update, if you
  updated to v5.1.6 via the self-update button rather than a manual
  `install.sh --upgrade` (which wasn't affected by this particular
  bootstrap gap, since it always re-derives its file list from
  whatever's in the currently-extracted tarball rather than from
  already-running code).

## [5.1.6] - 2026-08-17

### The self-update button had its own, separate static-assets gap

v5.1.5 fixed `install.sh` so a manual `install.sh --upgrade` correctly
deploys vendored static assets like `chart.umd.min.js`. That fix never
touched the in-app self-update button (Settings → Infrastructure →
Update), because it's a completely independent code path — its own
hand-maintained list of what to copy, generated into a helper script
and run via sudo, living entirely in `jen/routes/settings.py`. That
list had a comment explicitly excluding "other static/ subfolders
(nav_logo, favicon, generated JS, etc.)" — treating vendored release
assets the same as genuine user uploads. The Reports page stayed
broken for anyone using the self-update button specifically, on every
release, regardless of what v5.1.5 fixed elsewhere.

### What changed for users

- Reports charts actually render after clicking Update in Settings →
  Infrastructure, not just after a manual `install.sh --upgrade`.
- `favicon.ico` and `htmx.min.js` also get updated on self-update now,
  for the same reason.

### What changed under the hood

- `jen/routes/settings.py::self_update()`: replaced the
  `static/icons/brands/*.svg`-only copy command with a recursive copy
  of the whole extracted `static/` directory into the install dir,
  mirroring the v5.1.5 `install.sh` fix. `static/icons/custom/` (user
  uploads) is gitignored and never present in the release tarball, so
  this copy cannot reach it — confirmed by a real test asserting
  `icons/custom` never appears anywhere in the generated helper
  script.
- 3 new tests using the existing real-tarball-and-captured-helper-
  script pattern from the v4.4.16 `run.py` regression test: the
  recursive static copy command is present, it never references
  `icons/custom` or `rm -rf`s anything under `static/`, and
  self-update still succeeds against a tarball with no `static/`
  directory at all (older/malformed release, shouldn't crash).

## [5.1.5] - 2026-08-17

### install.sh wasn't actually deploying the Reports fix

v5.1.4 vendored Chart.js locally to fix the Reports page, but the fix
didn't actually take effect on deployment: `install.sh` copies files
into the live install directory using a hand-maintained per-file list
(it only knew about `htmx.min.js` and `icons/brands/*.svg` by exact
name), and `chart.umd.min.js` was never added to that list. The
browser requested `/static/js/chart.umd.min.js`, got a 404, and the
`<script>` tag failed to load with no visible error — so the symptom
looked identical to the original CDN bug even though that part of the
fix was correct.

### What changed for users

- Reports charts actually render now after upgrading. Confirmed by
  simulating both a fresh install and an upgrade of a pre-5.1.4
  install against a realistic directory layout before shipping this.
- `favicon.ico` gets installed too — it had the exact same gap
  (missing from every install, not just this release, simply less
  noticeable than a broken feature page).
- `install.sh` no longer reaches out to `unpkg.com` over the network
  at install time to fetch htmx as a fallback — everything it needs is
  already bundled in the package tarball, so there's no reason for
  install-time internet access at all.

### What changed under the hood

- `install.sh`: replaced the hand-maintained per-file copy list
  (`icons/brands/*.svg`, `htmx.min.js` with a `curl` fallback to
  `unpkg.com`) with a single generic `cp -r "$SCRIPT_DIR/static/."
  "$INSTALL_DIR/static/"`, so any file added to `static/` in the
  future is installed automatically without needing a matching
  `install.sh` change. `static/icons/custom/` (user-uploaded device
  icons) is gitignored and never present in the source tree, so this
  copy cannot touch it — verified directly by simulating an upgrade
  with a fake pre-existing custom icon in place and confirming it
  survived.

## [5.1.4] - 2026-08-17

### Reservation active/inactive status, Reports fix, unified action menus

Three related changes: the Reservations page now shows whether each
reserved IP is actually in use right now; the Reports page's charts,
which were silently failing to render, are fixed; and every page with
a row of action icons (edit/reserve/delete and similar) now uses one
consistent "⋯" action-menu component instead of the old fixed icon
row, whose width and icon set used to shift depending on which
actions applied to a given row.

### What changed for users

- **Reservations**: a new Status column — **● Active** (the reserved
  IP currently has a live, non-expired lease bound to it), **○
  Inactive** (no current lease at that address), or **⚠️ Conflict**
  (the address is currently leased, but to a different MAC than the
  reservation itself). A new Status filter (All / Active only /
  Inactive only) alongside the existing subnet and search filters.
- **Reports**: charts render again. Root cause was Chart.js loading
  from an external CDN at runtime with no error shown on failure —
  fixed by vendoring it locally, matching the same convention already
  used for htmx.
- **Unified row actions**: Devices, Leases, Reservations, Database
  (backups), Settings → Alerts, and Settings → API Keys all now show a
  single "⋯" button per row that opens a dropdown of the actions that
  apply to that row. Rows that used to lose an icon or shift width
  depending on state — a device that already has a reservation, a
  lease already tied to a reservation, an API key that's already
  revoked — now show an explicit, always-present entry for that state
  (e.g. "Reservation exists", greyed out) instead of silently omitting
  the icon. A handful of other pages (Infrastructure's extra-server
  rows, the nav logo remover, plugin uninstall, saved-search delete,
  custom icon delete) keep a single button rather than a dropdown,
  since they have one incidental action next to a primary labeled
  button and no shifting-row problem to fix — those were simply
  re-skinned with the same icon set for visual consistency.
- Icons switched from emoji to small inline SVGs everywhere — no
  external icon font, no CDN dependency.

### What changed under the hood

- `jen/routes/reservations.py`: the v4 reservation query gained a
  `LEFT JOIN lease4` (matched on address, restricted to `state=0 AND
  expire > NOW()`) to compute active/conflict status per row, plus an
  `EXISTS`/`NOT EXISTS` clause for the status filter.
- `static/js/chart.umd.min.js` (new) — Chart.js 4.4.1, vendored.
  `templates/reports.html` now loads it locally instead of from
  cdnjs.cloudflare.com.
- `templates/_icons.html` (new) — hand-authored inline SVG macros
  (edit, trash, pin, dots, download, test, pause).
- `templates/base.html` — new `.action-menu` CSS component (same
  checkbox-toggle mechanism already used for the nav avatar dropdown,
  so open/close works without JS; a small script handles outside-click
  close, Escape, single-menu-open, and closing the menu when an item
  inside it is clicked).
- `_device_rows.html`, `_lease_rows.html`, `_reservation_row.html`,
  `database.html`, `settings_alerts.html`, `api_keys.html` rewritten
  to use the new pattern.
- 30 new tests: 8 for reservation status (active/inactive/conflict,
  expired/released leases not counting as active, filter correctness),
  7 for the Reports fix (no CDN reference remains, the vendored file
  loads and is served, real `lease_history` data renders correctly),
  and 15 across the action-menu conversions (Devices, Leases, and the
  Settings pages), specifically covering the conditional-item-count
  cases — a reserved device, a lease with a reservation, a revoked API
  key — that the redesign exists to fix.

## [5.1.2] - 2026-08-17

### Kea package detection and one-click install

A missing `kea-dhcp4`/`kea-dhcp6` binary previously surfaced as a raw
Python traceback in the config-authoring and subnet-edit preview
panels — genuinely broken output, not just unpolished. Fixed, and
turned into a real capability: Jen can now tell you whether the Kea
packages are actually installed and install them for you.

### What changed for users

- Settings → Infrastructure has a new "Kea Package Status" card
  (superadmin only) — "Check Installation" reports whether
  `kea-dhcp4-server`/`kea-dhcp6-server` are present on each configured
  server, with an inline "Install" button for anything missing.
- The "Author a starting config" wizard now catches a missing binary
  during Preview & Validate and offers to install it right there,
  re-running validation automatically afterward.
- The same clean handling was applied to the existing v4/v6 subnet-edit
  preview and apply flows, which had the identical latent bug.

### What changed under the hood

- `jen/services/kea_authoring.py`: `detect_installed_kea_services()`
  (checks both protocols together via `which`) and
  `install_kea_service()` (`apt-get update && apt-get install -y
  kea-{service}-server` over SSH, targeting Jen's documented Ubuntu
  24.04 platform).
- All three script generators that shell out to `kea-dhcp4/6 -t`
  (`kea_authoring.py`, `kea6.py`'s subnet patch script, and
  `subnets.py`'s v4 equivalent) now catch `FileNotFoundError` around
  the `subprocess.run()` call and emit a clean `missingbinary:<name>`
  sentinel instead of letting the traceback reach the browser.
- Two new routes: `POST /settings/infrastructure/check-kea-binaries`
  and `POST /settings/infrastructure/install-kea-binary/<service>`,
  both superadmin-gated.
- 20 new tests, including one that confirms all three generated remote
  scripts remain valid Python after the fix, and one reproducing the
  exact reported bug (missing binary during config authoring) to
  confirm the response is now structured JSON, never a traceback.

## [5.1.1] - 2026-08-17

### Fix: "Author a starting config" required subnets that had no way to be added

The wizard shipped in 5.1.0 required at least one subnet to already
exist in Jen for the target protocol before it would even render the
form — but authoring a config from scratch is exactly the situation
where nothing exists there yet, and there was no UI path to add a v6
subnet ahead of time. The only way through it was hand-editing
`jen.config` directly.

Subnets are now defined inline in the wizard itself (one per line,
`id = name, cidr[, paired_v4_subnet_id]` — the same syntax
`jen.config`'s own `[subnets]`/`[subnets6]` sections already use, and
pre-filled from any subnets Jen already knows about). On a successful
write, those subnets are saved into Jen's own config automatically, so
they show up on the Subnets page from then on without a separate step.

## [5.1.0] - 2026-08-17

### Author a starting kea-dhcp4.conf / kea-dhcp6.conf

Settings → Infrastructure now has an "Author a starting config" flow
for either protocol, for the case where Jen is managing a Kea install
that doesn't have a config file yet — most commonly, adding IPv6 to an
existing IPv4 deployment.

### What changed for users

- New buttons on the Kea API and Kea6 API cards in Settings →
  Infrastructure: "Author a starting kea-dhcp4.conf" / "kea-dhcp6.conf"
  (superadmin only).
- If the other protocol's config already exists on the target server,
  interfaces and database connection settings are pulled from it
  automatically rather than asked for — enabling IPv6 alongside a
  working IPv4 setup reuses what's already there. Live interface
  detection over SSH is the fallback only when neither protocol has a
  config yet.
- The Control Agent's own config is read to find the correct
  control-socket path for the new service, so the generated file is
  actually reachable through the same CA Jen already talks to.
- Subnets to include come directly from Jen's own configured subnet
  list, with a full-CIDR default pool narrowed later via the existing
  Subnets → Edit flow.
- Same Preview & Validate pattern as subnet editing: the generated
  config and each server's `kea-dhcp4/6 -t` result are shown before
  anything is written. Refuses to overwrite an existing file unless
  explicitly told to, and backs up first when it does.
- The IPv6 toggle's old "create it manually first" message now links
  directly to this flow instead.
- Deliberately excluded: HA peer configuration (never generated), and
  hooks beyond `host_cmds`/`lease_cmds` (the two Jen's own commands
  actually depend on) — not a guess at what a broader setup might want.

### What changed under the hood

- **`jen/services/kea_authoring.py`** (new) — shared between both
  protocols: `detect_sibling_config()` (reads the other protocol's real
  config, never surfaces its database password), `autodetect_interfaces()`
  (SSH-based fallback), `detect_ca_socket_path()`, `build_new_kea_config()`,
  and `render_author_config_script()` (same dry-run-then-apply contract
  as every other config-writing path in this project).
- **New routes** in `jen/routes/settings.py`:
  `GET /settings/infrastructure/author-kea/<service>`,
  `POST .../preview`, `POST .../<service>` — superadmin-gated.
- **`templates/author_kea_config.html`** (new).
- 41 new tests, including confirming the dry-run preview path sends
  exactly one SSH command per server (never a write), that a real v4
  config's database password never leaks through sibling detection,
  and that every combination of the generated remote script (dry-run/
  apply × overwrite/no-overwrite) is valid Python.

## [5.0.0] - 2026-08-16

### IPv6 (DHCPv6) support

The largest single change in Jen's history — full IPv6 visibility
across every major page, plus write support for reservations and
subnet editing, built alongside Jen's existing IPv4 management rather
than replacing any of it. Ships as `5.0.0`, not a `4.5.x` patch series,
to signal the scale honestly rather than bury it.

**Off by default, on every install — new and existing.** Nothing about
this release changes behavior for a v4-only setup: `ipv6_enabled`
defaults to `false`, `[kea6]`/`[kea6_db]`/`[subnets6]` are optional
`jen.config` sections that don't need to exist, and every v6 code path
checks the flag before doing anything. This is the single most heavily
tested property of this release — see `docs/ARCHITECTURE.md` §5 for the
full design writeup, including what's deliberately deferred and why.

### What changed for users

- **Settings → Infrastructure**: a new "Kea6 Control Agent API"
  section with the "Enable IPv6 support" toggle (superadmin only).
  Flipping it doesn't just change what Jen displays — it SSHes to every
  configured Kea server, confirms `kea-dhcp6.conf` actually exists, and
  starts/stops `kea-dhcp6-server` for real.
- **Leases, Devices, Reservations pages**: a new `IPv4 | IPv6`
  segmented control, entirely absent (not just disabled) when no IPv6
  subnets are configured. The Devices view groups leases by DUID so a
  single device's address and delegated-prefix leases show as one row,
  and shows a manufacturer icon when the DUID embeds a recoverable MAC
  (DUID-LL/DUID-LLT) — never a guessed one otherwise.
- **Subnets page**: v6 subnets tagged and shown either as a second
  detail block on a paired v4 card (via an optional config-driven
  `paired_subnet4_id`) or as their own card. Admins get a real "Edit"
  flow — address pool, preferred/valid lifetime, T1/T2, DNS — with the
  same dry-run Preview & Validate safety net v4.4.24 established:
  `kea-dhcp6 -t` runs against every configured server before Apply is
  even clickable, and the live config is never touched by the preview.
- **Reservations page**: admins can add or delete a v6 reservation
  (address, delegated prefix, or both on the same DUID) directly
  through Kea's own API — no manual JSON editing.
- **Dashboard**: a genuine IPv6 summary card (active leases,
  reservations) when enabled; an explicit "(IPv4 only)" label on the
  existing totals widget when it isn't — never a silently-incomplete
  number either way.
- **Global search** now covers IPv6 leases and reservations, respecting
  the same paired-subnet access rule as everywhere else: a subnet-
  restricted user sees v6 results only for subnets paired with a v4
  subnet they already have access to.
- **`/metrics`** gains `jen_ipv6_enabled`, `jen_subnet6_active_leases`
  (labeled by IA_NA/IA_PD), `jen_subnet6_reserved_hosts`, and
  `jen_kea6_up` — separate metric names, not folded into the existing
  v4 gauges.
- **IPAM Lite and Network Discovery plugins** now show an in-app note
  (only when IPv6 is enabled) and document in their own READMEs that
  they remain IPv4-only for this release — a full-address-space view
  doesn't have a sane equivalent for a `/64`.

### What changed under the hood

- **`jen/services/kea6.py`** (new) — the entire v6 service layer: Kea
  API command wrappers, the read layer (`list_lease6()`,
  `get_ipv6_reservations()`, `list_lease6_devices()`), the write layer
  (`add_v6_reservation()`/`delete_v6_reservation()`,
  `build_subnet6_patch_script()`), and the SSH-based service-state
  orchestration for the enable/disable toggle. `lease6`/`hosts`/
  `ipv6_reservations` column shapes confirmed directly against Kea's
  real `dhcpdb_create.mysql`, not assumed from the v4 schema — notably
  `lease6.address` is `VARCHAR(39)`, not the `INET_ATON` integer v4
  uses.
- **`jen/models/db.py`** — `kea6_db()`/`get_kea6_db()`, which reuse the
  existing `kea_db` connection pool when `[kea6_db]` targets the same
  database as `[kea_db]` (the common case) rather than always opening a
  redundant second pool.
- **`jen/models/migrations.py`** — migration 11, `lease6_history`.
  Deliberately a separate table from `lease_history`, not columns
  bolted on: NA/PD counts aren't comparable quantities, and a `/64` has
  no finite "percent used" the way a v4 `/24` does. Applies
  automatically on next restart like every other migration in this
  project's history — no manual step.
- **`jen.config`** — new optional `[kea6]`, `[kea6_db]`, `[subnets6]`
  sections. Every `[kea6]`/`[kea6_db]` value falls back to its v4
  counterpart when absent. `[subnets6]` entries accept an optional
  third field, `paired_v4_subnet_id`, for the Subnets page pairing.
- **Test suite**: `tests/test_kea6.py`, ~150 tests covering every layer
  above — config fallback, the DUID/MAC extraction edge cases (DUID-LL,
  DUID-LLT, DUID-EN, DUID-UUID), the one-to-many reservation shape, the
  toggle's all-or-nothing success semantics, and — critically — that
  the subnet-edit preview endpoint never sends more than one SSH
  command (the dry-run test), never a second apply/restart call.
- Found and fixed a real pre-existing test-isolation bug along the way:
  `tests/conftest.py`'s `_patch_extensions()` predated the `KEA6_*`
  extensions fields and never reset them, which silently corrupted
  global state for any test running after one that called
  `AppConfig.apply()`/`reload()` — invisible until this release's DB
  connection-pooling logic started comparing `KEA6_DB_HOST` against
  `KEA_DB_HOST`.
