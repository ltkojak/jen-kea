# Jen — Architecture & Threat Model

This document exists because a lot of Jen's security-relevant design
decisions only ever lived in CHANGELOG entries and one very long audit
conversation. Writing them down once means the next person touching this
code — future maintainer, contributor, or another audit session — starts
from the actual reasoning instead of rediscovering it from scratch.

## 1. System overview

Jen is a single Flask application, deployed as one process (`run.py`),
that manages Kea DHCP servers directly:

```
┌─────────────┐         MySQL (jen_db)        ┌──────────────┐
│   Browser    │◄──────────────────────────────│   MariaDB    │
│  (HTMX UI)   │         MySQL (kea_db)         │ (jen + kea)  │
└──────┬───────┘                                └──────────────┘
       │ HTTPS
       ▼
┌─────────────────┐   Kea command HTTP API    ┌───────────────┐
│   Jen (Flask)    │──────────────────────────►│  Kea DHCP4/6  │
│   run.py         │   SSH (config push,       │  Server(s)    │
│   www-data user   │   restarts, log reads)    │               │
└─────────────────┘◄──────────────────────────┘└───────────────┘
```

The command HTTP API is reached one of two ways, chosen by
`[kea] connection_mode` (`jen/services/kea.py`):

- **`ca`** (default) — one `kea-ctrl-agent` endpoint routes commands to
  each daemon by a `"service"` field. Every release before v5.10.0 did
  only this.
- **`direct`** — Jen talks to each daemon's own `http`/`https` control
  socket. ISC deprecated the Control Agent in Kea 3.0 and **removed it in
  3.2**, so `direct` is the only option on current Kea. `kea-dhcp4` and
  `kea-dhcp6` each get their own URL (`[kea] api_url` / `[kea6] api_url`,
  explicit port required), and the `"service"` field is omitted. For an
  `https://` socket Jen can present a client certificate (`[kea]
  api_client_cert` / `api_client_key`) — Kea's per-daemon TLS socket
  defaults `cert-required` to true, so mutual TLS is the norm. The client
  key sits under `/etc/jen/ssl` readable by `www-data`; a compromise of
  the Jen process exposes it exactly the way it already exposes the Kea
  SSH key — one more reason for the planned Kea-host helper (§3.3), not a
  new class of exposure. Each server's v6 endpoint and authored bind
  address are its own; `[kea6]` is the primary's override only.

Deliberately **not** an agent-based architecture. There's no separate
process running on each Kea server the way Stork's `stork-agent` works —
Jen connects out to each Kea server directly, either via the command HTTP
API (for reads/live status) or via SSH (for config file changes and
service restarts). This is a real, considered tradeoff:

- **Why:** a single-process, no-agent design is dramatically simpler to
  deploy and maintain for a solo admin managing a handful of servers. No
  agent to install/update/monitor on each Kea box, no separate
  agent-to-server protocol to secure.
- **The cost:** it doesn't scale to fleets the way an agent architecture
  does, and config changes go through SSH + generated scripts rather
  than Kea's native config-management hooks. See §3.3 below for how
  that's mitigated.

Jen's own data (users, sessions, audit log, alerts, devices, plugin
state) lives in `jen_db`. Kea's own data (leases, reservations, DHCP
options) lives in `kea_db` — a separate MySQL database that Kea itself
owns the schema for. In production these are typically two different
databases (possibly on different hosts); Jen never modifies Kea's schema,
only its data, and only through the same tables Kea's own tooling would.

## 2. Trust model summary

Jen has three tiers of user: `viewer` (read-only), `admin` (day-to-day
management, scoped to assigned subnets when subnet restrictions are
configured), and `superadmin` (full access, including database
export/import, plugin management, and system settings). The permission
matrix is enforced primarily through two decorators —
`@login_required` and `@_admin_required`/`@_superadmin_required` — plus,
for anything subnet-scoped, `current_user.can_access_subnet()` /
`add_subnet_restriction()` checked per-query.

That subnet-restriction layer has been the single most common source of
real bugs found across this project's audit history — not because the
underlying mechanism is flawed, but because it has to be applied
*consistently* by every route and secondary endpoint that touches
subnet-scoped data, and new endpoints have repeatedly been added without
it. If you're adding a new route that touches leases, reservations,
devices, or anything else tied to a subnet: apply subnet restriction
there too, even if it feels obviously admin-only. It's the checklist
item that has actually mattered in practice.

**IPv6 subnets have no scope of their own: one rule, one place (v5.68.0-beta.8 / Q143).** A user's scope is a list of
*IPv4* subnet ids, and IPv6 subnet ids are a separate numbering space, so a v6 subnet can only be judged through the v4 subnet
it is paired with (the third field of a `[subnets6]` line) — never by comparing its own id with that list, which is meaningless
when the numbers happen to match. The policy is stated once, in `jen/services/access.py`: an unrestricted user (a superadmin,
or an account with no subnet list) sees every v6 subnet Jen knows; a **paired** v6 subnet is accessible exactly when its
v4 subnet is in the user's list; an **unpaired** v6 subnet has no v4 side to inherit from, so it is for unrestricted users
only; a v6 subnet that is not in Jen's map is accessible to no one. Four names carry it — `subnet6_visible()` (pure, for the
Flask-free services that are handed a scope), `can_access_subnet6()`, `accessible_subnet6_map()` (the only v6 map a template
or loop may be given — never `extensions.SUBNET6_MAP`) and `assert_subnet6_access()` (404; "no such subnet" and "not yours" are
the same answer, so a scoped user cannot probe which ids exist). A forbidden explicit `?subnet=` is a 404, never a fallback
to an "all" view. `tests/test_ipv6_access.py` runs every v6 surface against one topology that includes the cases an id
comparison gets wrong, and refuses the string `paired_subnet4_id` in `jen/routes` and `jen/services` except where the pairing
is written or displayed as configuration. This is the same most-common-bug class as above: before beta.8 the v6 pages each
carried a private copy of the rule, and the ones that carried none (delete-reservation, the three subnet-edit routes, the
dashboard totals, the Subnets page) leaked.

**Step-up auth (v5.17.0 / Q6).** A live session is not enough for the
routes that manage a user's own MFA (enroll a second factor, regenerate
backup codes, add/remove a trusted device, an admin's MFA reset).
`session["auth_at"]` records when a password (and MFA, if enrolled) was
last verified; `access.recent_auth_required(minutes=10)` sends a stale
session through `GET /auth/reauth` first. `session.clear()` runs before
every `login_user()` so a pre-auth session can't carry anything into the
authenticated one, and `/logout` is POST-only (a GET renders a confirm
page) so a link or prefetch can't end a session. `audit()` and the
rate-limit `clear_*` helpers write synchronously — a security event is
never lost to an unseen background-thread error.

**OIDC single sign-on is IdP-authoritative (v5.25.0 / Q21).** Once an
account is linked to an identity provider, its role is recomputed from
the token's claims on *every* login and overwritten in `users.role` —
Jen never trusts a stale local value over what the IdP says right now.
A repeat login is matched ONLY on `(auth_provider='oidc', external_id)`
— the IdP's own stable subject (`sub`) claim — never on username or
email. Usernames and email addresses are reassignable at most IdPs (an
employee leaves, their email gets recycled to someone else six months
later); `sub` is defined by the OIDC spec to never be reused, so it's
the only claim safe to treat as a permanent identity. This also means
Jen deliberately never auto-links an OIDC login to an existing local
account by matching username or email — doing so would let anyone who
can get a matching username/email registered at the IdP silently take
over a pre-existing local account. The one sanctioned link path is
manual: a superadmin enters the external ID by hand on the Users page,
after confirming it out of band. An OIDC-linked account's local
password is a random value generated once and immediately discarded —
`/login` refuses it before ever reaching the password check, with the
identical generic message a wrong password gets, so the login form
itself can't be used to discover which accounts are SSO-managed.

**Kea config history at rest (v5.20.0).** `kea_config_revisions` bodies
are encrypted (the same `crypto.py` Fernet key as MFA secrets and alert
credentials — §3.6) — a database dump alone doesn't hand over Kea DB
passwords, HA peer credentials, or DDNS TSIG keys. Above that, the
config-history and diff pages themselves mask those same secret-shaped
keys for anyone who can see them at all; only a `superadmin` can reach
the real, unmasked body, and only through the same step-up gate as
above (`@_recent_auth_required(minutes=10)`), with every unmasked
download written to the audit log. A viewer or admin sees the same
masked diff a superadmin does — the step-up boundary is specifically
"the real secret values," not "the config history feature."

**Whole-config surfaces vs per-object surfaces (v5.49.0-beta.2; unified into
`client_subject.authorize()` at v5.63.0, Q82).** Surfaces
that render the whole Kea config — config history, Doctor, Kea authoring, the
Servers config views — and **Trace**, whose source (Kea's log) has no per-line
subnet boundary Jen can trust — require unrestricted subnet access
(`current_user.all_subnets`). Every per-object surface — leases, reservations,
devices, Explain, Timeline, Reconcile — filters by subnet instead: a restricted user (or a subnet-scoped
API key) sees an object only when every subnet it belongs to is one they can
access, and rows that carry no subnet at all (audit and alert matches) are for
unrestricted callers only. The three policies this section names —
per-object filtering, "every subnet a client is known in" (`all_known`), and
unrestricted-only — now live in one function, `jen.services.client_subject.authorize(subject,
rule=...)`, instead of being reimplemented per caller: `per_object` wraps the
same judgement `filter_client_view` (below) always made, `unrestricted` is
Trace's own gate expressed as a reusable rule, and `all_known` is available
for a future surface that needs it, though none of Q82's own five refactored
consumers currently does.

**A client that moves subnets (v5.49.0-beta.4).** One MAC can have a device row
in subnet A, an active lease in B and a reservation in B. Authorising on a
single "subject" subnet and then returning every object leaked B through A, so
`jen/services/access.py::filter_client_view` now judges the device, the lease
and the reservation each on its OWN subnet (Timeline and its API, the device
API, the Devices page's reservation lookup), recomputes the subject subnet from
what remains, and callers refuse only when nothing remains. Explain and Trace
keep their own rules (Explain rejects a subnet outside the caller's map; Trace
requires every subnet the client is known in). An unplaced device
(`last_subnet_id` NULL) belongs to no subnet a restricted user has: Global
Search, Devices edit/delete/bulk-delete and the API all treat it as
unrestricted-only.

**The event stream and Timeline (v5.42.0).** `jen/services/events.py` writes
one row per notable happening to the `events` table and hands the same event
to in-process subscribers (`jen.plugin_api.subscribe`). It is best-effort
telemetry: a failed row write or a raising subscriber is logged and never
propagates, and subscribers run on one shared bounded worker (v5.49.0-beta.2),
so a plugin can neither veto nor delay core behaviour. The Timeline page
(`jen/routes/timeline.py`) gates the whole response on the client's subnet and
then each row on its own `subnet_id`; rows with no subnet at all — audit and
alert matches that merely mention a MAC or IP — are hidden from restricted
users, because their text can name a subnet the user cannot see.

**Plugin API v3 — emit, row actions, search providers, API-key routes
(v5.57.0).** `jen.plugin_api.emit` re-exports the same `events.emit()` core
code calls, so a plugin can now write to the stream, not just observe it —
gated to a `plugin.<plugin_id>.<name>` kind (refused, logged, never raised,
same contract as every other `emit()` failure mode) so a plugin can never
write a core-looking kind it didn't earn. `register_row_action` and
`register_search_provider` both run **with the caller's own session**
(the three row partials and the search page render them inline, in the
same request as everything else on the page) and are subject to the same
subnet rules as core content: Jen drops a search provider's row whose
`subnet_id` the caller cannot access, and for a restricted caller, any row
with no `subnet_id` at all — the plugin's own filtering is never trusted
alone (the same defence-in-depth rule as `filter_client_view`, above).
`api_key_required` (`jen/services/api_auth.py`, shared with
`jen/routes/api.py`'s own REST v1 routes) is the one way a plugin route
under `/api/v1/plugins/<plugin_id>/…` authenticates a Bearer key; it sets
`g.api_key` and refuses on 401/403, but a plugin route is still Jen code
running in Jen's process — it must scope its own queries by
`filter_subnet_ids(g.api_key, …)` itself, the same as any other API-key
route. `register_alert_type` merges into the same three dicts a core alert
type lives in (`jen/services/alerts.py`), so a registered type is
selectable, templatable and sendable exactly like a core one, with no
separate code path to keep in sync.

**Investigation providers (v5.68.0-beta.4, Q139).** `register_investigation_provider` runs on the same terms as the search
provider above — with the caller's own session, in the request — and adds a second place a plugin's own tables meet a restricted
caller. The seam is narrower here: the provider is handed the `ClientSubject` that `client_subject.authorize` already judged for
this caller (a deep copy, so it cannot edit what the page or the next provider sees), `/client` only asks providers at all for a
client the caller can place in a subnet they may see (the same `names_a_subnet` gate that makes a denial the same answer as
not-found), and `jen/services/investigation_providers.py` validates what comes back (length caps, a row cap, every `href` a
single-slash path inside Jen) rather than trusting the plugin. What a plugin looks up inside its own tables remains its own scope
duty, exactly as for a search provider, and every bundled provider is covered by the plugin authorization matrix
(`tests/test_authz_matrix_plugins.py`).

**A stored object is judged by its own subnet (v5.68.0-beta.11, Q146).** The rule the core already follows for a reservation, a
device or an alert row applies to what a plugin stores about a client: the subnet that decides whether a caller may see a stored row
is the subnet the row was stored in (for a switch position, the subnet of the switch). Where the client is now is a fact the page may
show, and only to a caller who may see that subnet; it never widens access. The first three providers (wol, presence, switchport
1.1.0) judged by the client's current subnet first, falling back to the stored one — Q100's precedence for a *wake* (an act on a live
host), applied to the *display* of stored data — so a favourite saved in B appeared to a caller scoped to A the moment the client
moved to A, and a switch's last five positions were printed without asking where each switch was. The harness of each carries the B
to A case, and the authorization matrix drives the three through a real `/client` request.

**Stored object versus live act (v5.68.0-beta.12, Q147).** Q146 applied that rule to the Investigation card and left the same three plugins'
pages, mutations, search providers and APIs judging by the client's current subnet; the rule now holds on every surface (the matrix
drives list, add, delete, move, search and API in both directions with one shared moved-client fixture, `tests/stored_object_fixtures.py`).
The distinction it needs is between two kinds of thing. A **stored object** (a favourite, a tracked device, a switch position) belongs to
the subnet it was stored in and is judged on that alone; where the client is now is derived at read time and shown only to a caller who may
see that subnet. A **live act** (a wake, a probe, a poll) acts on the device and is judged on where the device is now, because that is
where it lands; and it never borrows what a hidden stored object holds - a wake for a host whose favourite the caller may not see goes ahead
with no SecureOn password and no stored-subnet fallback, so no secret crosses a subnet boundary and nothing says the favourite exists.
A plugin column that an event rewrites to follow the client is not a stored subnet; Presence's `pr_tracked.subnet_id` is the owner subnet,
changed only by an audited move by a caller who can see both subnets.

**Two invariants the next review found were half-applied (v5.68.0-beta.14, Q149).** Each of the last three reviews found the second-order
consequence of the previous fix, so an invariant is now stated with every object and every surface it governs, and the failure path of each
check is a test case too. (1) **A persisted row's identity includes everything its access decision depends on.** The Problems alert was keyed
by subnet in beta.13 but the stored row was not: the unique key was (server, kind, client, address), so the same client's NAKs that name no
address in subnet B, B and A were ONE row whose subnet was reassigned to the newest event's while its count, times and alert state stayed -
B's history, and a qualification B earned, ended up on an A row and was retried there. Migration 33 adds `scope_key` (`COALESCE(subnet_id,
-1)`, because a NULL cannot be part of a unique key) to the key, no upsert assigns the subnet, and `collect` groups by it. (2) **A lookup that
raises is not "absent".** An authorization lookup that gates a write has three outcomes - found, not found, FAILED - and a failed one refuses
without writing or auditing anything. Wake & Actions' and Presence's existence lookups used to degrade to "no such row" on an exception, so with
the database failing for that one statement the route proceeded as a new object judged on the client's current subnet and the upsert rewrote a
row a hidden subnet owns (wol 1.1.3, presence 1.2.1; the other four bundled plugins were checked and have no such lookup).

**A writer scopes by the data it carries, and authorization and mutation are one transaction (v5.68.0-beta.15, Q150).** Two more instances of the
rules above that the next sweep found. (1) *Scope what you write by the data it contains, not by the client it is about.* Switch Port Locator's move
alert and Timeline event named two switches and two ports but were sent with the subnet of the CLIENT's lease, so the names of switches in subnets B and
C reached a channel scoped to A. Every read surface had judged a stored position by its switch's subnet since 1.1.2; the writer now does too (1.1.4): both
switches in one attributable subnet -> that subnet; different subnets or either unattributable -> subnet None, the alert sent `scoped=True` (channels with no
subnet scope only) and the event unrestricted-only - never a per-scope redacted copy. A Presence transition event now carries the tracking's owner subnet
(it carried none, so the owner-scoped user never saw their own device go online). (2) *A check and the write it authorizes are one transaction.* Wake & Actions
and Presence read the existing row on one connection, judged its owner, and wrote on another (`INSERT ... ON DUPLICATE KEY UPDATE`, `UPDATE ... WHERE mac=%s`,
`DELETE ... WHERE mac=%s`), so a row another admin created or moved in between was rewritten. Each now does both on ONE connection: the row is read
`SELECT ... FOR UPDATE`, judged on its own stored subnet, and written with the judged owner as a predicate (`subnet_id <=> owner`) and the count checked (an
UPDATE that changes nothing counts 0 in MySQL, so a 0 is resolved by looking again under the lock: only the same owner is a success); creation is a plain
`INSERT`, and a 1062 (or a 1213 deadlock between two inserts of one key) is handled by locking and judging the row that WON, never by an unconditional
`ON DUPLICATE KEY UPDATE`. wol 1.1.4, presence 1.2.2; the other four bundled plugins' upserts are unrestricted-only or poll-owned and carry no cross-scope
judgement.

**Providers run under a budget Jen enforces (v5.68.0-beta.11, Q146).** `jen/services/provider_budget.py` runs every search and
investigation provider on one shared pool of four threads inside a copy of the caller's request context (the same authenticated user
the page loaded). The request waits at most one second for the group, shows a provider that has not answered as "unavailable (over
1 s)" and goes on; a call still running cannot be stopped, so it keeps its slot, which bounds the damage a hung provider can do: eight
calls outstanding, then new ones are refused as "busy" instead of queueing. Before this the budget was a log line written after the
provider returned, and a provider that hung held the web worker for as long as it liked. **What is and is not guaranteed (v5.68.0-beta.22, Q157):** a page WAITS a bounded time for its
providers (one second for the group) and goes on; a provider that never returns keeps its thread - and its slot - until Jen restarts (a Python thread cannot be stopped), and once enough of them
hang every later provider call is answered "busy"/"unavailable" for the life of the process. Bounded waits, not termination; Health does not yet show the pool's saturation. Hung-provider
containment (an audit of every bundled provider's I/O for finite timeouts and a Health row on `provider_budget.stats()`) is a deferred candidate, not a feature.

**One identity, one place to resolve it (v5.63.0, Q82).**
`jen.services.client_subject.resolve()` is now the only place a typed
identifier (MAC in any separator style, IPv4, IPv6, DUID, or a hostname —
disambiguated against candidates when more than one client uses it) becomes
device + lease(s) + reservation(s) + v6 addresses. Before this, Timeline,
Explain, Trace and the client-shaped REST API each ran their own version of
that lookup, and every Q54–Q56 cross-subnet leak was two of them disagreeing
about the answer. The Investigation page (`GET /client?q=&tab=`) is the one
page built on it directly; Explain, Trace and Timeline keep their own
standalone URLs and their own routes still run their own authorization —
the Investigation page's tabs for those three embed the SAME already-tested
route's own result (via `hx-get` and each route's existing HX-partial
branch), never a second, re-derived copy of the same decision.

**IPv6 and DUID subjects, and the Changes tab (v5.68.0-beta.1, Q134).** `resolve()`
now takes an IPv6 address (through lease6, or a v6 reservation of it, to the DUID
that holds it) or a DUID (straight to its leases and reservation), gated on
`ipv6_enabled` like every v6 path. The MAC — the hardware address Kea captured on a
lease, else the one a DUID-LL/LLT embeds, labelled `mac_source` so the page says
which — carries the subject on into everything keyed by MAC, and Explain, Trace and
Config stay DHCPv4 engines that say so. `authorize()` judges a v6 lease or
reservation on its OWN v6 subnet's `paired_subnet4_id` (the rule Devices and global
search already apply; an unpaired v6 subnet is unrestricted-only), recomputes the MAC
from what survived (`mac_from_v6`, the one rule `resolve()` and `authorize()` share —
a MAC that only a hidden lease supplied is never handed on), and, when a v6 subject
was found only through objects the caller cannot see, drops its MAC, DUID, device and
v4 side exactly as a typed IPv4 address held through a hidden lease already does; the
one thing kept is the MAC embedded in a DUID the caller typed themselves.
The Changes tab (`jen/services/client_changes.py`) reads `kea_config_revisions`,
which is admin content, so it follows `/servers/<id>/config-history`'s own gate (an
admin with access to every subnet) and is not offered to anyone else; it compares
each of the newest 50 revisions of each server with the one before it over the
client's path only (subnet by id or CIDR, shared network, the pools its addresses fall
in, classes, its own config-file reservation, and — since v5.68.0-beta.11 — the service's
global DHCP settings: global options, lifetimes and timers, the reservation modes and
identifiers, the client-id handling; never loggers, control sockets, hooks, interfaces or
the lease database) and shows masked values.

**What Explain evaluates, and why-not (v5.68.0-beta.2, Q135).** The Explain engine
(`jen/services/dhcp_explain.py`) stays pure; `jen/services/explain_inputs.py` builds its client
from the MAC, the lease row, Kea's own log and what was typed, each input labelled by source, and
`jen/services/explain_context.py` is the one place that wires the read-only lookups the engine is
handed (pool occupancy and the holder of a reserved address, both fixed statements over `lease4`).
Two scope rules: a lease in a subnet the caller may not see contributes nothing to the inputs, and
a holder lease in such a subnet is dropped, never blanked; and Kea's log — which has no per-line
subnet boundary — is read only for an admin with access to every subnet, the Trace rule, through
the same helper-only `tail-log` op (no new helper op, no new sudo string), cached 30 s. What the
log carries at each level was measured on Kea 3.0.3, 3.2.0 and 3.3.1 by
`tests/kea_compat/test_log_levels.py` and is written into the user guide.

**Doctor and Trace are read-only views over data Jen already holds.** Doctor
(`jen/services/config_doctor.py`) is pure analysis of the config Jen already
reads from Kea. Trace (`jen/routes/trace.py`) reads the tail of the Kea log
through the existing helper `tail-log` op — deliberately not a packet capture,
so §3.3's narrow helper surface is unchanged.

**The authorization matrix is an enforced invariant, not a convention
(v5.62.1, Q81).** `tests/test_authz_matrix.py::SURFACES` proves every
diagnostic route — one that can resolve or display data about a single
client — refuses to leak another subnet's client through it. Nothing used to
stop the next such route shipping without a row in `SURFACES`; the comment
saying "adding a surface later is one row" was a convention someone had to
remember. `jen.services.access.diagnostic_surface` makes it mechanical
instead: every route it decorates is resolved, once, into
`access.DIAGNOSTIC_SURFACES` right after all blueprints register (Flask
defers a Blueprint route's endpoint/methods/rule until
`app.register_blueprint()` runs, so the triple can't be read at decoration
time), and `test_authz_matrix.py` asserts the decorated set and the set
`SURFACES` actually exercises are identical, in both directions — a
decorated route with no row, or a row whose route stopped being decorated,
both fail CI by name. A second scanner statically greps every route
function in `jen/routes/*.py` for a direct reference to a client table
(`lease4`, `hosts`, `devices`, `events`, `alert_log`) and requires it to be
either decorated or named in `ROUTE_ALLOWLIST` with a one-line reason — the
backstop for a route that touches client data but was never added to
`SURFACES` at all.

**Everything the resolver derives is judged, and plugin routes are inside the
invariant (v5.65.2, Q91).** Two seams were found by audit. `authorize(rule=
"per_object")` used to judge only the three object lists (device, leases,
reservations): the MAC an address resolved to, `holder_mac`,
`previous_holders`, `subnet_ids` and — worst — the MACs behind an ambiguous
hostname reached the page unfiltered, so a subnet-scoped admin could learn
another subnet's MACs by typing a shared hostname or an address in it. Now
`macs_for_hostname` filters every source by the caller's subnets (a row with no
subnet is for unrestricted callers only), an address held through a lease the
caller cannot see hides its holder and everything found through it, a global
(subnet-0) reservation is kept for everyone (it has no subnet to restrict on,
and Explain already shows it), and the page renders only `view.candidates`,
each candidate resolved and judged like a subject of its own; a denial and a
not-found are one message, so the page is not an existence oracle. Alert rows
carry no subnet, so the Overview's "last alert" is judged on the CLIENT, not the row
(v5.68.0-beta.1, Q134): it is shown to a caller who may see every subnet, and to a restricted
one only when the resolved view names a subnet they may see (`client_subject.names_a_subnet`) —
an alert about THEIR client — and what is shown is the alert's type, status and time, never its
message, which can name a subnet. Matching is on whole tokens (`10.0.0.5` no longer matches
`10.0.0.50`). The Alerts log and the dashboard's alert strip offer an Investigate link only to
unrestricted callers, because the identifier is read out of the message they are not shown. The Config and
Explain tabs evaluate only a subnet a lease, a reservation or an explicit
`?subnet=` fixes — otherwise they show a picker of the caller's subnets — and
capabilities are CONFIRMED (§3.14), never assumed. The second seam: the
diagnostic surfaces were collected inside `_register_blueprints`, before any
plugin registered a route, `diagnostic_surface` was not in `plugin_api`, and
the scanner read only `jen/routes`. Collection now runs after `load_plugins`,
`plugin_api` exports the decorator, and two static guards
(`TestEveryDiagnosticRouteIsAccountedFor`) require every route in the
diagnostic route files and every route a bundled plugin registers to be
decorated or named with a reason — "it calls a service" is no escape.
`tests/test_authz_matrix_plugins.py` runs the same B-marker matrix against a
second app with every bundled plugin enabled, with state checks for the routes
that write by id or address; a cell that fails today is `xfail(strict)` with the
release that fixes it. `plugin_api.can_access_subnet` /
`api_key_can_access_subnet` give plugins one answer for "no attributable
subnet": `None` is False unless the caller is unrestricted or opts out
explicitly — core's rule, instead of four plugins each writing
`if sid is not None and sid not in allowed` (which makes None mean allow).

**A fix to a definition is a fix to every use (v5.68.0-beta.18, Q153).** "This lease is current" is `state = 0 AND expire > NOW()`: Kea keeps a
state-0 row past its expiry until reclamation removes it, so `state = 0` alone calls an expired lease current. Q145 (beta.10) defined the
predicate and applied it to "every current-lease query named above" - a list written from one grep of `client_subject`, pinned by a guard over
three files - and twenty-five other queries in the tree kept the bare `state=0` (the default Leases view, every per-subnet count, the delete
safety check, the API summary, Reports, the snapshot that feeds history and the forecast, the alert lease map, the device scan, DDNS, the setup
wizard, three bundled plugins): an expired lease counted as active, as pool consumption and as a device that was "seen". The definition now lives
in one Flask-free module, `jen/services/leases_sql.py` (`ACTIVE_LEASE4/6`, `active_lease4('l')` for an aliased table, `NOT_ACTIVE_LEASE4/6`), and
`tests/test_active_lease.py::TestTheWholeTreeHasOneSpelling` parses EVERY Python file under `jen/` and `plugins/` and fails on a SQL string that
spells `state = 0` / `state != 0` by hand - the allowlist (`HISTORICAL`) holds the deliberately historical queries, each with its reason, and a
stale entry fails too. Plugins receive the constants through `jen.plugin_api` only. The rule for the next definition: a change to what something
MEANS carries the repository-wide grep of its uses as a deliverable (the count goes in the report) and a source test over the whole tree, never
over a file list.

**The subnets themselves are scoped, and the oracle rule reaches Explain (v5.68.0-beta.21, Q156).** `/about` printed every configured subnet's id, name, CIDR and
active-lease count to any logged-in user - the authorization matrix had allowlisted it as "no per-client fields", which was true and was not the rule: the
subnets are the thing scoped, not only the rows about clients. It iterates `current_user.filter_subnet_map` now (the lease counts are taken only for those), and
the matrix entry says so. The Explain route filtered a client's RESERVATIONS after it had chosen the subnet from them: a MAC whose only reservation sat in a hidden
subnet chose that subnet, was refused ("You do not have access to that subnet") and got a different page from a MAC nobody had ever seen. `usable reservations`
(global, or in a subnet of the caller's) are computed before the choice and are the only reservations the route knows, exactly as `usable_lease` is for leases
(Q145); `TestAReservationInAHiddenSubnetIsNotAnOracle` renders both and compares the pages.

**The six layers of a contract (v5.68.0-beta.19, Q154).** A Q that introduces a contract - "pool consumption is the active leases inside the pool union",
"a threshold alert has a transition state", "every secret is written private" - used to apply it to the layer the bug was found in, the LIVE page, and
the next review found the same contract false one layer down, three betas in a row (beta.18's three contracts each had a live-page fix and a
stale persisted, derived, delivered or restored twin). A contract has six layers, and the last step of every Q that states one - and the first
of every audit - is to name, for each, where it is true and which test says so: (1) **live** - the page or job that computes it now; (2) **persisted**
- what is stored (`lease_history`); (3) **derived** - what is computed from the stored thing (Health, the forecast, the forecast alert, Prometheus,
Reports, the dashboard history); (4) **delivered** - did anyone receive the alert (an alert marked handled when no channel took it is not handled);
(5) **restored** - the recovery tool writes the same secrets the installer and the app do, under the same discipline; (6) **exported** - the backup,
the support bundle, the API. Beta.19's own count for beta.18's contracts: pool consumption - live (alerts, dashboard, API: beta.18), persisted
(`lease_history.pool_used`, migration 34), derived (Health, forecast, forecast alert, Prometheus, Reports, dashboard history: `tests/test_pool_used.py`'s
nine surfaces), exported (the support bundle carries `peak_pool_used`); alert transition state - live, persisted (settings), delivered
(`notified`, backoff retries); private writes - live, installer, restored (`jen/tools/restore.py`).

**A lock is an inode (v5.68.0-beta.20, Q155).** `flock` is held on the file a descriptor points at, not on a name, so a lock "repaired" by renaming a fresh
file over its path is a SECOND lock: an installer still holding the old inode and Jen locking the new one both held "the" lock, and the lost update the
lock exists to prevent was back (beta.19's `_replace_lock_with_private_file` did exactly that, and the reviewer confirmed the kernel behaviour). The rules now:
a lock file is OPENED ONCE, with `O_NOFOLLOW`, by one primitive - `tools/private_write.py take_lock` on the installer's side (`--hold-lock`, a coprocess that
prints `locked` and keeps the flock until it is signalled or the installer dies) and `config._open_lock` on Jen's - and an existing file is normalised IN PLACE
(`fchown` to the service user, `fchmod` 0600 on the open descriptor; neither drops an flock; a file with more than one link or that is not a regular file is
refused). A file Jen cannot open refuses the save with the exact fix (`chown <service user>; chmod 600` on the same inode) - no `-L` test followed by an
`exec {fd}>>`, no `install` of a new file, no rename. `tests/test_config_file_lock.py::TestTheLockFailsClosed` holds the flock from a child on inode A and
makes the file unopenable: the save is refused, the inode number is unchanged, the config is unchanged until the holder exits.

## 3. Deliberate trust boundaries

These are places where Jen makes a conscious security tradeoff rather
than an oversight. Documenting them here so future changes are informed
decisions, not accidental regressions.

### 3.1 The self-update sudoers grant

`jen-sudoers` grants `www-data` (the user Jen runs as) exactly three
passwordless commands, matched by `sudo` byte-for-byte:

```
/usr/bin/systemctl restart jen
/usr/bin/systemctl start --no-block jen-update.service
/usr/bin/systemctl start --no-block jen-plugin-install.service
```

None of the three takes any input from Jen. `jen-update.service` and
`jen-plugin-install.service` are both root `oneshot` units that run
`/usr/local/sbin/jen-update-root.py` — owned `root:root`, mode `0700`,
**outside** every directory `www-data` can write — the first with no
arguments (re-derives "the current latest release" from the pinned
`ltkojak/jen-kea` GitHub repo, verifies the tarball's SHA-256 against
the published `SHA256SUMS`, and only then installs — see §6 for the
staged/rollback flow), the second with exactly one fixed flag,
`--plugins` (re-derives a requested plugin install/removal from
`plugins/registry.json` the same way — see §3.10).

**Why this is the boundary:** even a fully-compromised `www-data` can
only trigger "install whatever GitHub currently publishes as latest"
or "(re-)install/remove the plugin whose id is in this marker's
filename, whatever `plugins/registry.json` currently says about it". It
cannot pass a version, a URL, a checksum, or any file content into
either privileged step, because nothing it controls reaches that
script as trusted input — see §3.10 for exactly what a plugin-install
marker is (and isn't) trusted for.

**History — why it looks this way (v5.2.6):** the previous design had
`www-data` write `/tmp/jen_update_install.sh` and `sudo` it. Since
`/tmp` is world-writable and `www-data` was the exact account allowed to
write that exact path, any code execution as `www-data` was root — the
sudoers rule couldn't tell "content the update flow verified" from
"content something else wrote". Moving the whole pipeline into a
root-owned script that takes no trusted caller input closed that; the
same request/execute split was applied again in v5.27.0 (§3.10) for
plugin installs, the one place that gap still existed.

**What this means for any future change:** rule 8 in `CLAUDE.md` — a
changed `sudo` command string is a changed sudoers line in the same
commit, and this section is updated with it. Never add a parameter to
any of the three commands, nor derive a decision from the *content* of
any file `www-data` can write — a plugin marker's filename (which
plugin id, which action) is the only thing read from it, never its
bytes.

**Stated invariant (v5.67.0-beta.7, Q119): root never imports the `jen`
package.** `install.sh`'s own `verify_install()` used to call
`"$PYBIN" -c "from jen import create_app; …"` unwrapped, as root, to
syntax-check templates and modules — but `create_app()` calls
`load_plugins()`, which imports every enabled plugin out of
`$CONTENT_DIR/plugins`, a directory the *service user* owns. A
compromised service account that planted a plugin there got it imported
as uid 0 on the next `install.sh` run (upgrade, `--unattended`,
`--repair` all reach `verify_install()`). Fixed: both checks run through
`runuser -u "$JEN_USER"`, exactly like the existing DB-seeding step that
already called `create_app()` correctly. The only Python `install.sh`/
`uninstall.sh` ever run directly as root is `jen-update-root.py` itself
— a dedicated, pure-stdlib script that never imports `jen` at all — and
`jen.tools.restore` (invoked by `sudo ./install.sh --restore`/
`--rollback`), which genuinely needs root for `os.chown`/`systemctl` and
is its own, separately-reasoned-about trust boundary (§6.2), not an
inline snippet. `tests/test_no_root_jen_imports.py` scans every inline
`-c "..."` python invocation in both scripts and refuses one that
imports `jen` (statically or via `__import__`) without `runuser`.

**The restore tool writes under the same discipline as the installer (v5.68.0-beta.19, Q154).** `jen.tools.restore` runs as root and was the one writer
exempt from it: `write_bytes` then `chmod` (so under the installer's umask 022 a previously absent SSL/SSH/MFA key was born 0644 until the chmod), a symlink
the service account had left at a live path was followed by root, a kill mid-write truncated the live file, and a failing `chown` was a printed warning.
`_restore_private` is now the only way it writes a file - `_write_file`, `_copy_file` and `_restore_tree` (the rollback) all call it: the destination must be
under the restore root (`/etc/jen` or the content directory) with no symlink component below it, and a symlink or non-regular file at the destination is
refused (`RestoreRefused`), never followed; a unique `O_CREAT|O_EXCL|O_NOFOLLOW` 0600 temp in the destination's own directory; the source streamed in 1 MiB
chunks and fsynced; the recorded owner applied to the open descriptor with `fchown` (a failure ABORTS the restore - a secret owned by the wrong account is not
a restore) and then the mode; `os.replace` and an fsync of the directory, so the path is the old file or the complete new one. The allowlist entry that exempted
`restore.py` from `tests/test_private_files.py`'s source scan is gone.

`jen-update-root.py` must never derive a decision from `sys.argv`
reachable via the sudoers grant above beyond the fixed `--plugins`
dispatch (`tests/test_jen_update_root.py` pins this). `--check-layout`
and `--write-layout-markers` (v5.67.0-beta.5, Q117 — see "Relocatable
install" below) are a deliberate, narrower exception to that rule's
*spirit*, not a loophole in it: neither is ever reachable through the
sudoers grant at all. `jen-sudoers` still pins the two systemd units'
`ExecStart` lines byte-for-byte (no argv, or exactly `--plugins`), and
the installed script is `root:root` mode `0700`, so a compromised
`www-data` cannot exec it directly with *any* argv, pinned or not.
Only a human already running `install.sh`/`uninstall.sh` as root
(`sudo ./install.sh`, `sudo ./uninstall.sh`) ever calls either flag — a
direct function call from an already-root process, not a privilege
escalation path. A genuinely new sudoers-reachable flag is still held
to the original, stricter rule.

**systemd sandboxing (v5.17.0 / Q6 6E).** `jen.service` runs with
`ProtectSystem=strict` (only `/etc/jen` and `/var/lib/jen` writable —
`/opt/jen` is read-only since v5.13.0), `PrivateTmp`, `PrivateDevices`
and the `Protect*` / `Restrict*` family. It deliberately does **not**
set `NoNewPrivileges`, `CapabilityBoundingSet` or `ProtectProc`: Jen's
only privileged action is `sudo` (the three commands above, and the
banner-warned legacy `python3` path on un-migrated Kea hosts), which
needs the setuid transition. `jen-update.service` — the root updater —
is intentionally left un-sandboxed; it writes `/opt/jen` and
`/usr/local/sbin`. `tests/test_service_hardening.py` pins both.
`jen-plugin-install.service` (§3.10) is the same shape for the same
reason — it also writes under `/opt/jen` as root — but isn't itself
covered by that test, since it's a plain `ExecStart` of the same
already-hardened script with a different flag, not a second
independently-configured unit.

**Release channels (v5.32.0).** The root script decides *which* release
to install from two inputs it reads itself: GitHub's release list and
`[updates] channel` in `/etc/jen/jen.config` (`stable` or `beta`,
anything else read as `stable`). The web process writes that key
through `AppConfig` and offers the same release on the Updates page,
but nothing the web process says reaches the root side — the channel
lives in the INI precisely because the script reads the INI and never
the database. A beta is filtered by GitHub's `prerelease` flag, which
only the release workflow sets (any tag with a prerelease suffix); the
signature and checksum verification below is identical for both
channels. The version grammar and the picker are one block of code in
`jen/version.py`, embedded byte-for-byte in the script and diffed by a
test, so the two sides cannot drift on what "newer" means.

**Relocatable install (v5.67.0, Q114): where root's paths come from is
its own trust boundary, separate from `jen.config`.** `install.sh` can
put the app tree, `/etc/jen` equivalent and data directory anywhere
(`docs/installation.md` Method 1c) instead of the historical
`/opt/jen`/`/etc/jen`/`/var/lib/jen`. That choice has to reach
`jen-update-root.py` somehow — but `jen.config` is exactly the wrong
place to read it from: unlike the update channel above, a *path* is
something the root side then trusts absolutely (it's about to `chown`,
extract a tarball, and write a systemd unit there), and `jen.config`
lives inside `/etc/jen`, which is `chown`ed to `www-data`
(`install.sh` — see §6.1). Reading a layout path from it would let a
fully-compromised `www-data` redirect root's own writes anywhere it
chose, defeating the entire boundary this section exists to describe.

The layout instead lives in `/etc/jen-layout.conf` — root:root, mode
`0644`, and deliberately **outside** `/etc/jen` itself, so nothing
`www-data` can write is ever in the path root reads to find out where
things are. `install.sh` writes it once, at first install; every later
`--upgrade`/`--repair`/`--configure` run and every invocation of
`jen-update-root.py` read it back (`load_layout()` there; rule 8 still
holds — this is a fixed path the script reads itself, never an
argument, exactly like the channel above). Absent means the historical
defaults, unchanged for every install made before this Q. Present but
failing validation (wrong owner, a symlink, group/other-writable, a
value outside the shared rules `docs/installation.md` Method 1c and
`docs/ARCHITECTURE.md` §6.1 describe) is a hard refusal — logged and a
nonzero exit from `jen-update-root.py`, `fatal()` from `install.sh` —
never a silent fallback to the defaults, the same fail-closed posture
as the checksum/signature checks elsewhere in this section.

**ONE checker (v5.67.0-beta.5, Q117).** A ChatGPT review of
5.67.0-beta.3, confirmed by Fable against the shipped commit, found
`install.sh`'s own bash copy of the path-validation rules had already
drifted from `jen-update-root.py`'s Python copy: the bash side's
forbidden-prefix list let `--config-dir /etc` or `--app-dir /usr`
through, both of which then got recursively `chown`'d/`chmod`'d by
`install_files()`. The fix was to delete the bash copy outright —
`install.sh` and `uninstall.sh` now both call
`jen-update-root.py --check-layout --for {install,upgrade,uninstall}
[--app-dir X --config-dir Y --data-dir Z]` (install.sh's own copy,
already running as root; uninstall.sh's installed `/usr/local/sbin`
copy) and treat its stdout/exit code as the single source of truth —
see the exception carved out for this in "What this means for any
future change" above. The contract this one checker enforces:

- **A dedicated directory, not just "not obviously wrong".** Every FHS
  shared root (`/etc`, `/opt`, `/usr`, `/usr/local`, `/var`, `/var/lib`,
  and the rest of the list in `jen-update-root.py`'s own
  `_LAYOUT_SHARED_ROOTS`) is refused outright, exact match — a sibling
  like `/optional-thing` is unaffected. A conservative path grammar
  (letters, digits, `.`, `_`, `-` per segment, 200 characters) closes
  the specific injection surface `install.sh` already has into a layout
  path: `sed -e s#@@APP_DIR@@#$INSTALL_DIR#g` when rendering
  `jen.service` (a `#` or `&` rewrites the sed expression), `%` as a
  systemd specifier, a space splitting `ExecStart`.
- **Every existing ancestor must be root-owned and not group/other-
  writable — a hard refusal, no CI-driven exception.** Q114 downgraded
  the writable case to a warning because GitHub's hosted runner ships
  `/opt` mode 777; that was wrong — a writable parent lets a local user
  rename the root-owned child aside and plant a symlink in its place for
  the next privileged run to follow, which is exactly the attack this
  check exists to close. The CI accommodation now belongs in CI itself
  (`.github/workflows/tests.yml`'s `install` job hardens `/opt` to 755
  before using it; `install-layout-negative` proves the refusal still
  fires against a 777 ancestor). `app_dir` itself (once it exists) gets
  the same treatment on every privileged run, not just at first
  install — `config_dir`/`data_dir` are intentionally `www-data`-owned
  (§6.1) so this direct check is `app_dir`-only; their safety comes from
  the ancestor walk and the marker below.
- **The dedicated-directory marker.** A layout target for a *fresh*
  install must be absent, an empty directory, or already carry a
  `.jen-directory` marker (`role`/`version`, plain `key = value` text,
  root:root 0644, same trust level as the layout file) — never a
  directory with unrelated real content, silently reused. A genuine
  pre-Q117 install has no marker yet: `--for upgrade`/`--for uninstall`
  recognize one by the same content each role's own install step always
  puts there (`config_dir` has `jen.config`; `app_dir` has `releases/`
  or a flat `run.py`; `data_dir` has `icons`/`branding`/`backups`/
  `keys`) and retroactively stamp the marker the first time they see it.
  An unrecognized, unmarked directory is tolerated on `--for upgrade`
  (refusing every upgrade until a human intervenes would be its own
  outage) but refused outright on `--for uninstall` (destructive, so it
  never guesses). `install.sh` itself stamps a fresh install's markers
  once `install_files()`/`migrate_content()` have actually created the
  three directories (`--write-layout-markers`, called after the
  install's own `--check-layout --for install` ran — that call is
  necessarily *before* anything exists, so it never writes a marker
  itself). A box from before Q114 has no layout file yet but a real,
  non-empty `app_dir`: `install.sh` detects that and sends `--for
  upgrade` rather than `--for install`, since the latter's absent/
  empty/marked rule exists only to stop a *fresh* install from silently
  reusing unrelated content.

  **What the marker is for, and what it is not (v5.67.0-beta.7,
  Q119).** It defends against an *operator's own mistake* — pointing a
  fresh install at a directory that happens to already hold unrelated
  content, or at the wrong pre-existing Jen directory during a recovery.
  It is **not** a defense against the *service account*: `config_dir`
  and `data_dir` are deliberately `www-data`-owned (so Jen itself can
  write `jen.config`/user content there), which means `www-data` can
  always delete or recreate `.jen-directory` outright. What the marker's
  write path (`write_layout_marker()`) *does* defend against is a
  narrower, sharper attack: a compromised service account planting
  `.jen-directory` as a *symlink* to a root-owned file elsewhere
  (`/etc/sudoers.d/jen`, `/etc/shadow`) so that the next privileged
  write through that name corrupts the symlink's target instead of the
  marker itself. `write_layout_marker()` refuses outright if anything
  already at that name isn't a plain regular file, and writes through a
  sibling `tempfile.mkstemp()` + `os.replace()` rather than opening the
  marker's own path directly, so even a symlink planted in the TOCTOU
  window between that check and the write is replaced, never followed.

`tests/test_layout.py` exercises `install.sh`'s own glue (argument-
building, key=value parsing, refusal pass-through) against a stubbed
checker; `tests/test_jen_update_root.py` exercises the real validation
rules — grammar, shared roots, nesting, ancestor ownership, the marker
contract — against real temp dirs.

**Secrets are private from their first byte (v5.68.0-beta.15, Q150).** `jen.config` (every database password and API credential), the SSL private
key and the Fernet key used to be written with `open(tmp, "w")` and tightened with `chmod` afterwards: created with the process umask (0644 under
systemd's default 0022), the secret written into it, and only then restricted. The only thing that closed the window was the directory's own mode
(`/etc/jen` is service-owned 0750 on a stock install), which is not a thing to depend on. `jen/services/private_files.py::write_private_file` is the
discipline in one place and is the same one the Kea-host helper uses for every file it writes (§3.3): a unique `O_CREAT|O_EXCL|O_NOFOLLOW` temp in the
target's own directory, mode 0600 from the first byte, written and fsynced, the FINAL owner and mode applied to the descriptor (never to a path another
process could swap), then `os.replace`. A file meant to be 0640 (the Flask secret key, the SSL key) is 0600 until it is complete. `run.py` sets
`os.umask(0o077)` first thing in `main()` (Docker and a hand-run server have no unit) and `jen.service.template` carries `UMask=0077`, so anything else the
service creates is private to it by default. The root self-updater and the plugin installer are separate units with their own umask and are NOT given
it (it would make every file they install unreadable to the service user; `tests/test_private_files.py` asserts that). The proof is a directory
watcher: it stats every entry of the directory in a tight loop while each real writer runs 300 times under umask 022, and no entry is ever seen with a
group or other bit before it is complete. A source test refuses a new write-mode `open()` / `Path.write_*` in `jen/` that is not on its reviewed list.

**What root trusts, and from where (v5.68.0-beta.16, Q151).** `$CONFIG_DIR` and `$CONTENT_DIR` are SERVICE-OWNED (§6.1): the service account can
plant any file or symlink in them. Two rules follow for everything the root installer and updater do, and `tests/test_invariant_sweeps.py` (S1, S9)
enforces them over the whole repository: **(1) root never copies, executes or installs anything into the app tree (`$INSTALL_DIR`, `/usr/local/sbin`,
`/etc/systemd`) from under those directories** - its inputs are the release tarball and its own snapshots, which live in `$ROOT_ROLLBACK_DIR`
(`$INSTALL_DIR/.rollback`, root-owned, go-rwx). The upgrade snapshot of `run.py` and the `jen/` package used to be written to `$CONFIG_DIR/backups` and a failed upgrade
`cp`ed it back as root (Q119 moved only the `ext.*` snapshot and called it closed): a compromised service account that planted a `run.py` there had it installed
by root. Now the snapshot is taken with `cp -a --no-dereference` from a source whose real path is verified to be under `$INSTALL_DIR`, and the rollback
(`_trusted_snapshot`) refuses one that is not root-owned, is a symlink, contains a symlink, or is not under `$ROOT_ROLLBACK_DIR`; snapshots a pre-5.68.0-beta.16
install left in `$CONFIG_DIR/backups` are no longer removed (v5.68.0-beta.20, Q155: root deletes nothing under a service-owned tree - the two `rm -rf` cleanups
that ran there were the leftovers' last use of it); the `jen.config.*.bak` copies are written under `$ROOT_ROLLBACK_DIR/config/` (root-owned 0700) and an existing
`$CONFIG_DIR/backups` is left exactly as it is and never read by root. **Root-side writers walk by directory descriptors (v5.68.0-beta.20, Q155).** `tools/private_write.py
--trusted-root DIR` and the restore tool's `_restore_private` open the root once and every component below it with `O_DIRECTORY | O_NOFOLLOW` relative to the previous
descriptor (created when absent); the temp, the lstat of the destination, the rename and the directory fsync are all relative to the LAST descriptor, so nothing is
looked up by pathname after it was checked: a symlink at any component is refused, and a directory swapped for a symlink while the write is in flight is refused
before the rename (the descriptor's directory is compared with what the path now names). The earlier version resolved the parent of the destination by pathname at the
moment of `open` and `rename`, so a symlink the service account planted at `$CONFIG_DIR/backups` was followed by root. **(2) a secret root writes into those directories is written private from its first byte** through `tools/private_write.py` (shipped in the tarball; the
installer's `_private_write`): a symlink at the live path is refused, a unique `O_EXCL` 0600 temp in the same directory, fsync, owner and mode on the descriptor
(a failing chown aborts), replace - the same discipline as `jen/services/private_files.py` and the Kea helper's `_install_private`. `write_config` used `cat >` under
umask 022 (created 0644, followed a planted link, tightened after every password was in it) and copied the backup with `cp`; both go through the tool now. Docker's
bootstrap (`run.py::_build_config_from_env`) writes through `write_private_file` (a crash mid-write leaves no live file, so the next launch regenerates it) and Docker's
`.env` is written under `umask 077`.

**A set of files is installed all-or-nothing, and a live file is never moved away first (v5.68.0-beta.16, Q151).** `certs.write_atomically` did `os.replace(live, live + ".prev")` BEFORE the
replacement existed (a failure right after left no live file at all), the HTTPS upload wrote certificate, key, CA bundle and combined chain one after another, and
`kea_tls.commit_rotation` promoted the Kea CA's four staged files one by one - after the remote servers had already moved to the new CA - so a failure at any step left a mixed or
missing set (a new key beside an old certificate: gunicorn refuses to start). `certs.commit_file_set(members, keep_prev=True)` is now the ONE place a set is installed and the only
place a `.prev` is made (S2): STAGE every member (a unique O_EXCL 0600 temp, final mode applied), SNAPSHOT every live member into memory without moving it and write `<name>.prev` as a
COPY, REPLACE each in order; on any failure every member already replaced is put back byte-for-byte (one that did not exist is removed), every staged temp is removed, and the
error is re-raised - or an OSError naming every path now wrong if a restore also failed. `write_atomically` is a set of one. The failure injection breaks the install before and
after every member in the staging, in the `.prev` copy and in the replace, and after each asserts the live set equals the original and no key/certificate mismatch exists. **What is and is not guaranteed (v5.68.0-beta.22, Q157):** the set is
all-or-nothing against every failure the code can HANDLE - an exception between two replaces, a failed `chown`, a full disk - and it restores what it replaced. It is not crash-consistent: a SIGKILL,
power loss or OOM-kill BETWEEN two `os.replace` calls leaves a mixed set on disk with nothing to finish or revert it at the next start. A durable journal (`<dir>/.jen-tx`: the previous and the new
generation, fsynced before the first replace, removed after the last, read by startup and by the helper's next op) is the deferred candidate that would close that window; until then a mixed set is
recovered from the `.prev` copies the commit leaves (`docs/troubleshooting.md`).

### 3.2 SSH host-key verification (trust-on-first-use)

Every outbound SSH connection Jen makes (`subnets.py`, `ddns.py`,
`servers.py`) uses trust-on-first-use: the first connection to a new
host is accepted automatically and the key is persisted
(`/etc/jen/ssh/known_hosts`), but a *changed* key on a later connection
to a previously-known host is rejected. This is implemented via two
shared helpers in `jen/services/auth.py` — `ssh_cli_opts()` (for plain
`ssh` CLI calls, using `StrictHostKeyChecking=accept-new`) and
`paramiko_load_known_hosts()` (for paramiko-based connections, pairing
`AutoAddPolicy()` with an explicit load + `save_host_keys()` after
connecting).

**Why not strict verification with pre-shared keys:** this would require
an out-of-band step to get each Kea server's host key onto Jen before
first use, which is real setup friction for a homelab tool whose main
value proposition is being easy to stand up. TOFU is the standard,
accepted middle ground (it's what `ssh` itself defaults to for a human
operator).

**What this means:** an attacker positioned to MITM the *very first*
connection to a given Kea server (before Jen has ever talked to it)
could plant a malicious key that then gets trusted permanently. On a
private homelab LAN this is a low-realistic-risk scenario. If Jen is
ever deployed somewhere the network path to Kea servers isn't fully
trusted, that assumption should be revisited.

### 3.3 SSH-based config push instead of native Kea config management

Jen changes Kea configuration over SSH — it edits the on-disk config
file, tests it with `kea-dhcp4 -t`, and only replaces the live file
(after a backup) if the test passes. It does **not** use Kea's Control
Agent API for config changes: a live-only API change is lost on Kea's
next restart unless something also rewrites the file, so editing the
file directly and testing before committing is more robust for Jen's
use case (persistent, restart-safe config). The tradeoff is that this
is more fragile to Kea version changes than native hook-based
integration would be — if Kea's config format or CLI flags change,
Jen's logic has to be updated to match.

**How the push happens (v5.11.0 — `jen-kea-helper`).** Every Kea-side
operation Jen performs — read a config, `kea-dhcpX -t` a candidate,
replace the live file, restart/enable/disable a daemon, tail a log,
install a Kea package — goes through a fixed-function helper on the Kea
host. `service` is one of `dhcp4`, `dhcp6`, or (v5.23.0) `d2`
(kea-dhcp-ddns) everywhere one of these ops accepts it:

- `jen-kea-helper` is a small pure-stdlib script installed at
  `/usr/local/sbin/jen-kea-helper`, owned `root:root` mode `0755`.
  `www-data` cannot read or modify it.
- Jen invokes it as `sudo -n /usr/local/sbin/jen-kea-helper <op>` with
  one JSON object on stdin; it replies with one JSON object on stdout.
  It **never executes anything it is handed** — stdin is data only.
- The **one** Kea-side sudoers line is
  `youruser ALL=(root) NOPASSWD: /usr/local/sbin/jen-kea-helper`. The
  bare command (no argument list) is deliberate: the control is the
  helper's own op allowlist and path walls (config files must sit
  directly in `/etc/kea` or `/usr/local/etc/kea` and match
  `*.conf`; logs must resolve under `/var/log` and end `.log`), not
  sudo's argument matching.
- **The invariant is now "no *unverified* self-update", not "no
  self-update at all" (v5.66.0, Q103).** The original v5.11.0 design had
  no `update` op whatsoever: "Jen writes a file the Kea host then runs
  as root" was exactly the capability being removed, and letting the
  helper update itself — trusting whatever Jen sent — would put it
  straight back. A maintainer report showed the cost of that: every
  helper update, forever, needed the legacy `NOPASSWD: /usr/bin/python3`
  grant (real root) added by hand and removed again. `update` (helper
  v6) keeps the invariant in a stronger, still-safe form instead of
  reopening it: a candidate is installed only when `ssh-keygen -Y
  verify` accepts a signature from the **Jen project's own release
  key** — the identical permanent ed25519 trust root §3.1's self-updater
  already uses, embedded in the helper byte-for-byte (a test diffs the
  two copies) — under a namespace distinct from the release-tarball's
  own (`jen-kea-helper`, never `jen-release`, so one signature can never
  be replayed as the other), **and** the candidate declares a strictly
  higher `HELPER_VERSION` than the one running (equal counts as
  not-newer; a downgrade is never installed, even signed). A
  fully-compromised Jen can therefore install a genuine, newer Jen
  release's helper, and nothing else — Jen's own SSH identity is never
  the thing being trusted, exactly as before. The op never touches
  sudoers and never restarts anything; candidate, signature and an
  optional local `/etc/jen-kea-helper/allowed_signers` (root-owned, not
  group/other-writable, ≤ 8 KiB — an ADDITIVE rotation/test hook, never
  a replacement for the embedded key) are written into a fresh
  `tempfile.mkdtemp()` beside the real binary and removed unconditionally
  when the op returns; the final install is a plain `os.replace()`.
  **Rotation:** add the new key alongside the old one in BOTH
  `RELEASE_SIGNERS` copies (`jen-update-root.py` and `jen-kea-helper`)
  for one release before switching which key `release.yml` signs with —
  the same shape as §3.1's own rotation note, done in the same commit
  so the two never drift (a test enforces the twin). A host below
  helper v6 has no `update` op at all: reaching v6 is a fresh
  install/upgrade over the legacy `sudo python3` path, pressing
  **Update helper** in Settings → Kea → SSH — it re-copies the current
  file, then asks the freshly-copied helper its own version rather than
  trusting what the copy script printed (v5.19.1 fix: it used to trust
  the echo, and separately used to treat any installed version as fully
  current instead of comparing against the version Jen actually wants)
  — or a manual `install -m 0755` by an administrator. That one hop
  still needs the legacy `sudo python3` grant present for that one run,
  same as a fresh install — the last time it is ever needed.
- **The legacy grant can remove itself — never create itself** (v5.49.0).
  Settings → Kea → SSH has **Remove legacy grant**: over that grant, a fixed
  script deletes `/etc/sudoers.d/jen-kea`, refusing unless the helper's own
  sudoers file exists, holds the helper line and passes `visudo -c`, and Jen
  itself refuses unless the helper already answers. It is not a helper op and
  adds no sudoers string; there is deliberately no opposite action, because
  writing `NOPASSWD: /usr/bin/python3` would be Jen handing itself root on
  the Kea host. Granting stays by hand (the page prints the commands).

**Helper protocol v2 (v5.16.0 — optimistic concurrency).** `read-config`
now also returns `"sha256"`, the hex SHA-256 of the raw config-file
bytes (whitespace and key order included — the point is to detect a hand
edit). `apply-config` accepts an optional `"expect_sha256"`: when
present, the helper takes an exclusive `flock` on a sidecar
`<path>.jen_lock` (never on the config itself — `os.replace` swaps the
inode), re-hashes the live file, and refuses with
`{"ok": false, "error": "conflict", "sha256": <current>}` **before**
running `kea-dhcpX -t` if it doesn't match (`""` means "must not
exist"). Success also returns the SHA of the bytes just written. Every
v2 response — protocol errors included — carries `"helper_version"`, so
Jen learns the real number from any op, not just `version`.
`JEN_HELPER_MIN_VERSION` stays 1: a v1 host keeps working, and
`JEN_HELPER_WANT_VERSION = 2` only drives an "upgrade available" hint.

**Helper protocol v3 (v5.23.0 — D2 support).** `"d2"` joins
`"dhcp4"`/`"dhcp6"` as a valid `service` for `read-config`,
`test-config`, `apply-config`, and `service`, resolving to the
`kea-dhcp-ddns` binary and the `kea-dhcp-ddns-server` /
`isc-kea-dhcp-ddns-server` unit pair. No protocol *shape* changed — a
v2 caller talking to a v3 helper sees identical dhcp4/dhcp6 behavior —
so this is purely an allowlist addition, not folded into
`JEN_HELPER_WANT_VERSION`: D2 is an optional subsystem most installs
never touch, and bumping the general "upgrade available" threshold to 3
would nag every operator instead of just the ones who open the DDNS
page's D2 tabs. `kea_host.d2_supported(server_id)` checks the
per-server recorded version directly, gating the D2 tabs only. A host
still on v1/v2 gets a plain "D2 needs jen-kea-helper v3+" message
instead of a `not-allowed` helper error — and, deliberately, is never
routed through the legacy `sudo python3` fallback for `d2` calls: that
engine's binary/unit-name logic treats "anything that isn't dhcp4" as
dhcp6, so a d2 call reaching it would have silently run `kea-dhcp6`
commands against D2's own config file.

**Helper protocol v4 (v5.29.0 — `install-tls`).** One new op, for the
https half of "Set up direct socket" (Settings → Kea): it writes the TLS
material a daemon's `https` control socket references — exactly three
files, `ca.crt`, `server.crt`, `server.key`, under the **fixed**
directory `/etc/kea/tls/<service>/`. The payload names the service and
carries the three PEM bodies; it never carries a path, so the op's whole
path wall is "these three basenames under this one directory" — the
same shape as the config-file wall, with nothing for a caller to steer.
The directory is created `root:root 0755`; each file is written tmp +
`os.replace`, owned `root:<daemon group>` (the unit's `User=`, else
`_kea`, else root — ISC's own packages run the daemons as root), `0640`
for the key and `0644` for the certificates; a pre-planted symlink at
the root, the service directory, or any target is refused. Content is
guarded only by PEM block markers and a 64 KiB cap: the helper is pure
stdlib and cannot parse PEM, so Jen validates the material it generated
(`jen/services/kea_tls.py`, with `cryptography`) before sending it, and
the helper only makes sure it's writing a PEM-shaped file and not, say,
a shell script into a root-owned directory. Ordering is what makes the
op safe to use: `install-tls` runs **before** `apply-config`, and the
apply carries the three paths as `tls_paths`, so a half-done push is
caught as `tlsmissing` by the config test rather than as a daemon that
won't start. Like D2, this is gated per host by
`kea_host.tls_supported(server_id)` (recorded version ≥ 4), not by
`JEN_HELPER_WANT_VERSION` — only the https path needs it — and a v1–v3
helper's `unknown-op` reply becomes a plain "needs helper v4" message.
There is deliberately **no legacy fallback** for this op: key material
never rides a generated root script.

**Helper protocol v7 (v5.66.0-beta.2, Q104 — hardening the signed
update, no protocol shape change).** A third-party review of v6's design
found three gaps in the machinery AROUND `update`, none in what it
verifies:
- **No PATH trust.** Every binary the helper runs (`kea-dhcp4/6`,
  `kea-dhcp-ddns`, `systemctl`, `apt-get`, `ssh-keygen`) is resolved
  through `_find_bin()`, a root-owned walk over a fixed `_BIN_DIRS` list
  (`/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`, `/usr/local/sbin`,
  `/usr/local/bin`, in that order) requiring each candidate be a regular
  file, root-owned, and not group/other-writable — never `shutil.which()`,
  never a bare name handed to `subprocess.run`. The helper's own shebang
  is `#!/usr/bin/python3 -I` (isolated mode), and every subprocess it
  spawns gets a fixed, minimal environment rather than the one it
  inherited. This was already safe on every real target (Ubuntu's
  `secure_path` covers it), but a root privilege boundary shouldn't
  depend on the caller's sudoers configuration staying that way.
- **`HELPER_BUILD`.** A helper-only change (like the PATH hardening
  itself) doesn't bump `HELPER_VERSION` — the protocol didn't change —
  so `op_update`'s old `new_version <= HELPER_VERSION` check would call
  such a file `not-newer` forever. `HELPER_BUILD` is a separate integer,
  bumped on every change to the file regardless of `HELPER_VERSION`;
  `update` now requires the candidate's build to be strictly higher when
  the version is equal (a protocol downgrade is still never installed,
  even with a higher build). `tests/kea_helper_build.json` pins
  `{"build": N, "sha256": <hash of jen-kea-helper>}` — a test fails
  unless a file change is paired with a build bump, the same discipline
  the `RELEASE_SIGNERS` twin test already enforces for the signing key.
- **Preflight and rollback.** A signed, strictly-newer candidate could
  still fail to run at all on this particular host (a syntax error, a
  Python-version incompatibility, a host-specific import failure) —
  `update` used to write and `os.replace` it with no check beyond "the
  signature verifies". It now runs the candidate's own `version` op in a
  throwaway process first (`/usr/bin/python3 -I <candidate> version`,
  fsynced, a 10 s timeout, the fixed environment) and requires it to
  answer `ok: true` with the exact version/build it declared; only then
  does it copy the CURRENT helper aside to `<path>.prev`, install the new
  one, and repeat the same check against the installed path — a failure
  there restores `.prev` and reports `postflight-failed` instead of
  leaving a broken helper live.

**Helper build 8 (v5.66.0-beta.4, Q106 — a build-only change; `HELPER_VERSION`
stays 7).** The one gap the rollback above still had: it only ran `if
prev_saved`, and `prev_saved` was only set when `_SELF_PATH` was already a
regular file — so on the rare host where it wasn't (no helper installed
yet, or something else occupying the path), a postflight failure on that
first `update` had no `.prev` to restore, and the new, broken bytes stayed
installed anyway. `update` replaces an installed helper, it never installs
one: `op_update` now refuses BEFORE writing or preflighting any candidate
bytes with `not-installed` whenever `_SELF_PATH` is not a plain regular
file, which makes the `.prev` copy — and therefore the rollback — always
happen from here on. A rollback that itself fails (`os.replace` raising —
disk full, permissions changed mid-flight) is reported as `rollback-failed`
naming both `_SELF_PATH` and `.prev`, rather than the misleading
`postflight-failed` (which implies the old helper is back); this is the
one signed-update failure that is a genuine incident needing hands on the
host. `tests/kea_helper_build.json` re-pinned to build 8.

**Helper build 10 (v5.68.0-beta.6, Q141 — a build-only change; `HELPER_VERSION` stays 7): the two-tier trust rule.** Build 7's `_find_bin()` required
every binary the helper runs to be `root:root`, and that was applied to the Kea daemon binary too. ISC's own packages do not ship it that way: a Kea 3.0.4
ISC deb installs `/usr/sbin/kea-dhcp4` as `_kea:_kea` 0750 (and ISC's container image owns it by its service account the same way), so every op that
validates a config (`_run_kea_test`, shared by `test-config` and `apply-config`) answered `missingbinary` for an installed Kea, from build 7 until this
build. The test fixture had been altered to fit the check (the system suite's Kea node chowned the binary to `root:root` under a comment asserting that real
packages do the same, never verified against the packages Jen targets); the lesson is that an altered fixture is a claim about production and is checked
against a real target before the check ships. The rule is now explicit about WHO executes the file:
- a binary the helper runs **as root** — `systemctl`, `apt-get`, `ssh-keygen`, and a `kea-dhcpX` that is `root:root` — must be `root:root` with no group/other
  write bit, exactly as before;
- the Kea **daemon** binary otherwise is run **as the account the daemon runs as** — `subprocess.run(..., user=, group=, extra_groups=[])`, the unit's `User=`
  (the same `systemctl show` lookup `_daemon_group` uses), else the binary's own owner — and is trusted only when it is a regular file owned by exactly that
  account, a system account (uid below 1000, never root), with no group/other write bit;
- anything else is `missingbinary` with the reason in `detail`, which `kea_host` carries to the Servers page line and the Health row.
Running `-t` as the daemon's own account is what the daemon does on every start, so a compromised `_kea`-owned binary gains nothing it did not already have, and
root never executes a file an unprivileged account can replace. The temp file `-t` reads is written 0644 explicitly and `_CLEAN_ENV` gains `HOME=/`. The ops list
above is unchanged; `tests/kea_helper_build.json` is re-pinned to build 10 and kea-compat records the binary's owner and run-as user per ISC image so the
suite goes red the day ISC changes it.

**Helper build 11 (v5.68.0-beta.13, Q148 — a build-only change; `HELPER_VERSION` stays 7): the validation run's credentials and its file.** The temp copy
`<conf>.jen_tmp` that `-t` reads is the whole Kea config, database credentials included, and was written 0644 so the daemon's account could read it; that
made another local account's reach depend on `/etc/kea`'s mode on whichever package was installed. It is now created with `os.open(..., 0o600)` (a stale
file of that name is truncated and re-moded, and a symlink is not followed) and `fchown`/`fchmod`ed on the descriptor — **owned by the
account that runs `-t`** (the daemon's own account when the binary is run as that account, root's own when it is `root:root` and run as root), **mode 0600**
either way — and removed on every exit path as before, so the minimum the validator needs is all that exists. The validation identity is also now the unit's
own: `_unit_account` reads `User`, `Group` and `SupplementaryGroups` in one `systemctl show -p User -p Group -p SupplementaryGroups`, the gid is the unit's
`Group=` when set (else the passwd primary), `extra_groups` are the supplementary gids (`grp.getgrnam`, or a numeric gid), and a group the host lacks
is `missingbinary` WITH the reason, never a guess. A unit with a group (TLS material readable through it) used to start under systemd and fail Jen's `-t`.
The ops list is unchanged and so is the sudoers line; `tests/kea_helper_build.json` is re-pinned to build 11 and kea-compat records `/etc/kea`'s owner and
mode per ISC image so the exposure window this closed is on record.

**Helper build 14 (v5.68.0-beta.16, Q151 — `HELPER_VERSION` stays 7): one identity, ownership that cannot silently fail, the set commit.** The promises build 13 made, kept by every
path. **One resolver:** `_daemon_group` (the unit's `User=` -> that account's passwd primary group, else `_kea`, else root) is deleted and `op_install_tls` takes `server.key`'s
group from `_unit_account` (the effective gid after `Group=`, numeric `User=` accepted; no non-root account -> root:root; an unresolvable user/group is `unit-account` with the
reason, never a guess) - the same identity validation runs as; before, a unit with `Group=kea-config` got a key its daemon could not read. A source test (S4) refuses a second
`systemctl show -p User`. **New-file ownership:** a brand-new config is `root:<effective daemon gid>` 0640 for a non-root account, `root:root` 0600 for a root daemon - never 0644
(it carries `lease-database.password`). **No swallowed ownership failure:** `_finish_private` lets `fchown` raise (the temp is removed, the live file untouched), `_chown` (the
swallowing wrapper) is gone, `install-tls`'s directory `chown`s and `op_update`'s are plain `os.chown`, and the one case a directory fsync legitimately cannot work
(EINVAL/ENOTSUP/EBADF) is named by errno in `_fsync_dir` - `op_update` treats any other fsync failure as a failed install and rolls back; S4 refuses `except OSError: pass` /
`suppress(OSError)` around `chown`/`fchown`/`replace`/`fsync` in the file. **The set commit:** `_commit_file_set([(path, data, uid, gid, mode)])` stages every member privately,
reads every live member into memory WITHOUT moving it, replaces each in order, and on any failure puts every replaced member back byte-for-byte (a member that did not exist is
removed) and reports `write-failed` naming every path that could not be restored; `install-tls` uses it, and `jen/services/certs.py::commit_file_set` is the same shape for the
Jen host (§3.1: the HTTPS upload, the Kea CA's `commit_rotation`, `ensure_ca`, `issue_client_cert`). The ops list and the sudoers line are unchanged.

**Helper build 13 (v5.68.0-beta.15, Q150 — `HELPER_VERSION` stays 7; one new op): private from the first byte, the lock on every op.** Sweep D found
three writers that created a fixed-name file with the process umask and fixed its mode afterwards: `op_apply_config` wrote `<conf>.jen_apply_tmp` (the whole
candidate config, database passwords included) with `open(tmp, "w")` and copied the destination's mode on after the fact, `op_install_tls` wrote `server.key`
0644 and `chmod`ed 0640 once the private key was on disk, and `shutil.copy2` made the `.jen_backup` copy the same way; the two deterministic temp names
(`.jen_tmp`, `.jen_apply_tmp`) were also shared by any two helper processes on one config, and the `.jen_lock` flock was taken only `if expect is not None`
(so `test-config` never locked and Author Config's applies never locked). **`_private_tempfile(directory, prefix)` is now the one way a file is created**:
a unique `.name.<16 hex>.jen_tmp` in the target's own directory, `O_CREAT|O_EXCL|O_NOFOLLOW`, 0600 from the first byte; `_install_private` writes and fsyncs it,
applies the FINAL owner/group/mode to the DESCRIPTOR (`fchown`, `fchmod` - never to a path another process could swap) and `os.replace`s it. A replacement of a
0600 config is never readable by another uid at any instant; the new-file mode (0644) and the key's final 0640 are reached only once the file is complete.
**The validation copy** is `root:<the daemon's effective gid>` 0640 - readable by the account that runs `-t` through its group, not writable by it (build 11
made the copy that account's own, so it could change the config between the write and the check) - and a root-run check keeps a root 0600 copy. **The lock**
(`_locked(path)`, an `flock` on `<path>.jen_lock`) is taken for EVERY `test-config`, `apply-config`, `remove-config` and `install-tls` (on the service's TLS directory),
and held for the whole op; `expect_sha256` stays the optional comparison it is. **The execute bit**: `_daemon_bin_ok` requires `S_IXUSR` (`os.access(X_OK)` is root's
answer - true when ANY class may execute - so a `_kea`-owned file with `o+x` and no `u+x` passed and then failed to exec as `_kea`); a root-run `root:root` binary needs
its owner bit; one run as the unit's account needs the group/other bit it will actually use (`_group_may_exec`). **`remove-config`** (the op list is now version, read-config,
test-config, apply-config, remove-config, service, tail-log, install-package, install-tls, update): removes a config file only if it still hashes to exactly the
required `expect_sha256` (a 64-hex value, never "" - there is no removing "whatever is there"), under the same lock; it is the rollback of an Author Kea Config target that had
no file (§3.11). The sudoers line is unchanged. `tests/test_kea_helper.py` proves it with a directory watcher that stats every entry in a tight loop while the real op runs
120 times under umask 022, plus two concurrent test-configs that each validate their own candidate, a test-config that waits for an apply, and the lock taken on every op.

**Helper build 12 (v5.68.0-beta.14, Q149 — a build-only change; `HELPER_VERSION` stays 7): identity first, trust second.** Build 11 consulted
`_unit_account` only after `_bin_owner_ok` had already decided a `root:root` binary was fine, and then returned "run as root": a root-owned binary under a
unit with `User=_kea` was validated by root, so the check could pass on a certificate, key or directory the daemon (running as `_kea`) cannot read - the same
class of mismatch Q141/Q148 had just closed for the other ownership. `_find_kea` now resolves the unit's identity FIRST (`User=` by name or numeric uid via
`pwd.getpwuid`, `Group=`, `SupplementaryGroups=`; `extra_groups` = `os.getgrouplist(name, gid)` ∪ the unit's, deduplicated, primary left out), verifies the
binary SECOND (`root:root` with no group/other write bit - which the unit's account must also be able to execute, via the other-execute bit or its group - or
owned by exactly the unit's system account), and runs `-t` as the unit's identity whenever the unit names one. **What runs as root, and when:** `-t` runs as
root only when the unit names no user, or root, and the binary is `root:root`; everything else drops to the unit's account, `setgroups` included. A user or
group the unit names that the host does not resolve is `missingbinary` WITH the reason, never a fall-through to root. With no unit user (a bare container),
the pre-5.68 rule is unchanged: the file's own system-account owner, or root for a `root:root` file. The ops list and the sudoers line are unchanged;
`tests/kea_helper_build.json` is re-pinned to build 12, and kea-compat records, per ISC image, who the daemon runs as beside who the helper would run the check as.

- `jen-config` mutation now happens **in Jen** (`jen/services/kea_config_edit.py`,
  pure functions) rather than inside a generated script. Read → mutate →
  apply is not a single atomic step on the Kea host, but since v5.16.0
  the write is guarded: the v2 helper enforces `expect_sha256` under the
  lock above, and a v1 / legacy host gets a best-effort compare in Jen
  (re-read, canonical-JSON diff against the last recorded revision,
  refuse on mismatch) with a one-per-request "no atomic guard" warning.
  Every config Jen writes — and every out-of-band change it notices on
  the next read — is also recorded in `kea_config_revisions` (jen_db,
  migration 20, extended by migration 21) as a diffable, restorable
  revision; see the admin guide.
- **The v1/legacy compare now runs BEFORE the write, not after
  (v5.28.0).** Through v5.27.x, `read_config_versioned()` returned
  `sha=None` for a v1/legacy host, so every caller's `expect_sha256`
  guard was silently a no-op — and on the rare caller that *did* wire
  up its own compare, the check ran against the helper's response
  **after** `apply-config` had already overwritten the file. Every
  caller now goes through one `_jen_side_conflict()` guard that runs
  first: it re-reads the live config and compares
  `"canonical:" + sha256(canonical(cfg))` — a sentinel standing in for
  "no raw sha available" — against the same sentinel computed when the
  config was first read for this request. A mismatch refuses the write
  with `code="conflict"` before anything is sent to the helper; the
  sentinel itself is stripped back to `None` before the real
  `apply-config` payload goes out, so a v2 helper never mistakes it for
  a raw-sha comparison. **v5.28.1** — a v1/legacy `apply_config()`
  success now also returns this same sentinel as `result["sha256"]`
  (computed from the config just written) instead of nothing at all, so
  a caller that stores "the sha we just wrote" to guard a *later*
  operation — `kea_changeset`'s revert, below — is never left guarding
  it with `None`.

**A hash always says what it hashes (v5.20.0 — `hash_kind`).**
`kea_config_revisions.sha256` has always held one of two genuinely
different quantities with no way to tell them apart: the helper's
raw-bytes hash (v2) or `sha256(canonical(cfg))`, a Jen-computed
stand-in (v1 / legacy) — and a v1→v2 upgrade meant the two got compared
against each other, always mismatching, so `config_history_restore`
always conflicted until a fresh Jen write happened to replace the
stored value. Migration 21 adds `hash_kind ∈ {raw, canonical, legacy}`
(`legacy` marking a pre-5.20.0 row of unknown kind); `record()` now
requires it as a keyword on every call. The first contact with a
server/service, and the first read after a `canonical` host's helper
crosses to v2, is recorded as a `baseline` revision rather than
`external` — a crossover is not a hand edit, it's Jen re-establishing
what it can trust to compare against. `config_history_restore` only
passes `expect_sha256` when the latest revision's kind is `raw`;
otherwise it reads the live hash immediately before applying, since a
`canonical`/`legacy` value was never comparable to the helper's raw
hash to begin with.

**The legacy-grant check runs at check time, not just install time
(v5.20.0).** `kea_host.check_helper()` — the one place Jen already
talks to a Kea host to ask its helper version — now also probes whether
`/etc/sudoers.d/jen-kea` (below) is still present and records that
alongside the version, so Health Center can warn about it without
adding an SSH round trip of its own (Health Center's own rule is no SSH
at render time). This closes a gap where a host could have both the
current helper **and** the old root grant, and nothing would say so.

**The legacy fallback.** A host that does not have the helper yet falls
back to the pre-5.11.0 path: Jen generates a Python script, base64s it,
pipes it over SSH into `sudo python3`, and runs it as root. That
requires the old `NOPASSWD: /usr/bin/python3` grant — which **is root,
full stop**: a compromised `www-data` on the Jen host is root on every
such Kea box. Jen shows an admin banner naming every server still on
this path, and flashes a warning on each use. **Success is now read
from the remote command's real exit status (v5.28.0), not sniffed from
stdout text** — `paramiko`'s `recv_exit_status()` is read after stdout/
stderr, since it blocks until the channel closes; before this, e.g.
`service_action`'s legacy path ran `systemctl restart ... || systemctl
restart ...; echo done` and treated the unconditional trailing token as
proof of success even when both attempts had failed. The fallback is
kept for compatibility and **is not removed anywhere in the 5.x line** —
removing it would break a clean upgrade for anyone still relying on it,
which is the MAJOR trigger. `CLAUDE.md` rule 9 still applies: any new
Kea-side capability is a new helper op **and** a documented change to
both sudoers subsections in `docs/admin-guide.md` and
`docs/troubleshooting.md`.

The Jen side of this same "www-data writes a root-run file" problem was
fixed in v5.2.6 (§3.1, §6); v5.11.0 closes the Kea side for hosts that
have adopted the helper.

**Investigation logging rides on the helper that is already there (v5.68.0-beta.3, Q138).** Turning a Kea
server's `kea-dhcp4` logger up to DEBUG for a bounded time adds NO helper op and NO sudo string: the
change is `kea_changeset.apply_change` (`apply-config` with the sha guard, `kea-dhcp4 -t` preflight,
revert on failure, an audit row and a config revision), the daemon learns of it through `config-reload` on
the control channel Jen already uses (restart through the existing `service` op only when the daemon answered and lacks
or refuses it - v5.68.0-beta.21, Q156: `_reload_support` is yes / no / unknown, and "unknown" (the API did not answer) REFUSES turning logging on, because a restart of a
production daemon must not follow from a Control Agent that was down - and (v5.68.0-beta.22, Q157) the SECOND call is judged the same way: `_daemon_step(..., allow_restart=False)`
for `turn_on`, so a `config-reload` that does not return 0 (a refusal, a connection failure, a timeout: one reply shape) puts the file back through `_revert_file` and restarts nothing; turn-off and the expiry restore still fall back to the restart, and say why), and the log is read through `tail-log`. The only thing the helper sees is a config whose
`kea-dhcp4` logger entry carries a `user-context` marker saying what to restore; `docs/admin-guide.md`
names the one logger entry Jen touches. **A marker that has lost its `restore` object is never read as "these keys never existed"
(v5.68.0-beta.13, Q148).** `kea_config_edit.clear_investigation_logging` validates the marker before it mutates anything: `restore` must be
`{"created": true}` or carry BOTH `severity` and `debuglevel`, each the literal `"absent"` or a real value. Anything else - a hand edit, a partial
write - returns `marker-invalid` with the logger and the marker left exactly as they were (it used to read as `{}`, so every key was "absent" and
the logger's severity and debuglevel were removed together with the marker). The change set aborts before any write, the index entry is KEPT and
flagged, the sweep records it as the entry's error every minute, the Health row goes red naming the server with the by-hand text, and *Turn it
off now* says the same; turning it on again over a damaged marker is refused too, since recording the current DEBUG values as "what to restore"
would make DEBUG the thing to put back. **A damaged marker is judged when it is seen, not when it is due (v5.68.0-beta.14, Q149).** Beta.13 validated
the marker only after its deadline check, so a damaged marker with a future `until` answered `nochange`, and the full scan adopted a live marker without reading
its `restore` - Jen knew logging was on and did not know it had lost the way back until the deadline. `kea_config_edit.validate_investigation_marker(cfg)` is now a
separate question (can the way back be trusted - a marker that is not even an object counts as damaged), asked first by `clear_investigation_logging`, by
`set_investigation_logging` and by every full scan: the entry is marked `damaged` on the scan that reads it (Health red at once, audit row once, the DEBUG left
exactly as it is, Turn on refused). The guidance no longer points at the damaged object: `by_hand_damaged` sends the operator to Servers → Config history, to the
revision recorded just before the oldest consecutive "investigation logging on" one (linked when the server is still in Jen), then to restore the logger from
that config or a backup, delete the `jen-investigation` user-context, validate, reload or restart, and press **Forget** - which Jen accepts for such an entry only
after reading the config and finding no marker in it.

### 3.4 API key scope

Originally API keys were deliberately global-scope (integration
credentials, not restricted-human access). v5.1.11 (migration 13) added
a per-key `subnet_access` column: `api_keys_create` clamps a key's
scope to what the creating user can themselves see (any "all" or
out-of-access subnet in the submitted form is dropped server-side), and
the `/api/v1/*` routes apply the same subnet restriction as the human
UI. A key with `subnet_access = NULL` is still global — that's the
default for a key created by an unrestricted admin, and remains a valid
"this is a trusted integration credential" choice.

**Writes (v5.34.0, Q33).** The API was read-only until then. Write
endpoints exist now for exactly the things that are Jen's own tables or
Kea's host database (reservations via `host_cmds`, device name/owner/
notes, subnet notes) — never for anything that edits a Kea
configuration file, which needs the changeset engine (§3.11) and a
human preview. Two additional controls: a per-key `can_write` flag
(migration 25), off by default so every pre-existing key stays
read-only; and a per-key rate limit on writes (60 a minute, applied by
`api_key_required(write=True)` itself since v5.65.8, so a plugin's write
endpoint shares the budget of the core ones). An API request has no
Flask-Login user, so every write is audited with the key's name as the
actor. The surface is described by `/api/v1/openapi.json`, generated
from one Python dict; a test walks Flask's URL map and fails when a
`/api/v1/` route and the document disagree.

**Client IP behind a proxy (v5.17.0 / Q6 6D).** Rate limiting, the audit
log and MFA trusted-device records all key off `request.remote_addr`.
When `[server] trusted_proxies` is set (a list of proxy IPs / CIDRs),
`TrustedProxyMiddleware` — installed ahead of Flask, and only when that
list is non-empty — rewrites `REMOTE_ADDR` from the rightmost
non-trusted `X-Forwarded-For` hop and `wsgi.url_scheme` from
`X-Forwarded-Proto`, but *only* when the immediate peer is itself in the
trusted list. An untrusted peer's forwarding headers are ignored
entirely. With the setting on, the Secure cookie flag and HSTS turn on
(the proxy is required to serve HTTPS) and gunicorn gets the same list
as `--forwarded-allow-ips`.

### 3.5 Floor-pinned (not exact-pinned) Python dependencies

Runtime dependencies are declared once, in `requirements.txt` at the
repo root (v5.4.1 — before that the same list was duplicated across
`install.sh`, `Dockerfile`, and `.github/workflows/tests.yml`, which had
already drifted). `install.sh`, the Docker build, and both CI jobs all
`pip install -r requirements.txt`; `requirements-dev.txt` adds the
test/lint tooling. `tests/test_dependency_consistency.py` fails CI if
any of those files re-introduces an inline package pin.

Each pin is a floor (`flask>=3.1.3`) rather than an exact version
(`flask==3.1.3`). This is deliberate: fresh installs automatically pick
up security patches without a maintainer re-reviewing and re-pinning
every dependency on every release. A full lockfile was considered and
rejected for this project's size and solo-maintenance model — it would
mean a deliberate re-lock for every security update, which won't happen
reliably, so stale-by-neglect deps would be the real outcome.

**The tradeoff:** installs aren't fully reproducible — two installs done
weeks apart could resolve to different exact versions — and there's no
protection against a hypothetically-compromised *newest* release of a
dependency (only exact-pinning + manual review addresses that).
`pip-audit` in CI (see below) is the compensating control: it checks
whatever actually gets installed against known CVEs on every push, so a
newly-disclosed vulnerability in a floor-pinned dependency gets caught
even without a version bump.

v5.5.0 — the self-updater started running `pip`. v5.8.0 moved that into
a `/opt/jen/venv` and made the update transactional — see §6.

### 3.6 MFA secret encryption at rest (v5.4.0)

`mfa_methods.secret` (the TOTP shared secret) is encrypted with Fernet
before storage — see `jen/services/crypto.py`. Backup codes,
trusted-device tokens, and API keys are one-way sha256 hashes because
Jen only ever needs to *check* them; a TOTP secret has to be recovered
in cleartext every 30 seconds to recompute the current code, so it's
encryption with an external key, not a hash.

**The key** lives at `/etc/jen/mfa_key` (0600), created on first use
with the same load-or-create + `$JEN_ROOT` fallback pattern as the
Flask session key (`_load_secret_key()`). It is deliberately **not** in
the database it protects and **not** in database exports.

**Why this is the boundary:** the threat is read access to the `jen_db`
`mfa_methods` table without corresponding access to the application
host's filesystem — a downloaded export, a read replica, a compromised
DB account, SQL injection, a shared DB host. An attacker who already
has `/etc/jen` has the app itself and this buys nothing; that's an
accepted non-goal, same framing as the sudoers grant in 3.1.

**What this means for future changes:** `verify_totp()` fails **closed**
on a decrypt failure (unreadable row skipped, never trusted) — a DB
restored/migrated without its key leaves users on backup codes / an
admin reset, never bypassed. Migration 17 does the one-time in-place
encryption of pre-existing plaintext rows and aborts startup (rather
than minting an ephemeral key) if the key can't be persisted. Any new
code path that reads `mfa_methods.secret` must go through
`crypto.decrypt_secret()` and must not treat a `SecretDecryptError` as
"authenticated".

**Passkeys (v5.31.0)** sit beside TOTP as a second factor
(`jen/services/passkeys.py`, py_webauthn) and need none of this:
`webauthn_credentials` holds the credential id, the *public* key, a
signature counter and a name — nothing that verifies anything on its
own. The trust boundary is different and lives in the ceremony, not at
rest: the relying-party id and origin are derived from the request Jen
is serving (`request.host` minus port; `request.host_url`, which the
trusted-proxy middleware has already corrected), pinned into a
single-use session state with a 5-minute expiry when the challenge is
issued, and verified against on the response — the browser's own
`clientDataJSON.origin` is checked against what Jen expected, never
trusted alone. The state is popped before verification, so a failed
attempt cannot be replayed. A non-advancing signature counter (when
either side's is non-zero) is treated as a cloned authenticator and
refused. The consequence operators must know: a passkey is bound to
the hostname users type, so renaming or re-addressing Jen invalidates
every enrolled passkey. Passwordless login is deliberately not offered;
the password stays the first factor.

### 3.7 The plugin registry's trust root, and checksum-verified installs (v5.21.1)

`plugins/registry.json` — the list Settings → Plugins shows and
installs from — is fetched from
`raw.githubusercontent.com/ltkojak/jen-kea/main/plugins/registry.json`:
this repository's own `main` branch. That's a mutable ref, not a
pinned commit or tag, but it carries no more trust than the app itself
already requires — anyone who could tamper with it could just as
easily tamper with a Jen release the same way they'd tamper with any
other software supply chain rooted in this repo. `fetch_registry()`
(`jen/services/plugins.py`) trusts every field in it as-is; nothing
about the registry itself is independently re-verified.

**What IS independently verified is each plugin's package.**
`install_plugin()` downloads `<download_url>/plugin.zip` and refuses
outright — no exceptions — if the registry entry has no `sha256` or if
the downloaded bytes don't match it, the same fail-closed rule
`jen-update-root.py` applies to Jen's own release tarball.
`download_url` is pinned to a
release **tag** in the plugin's own repository (`.../raw/vX.Y.Z`), not
`main` — a tag doesn't move, so the checksum computed against it at
release time stays valid forever, where a checksum computed against a
moving branch would go stale the next time that branch's tip changed.
This closes the actual gap a compromised plugin repository (or a
compromised registry.json pointing at one) would otherwise exploit: a
plugin's `manifest.json` runs arbitrary `db_migrations` and its
`plugin.py` is imported and executed as `www-data` on install, so an
unverified zip is remote code execution, not just a bad file.

**v5.21.1 removed the one thing that used to be "live" here.**
`fetch_registry()` briefly (v5.3.x) live-fetched each plugin's own
`manifest.json` from `main` to overlay version/description/
db_migrations, so a release didn't need a second manual commit here to
stay accurate. That's gone: once `download_url` is pinned to a tag,
live-fetching from `main` could report a version and migration list
that doesn't match what `install_plugin()` actually downloads and
checksums from the tag. `plugins/registry.json`'s own fields are the
source of truth again, updated by hand in the same commit that pins a
new tag and its checksum — see `plugins/README.md` for the release
checklist.

**The bundled copy is the same code the registry pins (v5.28.2).** The
trees under `plugins/` are what a fresh install sees before it ever
fetches the registry, and what CI's real-manifest migration tests run
against both MariaDB and MySQL 8 — and they had drifted from the
plugin repos for a year in both directions (bundled IPAM a year old;
bundled Network Discovery carrying a scan-breaking bug the repo had
fixed). They're now resynced from the tagged releases the registry
pins, and `tests/test_plugin_registry.py::TestBundledCopiesMatchRegistry`
fails CI if a registry entry and its bundled manifest ever disagree on
version, `requires_jen`, `db_migrations`, or nav. Each plugin repo's
own CI (`tools/verify.py`) enforces the other half: the published
`plugin.zip` is a byte-for-byte rebuild of the tagged tree.

**Plugin migrations are plain SQL, so idempotency comes from the
runner, not the dialect (v5.28.2).** The only way to write a
re-runnable `ALTER TABLE` in plain SQL was MariaDB's `IF [NOT] EXISTS`,
which MySQL 8 lacks — so a plugin was either MariaDB-only (IPAM was,
silently, since its v1.3.0) or non-idempotent. `run_plugin_migrations()`
now records a migration whose only error is duplicate column (1060),
duplicate key name (1061), or can't-DROP-doesn't-exist (1091) as
already applied and continues; these three mean exactly "the schema
is already where this migration puts it," and nothing else (a syntax
error, an unknown table or column) is caught. Together with the
tracking table this gives a plain `ALTER` the same safety `CREATE
TABLE IF NOT EXISTS` always had, on both databases.

The registry record and its `sha256` share the same GitHub trust root
as §3.9's release signing — the checksum binds the downloaded package
to what `registry.json` says it should be, not to an authority
independent of this repository.

### 3.8 Content-Security-Policy: nonce-based script-src, `style-src` keeps `'unsafe-inline'` (v5.22.0)

Through v5.21.x, `Content-Security-Policy` allowed `'unsafe-inline'` for
both `script-src` and `style-src` — templates carried ~148 inline
`on*=` handlers and ~23 literal `<script>` blocks, so a strict
script-src wasn't reachable without touching most of the frontend.
v5.22.0 does that work for scripts: `jen/services/csp.py::nonce()`
generates one unguessable value per request (`g.csp_nonce`, exposed to
templates as `csp_nonce`); every `<script>` tag carries
`nonce="{{ csp_nonce }}"`, and every inline handler was converted to
either base.html's `data-confirm`/`data-href`/`data-submit` delegated
dispatcher or a named function bound with `addEventListener` (delegated
wherever the element lives inside an htmx-swapped partial, since a
direct binding wouldn't survive the swap). `script-src` is now `'self'
'nonce-<value>'` — no `'unsafe-inline'` — and `htmx.config.allowEval =
false` closes the eval-based escape hatch htmx otherwise keeps open for
`hx-on` and `js:` expressions Jen doesn't use.

`img-src 'self' data:` (v5.31.1) is the one directive that widens
beyond `'self'`, and only for images: the TOTP enrolment QR and
uploaded avatars are `data:` URLs, and without an `img-src` of its own
they fell through to `default-src 'self'`, which does not include the
`data:` scheme — the QR was a broken image from v4.4.5 (when the
header arrived) until this. A `data:` image cannot execute anything
under this policy; scripts, styles, frames and objects are unaffected.

`style-src` keeps `'unsafe-inline'` deliberately. Templates carry over
1,200 inline `style=""` attributes; hardening that would mean rewriting
the presentation layer into stylesheets, not converting a fixed,
enumerable set of event handlers — a redesign, not a hardening pass.
The risk this leaves open is narrower than an unrestricted style-src
might suggest: CSS injection can exfiltrate data via `background:
url(...)` selectors or deface the page, but (unlike script-src)
Chrome/Firefox/Safari don't execute arbitrary code through `style=`
content, and every user-controlled string rendered into HTML in this
app already goes through Jinja's autoescaping — an attacker would need
a separate HTML-injection bug first, at which point script-src's own
removal of `'unsafe-inline'` is the more consequential guard.

The rollout shipped in two steps within the same release: step 1 added
the nonce infrastructure and handler conversion but sent the
nonce-based policy only as `Content-Security-Policy-Report-Only`,
alongside the still-permissive enforcing header — any conversion gap
would show up as a browser-console violation report without breaking
anything live. Step 2 (after confirming CI and a review pass found
nothing) promoted the nonce-based policy to the enforcing header and
dropped Report-Only. `tests/test_csp.py` guards the invariant going
forward: every `<script>` has a nonce, no htmx-swapped partial contains
one at all, no inline `on*=` attribute remains (checked repo-wide, with
a staleness-checked allowlist for the one non-live occurrence in
`branding.py`'s SVG-upload rejection regex), no `javascript:` href, and
the header itself carries a fresh nonce per request that matches what
the page actually renders.

**Bundled plugin templates got the same conversion; a registry-installed
copy did not.** (Written when those two were the only bundled plugins; every
directory under `plugins/` is a bundled copy now — `shipped_plugin_ids()` — and
seven ship today.) `plugins/ipam/` and `plugins/network-discovery/` in
this repo are Jen's own bundled copies, converted in this release like
every other template. The plugin *registry* (§3.7) installs from each
plugin's own separately-versioned external repository
(`jen-plugin-ipam`, `jen-plugin-network-discovery`), pinned to a tag
that predates this work — installing or updating via Settings → Plugins
still pulls the older, unconverted templates until those repositories
ship their own nonce/handler fix and the registry entries are re-pinned
to a new tag in a later release. Until then, a registry-installed
instance of either plugin will have inline handlers that a strict
script-src blocks — buttons that did nothing, not a crash — see the
CHANGELOG.

### 3.9 Signed release manifests (v5.26.0)

Through v5.25.x, `jen-update-root.py` verified a release by checksum
alone: it refused to install a tarball whose SHA-256 didn't match the
`SHA256SUMS` asset GitHub published alongside it (§3.5's neighbor —
`verify_release_checksum()`). That's real protection against a
corrupted or truncated download, but not against a forged one — anyone
who could publish an arbitrary `SHA256SUMS`/tarball pair to this
repository's releases (a compromised PAT, a hijacked Actions run) could
get every Jen instance's auto-updater to install it, since nothing
tied the checksum file back to a human decision to cut a release.

From v5.26.0, `release.yml` also signs `SHA256SUMS` with `ssh-keygen -Y
sign`, publishing `SHA256SUMS.sig` alongside it, using an ed25519 key
whose private half exists **only** as the `RELEASE_SIGNING_KEY` GitHub
Actions secret — it has never been written to disk on this repository's
maintainer's own machine, nor checked into history. `verify_release_signature()`
(`jen-update-root.py`) checks that signature with `ssh-keygen -Y
verify` against `RELEASE_SIGNERS`, the public half embedded as a module
constant — the permanent trust root every deployed Jen instance carries
regardless of what GitHub's API returns on a given request. No new
dependency: `openssh-client` (and therefore `ssh-keygen`) is already a
baseline assumption for every target OS this project supports, the
same as the SSH-based config push in §3.3.

**Fail closed, from the release that introduces it.** v5.26.0 is both
the first release whose updater code knows how to verify a signature
*and* the first release that ships one — there is no "signing becomes
mandatory two releases from now" transition window. A missing
`SHA256SUMS.sig` asset is refused exactly like a missing `SHA256SUMS`
already was: `jen-update-root.py` aborts before even downloading the
(large) tarball, not merely before installing it.

**Key rotation.** `RELEASE_SIGNERS` is a single "allowed signers" line
today (`release@jen ssh-ed25519 <base64>`) but the format allows more
than one line — rotating the signing key means adding the new public
key as a second line for one release before the `RELEASE_SIGNING_KEY`
secret is switched to the new private key, then removing the old line
one release after that, so there's always at least one release where
both the old and new key verify.

**What this does and doesn't protect against.** The signing key is a
GitHub Actions secret, so the trust root is "this repository's Actions
environment", not an offline key: it defeats anyone who can replace
release assets or `SHA256SUMS` WITHOUT that secret (a leaked PAT, a
hijacked asset upload) and does not defeat a compromise of the
workflow/signing environment itself (a malicious `release.yml` change
on `main` followed by a tag, or GitHub's own Actions infrastructure).
Independent/offline signing, HSM-backed keys, GitHub Environment
approval on the release job, and separately signed plugin manifests are
roadmap, not shipped.

### 3.10 Root-owned plugin installs (v5.27.0)

§3.7 covers what's verified about a plugin package — a tag-pinned
`download_url` and a checksum that must match. Through v5.26.x that
verification still ran as `www-data`, and the verified files still
landed in a directory `www-data` owns: `/var/lib/jen/plugins/<id>`,
the same tree `discover_plugins()` imports `plugin.py` from and runs as
part of the running process. A `www-data` process that could get a
malicious file into that directory by any *other* means — a bug
elsewhere, a dependency vulnerability, anything short of a full root
compromise — could plant a `plugin.py` that Jen itself would load and
execute on the next restart, surviving that restart indefinitely. This
was an accepted-for-now gap recorded in earlier drafts of §6.1: bundled
plugins were already root-owned and read-only; registry-installed ones
were not.

v5.27.0 closes it with the same request/execute split §3.1 already
uses for Jen's own updates. `install_plugin()` / `uninstall_plugin()`
(`jen/services/plugins.py`) no longer download, verify, extract, or
delete anything themselves on a real systemd host (Docker and dev
checkouts have no unit to trigger and keep the pre-5.27.0 in-process
behavior, unchanged). Instead:

1. `www-data` writes an empty `<plugin_id>.install` or
   `<plugin_id>.remove` marker into
   `extensions.CONTENT_PLUGIN_REQUESTS_DIR`
   (`/var/lib/jen/plugin-requests/`) and triggers
   `jen-plugin-install.service` (§3.1) — the marker's *filename* is the
   only thing the privileged side reads from it; the file itself is
   empty.
2. `jen-update-root.py --plugins`, running as root, re-derives
   everything from `plugins/registry.json` fresh — the exact same
   fetch, tag-pinning check, and checksum verification §3.7 describes,
   duplicated into this standalone script rather than imported, since
   it can't import the `jen` package — then lands the verified files at
   `/opt/jen/plugins-installed/<id>`, `root:root`, mode `a+rX,go-w`:
   readable and executable by `www-data`, writable by nothing but root.
3. It writes a one-line `<plugin_id>.<action>.result` (`ok` or
   `error: <reason>`) back into the same request directory for the page
   to show, and deletes the marker. It never touches the database
   either way, same as the in-process path it replaces.

**QUEUED → CONFIRMED, not "queued counts as done" (v5.28.0).** Through
v5.27.0, `install_plugin()`/`uninstall_plugin()` wrote the `plugins`
table row, set `restart_pending`, and audited the action **before**
the root side had actually run — a request that failed root-side still
looked like a success everywhere except the (never-shown) result file.
`consume_plugin_results()` (`jen/services/plugins.py`) is now the only
thing that applies that state, and only once a `.result` file proves
the root side finished: it's called both from `plugins_page()`'s own
render and from the `install_status` poll route, so a result is picked
up on the very next page load even if the operator closed the tab
before the poller ever ran. `jen-update-root.py`'s own request loop is
symlink-safe end to end (the actual finding this rollup exists for): a
`www-data`-writable request directory being swapped for a symlink, or
one request being pre-created as a symlink to an arbitrary file, is
refused/unlinked-not-followed rather than giving root a path to
truncate or overwrite; a plugin swap renames the old live directory
aside before renaming staging into place, so a crash mid-swap leaves
either the old or the new copy fully intact, never a half-deleted
directory; and because a oneshot unit ignores a second `systemctl
start` while already running, the request loop drains markers in a
pass-until-stable loop instead of processing one batch and exiting, so
a request written while the run is already in flight is still picked
up in the same invocation.

**Apply before delete, restore instead of discard (v5.28.1).**
`consume_plugin_results()` used to delete the `.result` file and only
*then* apply it to Jen's own state — a crash or exception in that gap
lost the only authoritative record of what the root side actually did.
It now applies first and deletes only once that succeeds; an exception
leaves the file in place, logged, and retried on the next call (safe,
since every state change it makes — the DB row, the enable marker,
`restart_pending` — is idempotent). `_sweep_stale_plugin_dirs()`
(`jen-update-root.py`) had the same gap one step earlier: a crash in
the exact window between the swap's two renames — the live directory
already moved aside to `<id>.old-<ts>`, staging not yet moved into
place — left no live directory at all, and the sweep simply deleted
the `.old-<ts>` right along with the never-verified-complete
`.staging-<ts>`, discarding the one intact copy that existed. It now
groups leftovers by plugin id first: a live directory already present
means the swap finished and every leftover for that id is stale
(unchanged); a missing live directory with at least one `.old-<ts>`
restores the newest one back to live before deleting the rest
(including any staging copy, never a restore candidate); only staging
leftovers means an interrupted first-ever install, with nothing to
restore.

**A plugin's own DB migrations now gate whether it activates
(v5.28.1).** Through v5.28.0, a failing migration only logged loudly
(the v4.4.19 fix, `load_plugins()`) or, on the root path, was reported
back but still enabled the plugin. Now: the in-process installer
(Docker/dev) runs migrations against the manifest in the *staging*
copy before the crash-safe swap, so a failure leaves an existing
install completely untouched; the root path's `_apply_plugin_result()`
runs migrations itself (Jen has DB access there, the root-run request
processor never did) and refuses to enable a plugin whose migration
failed, recording `plugin_migration_failed:<id>` for a red "migration
failed — not enabled" chip on the Plugins page; and `load_plugins()`
only keeps the original v4.4.19 "load anyway" property for a version
that has *already* migrated cleanly once before
(`plugin_migrated_ok:<id>` matches the manifest's `version`) — the
case that fix actually targeted, an unrelated/format quirk on an
already-working install. A version that has never migrated cleanly, or
a newer version whose migration just failed for the first time, is not
loaded at all: running new code against a schema its own migration
never reached is worse than the plugin disappearing from the nav until
it's fixed.

`discover_plugins()` gained a third scan tier between the bundled tree
and the legacy writable one (§6.1) for this: `extensions.PLUGIN_DIR_ROOT`.
A plugin can transiently exist in both the legacy writable location and
the new root-owned one (mid-migration, or a box that installed before
v5.27.0) — the writable copy still wins in that case, and the root
install's own final step deletes the writable copy once it lands,
so steady state converges on exactly one copy per plugin. `_plugin_dir()`
now searches the root-owned tree too (v5.28.0 fix — it didn't, so
Enable/Disable was a silent no-op for any plugin installed this way).

**Why not fold this into `jen-update.service` itself:** that unit's
entire contract is "no arguments, re-derive the Jen release to install."
Overloading it with a second, unrelated responsibility (which plugin,
which action) would mean either adding real arguments — reopening the
"nothing attacker-controlled reaches this script" property §3.1 depends
on — or inventing some other side channel for the same information,
which is just this marker-file design with extra steps. A second
fixed-argv unit keeps each privileged entry point doing exactly one
thing.

**Plugin OS-package dependencies ride the same split (v5.30.0, Q30).**
A plugin that shells out to a system binary (Network Discovery → nmap)
declares it in its manifest and registry entry as `"os_packages":
["nmap"]`. Jen's web process only ever *reports* what's missing
(`shutil.which`) and, on a systemd host, writes a third marker,
`<id>.deps`, and triggers the same zero-parameter
`jen-plugin-install.service`. The root-run script re-derives the
package list from the registry it fetches itself — the marker is empty,
and even a marker with contents is ignored beyond its filename — and
then applies its own **built-in allowlist** (`_DEPS_ALLOWED_PACKAGES`,
just `nmap` today) before running `apt-get install -y -qq <pkgs>` (one
retry after `apt-get update`). The allowlist is the control, the same
philosophy as the Kea helper's op table (§3.3): a registry entry, or a
compromised one, can only ever ask for a package this version of the
script already agreed to install; widening it is a Jen release. The
result lands as `<id>.deps.result` and is consumed like an install
result (audit `PLUGIN_DEPS` / `PLUGIN_DEPS_FAILED`; no restart — the
plugin checks for its binary at call time). Docker and non-systemd
hosts see the `apt install` command instead, as before. Rule 8: the
sudoers grant is unchanged — the unit and its argv are the same.

### 3.11 Multi-server change sets (v5.28.0)

Every route that pushes one config edit to more than one Kea server
(add/delete/edit a subnet, a shared network, DHCP options, client
classes, DDNS naming, D2 domains/keys) used to run the same
read → mutate → apply → restart loop independently per server, with no
knowledge of whether an earlier server in the loop had already
committed. A validation failure on server B left server A's write in
place; a concurrency conflict on B did too. `jen/services/kea_changeset.py`'s
`apply_change()` is now the one place this logic lives, in four phases:

1. **Plan** — read and mutate every SSH-configured server's config in
   memory. A "skip" outcome (e.g. "already applied there") is recorded
   as informational and that server drops out; any other non-"ok"
   outcome aborts the whole change set here, before anything is
   written anywhere.
2. **Preflight** — `test_config()` every remaining target. Any failure
   aborts the whole set, still before any real write.
3. **Commit** — `apply_config()` each target in order. If one fails
   (most commonly a concurrency conflict caught only at write time,
   since a sha check is inherently a write-time guarantee, not
   something preflight can prove in advance), every already-committed
   target is reverted, in reverse order, back to what `read_config_versioned()`
   saw for it in the Plan phase. `apply_config()`'s own commit call
   backfills `result["sha256"]` with a canonical sentinel when a
   v1/legacy write reports none (§3.3) specifically so this revert has
   a real value to guard its own `expect_sha256` with, instead of `None`
   — no guard at all. A revert that itself fails is reported as
   `rollback_failed` — a mixed state needing hand intervention
   (Servers → Config history → restore) — rather than silently retried
   or hidden. **v5.28.1** — the failure message now names three groups
   explicitly instead of one ambiguous "revert failed" line that read
   backwards: `still_new` (targets whose OWN revert call failed — they
   still have the NEW config, not the old one, despite the word
   "failed"), `rolled_back` (committed targets NOT in that set),
   `untouched` (the one target whose commit itself failed first,
   triggering the revert, and so was never written to at all).
   **v5.65.6 (Q95)** — a revert whose own *restart* fails (the previous
   config is back on disk but the daemon will not start on it) is the same
   state as the restart-phase rollback below: an `error` line, `rollback_failed`,
   the server in `needs_hands`, and the persisted Servers banner. It was a
   `warning` line and status `aborted`, which `record_outcome` never persists,
   so an operator could miss that Kea was down on a server that had just been
   "rolled back". A mixed case (one target's revert call fails, another restores
   but will not restart) lists both, each described for what happened to it.
4. **Restart** — attempted for every committed target regardless of
   whether another target's restart already failed. **v5.65.1 (Q90)** —
   if any restart fails, the change did not stand, so EVERY target is put
   back: `apply_config(before_cfg)` (guarded by the sha the commit
   returned) and a second restart, in reverse order. All back and
   running gives `rolled_back` (the failing restart's stderr tail is in
   the lines; `last_code` is `restart-failed`, so code-gated callers do
   not treat it as done); any revert or second restart that fails gives
   `rollback_failed` with `needs_hands` naming those servers and the
   by-hand line (Config history → restore, restart Kea there). Reverting
   only the failed server would leave the servers disagreeing — the state this module exists to prevent. Before
   v5.65.1 a failed restart left the NEW config on disk and the daemon
   down (`restart_failed`, "the config is still live and valid — restart
   it by hand"), which is false when the daemon cannot start from the
   config it was just handed; the system-boundary suite's scenario 3
   proved it and `restart_failed` is retired. `config.applied` is
   emitted only when the change stands.

   **Nothing here raises (v5.65.1).** Each host call in the preflight,
   the commit, the revert and the restart goes through `_safe()`:
   `kea_host.apply_config` and friends catch only the helper's own
   errors, so a refused SSH connection used to escape Phase 3 with the
   first server already committed (scenario 2). A raised error is now a
   recorded failure and the revert proceeds; a revert that cannot
   connect is `rollback_failed`.

   **Surfaced (v5.65.1).** `apply_change` records a `rolled_back` /
   `rollback_failed` outcome in the `changeset_attention` setting
   (`record_outcome`); the Servers page shows it as a banner with the
   failing lines until an admin dismisses it or a later change set
   succeeds.

   **A list of incidents, not one slot (v5.65.10).** The setting holds
   `{"incidents": [{status, service, summary, at, needs_hands, failed_restart,
   lines}]}`. Every rolled-back / failed-rollback outcome is appended (the same
   trouble again refreshes its incident; the list is bounded and drops clean
   rollbacks first), so a `rolled_back` on one server can never replace an
   unresolved `rollback_failed` on another, and two failed rollbacks show both
   servers. A clean run resolves each incident it covers: a `rolled_back` one
   always, a `rollback_failed` one only when the run was for the same service and
   covered every server in its `needs_hands`; the key is cleared when none is
   left. The pre-5.65.10 single-note shape is read as a list of one. Dismissing
   is an admin action and clears all of them.

**Author Kea Config is a change set too (v5.68.0-beta.15, Q150).**
`routes/settings/authoring.py` used to loop `for server in KEA_SERVERS`
calling `apply_config` per server: no preflight of the other targets, no
expected sha (so "overwrite" replaced whatever was on each host at commit
time, whatever the preview showed), no rollback, and Jen's own
`[subnets]`/`[subnets6]` written when ANY server succeeded. Two additions let the
four phases above apply to it unchanged. **A per-target candidate**
(`candidate_for(server, cfg)`, with `tls_paths_for(server)`): the config each
server gets is its own (its interfaces, its bind address, its TLS files), built
for every server BEFORE the first write - a server whose candidate cannot be
built stops the whole thing. **An absent-is-expected target**
(`absent_is_expected=True`): a host that answers and has no config file is a normal
target with expected sha `""` (the helper's own "must not exist") and
`allow_overwrite=False` at commit, so a file that appeared in the meantime is never
overwritten; a host that cannot be READ (SSH down, a helper that answers badly) is
not "absent" and aborts. The preview reads each server's file state and the form
carries it back as `base_sha_<id>` (`""` = no file): "overwrite" then means
"replace the file I previewed", never "replace whatever is there", and an existing
file with no previewed sha is refused. Rollback is the same phase 3 revert with one
more case: a target that had NO file before is put back by REMOVING the file Jen
wrote (`kea_host.remove_config` -> the helper's `remove-config` op, guarded by the
sha Jen's own write reported and taken under the same `.jen_lock`, so a file
someone else has since replaced is left alone); a host without that op (an older
helper, the legacy path) cannot do it, which is a `rollback_failed` incident naming
the file to delete by hand. `restart=False`: authoring never restarts the daemon.
Jen's `[subnets]` is written only on `status == "ok"`. A source test refuses any
route that calls `apply_config` inside a loop.

**Everything Jen does locally joins the transaction, and the transaction only runs on an engine that can roll back (v5.68.0-beta.16, Q151).**
(1) `finalize(result)`: `_run_change` gains a callback that runs after every target committed (and restarted, when `restart`). Author Kea Config's
`write_subnets_config` used to run after the "ok", in the route, with only `ValueError` caught: an `OSError` 500ed with Kea changed and Jen's map old, and a
Kea-valid, Jen-invalid subnet name failed after every server had already committed. It now runs inside the change set: if it raises, EVERY target is put
back exactly as for a failed restart (`_put_everything_back`: the previous config re-applied, or the file Jen created removed), a revert that fails is
`rollback_failed` (an incident on the Servers page), and the result is `rolled_back` with `last_code == "finalize-failed"` - never ok; the exception's own text
is logged, not shown. `_parse_subnet_lines` also validates every typed name with `invalid_subnet_name_reason` before the preview and before the change
set starts. (2) `helper_only`: `kea_host.test_config`/`apply_config` take `helper_only=True`, which refuses with `HELPER_REQUIRED` instead of falling back to the
legacy `sudo python3` script, and `apply_change(helper_only=True)` passes it to every host call including the restore. Author Kea Config checks
`kea_host.helper_build()` (one live `version` round trip) on EVERY target before anything else and refuses unless each is at build 13 or later - the build with
`remove-config`, the only way "put it back as it was" is true for a file Jen created: a helper-less target used to be written through the legacy script and then
could not be undone (A written, B failing, `rollback_failed`, A keeps the file). A host that cannot be reached is reported as unreachable, not as "needs Update
helper". The legacy script (`kea_authoring.render_author_config_script`) is NOT deleted: it is the banner-warned fallback that still serves a helper-less host's
single-step edits and CLAUDE.md keeps it through 5.x; it is reached only behind a `helper_only` guard (test: the S5 sweep), and it writes private from its first
byte now (a mkstemp temp, the backup made with the original's owner and mode, a new file root:<directory group> 0640).

**What this does NOT cover.** `install_kea_binary`/`check_kea_binaries`, HA
actions, and the Windows import wizard (which has its own single-primary-server
preview==apply guarantee — see the wizard's own code) are unchanged by this module.

**Why a restart failure now reverts (v5.65.1).** The pre-5.65.1 design
argued that reverting a valid config over a service problem throws away
a good config. In practice the restart has already stopped the old
process, so "leave the config and restart it by hand" left the operator
with a stopped DHCP server and an unexplained new file; the maintainer
chose the invariant — a change set either stands or every server is
back where it was — over the banner. Jen's own bookkeeping (`SUBNET_MAP`,
the audit log) is written only when the change stands — `status` is
`"ok"`, `"nothing"` (every target was a no-op skip) or `"noservers"`
(nothing SSH-reachable to push to); `kea_changeset.NOT_APPLIED`
(`"aborted"`, `"rolled_back"`, `"rollback_failed"`) leaves it untouched,
matching whatever actually ended up on the Kea servers themselves.

**Fail closed when a v1/legacy host can't be reread (v5.28.1).**
`_jen_side_conflict()`'s best-effort compare (§3.3) used to return
`None` — "no conflict, proceed" — when the reread itself failed (host
unreachable, SSH error), on the reasoning that a transport failure
isn't evidence of a real conflict. In practice that meant the one host
Jen can't verify is exactly the one it wrote to anyway: an unreachable
server now refuses the write outright, with a plain "could not verify
the current configuration — no changes were written" rather than
guessing that nothing changed underneath it.

### 3.12 The Jen-managed Kea CA: a CA private key on the Jen host (v5.29.0)

Settings → Kea → "Set up direct socket" (https) makes Jen a certificate
authority for the Kea control link: `jen/services/kea_tls.py` keeps a
private CA at `/etc/jen/ssl/kea-ca.key` (EC P-256, 10 years), issues a
5-year server certificate per (server, daemon) that the helper's
`install-tls` op (§3.3, protocol v4) lands under `/etc/kea/tls/<service>/`,
issues Jen's own client certificate, and writes the daemon's socket
with `cert-required: true`. The daemon then accepts no client but Jen.
That is the point: a control socket that accepts any client with the
basic-auth password is exactly as strong as that password crossing
the wire, and ISC's own guidance for `http` sockets is "in the clear".

**The tradeoff (maintainer decision, 2026-09-13):** the CA's private
key lives on the Jen host, readable by the Jen service user (written
mode `0600` by that user; the key never leaves the host). A
compromised service user can therefore mint a client certificate that
every Kea daemon on Jen's CA accepts. Accepted because that same
service user already holds the SSH key that pushes root-level
configuration to every Kea host (§3.3) and the Kea API credentials
themselves — minting a certificate adds no capability it doesn't
have, only *persistence* beyond a credential change. The mitigation
for persistence is **Rotate Kea CA**: a new CA and client certificate,
new server certificates pushed to every host, after which nothing
signed by the old CA is trusted anywhere. The alternative considered
— a CSR flow where each Kea host generates its own key and Jen only
signs — was rejected: the server key would ride the same SSH channel
the whole config already does, so it gains nothing, while making a
one-click setup a four-step one. Moving the *signing* behind the
existing root request/execute split (§3.1's pattern) so the CA key is
root-only and the service user can only request a certificate is the
noted future hardening; it is not built.

**Two rules the flow makes true.** (1) *Probe, then commit.* Jen writes
its own configuration (URL, mode, trust anchor, client certificate)
only after the new socket has answered a `version-get` **and** a
`config-get` that identifies as the intended daemon — a Control Agent
still listening on the same host answers `version-get` identically,
which is the 2026-09-13 dashboard-blank trap (§3.11's D1) that this
path cannot reproduce. The probe uses the CA and client certificate
Jen has *not* adopted yet (explicit `verify`/`cert` overrides on the
probe), so a failed probe leaves Jen's settings exactly as they were.
(2) *Material before reference.* `install-tls` runs before the config
that references the files is applied, and the apply carries the three
paths as `tls_paths`, so a missing file is a `tlsmissing` preflight
refusal, never a daemon restarted into a config it can't load. Rotate
is staged the same way: new CA and client certificate written beside
the live ones as `.next`, every server pushed, restarted and probed
with the staged material, promotion only when all of them answer; a
failure part-way re-issues the already-pushed servers from the still-
live old CA. Jen never sets `api_tls_verify = false` through this
path, and never overwrites an `api_ca` that isn't its own — an
operator who brought their own CA keeps it and configures https by
hand, as before.

**Why not Let's Encrypt.** ACME issues server certificates for names
it can validate; the Kea link needs *client* certificates, and homelab
management addresses are RFC 1918 IPs with no public name. Let's
Encrypt for Jen's own web UI is a separate, legitimate feature and
unrelated to this.

### 3.13 The theme system: a superadmin-authored custom palette reaches every page as unescaped CSS (v5.55.0)

`jen/services/theme.py` generates every color/radius token block
`base.html` emits, via Jinja's `|safe` — including the install's own
custom palette, when Settings → Appearance → Theme has one saved. `|safe`
means Jinja's normal HTML autoescaping does not run on that string; it
reaches every authenticated page's `<style>` block exactly as written.

**The boundary is `validate_palette()`, not the render path.** Every one
of the eleven color fields is checked against `^#([0-9a-f]{3}|[0-9a-f]{6})$`
(case-insensitive) before it is ever written to the `settings` table —
`url(`, `;`, `}`, `expression(`, a named color, an 8-digit alpha hex,
anything that isn't exactly a 3- or 6-digit hex value, is rejected at
save time, not sanitized. `render_css()` does not re-validate; it trusts
that whatever is in the `theme_custom` setting already passed that
check. This is the same shape as `jen_config_edit.py`'s pure edit
functions and `kea_authoring.py`'s config generation elsewhere in this
app: one narrow, well-tested function is the entire trust boundary, and
everything downstream of it is allowed to trust its output completely.

**Why `|safe` at all, rather than escaping and losing the CSS.**
Autoescaping a CSS value would just print the literal string `--bg:
%2523...` instead of coloring the page — HTML-escaping is the wrong
tool for a value that has to remain CSS. The alternative (an inline
`style=""` per element, or a `<style>` block built with string
concatenation instead of Jinja) doesn't change the trust question:
either way, a string a superadmin controls ends up as literal CSS on
every page, and the only real question is whether that string was
validated first. It was, at write time.

**Why superadmin, not admin.** Unlike nav color/logo (Settings →
Appearance → Branding, admin-accessible, pre-dates this), a custom
theme palette is CSS every authenticated user's browser parses, and the
install *default* theme changes what every viewer sees before they've
chosen one for themselves — the same trust tier as the other
install-wide, non-per-subnet settings in this blueprint
(`jen/routes/settings/theme.py`'s three routes are all
`@superadmin_required`).

**What this does not protect against.** A malicious superadmin can
already do far more damage through Settings → Kea, Database, or the
Kea-host SSH surface than a color palette allows; this boundary exists
to keep a *non*-malicious superadmin's typo (a stray `<` in a form
field, a copy-pasted value with trailing garbage) from becoming a
broken `<style>` block or, worse, closing it early — not to defend
against a superadmin acting in bad faith.

### 3.14 Per-server capabilities: one place that knows what a Kea server can do (v5.64.0)

Availability used to be decided by whoever needed it, from the raw
ingredients — a helper version compared to a threshold, a Kea version tuple,
"is this direct mode" — and each site worded its own reason. The helper-version
gate alone lived in three places (the SSH card's button, the installer's
"already" answer, the feature's own check), which is what the old rule
"change all three together" was guarding against.
`jen.services.capabilities` is now the single answer: `derive()` (pure — no
I/O) turns a Kea version, the connection mode, the recorded helper version and
the Dhcp4 config Jen already caches into a frozen `ServerCapabilities`;
`for_server(id)` gathers those inputs (memoised per request, the Kea version
cached 60 s per server, dropped by a Health Center refresh) and calls it;
`ServerCapabilities.why(name)` is the one sentence a page shows when a
capability is off. Health Center → Kea → "Server capabilities" lists what is on
and off per server, built from the status rows that run already fetched.

| Capability | On when | Derived from |
|---|---|---|
| `control_agent` | Control Agent mode and Kea < 3.2 (`ca_deprecated`: 3.0–3.1; `ca_removed`: ≥ 3.2) | mode, Kea version |
| `direct_control` | Jen is in direct mode | mode |
| `direct_socket` | Kea ≥ 2.7.2 (unknown counts as yes) | Kea version |
| `helper` / `tls` / `trace` | a helper version is recorded / ≥ 4 (`install-tls`) / ≥ 5 (`tail-log`) and SSH is configured | recorded helper status, SSH host |
| `packet_stats`, `config_test` | the server answered `version-get` | reachability |
| `packet_drop_reasons` | Kea ≥ 3.2 (the extra `pkt4-*` counters, Q52) | Kea version |
| `ha_commands`, `lease_cmds`, `host_cmds` | `libdhcp_ha.so` / `libdhcp_lease_cmds.so` / `libdhcp_host_cmds.so` loaded | Dhcp4 `hooks-libraries` |
| `ddns` | `dhcp-ddns.enable-updates` is true | Dhcp4 config |
| `kea32_ready` | direct mode and (no SSH, or the helper is current) | mode, helper, SSH |

Two things it does not pretend. A server that never answered has no version, so
every version-gated capability is off and `reachable` says why. The hook- and
DDNS-derived capabilities come from the config Jen already caches for the
ACTIVE server; another server's config is not fetched for a capability
lookup, so they are off there with a `why()` that says Jen has no config to
read (`hooks_known` is the flag). A host Jen has never heard from
(`helper_known` False) is not the same as one recorded as having no helper:
Trace still makes its one attempt on the former and refuses the latter
without touching SSH. It also attempts a host recorded with an OLD helper
(below v5): a recorded version can be stale, and the attempt is how Jen
learns the real one, so the route gates on `helper` (known missing), not on
`trace`, which is what pages display. `tests/test_capabilities.py` pins the derivation table
and a scanner proving no route re-derives any of this itself;
`tests/kea_compat/` checks the derivation against the real daemon.

### 3.15 The unauthenticated surface (v5.66.0-beta.4, Q106)

Every route below answers with no session cookie and no API key — named here
once, together, rather than left implicit route by route. `tests/test_public_surface.py`
walks the real URL map and pins this as the exact set; a route that starts
answering anonymously without being added here on purpose fails that test.

- **`GET /api/v1/health`** — the self-updater's version confirmation and a
  recovery restore's health poll both need to reach it before Jen has ever
  had a chance to authenticate anyone; it answers `jen_version` alone
  (v5.65.12, Q101), never Kea's state.
- **`GET /api/v1/openapi.json`** — the OpenAPI document describing this same
  API surface. It's built from one static dict (`jen/routes/api_spec.py::build_spec`)
  with no database access; the only instance-specific values it ever carries
  are `info.version` (already public on `/api/v1/health`) and
  `servers[0].url` (the request's own host, reflected back) —
  `tests/test_api_spec.py` pins that as a property, not an implementation
  detail to trust. A caller with the spec in hand learns nothing about a
  real install it couldn't already infer from the source, which is public.
- **`GET /login`, `GET /login/oidc`, `GET /login/oidc/callback`, and the
  mid-flow MFA/passkey steps (`/mfa/verify`, `/mfa/enroll`)** — no route in
  the sign-in sequence can require a session, since a session is exactly
  what it produces. Every one of these fails closed on its own terms
  (a bad password, an expired pending-MFA state, a locked-out IP) rather
  than by inheriting a generic auth gate.
- **`GET /static/<path:filename>`, `GET /content/icons/<name>.svg`,
  `GET /content/branding/<filename>`, `GET /favicon.ico`** — page assets:
  CSS, JS (including the vendored htmx and Chart.js), the PWA manifest
  (`static/manifest.webmanifest` — deliberately no service worker, see
  `tests/test_pwa_manifest.py`), an uploaded custom icon, the nav logo, the
  favicon. The same posture browsers already assume for anything an
  unauthenticated `<img>`/`<link>` tag can reference.
- **The HTTP→HTTPS redirect** (`jen/httpredirect.py`, only running when SSL
  is configured) — a separate stdlib HTTP server on port 80, outside the
  Flask app and its URL map entirely; it does exactly one thing, an
  unconditional redirect to the HTTPS URL, and never touches a session.

Everything else — every other `/api/v1/*` route included — checks a session
or an API key before doing anything else, several of them (`/api/v1/subnets`,
`/api/v1/servers`, `/api/v1/leases`, `/api/v1/devices`, `/api/v1/reservations`,
`/api/v1/events`, `/api/v1/timeline/<mac>`, `/api/v1/health/kea`,
`/api/v1/health/checks`, `/api/v1/health/readiness`) with a hand-rolled
`_api_auth()` check as the first line of the view rather than a decorator —
which is exactly why `tests/test_public_surface.py` drives real anonymous
HTTP requests instead of scanning for `@login_required`-shaped decorator
names: a static scan would have missed every one of them.

### 3.16 Plugin table ownership, derived from a manifest's own migration DDL (v5.66.0-beta.5, Q107)

Before this Q, every export/backup/recovery-bundle/restore path in
`jen/services/dbexport.py` worked off one fixed constant, `JEN_TABLES` — the
26 tables Jen's own core schema owns. None of the 20 tables the 7 bundled
plugins own (`ds_targets`, `ipam_subnets`, `sp_ports`, `wd_checks`, …) were
ever in it, so every backup, scheduled or manual, and every recovery bundle
silently dropped every plugin's data. Worse than losing it outright: restoring
one also restored its stale `plugin_schema_migrations` rows, and
`load_plugins()` reads "migration already applied" as "table already
exists" — so the table was never recreated either, on that install, ever,
until someone noticed and intervened by hand.

The fix is a derivation, not a second registry to keep in sync by hand.
`jen/services/plugins.py::owned_tables(plugin_id)` parses (never executes) the
plugin's own `manifest.json` `db_migrations` DDL — every `CREATE TABLE`,
`DROP TABLE`, `RENAME TABLE`/`ALTER TABLE … RENAME TO` — and derives the set
of tables that plugin owns *right now*, after every migration it ships. A
plugin whose ownership can't be expressed as "whatever my own DDL creates"
(a table named by a computed/legacy migration, say) can override it with an
explicit `"backup_tables": [...]` array in its manifest instead — checked for
the same collisions (against `JEN_TABLES` and against every other plugin's
own tables) either way. `all_owned_tables()` enumerates which plugins are
actually installed via `discover_plugins()` — a real directory scan, the
same one `load_plugins()` itself uses — and calls `owned_tables()` for each,
giving `dbexport.py` one derived universe of "every table any export/backup/
restore path ever needs to know about" with no manually maintained list
anywhere to fall out of sync. Deliberately never Jen's own `plugins` DB
table: that table is write-only bookkeeping the registry-install flow
populates (`record_plugin_row()`), and plain `enable_plugin()` — the only
way a bundled plugin ever actually gets enabled — never touches it at all,
so querying it here would silently miss every bundled plugin's data (caught
by system-test scenario 15, which enables plugins the ordinary way).

`dbexport.export_tables()` is that universe (core `JEN_TABLES` plus every
currently-installed plugin's owned tables) and is now the one thing behind
every export path — the manual "Export" tab, both scheduled and on-demand
backups, and the recovery bundle all call it, so a plugin installed today is
in tomorrow's 3 a.m. backup with no code change anywhere else. A restored
export's `_meta.format: 2` carries `plugin_tables: {plugin_id: {version,
tables}}` — the per-plugin scope the restore side needs; a pre-Q107 export
has no such key (`format: 1`) and is handled as its own path below.

The restore order in `dbexport.import_jen()` is fixed, and deliberately never
trusts a migration row over checking the table itself exists:

1. **Core tables import first, except `plugin_schema_migrations`** — its
   rows from the file are never restored as-is; a stale "already applied"
   row is exactly the bug above.
2. **For each plugin named in the export whose code is on THIS machine**,
   its `plugin_schema_migrations` rows are cleared and its migrations are
   re-run through the normal runner (`run_plugin_migrations()`) — its tables
   come from the CODE's own `CREATE TABLE IF NOT EXISTS`, never from DDL
   embedded in the export file, and the migration rows that mark it done are
   the runner's own, not the file's.
3. **That plugin's row data imports** the same column-intersection way core
   tables always have — a column added to the schema since the export just
   takes its default.
4. **A plugin named in the export whose code is NOT here is skipped**, named
   in a warning; its data is untouched in the file/bundle, ready for a later
   install of that plugin to bring back.
5. **A format-1 export** (everything before this Q — never carried plugin
   row data to begin with) has no per-plugin scope to read, so every
   *currently installed, code-present* plugin gets the same clear-and-rerun
   migration treatment, for the same "never trust a stale migration row"
   reason — it recreates the schema even though there was never any row data
   in the file to go with it.

`dbexport._plugin_invariant_violations()` checks once, at the end of any
restore, that the invariant actually holds — a recorded migration always
implies its table exists — and reports it as a warning line if it doesn't.
It is deliberately not a hard failure: the real, permanent fix is
`jen/services/plugins.py::self_heal_missing_tables()`, called from
`load_plugins()` before a plugin's normal migration check on every Jen
start from now on. It detects exactly this "migration recorded but table
missing" state per table and repairs it the same way — clear the migration
row, re-run — which also means an install broken by a *pre*-Q107 restore
repairs itself the next time Jen starts, no manual intervention needed. It
emits a `plugin.schema_repaired` event and a `PLUGIN_SCHEMA_REPAIRED` audit
row when it actually heals something, so a repair is visible, not silent.

## 4. CI/CD verification

As of the process work following the v4.4.10 audit series:

- **`tests.yml`** (reusable workflow) runs on every push and PR via
  `ci.yml`, and gates every tagged release via `release.yml`:
  - `pytest` against a real MariaDB service container — the full test
    suite, not a subset.
  - `bandit` (static security analysis) against `jen/` and `plugins/`,
    diffed against `.github/bandit-baseline.json` — a snapshot of
    findings that existed as of this writing, each manually traced and
    verified safe (whitelisted table/column names, int()-cast values,
    the TOFU SSH model described above). New findings introduced after
    the baseline fail CI; the existing, reviewed backlog doesn't block
    anything.
  - `pip-audit` against the actual installed dependency set.
- **`/api/v1/health` answers from Jen alone and carries only `jen_version`
  (v5.65.6, Q95; trimmed to this in v5.65.12, Q101 a).** The self-updater
  confirms the running version by polling it with a 5 s timeout, and the restore's
  health poll does the same; it used to call Kea live, twice, so with Kea unreachable
  (a condition Jen is meant to survive) it took ~20 s and a HEALTHY update or restore
  was rolled back — it still never calls Kea. Its body used to also carry `kea_up`,
  `kea_version`, `kea_checked_at` and `subnets`: v5.65.8 added a per-server list to
  this public page, v5.65.10 moved that (as `servers`, cached, no extra probe) to the
  key-gated `GET /api/v1/health/kea` but kept the single-server summary and the
  subnet count here, and v5.65.12 established that every real consumer of this route
  (the self-updater's version confirmation, the restore poll, the system suite) reads
  `jen_version` only — the rest was reconnaissance for no benefit to a caller with no
  key, so it moved there too. `GET /api/v1/health/kea` probes the active server
  once: `probe_kea_health(server)` is the one Kea probe (a single `version-get`
  that also writes the cache entry), used by `kea_is_up`, the status page and the
  API alike, and the active server is chosen from the cache (`cached_active_server`),
  not by re-running the HA election. It used to make two to six calls, so a dead
  server cost two timeouts.
  `tests/test_health_endpoint.py` and system scenario 11 pin it.
- **`kea_command()`'s transport exceptions are canned (v5.65.12, Q101 b).**
  A `ConnectionError` and a `Timeout` were already canned (the connect message
  names the API URL — admin-facing and useful, kept); the catch-all
  `except Exception` below them used to return the exception's own `str(e)`,
  rendered verbatim on the dashboard's config-error banner and the Doctor page —
  a TLS handshake failure, a malformed response, anything else the transport
  raised. It returns a generic sentence now and logs the exception with the URL
  and command name. `tests/test_no_raw_exception_leaks.py`'s scanner gained a
  pattern for this exact shape (a plain `{"text": str(e)}` result dict, which
  none of its `flash()`/`jsonify()`/`api_error()` patterns ever matched) so a
  regression here is caught the same way a route-level leak is.
- **Dependabot** watches the GitHub Actions used in these workflows and
  opens PRs to bump pinned commit SHAs forward when new releases exist.
- **`system-tests.yml`** (v5.64.x, Q84) sits beside `kea-compat.yml`: weekly, on
  demand and on release-candidate tags, and deliberately NOT called from `ci.yml`
  or `release.yml`, so a slow or flaky boundary test never reddens a push or a tag.
  `tests/system/` runs Jen under gunicorn against real Kea hosts (kea-dhcp4, sshd
  and the helper Jen installs), MariaDB and two fault injectors, with no mocks.
  Since v5.65.6 it also runs on every `vX.Y.Z-beta.N` tag, the CRITICAL subset only
  (Docker boot, restore, the change-set partial failure, both rollback scenarios,
  and `/api/v1/health` with Kea frozen); the full set stays weekly / rc / dispatch.
  It exists to hold two invariants the unit suite cannot: (1) a config change set
  never raises out of `kea_changeset` and never leaves the servers disagreeing,
  including when a restart fails after the write (the before-config is re-applied
  and the server restarted again, reported `rolled_back` or `rollback_failed`);
  (2) the image Jen ships actually boots (`WORKDIR /opt/jen` plus gunicorn's
  `--chdir`), which the `shipped-compose` job proves with a real
  `docker compose up` of the shipped compose file.

None of this replaces a real external security audit. It's the
realistic, zero-budget equivalent: automated checks that catch
regressions and known-CVE dependencies going forward, plus a documented
paper trail for what's already been manually reviewed.

## 5. IPv6 support (v5.0)

v5.0 added IPv6 (DHCPv6) support alongside Jen's existing IPv4 management —
read-only visibility across every major page, plus write support for
reservations and subnet pool/timer editing. This section describes what's
covered, what's deliberately deferred, and the design decisions that keep
it a genuinely additive change rather than a rewrite.

### 5.1 Off by default, verified off by default

`ipv6_enabled` (a `settings` table key, same pattern as `restart_pending`)
defaults to `false` on every install — new and existing. Every v6 code
path is written to check it first: `SUBNET6_MAP` is never populated for
display, no v6 nav/UI element renders, and no v6 Kea command fires unless
it's explicitly on. This isn't just a design intention — it's the single
most heavily tested property in the v6 test suite (`tests/test_kea6_*.py`,
`test_kea6_config.py::TestZeroBehaviorChange` and equivalents throughout), because a
regression here would mean every v4-only install silently starts doing
extra work or showing broken UI on upgrade. `[kea6]`/`[kea6_db]`/
`[subnets6]` are all optional `jen.config` sections; when absent, every
v6 connection value falls back to its v4 counterpart at config-load time
(`jen/config.py`'s `AppConfig.apply()`) rather than requiring separate
credentials — the common real-world case is one Kea Control Agent
proxying both `kea-dhcp4` and `kea-dhcp6`, and one shared MySQL database.
The one exception (v5.10.0): in `connection_mode = direct` there is **no**
fallback for `[kea6] api_url` — a `kea-dhcp4` daemon can't answer DHCPv6
commands, so v6 needs its own control-socket URL or v6 API calls return
an error dict.

### 5.2 Data model

- **`SUBNET6_MAP`** is a fully independent map keyed by Kea's own v6
  subnet IDs, which do **not** share a numbering space with v4's — the
  same integer can validly appear in both `[subnets]` and `[subnets6]`
  and refer to two unrelated subnets. An optional `paired_subnet4_id`
  field (a third comma-separated value in a `[subnets6]` entry) lets an
  admin explicitly associate a v6 subnet with its v4 counterpart so the
  Subnets page renders them as one card with two detail blocks.
  Deliberately config-driven, not auto-detected by name/VLAN matching —
  guessing wrong and silently merging two unrelated subnets is worse
  than requiring one config line.
- **`hosts` is the same table for v4 and v6** — it gained
  `dhcp6_subnet_id`/`dhcp6_client_classes` columns alongside its existing
  v4 columns (this is Kea's own schema, not something Jen added). One
  `hosts` row (one DUID) can carry both a v4 and a v6 reservation at
  once.
- **`ipv6_reservations`** is a genuine one-to-many junction table off
  `hosts` — a single device can hold both an address (IA_NA) reservation
  and a delegated-prefix (IA_PD) reservation simultaneously. Every v6
  reservation read/write path in Jen represents this directly (a device
  row with a list of reservations), not retrofitted from a
  one-reservation-per-device assumption inherited from the v4 code.
- **`lease6`** columns are read from `SHOW CREATE TABLE` against the
  database `kea-admin db-init` creates for each supported Kea (3.0.3, 3.2.0,
  3.3.1 — recorded in the kea-compat artifacts and asserted by
  `tests/kea_compat/test_db_moves.py`), not assumed from the v4 schema:
  `address` is **`BINARY(16)`** — sixteen raw bytes, not the `INET_ATON`
  integer v4 uses and not the `VARCHAR(39)` text this note used to claim
  (v5.67.0-beta.16, Q130); `ipv6_reservations.address` and `excluded_prefix`
  are `BINARY(16)` too; `duid` is `VARBINARY(130)` like `hwaddr`;
  `hwaddr`/`hwtype`/`hwaddr_source` were added in a later Kea schema
  version so are nullable. **Every IPv6 reader goes through
  `kea6._addr_text()`** (16 bytes → the compressed text, a `str` unchanged,
  `None` unchanged), in Python rather than `INET6_NTOA`, so one path serves
  MariaDB 10.11/11.4 and MySQL 8.0. A lease6 search for a *whole* address is
  an exact `address = INET6_ATON(…)`; any partial search (a fragment) is
  filtered in Python over the converted text, hostname and DUID of the rows
  the subnet/type/state filters leave — IPv6 tables at this scale are small.
  Jen never writes these columns: reservations go through Kea's `host_cmds`
  hook, which takes text. MAC display for a v6
  lease prefers Kea's own populated `hwaddr` when present, falling back
  to manual DUID-LL/DUID-LLT parsing (`jen/services/kea6.py`,
  `extract_mac_from_duid()`) only when it isn't — and returns nothing
  (never a guess) for DUID-EN/DUID-UUID, which have no embedded
  link-layer address at all.
- **`lease6_history`** is a separate table from `lease_history`, not
  columns bolted on: v4's single active/dynamic/pool-size-percentage
  model doesn't map onto v6, where IA_NA and IA_PD are different,
  non-comparable quantities and a `/64` pool has no finite "percent
  used" the way a v4 `/24` does. Active-lease counts are tracked
  per-type; there's no pool-size or utilization-ratio column, and none
  of `/metrics`' v6 gauges (`jen_subnet6_*`) attempt one either — this
  is the same reasoning applied consistently at three separate layers
  (schema, metrics, alerts — see 5.4).

### 5.3 The enable/disable toggle reaches real infrastructure

Flipping "Enable IPv6 support" (Settings → Kea, superadmin
only) is two layers, not one: the `ipv6_enabled` display flag above, and
actual SSH-driven service-state orchestration
(`jen/services/kea6.py::set_ipv6_service_state()`) that connects to
every configured Kea server, confirms `kea-dhcp6.conf` genuinely exists
first (Jen never authors one from nothing), and runs
`systemctl enable --now kea-dhcp6-server` (with the same dual-name
fallback to `isc-kea-dhcp6-server` the v4 restart logic already has).
The display flag only flips to enabled if **every** server succeeds;
disabling always flips it off regardless of partial SSH failure, since
"off" is the safe state to fail toward and any server that didn't
actually stop is surfaced as an error rather than silently trusted.

### 5.4 Write-side: reservations and subnet editing

Both go through the same trust boundary already established for v4
(§3.3), not a new one:

- **Reservations** use Kea's own `reservation-add`/`reservation-del`
  commands via the Control Agent API (`host_cmds` hook — the same one
  the v4 add/edit-reservation flow already requires), not direct SQL
  writes to `hosts`/`ipv6_reservations`. This keeps Kea's in-memory host
  cache and the database in sync automatically.
- **Subnet pool/timer editing** reuses the exact SSH config-push pattern
  from §3.3 and the v4.4.24 Preview & Validate work: a generated Python
  script patches `kea-dhcp6.conf`, tests it with `kea-dhcp6 -t` against a
  temp file, and only replaces the live config (after a backup) if the
  test passes. The dry-run preview endpoint never writes to the live
  config under any outcome — this is directly tested
  (`TestEditSubnet6PreviewRoute`) by asserting the SSH session only ever
  sees one command (the test), never a second apply/restart call. What's
  genuinely different from v4: `preferred-lifetime` and `valid-lifetime`
  are distinct fields (v4 only has one), DNS is delivered via the
  `dns-servers` option (code 23, space `dhcp6`) rather than v4's
  `domain-name-servers`, and there's no `routers` field at all — DHCPv6
  has no default-gateway option; that's Router Advertisement's job,
  entirely outside Kea.

**Author Kea Config is a change set too (v5.68.0-beta.16, Q151).** The generated-script description above is the preview/edit path;
the authoring route that writes a whole `kea-dhcpX.conf` goes through `kea_changeset.apply_change()` (§3.11) like every other write - every subnet name is
validated before anything is touched, every target must report helper build 13+ (the legacy `sudo python3` script is never used for it: it could not create the
file private or put a failed write back), and Jen's own subnet record is written inside the change set by a `finalize` callback whose failure puts every
server's config back.

### 5.5 What's explicitly deferred, and why

Stated plainly rather than left to be discovered mid-implementation:

- **Cross-protocol device correlation.** Jen does not attempt to link "this
  v6 lease" and "this v4 lease" as the same physical device. Privacy-extension
  IPv6 addresses rotate, and DUID-to-MAC extraction only works for two
  of several DUID types (DUID-LL, DUID-LLT — not DUID-EN or DUID-UUID).
  A wrong automatic correlation is worse than none; v4 and v6 device
  lists are genuinely separate. `jen/services/kea6.py::list_lease6_devices()`
  groups v6 leases by DUID (so one device's IA_NA and IA_PD leases
  collapse into one row) but never cross-references the v4 `devices`
  table.
- **No v6 equivalent of the IP Map page.** Full-address-space
  enumeration doesn't extend to a `/64` — there's nothing meaningful to
  render. If an address-list view is ever wanted for v6, it would need
  to be "reservations + active leases only," a genuinely different page,
  not an extension of the existing one.
- **IPAM Lite and Network Discovery plugins remain IPv4-only.** Both
  document this directly in their own README and show an in-app note
  (gated on `ipv6_enabled`, invisible on v4-only installs) rather than
  silently producing incomplete results. Full-address-space IPAM and
  active network scanning don't have a sane v6 equivalent at homelab
  scale for the same "/64 has no finite space to enumerate" reason as
  the IP Map.
- **Alerting stays mostly v4-shaped.** `kea_down`/`kea_up`/`ha_failover`
  already generalize (they alert on Kea server reachability, not
  protocol-specific data). Utilization/pool-exhaustion alerts are
  deliberately **not** ported to v6 — same "/64 percentage is
  meaningless" reasoning as the schema and metrics decisions above.
  `new_lease`/`new_device`/`stale_reservation` stay v4-only because
  they're built on the `devices` table, which cross-protocol correlation
  concerns (above) keep v4-only. See the comment block above
  `ALERT_TYPE_LABELS` in `jen/services/alerts.py` for the full per-type
  reasoning, including the discovery that `reservation_added`,
  `reservation_deleted`, and `kea_config_changed` aren't actually wired
  to fire from any v4 route today either — there was nothing to
  generalize to v6 for those three.
- **Heavy prefix-delegation topologies.** This covers straightforward
  dual-stack LANs (address reservations, a delegated-prefix reservation
  or two) well. A full PD-relay-chain setup is a different, harder
  problem that would need its own scoping.

## 6. Serving model (v5.5.0)

Through v5.4.x, `run.py` *was* the server — `werkzeug.serving.make_server`
/ `app.run`, i.e. the Flask development server. `threaded=True` (v5.3.3)
stopped one slow request from blocking every other user, but it was
still the dev server: unbounded thread spawning, no request timeouts,
no graceful drain on restart.

v5.5.0 puts **gunicorn** in front. `run.py` is now a launcher, not a
server:

- **No SSL:** `os.execvp` gunicorn bound to the HTTP port. `run.py` is
  replaced by the process; systemd owns gunicorn directly and SIGTERM
  goes straight to it.
- **SSL:** gunicorn runs as a child process (`--certfile/--keyfile`,
  HTTPS port); `run.py` stays as the parent, runs the HTTP→HTTPS 301
  redirect (`jen/httpredirect.py`, stdlib only) on its main thread, and
  forwards SIGTERM/SIGINT to gunicorn. gunicorn can only terminate TLS
  process-wide, so the plain-HTTP redirect genuinely can't share its
  process — hence the split. A `systemctl restart jen` now drains
  in-flight requests (gunicorn `--graceful-timeout 30`,
  `jen.service` `TimeoutStopSec=40`) instead of cutting them.

**Single worker, many threads.** `--workers 1 --threads N` (N =
`[server] threads`, default 8, Settings → System). Jen is
I/O-bound — DB, Kea Control Agent API, SSH — not CPU-bound, so threads
carry the concurrency fine. `-w 1` is also load-bearing for correctness:
the backup scheduler and the `check_alerts` loop are **single-process**
background work. They were started by `create_app()` before v5.5.0 —
which would have run them once per gunicorn worker. Now the factory only
builds the app; `jen/wsgi.py` (imported once by the single worker) calls
`jen.services.background.start_background_workers()`. A multi-worker
gunicorn would reopen the "scheduler runs N times, alerts fire N times"
problem and is deliberately not offered — that's a separate project
needing a dedicated worker process or a distributed lock.

**Werkzeug fallback.** If gunicorn can't be imported or spawned — a
botched dependency install, a non-Linux dev box — `run.py` logs a
CRITICAL and falls back to the old werkzeug path (which then starts the
background workers itself). This is a safety net so the console never
goes dark on a bad update; it is not a supported way to run in
production, and it says so, loudly, in the log on every start.

**Telling systemd apart from Docker and a dev checkout (v5.67.0-beta.6,
Q118).** `jen/services/runtime.py::deployment() -> "systemd" | "docker"
| "dev"` is the single place that question is ever answered —
`/.dockerenv` for a container; otherwise the rendered unit's own
`Environment=JEN_SERVICE_MANAGER=systemd` line, or (its fallback,
covering a unit rendered before this release or a hand-written one from
`docs/manual-install.md`) `INVOCATION_ID`, which systemd sets for every
unit it starts, for systemd; dev otherwise. It deliberately never reads
`JEN_ROOT`: v5.67.0-beta.2's relocatable install made the rendered unit
set `JEN_ROOT` on every production install too, which broke the three
places that used to infer deployment from it —
`jen.services.plugins.is_systemd_host()` (now a one-line wrapper around
`deployment()`), `jen.services.content.content_dir_incomplete()`, and
`jen/__init__.py`'s venv-migration check — each silently treating a real
systemd host as a dev/Docker checkout from v5.67.0-beta.2 through
beta.5: no Update or Restart control on Settings → System, plugin
installs routed onto the in-process path meant for Docker, and a
genuinely incomplete data directory never flagged. See
`docs/troubleshooting.md`'s entry for the affected betas and the manual
way out for a box already stuck on one of them.

**venv + transactional self-update (v5.8.0).** Two paired changes to how
Jen's code and dependencies land on bare metal.

*The venv.* Jen's Python dependencies live in a virtualenv, not system
site-packages — no more `pip --break-system-packages`. As of **v5.14.0**
each release gets its **own** venv at `releases/<X.Y.Z>/venv`, built for
exactly that release's `requirements.txt`; `jen.service` runs
`/opt/jen/current/venv/bin/python /opt/jen/current/app/run.py`. `run.py`
still carries a re-exec shim (it prefers `<run.py dir>/../venv`, then the
flat `/opt/jen/venv`) as a safety net for a still-flat box and for
Docker, but on a versioned box the unit already names the right
interpreter. Pre-5.14 the venv was the single flat `/opt/jen/venv` and
the unit ran `/usr/bin/python3 /opt/jen/run.py`.

The venv is **`root:root`** — the `www-data` service account reads and
executes the interpreter and site-packages but never writes them (it's
byte-compiled as root at install time so there's no lazy `.pyc` write).
A writable venv would be a persistence foothold for a compromised
`www-data`: swap a package's code and Jen runs it on every restart. Only
`install.sh` and the root self-updater modify it. Docker doesn't use a
venv at all — the container is the isolation — and reaches the app
through the same `JEN_ROOT` fallback.

*The transactional updater.* `jen-update-root.py` was
*replace-then-try-deps*: overwrite `/opt/jen`, then `pip` non-fatally,
then restart — which silently shipped a half-updated app if a release
genuinely needed a new library. As of **v5.14.0** it builds the whole
release under `releases/<X.Y.Z>.staging-<ts>/` (extract the tarball into
`app/`, build `venv/`, `pip`, compile, import-check) and the install is
`os.rename()` of the staging dir into place plus an `os.replace()` of the
`/opt/jen/current` relative symlink — atomic on POSIX. **Any failure**
flips the symlink back to the previous release (its directory was never
touched, so it is its own rollback — no snapshot/restore of the app tree
at all) and restarts. The out-of-tree files an update replaces
(`jen.service`, `/etc/sudoers.d/jen`, the updater itself,
`jen-update.service`) are still snapshotted and restored, so a bad unit
file can't survive the rollback. The per-release venv finally makes the
rollback a **true point-in-time revert** — the old release's venv is
exactly the dependencies it shipped with.

The first run on a still-flat box ("migration run" — no `current` symlink
yet) keeps `snapshot_install()` / `restore_snapshot()` for exactly that
one case: it snapshots the flat tree, builds the versioned layout, and on
success removes the flat `jen/ run.py templates/ static/ plugins/ venv/`.
`sudo ./install.sh` does the same migration immediately.

Two small deliberate choices worth stating: `/api/v1/health` is
**unauthenticated** (its body is Jen's version alone, since v5.65.12 —
Kea's state and the subnet count moved to the key-gated `/api/v1/health/kea`)
and the updater's post-restart version confirmation depends on it; and the
snapshot copies symlinks *as* symlinks (`copytree(symlinks=True)`) —
v5.8.4, after a stray dangling `templates/templates` link from an old
install made every snapshot raise before the swap.

The venv build (`_build_release_venv()`, pre-5.14 `ensure_venv()`)
requires a venv with a *working `pip`* (a half-built venv from a failed
`python3 -m venv` is wiped and rebuilt), and — running as root already —
`apt-get install`s `python3-venv` (v5.8.3: `apt-get update` + one more
retry on a box with stale indices). Because the venv build now happens
against a brand-new staging path, a failure there aborts the update with
nothing touched. The post-restart health-check timeout is 90s (was 45),
overridable via `[server] update_health_timeout`. The health and version
probes talk to the app's real port — HTTPS directly when certs are
present — and neither follows redirects nor verifies TLS on the loopback
call, so an SSL install with a hostname cert isn't mistaken for a dead
one (v5.8.2 chased `jen/httpredirect.py`'s 301 into a failing TLS
handshake and rolled back healthy HTTPS upgrades).

**The 5.13.0 → 5.14.0 transition.** The updater already deployed on a
5.13.x box is the flat one; it installs the 5.14.0 tarball — the new
`jen.service` included — but has no `current` symlink, so the new unit
can't start. That box fails the health check and **cleanly rolls back to
5.13.0**. Operators take 5.14.0 with `sudo ./install.sh` once (it builds
the versioned layout and removes the flat leftovers); every in-app update
from 5.14.0 onward is the atomic-symlink path.

**Still not offered:** a reverse proxy is not required and not
configured by the installer. Terminating TLS in nginx/caddy and running
gunicorn HTTP-only behind it is a valid deployment, just not the
default — the default keeps the "one `install.sh` and done" story.

**The investigation-logging sweep (v5.68.0-beta.3, Q138).** One APScheduler job
(`jen_investigation_sweep`, every minute, `max_instances=1`, started with the other two by
`scheduler.start_scheduler()` and so single-process like them) restores any expired investigation-logging
marker. Its cheap path reads only a settings index of what this Jen knows is on; every tenth run it also reads
every SSH server's config (the helper's `read-config`) to restore an expired marker nobody indexed — the marker
lives in the Kea config itself, so a restored database or a second Jen leaves nothing stranded — and to adopt a
live one so the banners show it. A restore that fails stays indexed with its error (the Health row reads that,
never SSH at render time) and is retried the next minute.

**Its state machine (v5.68.0-beta.9, Q144).** Putting a log level back is two steps that fail on their own: the FILE (the
`loggers` entry and its marker, written through `apply_change`) and the DAEMON (which has to re-read it - `config-reload`, else a
restart). An index entry carries `file` ("debug" | "restored"), `daemon` ("debug" | "restored" | "unknown") and `pending` (the daemon
step still owed), and is dropped only when file AND daemon are both restored. That closes a hole the first version had: a restore whose
reload was refused and whose restart failed had already cleaned the file, so the next minute's change set found no marker, reported
"nothing" - which meant "done" - and forgot a daemon still at DEBUG 55. Now a "nothing" with a daemon step owed runs the step, and a
half-finished restore is retried by the sweep even before its time is up. The enable side mirrors it: `turn_on` saves the entry as soon
as the file is written (writing it took responsibility for it), BEFORE the daemon is asked, and on a failed daemon step puts the file
straight back through the change set - or, if that fails too, keeps the entry so the sweep finishes it. A server removed from Jen while
its entry exists is not dropped: the entry is kept (with the server's name, SSH host and config path) and marked removed, the Health
row fails with the by-hand restore, and the settings forms that would stop Jen reaching a server refuse until `turn_off` has
succeeded. An admin who restored such a server by hand tells Jen so with one button on the Servers page. Adopting a marker the sweep
did not index, and a refused removal, each write an audit row. **The damaged state (v5.68.0-beta.14, Q149).** An entry whose marker lost its
`restore` object carries `marker_invalid` (and the Config history revision to start from). It is set by whichever sees the marker first - the restore step
when it is due, or the full scan (every tenth run) the minute it reads one, even with an hour to go - and cleared when a later scan finds the marker
readable again. Nothing in this state writes to the Kea host: the DEBUG stays exactly as it is until a person puts it back and presses Forget, which
re-reads the config and refuses while any `jen-investigation` marker is still in it.

**The Problems sweep (v5.68.0-beta.5, Q140).** The second core scheduler job this round added
(`jen_client_problems_sweep`, every five minutes, `max_instances=1`, `coalesce`, single-process like the first two) reads each SSH server's
DHCPv4 log through `kea_host.tail_log` with `helper_only=True` - the helper's bounded `tail-log`, never the legacy `sudo tail`, which
cannot serve 1000 lines and would pass a partial log off as a complete one - and the lease database, and upserts `client_problems`.
It adds no helper op and no sudo line. Because the sweep and the web threads are one process, its per-server watermark and its
lock need no cross-process coordination; a second Jen against the same database would double-count lines and is not a supported
shape. The page, the lazy answer and the dashboard widget are diagnostic surfaces (`@diagnostic_surface`, a row each in the
authorization matrix): every read is filtered by `add_subnet_restriction` on the row's own `subnet_id`, so a row with no subnet is
for callers who may see every subnet, as in section 2.

**What the Problems sweep may and may not infer (v5.68.0-beta.9, Q144).** A log line is evidence about ONE moment, and the sweep
reads it as that. A row's subnet is where the event itself says - the subnet its address is in, else the subnet Kea selected for the
very transaction (a DEBUG line sharing the event's transaction id) - and never where the client is now, which would show a NAK from
one subnet to a user of the subnet the client has since moved to; a row with no subnet is for callers who may see every subnet, and an
alert about it (`alerts.SCOPED_ALERT_TYPES`) fails closed for a channel that has a subnet scope. A DNS-update failure, whose line names
no client, is attributed to the allocation nearest BEFORE it in the log (the same transaction when the line carries one), never to
whoever holds the address last. `first_seen` and `last_seen` are the events' own times: Kea writes its log in the host's local time, so
the sweep measures the host's offset from UTC against the lease database (the newest allocation lines against the lease rows'
`expire`, to the nearest quarter hour), remembers it per server, and assumes UTC for a server that has shown it nothing - the Problems
page says which. The alert window is judged against now, a server's first read sets its watermark without alerting (a backlog is not
news), and `alerted_at` is set only when a channel actually took the alert: `alert_attempted_at` (migration 31) records every try and a
failing delivery is retried every half hour, not every five minutes and not never.

**The alert is decided per (kind, client, subnet), and a decision survives the log rotating (v5.68.0-beta.13, Q148).** The count that
crosses `client_problem_threshold` was kept per (kind, client) across every subnet, then reported to a channel scoped to one of them:
two NAKs in a subnet a channel cannot see plus one in its own read as the three that fire, and the message said so, while the Problems page
would have shown that channel's users one. `client_problems.collect` now keys `recent` by (kind, client, subnet) with `None` a key of its
own ("no attributable subnet", for unrestricted channels only, as before), the delivery is recorded on that subnet's rows alone, and the page
keeps grouping by client for display. The retry used to re-read the same 1000-line tail to re-check the threshold, so on a busy server the
lines that qualified the alert rotated out inside the 30-minute retry bound and an alert the sweep had decided to send was never sent
though its row said it failed. Migration 32 adds `qualified_at` and `qualified_count`: the sweep writes them on a key's rows when it first
crosses the threshold, the retry reads THEM rather than the tail until the alert is delivered, the row is resolved, or the qualification is
24 hours old (then cleared; a recurrence earns a fresh one), and the message carries the persisted count and the time it qualified.
A delivered alert clears the qualification on that subnet's rows (v5.68.0-beta.14): nothing is left to retry. **A row's subnet is part of
its identity (v5.68.0-beta.14, Q149).** Migration 33 added `scope_key` (`COALESCE(subnet_id, -1)`) to the unique key, so the same client's events
in subnet B, B and A are two rows - each with its own count, first/last time, alert state and resolution - and the newest event no longer moves a
row between subnets. The migration deletes the existing rows (they may be cross-contaminated) and resets each server's log watermark: the inbox
starts again and the next sweep refills it from the log tail, the first read of a server recording without alerting as always.

### 6.1 On-disk layout (v5.13.0, extended in v5.14.0, relocatable since v5.67.0)

Through v5.12.x the application tree under `/opt/jen` held user-writable
content — custom icons, the uploaded favicon and nav logo, database
backups, registry-installed plugins, the secret-key/MFA-key fallbacks —
so `www-data` needed write access to parts of the tree it also executes.
That is a persistence foothold: anything that can write a `.py` file Jen
imports, and later run it as `www-data` on the next restart, has a way to
stay resident across an update. v5.13.0 split the two apart; v5.14.0
added the versioned release directories.

The table below uses the historical defaults — `/opt/jen` (`app_dir`),
`/etc/jen` (`config_dir`), `/var/lib/jen` (`data_dir`) — what every
install gets when `/etc/jen-layout.conf` is absent, which is every
install before v5.67.0 and any install since that never asked to
relocate. §3.1 above covers where that file lives and why, and (since
v5.67.0-beta.5, Q117) the single `jen-update-root.py --check-layout`
implementation that now enforces every rule for both `install.sh` and
`uninstall.sh`: the three directories may not be nested inside one
another; none may live under `/tmp`/`/run`/`/proc`/`/sys`/`/dev`/
`/home` or be (or live under) a shared FHS root like `/etc`/`/opt`/
`/usr`/`/var`; each must satisfy a conservative path grammar; every
existing ancestor must be root-owned and not group/other-writable, a
hard refusal re-checked on *every* privileged run, not just at first
install; and each must carry (or earn, by content, on upgrade) a
`.jen-directory` marker before an install/upgrade/uninstall trusts it.
`docs/installation.md` Method 1c is where an operator actually sets
these at install time.

| Path | Holds | Owner / mode | What an upgrade does |
|------|-------|--------------|----------------------|
| `/etc/jen-layout.conf` (v5.67.0) | `app_dir`/`config_dir`/`data_dir`, if this install relocated any of them | `root:root`, `0644` | Written once, at fresh install. Never touched by an upgrade; hand-editing it to relocate an *existing* install is refused — `docs/runbooks.md` §5 is the real procedure. |
| `<app_dir>/.jen-directory`, `<config_dir>/.jen-directory`, `<data_dir>/.jen-directory` (v5.67.0-beta.5) | That directory's `role` and the Jen `version` that stamped it | `root:root`, `0644` | Written once `install.sh` has actually created the three directories (`--write-layout-markers`). A pre-Q117 install earns its markers retroactively, the first time `--check-layout --for upgrade`/`--for uninstall` recognizes each directory by its own real content. |
| `<app_dir>/releases/<X.Y.Z>/app/` | One release's full tree: `jen/`, `templates/`, `static/`, `plugins/` (every bundled plugin directory, seven today; `shipped_plugin_ids()`), `run.py`, the shipped external files (including `jen.service.template`), `docs/` | `root:root`, `a+rX` — read-and-execute only for `www-data` | Built whole under a `.staging-<ts>` sibling, then `os.rename()`d into place. Byte-compiled as root. The previous release's directory is left untouched. |
| `<app_dir>/releases/<X.Y.Z>/venv/` | That release's virtualenv, built for its own `requirements.txt` | `root:root` | Built fresh per release — the rollback is a true point-in-time revert of dependencies too. |
| `<app_dir>/current` | Relative symlink → `releases/<live>` | symlink | Flipped with `os.replace()` (atomic). A rollback flips it back. |
| `<app_dir>/` (flat, pre-5.14) | `jen/`, `run.py`, `templates/`, `static/`, `plugins/`, `venv/` | `root:root`, `a+rX` | Removed by the migration run / `install.sh` once the versioned layout is live. Docker stays flat. |
| `<app_dir>/plugins-installed/` (v5.27.0, §3.10) | Registry-installed plugins landed by `jen-plugin-install.service` | `root:root`, `a+rX,go-w` — read-and-execute only for `www-data` | Written only by `jen-update-root.py --plugins`, one plugin id at a time, via a staged-directory `os.rename()`. Untouched by a Jen release upgrade. |
| `<config_dir>/` | `jen.config`, its backups, TLS certs (`ssl/`), SSH keys (`ssh/`) | `www-data` | Never touched, except that `install.sh --configure` rewrites `jen.config` through `tools/private_write.py` (refuses a symlink, 0600 from the first byte). Root never reads a code snapshot or anything else back out of it (§3.1). |
| `<app_dir>/.rollback/` (v5.68.0-beta.16) | Root's own rollback material: `run.py.<ts>`, `jen.<ts>/` (flat-layout upgrade snapshots) and `ext.<ts>/` (the units, sudoers, `jen-update-root.py`) | `root:root`, `700` | Replaced on every upgrade; the rollback restores from it only after `_trusted_snapshot` (root-owned, no symlink, under this directory). |
| `<data_dir>/` | User content: `icons/`, `branding/` (`nav_logo.*`, `favicon.ico`), `backups/` (database backups), `plugins/` (legacy registry-installed, pre-5.27.0 — see §3.10), `plugins-enabled/` (enable markers), `plugin-requests/` (v5.27.0 install/remove markers + results), `keys/` (`.secret_key`, `.mfa_key` fallbacks) | `www-data`, `750` | Never touched. Populated once, on the upgrade to 5.13.0, by moving the old locations out of `<app_dir>`. |
| `/tmp` | Scratch only (`PrivateTmp=yes`) | per-service namespace | n/a |

`jen.service` is **rendered**, not shipped ready-to-use (v5.67.0):
`jen.service.template` carries `@@APP_DIR@@`/`@@CONFIG_DIR@@`/
`@@DATA_DIR@@` placeholders, filled in by `install.sh`'s
`render_jen_service()` at install time and by `jen-update-root.py`'s copy
of the same function on every later in-app update (`install_external_files()`
there renders instead of copying verbatim specifically so a relocated
install's unit is never silently overwritten with one hardcoded back to
the defaults). The rendered unit sets `Environment=JEN_ROOT=<app_dir>/current/app
JEN_CONFIG_DIR=<config_dir> JEN_CONTENT_DIR=<data_dir>` and
`ReadWritePaths=<config_dir> <data_dir>`; `systemd-analyze verify` checks
the rendered result both in `install.sh` (`verify_install()`) and in CI.

`extensions.JEN_ROOT` reads `<app_dir>/current/app` when it exists, else
the flat `<app_dir>` (the `JEN_ROOT` env var overrides both, for dev and
CI, and is how the rendered unit's `Environment=` line reaches the app
without any layout-specific code in `jen/extensions.py` itself).
Because `current` is a symlink flipped atomically, a running worker
that opened a file under it keeps reading the old release until it
restarts — which the updater does anyway.

`extensions.CONFIG_DIR` (v5.67.0) and `extensions.CONTENT_DIR` are the
single read surfaces for the `<config_dir>` and `<data_dir>` rows,
mirroring each other exactly: `JEN_CONFIG_DIR`/`JEN_CONTENT_DIR` env
override wins; else, in a source checkout (`JEN_ROOT` set),
`$JEN_ROOT/etc`/`$JEN_ROOT/var`; else the historical `/etc/jen`/
`/var/lib/jen`. `CONFIG_FILE`, `MFA_KEY_PATH`, `SSL_CERT`/`SSL_KEY`/
`SSL_CA`/`SSL_COMBINED`, `SSH_KEY_PATH` and `SSH_KNOWN_HOSTS` all derive
from `CONFIG_DIR`; `PLUGIN_DIR_ROOT` derives from the install root (the
same `<app_dir>` `JEN_ROOT` resolves against, with the versioned
layout's `/current/app` suffix stripped back off) rather than
`CONTENT_DIR`, since root-owned plugin installs live under the app tree,
not the data tree — see §3.10. The app factory best-effort *copies*
any content still in an old `/opt/jen` location into `CONTENT_DIR` on
every boot (idempotent, never clobbers, never crashes the factory) — a
safety net for a box the root-side move missed, and for the Docker named
volume that used to mount at `/opt/jen/static/icons/custom`. Serving is a
dedicated blueprint (`/content/icons/<name>.svg`,
`/content/branding/<file>`); the old `/static/icons/custom/…` and
`/static/nav_logo.*` URLs are gone.

Bundled, root-owned, and legacy-writable copies of a plugin can all
exist for the same id at once (a box that installed `ipam` from the
registry, then upgraded, then reinstalled it under v5.27.0's split —
see §3.10). `discover_plugins()` scans bundled, then
`/opt/jen/plugins-installed` (root-owned), then `/var/lib/jen/plugins`
(legacy writable) — whichever of the three was scanned last for a
given id wins, so a legacy writable copy still shadows a root-owned one
until the root install's own final step removes it. Uninstalling a
bundled-only plugin disables it rather than deleting release-owned
files.

### 6.3 Concurrency, pool sizing and retention (v5.68.0-beta.17, Q152)

Jen runs one gunicorn worker with N threads (`[server] threads`, default 8) and one scheduler in the same process. Three things that were each
right for one request at a time were not right for N, and one family of tables had no lifecycle at all.

**The config file has one writer at a time.** Every `AppConfig` writer (`write_value`, `write_values`, `write_subnets`, `write_subnets6`,
`mutate`) is read-modify-write: read `jen.config`, change one thing, replace the file. Two Settings saves at once - two admins, or a save racing
the setup wizard or Author Kea Config's `[subnets]` write - were a lost update: the second read missed the first write. A single class-level
`RLock` (`AppConfig._write_lock`) is held from the read to the end of the reload, so what a writer reads is what is on disk when it replaces it and
the `extensions.*` globals are re-derived in the order the file changed. It is an RLock because `mutate`'s callback may call a writer, and
class-level so every instance serialises against every other. Readers take no lock: `os.replace` means they see the old file or the new one.
It guards threads in this process only - the installer is another process, see the next paragraph.

**...and the installer takes the same lock (v5.68.0-beta.18, Q153).** `install.sh --configure` runs an interactive wizard and rewrites `jen.config` with Jen
running, so a Settings save made during the wizard was overwritten by the installer's older copy (and everything the wizard never asks about - `[oidc]`,
extra Kea servers, `[kea6]`, `[subnets6]`, the update channel - was dropped with it). Every writer now also takes an exclusive advisory `flock` on
`<config>.lock` for its whole read-modify-replace (once per thread: the RLock allows a nested writer and a second descriptor in the same thread would queue
behind the first), waiting up to 30 s and then raising `ConfigFileLocked` (a Settings save says why instead of writing); the lock file is created 0600 owned
by the service user and never opened through a symlink. **It fails closed (v5.68.0-beta.19, Q154):** beta.18 degraded to the in-process lock alone, with a
log line, when the lock file could not be opened - exactly when something is wrong with it, the lock was silently gone. A symlink is now refused, and a file this
account cannot open (a root-owned 0600 one from an older run, a mode of 000) refuses the save (`ConfigFileLocked`) with the path, the reason and the `chown`/`chmod`
that fixes it. (beta.19 first "repaired" such a file by renaming a new one over it; v5.68.0-beta.20, Q155, removed that - a lock is an inode, see §2: the file is
normalised in place by the installer on every upgrade and `--configure`, never replaced.)
`install.sh` requires `flock` (the preflight checks it, the dependency step installs `util-linux` when it is missing, and `--configure` refuses without it).
`install.sh --configure` takes the lock before it reads anything (`_config_lock_acquire`) and holds it through `write_config`; because the wizard is
interactive, `write_config` then re-reads the live file and merges the answers INTO it (`tools/config_merge.py`): a key the wizard did not ask about keeps its
live value, a key the operator changed in the wizard wins, and a key the operator left as it was never undoes a newer save. Every other write the installer makes
of the config or its backup goes through `tools/private_write.py --lock`. **`--configure` seeds the wizard from the live file (v5.68.0-beta.21, Q156).** The wizard reads
the Kea connection, the Kea database, the SSH target and the DDNS settings (fifteen answers) with `_cfgval` - an answers file, else the `JEN_*` environment, else EMPTY - and
never prompts for them (Jen's own /setup connects Kea), so an interactive `--configure` wrote them blank; the merge faithfully applied the blanks (a blank differs from the
snapshot), and a configured box restarted into /setup without its Kea connection or its DDNS token while upgrading.md promised the opposite. The merge test built the
wizard's file FROM THE SNAPSHOT, a wizard install.sh does not have. `_run_configure_mode` now calls `_seed_answers_from_live` (through `tools/config_merge.py --answers`)
before the wizard: every one of the fifteen the live file holds goes into `ANSWERS` unless an answers file or an environment variable already has it, which also makes the
merge's "the operator accepted the default, live wins" rule reachable. A CI install leg installs a box with a Kea connection, an SSH target and a DDNS token, runs
`--configure` with an answers file that says nothing about Kea, and greps them all still there. v5.68.0-beta.22 (Q157) extends the seed to the five PROMPTED answers (`WIZARD_DEFAULTS`: the two ports and the Jen database's host, user, name): `--answers` prints them as `DEFAULT_<name>`, `LIVE_DEFAULTS` holds them and `_ask` offers that as its default, so Enter or an unattended run keeps what is configured; the seed reads the tool's output into a variable (a failing exit is a `fatal` naming the file and the code, not an invisible process-substitution status) and a multi-line value travels on one line (newlines as backslash-n, backslashes doubled) and is unescaped with `printf %b`. `AppConfig.mutate` hands its callback the parser to change and writes THAT parser
when it returns, so a writer called from inside the callback would write to disk and then be silently overwritten; it now raises
`RuntimeError("mutate the parser you were given")` (the old test codified "the outer write then wins").

**The provider pool is sized for the server, not for one page.** Investigation and search providers (one per bundled plugin) run on a shared
pool so the one-second budget is a bound (`jen/services/provider_budget.py`). It had 4 workers and a ceiling of 8 outstanding calls, with
seven providers per page: a second admin's page opened while the first's seven calls were in flight got one slot and six "unavailable (busy)"
cards. The workers now follow `[server] threads` and the ceiling is `max(16, 2 x threads x registered providers)`, set once by `configure()`
after the plugins have registered (a plugin install needs a restart, so the count is fixed for the process). A call over the ceiling waits for a
slot until ITS PAGE's deadline and is shown "busy" only if the deadline passes while it waits; abandoned calls still keep their slot until they
really end, so hung providers cannot pile up past the ceiling.

**One read of the Kea log per server, shared.** The live watch on Trace re-tailed every 3 s per watcher; two admins on one server doubled the
load on the Kea host. `jen/services/log_tail.py` keeps one read per (server id, path) for `WATCH_STEP_S` (3 s) and makes a reader that
arrives mid-read wait for it; Trace and Explain's log read (the layer below its own 30 s per-MAC cache) both use it, the Problems sweep does not
(it needs a current read, every five minutes). A failed read is kept for the window too.

**An alert's state knows whether anyone was told (v5.68.0-beta.19, Q154).** `alert_state:<type>:<key>` is a JSON object: `a` active, `n` notified, `t` last
attempt, `c` attempts since it last changed, `d` when it was notified. beta.18 set the state after the send whatever the send returned, so every channel down - or
no channel eligible yet - suppressed the warning until the condition recovered, and a later `_ok` went out for a warning nobody had received. `notify_condition`
is the one helper (utilization high/ok, pool exhaustion/ok, packet health/ok, cert_expiring per 30/7/1-day bucket, pool_forecast): `n` becomes true only when at
least one ELIGIBLE channel returned ok (`send_alert` answers `[(channel, ok, error)]`, empty when none was eligible); until then it retries with backoff (1, 2, 4
... 60 minutes) for as long as the condition holds, including after a channel is enabled later; one successful channel counts as told (the others are not
retried); the `_ok` is sent only when `n` was true; `repeat_after` is the forecast's weekly reminder. A value written by beta.18 (`"1"`/`"0"`) read as
active-and-notified / inactive.

**Recoveries are state too, and nothing is gated on the calendar day (v5.68.0-beta.20, Q155).** `notify_condition` ignored the `_ok`'s result and cleared the state, so a
recovery that failed was never retried and the operator kept "high" forever. The object gains `r` (recovery pending): when the `_ok` is not delivered the condition goes
inactive with `r` set and every pass retries the `_ok` with the same backoff until a channel takes it (none eligible counts as not delivered, so enabling the channel
later delivers it); the WARNING is never re-sent while a recovery waits, and if the condition returns first the earlier warning stands (`r` clears, nothing is sent).
beta.18's `"1"` now reads as active and NOT notified - beta.18 wrote it without checking the send, so "delivered" was a guess that hid an undelivered warning until
recovery - which costs one attempt on the next pass after the upgrade (a possible single duplicate beats a missed warning). The state is written only when it changed (the
quiet path used to upsert one settings row per type and subnet on every 30-second pass). The certificate and forecast conditions were evaluated once per process-day,
so the backoff above could not run: a one-day certificate warning whose channel was down was next tried tomorrow, after the certificate expired. The alert loop now
evaluates them every `CONDITION_INTERVAL_MINUTES` (15) - free for a delivered condition, since nothing is read from a channel and nothing written - with the two
expensive inputs, the certificate file's days-left and the forecast fit, cached for `CONDITION_CACHE_MINUTES` (60). `tests/test_alert_delivery.py` runs the real
`check_alerts` loop on an injected clock (`time.sleep` advances `alerts._utcnow`): a cert warning whose first send fails is attempted again two minutes later, the
forecast likewise, and the file is read once an hour.

**Liveness (v5.68.0-beta.19, Q154).** Health's *Background workers* row asks `background.liveness()`: the scheduler object exists and `.running`, every core job
is registered (`scheduler.CORE_JOB_IDS`), the alert-loop thread and the plugin periodic thread `is_alive()`; `start_scheduler` records why it did not start. The
*Problems inbox sweep* row is a skip for `MISS_LIMIT x SWEEP_INTERVAL_S` after the workers started and a failure after that when the sweep has never run. v5.68.0-beta.20
(Q155): `liveness()` also reports the **event dispatcher** (`events.dispatcher_running()`, with `events.queue_depth()`) - with it dead `emit()` does not fail, it runs every
subscriber inline on the thread that emitted, and the row used to stay green. beta.20 made the dispatcher down with the other three alive a `warn`; **v5.68.0-beta.21 (Q156) made a dead
dispatcher thread a `fail`** - one contract, stated once here and in the Health table: the row FAILS when any worker is not alive (the dispatcher included, and it is named when it is down too)
and WARNS when the dispatcher is alive but not keeping up (below).

**What each `lease_history` column means (v5.68.0-beta.19, Q154).** `active_leases` - the subnet's whole count of active, unexpired leases
("active clients"; a reservation outside every pool is one). `pool_used` - the active leases INSIDE the subnet's pools at snapshot time
(`pools.consumption`); the number every derived capacity figure divides by `pool_size` (Health's pool row, the forecast and the pool-forecast
alert, Prometheus' `jen_subnet_utilization_ratio`, Reports' free/utilisation/high-water/projection, the dashboard's history percentage). It is
NULL for every row written before migration 34 and for a snapshot taken while Kea's config was unreadable, and a NULL row is ignored (never read as
0, never back-filled - what was in the pools then cannot be reconstructed): the forecast says "insufficient history" until enough new snapshots
exist. `pool_size` - the total of every pool (`pools.total_pool_size`). `reserved_leases` - how many reservations are CONFIGURED in the subnet (charted as
"Reservations configured"; it is not how many hold a lease). `dynamic_leases` - active leases whose hwaddr matches no hwaddr-type reservation (a
client-id reservation counts as dynamic, so it is not a capacity series; the column stays for exports).

**Retention, in one place.** Every history table Jen writes, with what prunes it:

| Table | Pruned by | Setting (default) |
|---|---|---|
| `lease_history` | `alerts.purge_history()` | `history_retention_days` (90) |
| `lease6_history` | `purge_history()` - IPv6 on or off | `history_retention_days` (90) |
| `server_stats` | `purge_history()` | `history_retention_days` (90) |
| `events` | `purge_history()` | `events_retention_days` (90) |
| `alert_log` | `purge_history()` (`_purge_old_alert_log`) | `alert_log_retention_days` (180) |
| `audit_log` | `purge_history()` by `created_at` | `audit_retention_days` (90; 0 = keep forever) |
| `client_problems` | the daily cleanup (`client_problems.prune`) | 30 days, fixed |

`purge_history()` (v5.68.0-beta.19, Q154) touches `jen_db` ALONE - each table in its own try, one failure never stops the rest - and is called by the snapshot
job in a `finally` after the Kea snapshots (so a Kea outage cannot stop Jen's own retention, which used to run inside `take_lease_snapshot` after the Kea
database was opened) and by the daily 00:05 cleanup. The audit-log cleanup it replaced (and the immediate one on the Settings page) deleted by a `timestamp`
column the table does not have (`created_at`), so it had never removed a row.

`alert_log` is also the source of the Prometheus counter `jen_alerts_sent_total`, and a counter that drops is read as a reset: what the job
removes is first counted into `settings.alert_log_pruned_totals` (JSON keyed `type|status`) in the same transaction, and the metric is the
live rows plus that total, so the exported number never goes down. **The purge serialises before it counts (v5.68.0-beta.20, Q155).** beta.17 counted the
expiring rows and only then took `FOR UPDATE` on the totals row, and the purge runs from the alert thread every `snapshot_interval_minutes` AND from the daily 00:05
cleanup: two overlapping passes both counted the same rows, so a counter that by design never decreases was permanently high, and a `FOR UPDATE` on a row that does not
exist yet (the first purge) serialised nothing. `_purge_old_alert_log` now `INSERT IGNORE`s the totals row (its own committed statement - the shared lock a duplicate
`INSERT IGNORE` takes is gone before the exclusive one is asked for, or two passes would deadlock), takes it `FOR UPDATE`, and only then counts, deletes and adds; a
second pass waits at the lock and finds the rows gone. The DELETE's rowcount must equal what was counted, else everything rolls back and the pass is logged as failed;
stored totals that are not a JSON object are never overwritten (the rows stay, the pass fails). A failed pass returns `None` and `purge_history` reports `None` for
`alert_log` like every other table - it recorded `0` ("nothing to remove") before. `tests/test_alert_log_retention.py` holds the totals row from a test connection and
asserts a purge WAITS before counting, and runs two real purges at once (six rounds, with and without the totals row) asserting every row is counted exactly once.
`lease6_history` had existed since v5.0 and nothing wrote it; with IPv6 on
the snapshot pass now writes one row per IPv6 subnet (active leases by type, reservations by type - no pool size, a /64 has none to measure),
and with IPv6 off nothing in this path runs (`TestZeroBehaviorChange`).

**The log reader decides before it asks (v5.68.0-beta.21, Q156).** `explain_context.read_log` computed the order of the servers - one HA `status-get` each, a 10 s timeout for a
Control Agent that is down - before it looked at `allowed`, its cache or `fetch=False`, so the Overview's "never a fresh round trip" read paid for it on every `/client` render and
again for each of Explain, Config and Changes (`LOG_TTL_S` bounded the log read, not the probe). The order is now `allowed`, the configuration-only states, the per-MAC cache,
`fetch`, and only then `_evidence_servers()`, which is memoised for `LOG_TTL_S` (keyed by the configured server ids): at most one `status-get` per server per 30 seconds across
every caller. `TestTheHaQuestionIsAskedRarely` counts the probes: zero for an Overview render and for a cached read, one per server for a whole page's worth of readers, one more
after the window.

**Background work that has to keep its promises (v5.68.0-beta.21, Q156).** A sweep of every thread, loop, job and pool with seven questions (what if the body raises, the
database is down at start, a connection or lock is held across I/O, something grows without bound, a worker hangs, a second worker runs it, SIGTERM arrives) found six
contracts that did not hold. *The daily summary:* it was due when `now.hour == h and now.minute == m`, checked once per outer cycle, and a cycle is 6 x (probe + 5 s) - 90 s
with one server down, plus the heavy block - so the one-minute window was missed with no log line. It is due AT OR AFTER its time, once per day, with `daily_summary_sent` (the
date) persisted so a restart after the summary does not send it twice; a start after the configured time with NO record counts as sent today (it must not announce a "daily"
summary at an arbitrary hour because the process started then), and a summary that failed to build is retried no more often than every 15 minutes and is not recorded as sent.
*The settings cache:* a failed reload left its timestamp alone, so the next call reloaded again - and with the Jen database down each attempt costs a pool creation (10 s connect
timeout) and a direct connect (10 s): `check_session_timeout` on every request and about four reads per subnet per alert-loop pass made a pass take minutes and the 5 s kea_down
cadence was lost. The cache now keeps serving the last values it read (`default` only when it never read any) and retries after `_SETTINGS_RETRY_S` (5 s); `db.get_jen_db` /
`get_kea_db` record a failed pool creation and within `_POOL_RETRY_S` (10 s) only try the direct connect, once per call, outside the pool lock. *Plugin periodic jobs:* a job that
was `running` was skipped for ever and `_run_one_periodic` has no deadline, and `Thread.start()` ran outside the lock with no rollback; the start is guarded (a failure is a failed
run, `running` back to False), each run records `last_finished` and the outcome of the last three, `liveness()` carries `periodic_jobs()`, and the Background workers row FAILS for
a job `running` more than twice its interval (naming plugin and job) and warns when its last three runs failed. *The event dispatcher:* a dispatcher stuck inside a subscriber is ALIVE, so beta.21
reported {running, queue_depth, last_dispatch_age_s, dropped} and warned when events were queued and none had FINISHED for a minute. v5.68.0-beta.22 (Q157) judges it by what is waiting NOW:
each queued event carries its enqueue time, the loop stamps when it STARTED the event it is on, and `dispatcher_status()` = {running, queue_depth, current_age_s, oldest_queued_age_s,
last_dispatch_age_s, dropped_recent (the last 10 minutes), dropped_total}; the row WARNS when `current_age_s` or `oldest_queued_age_s` exceeds 60 s or there were drops in the last 10
minutes (the lifetime total is only text - one old overflow no longer warns for the life of the process, and an idle hour followed by a burst no longer reads as stuck), and FAILS when the
thread is dead. *Orphaned state:* `_clear_orphan_states` deletes `alert_state:<type>:<key>` rows
whose subnet or server is no longer configured (no `_ok`; since beta.22 an empty live set clears too - see "Every claim is backed..."), and the Problems sweep deletes the per-server settings keys of a removed server.
*The device seed:* the `known_macs` seed ran once before the alert loop, so a Jen database that was down at start left it empty for the life of the process and every known
device that was offline at start fired `new_device` when it came back; it is retried at the top of each cycle until it works and `new_device` waits for it.

**Every claim is backed by the result of the call that made it (v5.68.0-beta.22, Q157).** beta.21 fixed several contracts at the FIRST call and left the second with the old shape. *The daily
summary* returned True after `send_alert(...)` whatever the channels answered and the loop recorded the day as sent; it now returns "delivered" (an ELIGIBLE channel took it), "undelivered" (it
was built and nobody did) or "failed" (it could not be built), keeps the built text in `_pending_summary` so a retry does not rebuild, records `daily_summary_sent` ONLY on delivery,
retries "undelivered" with the notification backoff (1, 2, 4 ... 60 min) and "failed" every 15 minutes, and logs a record that could not be written (`set_global_setting` returns a bool; a
restart may then send one duplicate - the documented trade-off against sending none). A start with the Jen database down no longer reads `daily_summary_sent` through an empty cache:
`_summary_sent_date()` returns `UNKNOWN` until the settings table has been read (`user.settings_ever_loaded()`), and the loop sends nothing until it knows. *The settings cache reload is
single-flight*: one thread reloads (a non-blocking lock; a first-ever load waits for the holder once), everyone else returns the stale cache, and the holder alone moves
`_settings_next_try` - fifty threads during an outage are one connect attempt. *The kea6 pool* has the same throttle as the jen and kea pools (the direct connect outside the lock).
*A failed periodic-job start* is retried after `min(interval, 60 s x 2^(failures-1))` - it advanced `next_due` by a whole interval before the spawn and the failure branch did not put it
back. *Orphan cleanup* no longer skips an empty set: `SUBNET_MAP` / `KEA_SERVERS` are the last APPLIED config, so empty means the last subnet or server was removed; the gate is whether a config
has been applied at all (`extensions.cfg`). *The config lock* turns every flock failure into `ConfigFileLocked` with the errno, and names the DIRECTORY (not a lock file to chown) when the
file could not be created.

**`read_log` chooses the newest complete exchange across servers (v5.68.0-beta.22, Q157).** It broke at the first server in order (HA-active first) whose exchange was complete and never compared
times across servers, so after a failover the old active's older exchange beat the standby's newer one. It now collects the complete exchange of every reachable server and takes the newest by
its last line corrected by `_clock_offset_s` - ordered only when BOTH offsets are known; within `CLOCK_TIE_S` (5 s) or with an offset unknown, the first in `_evidence_servers` order wins, and the
view carries `also_seen_on` (names), shown on the Explain tab as "another server also logged this client at about the same time". Incomplete exchanges stay the fallback only when no server has
a complete one, and fields are never mixed across transactions. The IP map follows the same rule as every subnet surface: a user who may see no subnet at all gets "no subnet you can see" and
nothing is queried (it used to fall back to the first configured subnet; found by the grep for the old spelling), and the authorization matrix has the cell.

**The Problems inbox caps what a log can add (v5.68.0-beta.21, Q156).** A group is keyed by (kind, client, address, subnet), so a thousand-line tail of declines from
spoofed MACs and requested addresses added up to a thousand rows per sweep, kept 30 days; `MAX_DB_ROWS` bounds only the two lease-database kinds. At most
`MAX_NEW_KEYS_PER_SWEEP` (200) NEW keys are recorded per server per sweep (`_cap_new_keys`: a key that already has a row always updates; of the new ones the newest
`last_ts` are kept); the rest are counted in `summary["dropped_keys"]`, logged once per sweep and stored (`client_problems_dropped`) for the Problems sweep Health row,
which warns "N problem keys dropped last sweep - a NAK storm?" until a sweep drops nothing.

**The Problems sweep records whether it can read.** Per SSH-configured server it keeps the last successful read, the last error and the
count of misses in a row (settings keys `client_problems_read:`, `_err:`, `_miss:<id>`) and its own last run (`client_problems_swept`); the Health
Center row `problems_sweep` fails after `MISS_LIMIT` (6) misses - thirty minutes - or when the sweep itself has not run for that long, and reads
only these records, never SSH.

### 6.2 Recovery bundle (v5.44.0)

`jen/services/recovery.py` builds a single encrypted archive
(`jen-recovery-<host>-<ts>.tar.enc`) that a new install can restore from
via `sudo ./install.sh --restore <bundle>` — see the admin guide's
"Recover Jen on a new machine" runbook for the operator-facing flow. The
payload is deliberately simple: a plain uncompressed tar of the members
below, encrypted with a key derived from an operator-supplied passphrase
via Scrypt (N=2^15, r=8, p=1) — no key material is stored anywhere;
losing the passphrase loses the bundle. A corrupted or edited bundle
fails the same way a wrong passphrase does — the readers deliberately
never distinguish the two, to avoid leaking which guess was closer.

*Two envelope formats, both readable (v5.65.0).* `JENREC1` — `MAGIC ||
salt || nonce || AES-GCM(whole tar)`, `MAGIC` as the associated data —
is one AEAD message, so writer and reader each hold the bundle in memory
(peak about 3x its size, hence its 200 MB cap, which `encrypt()` still
enforces before key derivation). The export route now writes `JENREC2`,
a chunked AES-GCM stream, so a bundle is never in memory on either side:

```
header  = "JENREC2"(7) | version(1) | salt(16) | chunk_size(4, BE) | nonce_prefix(8)   (36 bytes)
chunk n = AES-GCM(key, nonce = nonce_prefix | n(4, BE),
                  plaintext = chunk_size bytes of the tar (the last chunk: the tail + an 8-byte
                              BE trailer holding the total tar length),
                  AAD = header | n(4, BE) | is_last(1))
```

The counter and `is_last` are authenticated, and so is the header (salt,
nonce prefix, chunk size) through the AAD, so a chunk cannot be dropped,
duplicated, reordered, truncated off the end, appended after, or moved
into another bundle without a tag failing. The reader never trusts a
length or a flag it has not authenticated: it decides "is this the last
chunk" from EOF and the AAD makes a wrong guess fail; it refuses a chunk
size outside 4 KiB–64 MiB before allocating anything; and on the first
failure of any kind it truncates what it had written and raises the same
`BadPassphrase` as a wrong passphrase. Chunks are 4 MB, so writer and
reader hold about two chunks: `build_stream()` writes tar entries
straight into the cipher (files are handed over as paths and read in
small pieces), `decrypt_stream()` writes plaintext to a scratch file
that `restore.py` extracts from and deletes. The cap is now 2 GB of tar,
checked against the file sizes before anything is written and again by
the running total. `restore.py` detects the format by magic
(`decrypt_any()`); its extract and rollback paths copy files in 1 MiB
reads rather than reading each whole. The database dump inside the bundle
was still assembled in memory by `dbexport` until v5.66.0-beta.4 (Q106):
`dbexport.write_jen_export()` now streams it, one row at a time from a
server-side cursor, straight to a 0600 temp file beside the bundle's own —
`audit_log` ("can be large") no longer means holding the whole table (and
a second, `json.dumps`'d copy of it) in memory just to build the export.
The RESTORE side is the one that still holds the whole document at once
(`gzip.decompress` + `json.loads` of the entire export) — a streaming
IMPORTER would need a line-delimited format, a bigger change left out of
this Q on purpose — so the recovery manifest now records the export's
uncompressed size and row count, and `jen.tools.restore` checks that,
times a measured (not guessed — `tests/test_dbexport_streaming.py`)
memory factor, against `/proc/meminfo`'s `MemAvailable` BEFORE it stops
or touches anything, refusing rather than risking an OOM kill mid-import.

**The bundle is everything in §6.1's `/etc/jen/` row and most of
`/var/lib/jen/`, in the clear once decrypted — it is explicitly NOT
redacted.** That is the whole point (a partial bundle can't reconstruct
a working install), but it means the file is exactly as sensitive as
`/etc/jen` itself: `jen.config` (every DB, Kea Control Agent, and OIDC
credential Jen holds), the MFA encryption key (§3.6 — without it, every
stored TOTP secret and passkey the export/import cycle otherwise
survives becomes permanently unreadable), the Jen-managed Kea CA and
Jen's own HTTPS key if configured (§3.12), and the SSH keypair used for
every Kea host (§3.2). Alongside those: a full `write_jen_export()` of
every `jen_db` table AND every table any installed plugin owns (§3.16 —
`dbexport.export_tables()`, not just the fixed core set; optionally minus
`audit_log` — "without audit history" on the bundle form), and
`/var/lib/jen` content minus `backups/` (redundant
with the fresh export just taken) and the plugin-code trees under
`plugins-installed`/legacy `plugins/` (§3.10) — a restore re-registers
installed plugins by id/version and leaves fetching their code to the
existing registry-install path, the same trust boundary as §3.7, rather
than smuggling arbitrary plugin code through the bundle. The export
route requires superadmin plus step-up re-authentication
(`recent_auth_required`, same gate as other high-sensitivity actions)
and is audited (`RECOVERY_BUNDLE_EXPORT`); the page itself carries an
explicit non-redaction warning rather than relying on an operator to
infer it.

Restore (`jen/tools/restore.py`, invoked by `install.sh --restore`) runs
as a standalone script against an already-`install.sh`'d box — it never
sets up the venv, systemd unit, or sudoers grant, and it never touches a
Kea host directly (a bundled `kea-configs/*.json` is a reference copy
only). It refuses outright — before writing anything — if the bundle's
Jen MAJOR doesn't match the target install's, or if a Kea server named
in the bundle's own (not-yet-installed) `jen.config` is reachable right
now and running a different Kea MAJOR than the manifest recorded at
export time; an unreachable server only warns, since Kea may simply not
be up yet during a recovery. Restored `/etc/jen` files keep the mode
`§6.1` already specifies (`0600`) and take on whatever ownership already
exists at the destination, rather than the script guessing a service
username.

Restore is a lifecycle, not just a write (v5.49.0-beta.4): stop the service
if it is a running systemd unit, snapshot `/etc/jen`, the content directory and
the database to `<content>/backups/pre-restore-<ts>/`, apply, start, poll the
unauthenticated `/api/v1/health`, and roll the snapshot back on any exception
or a failed health-check (`--rollback <dir>` repeats it by hand; `--no-stop`
skips the service control). `systemctl` is run with list arguments from the
installer's own root context — the same "installer run via sudo" boundary as
every other `install.sh` mode, so it adds no sudoers line.

## 7. Known gaps (as of this writing)

Documenting these here rather than letting them go unstated:

- **The Health Center (`/health-center`, v5.12.0) is deliberately
  read-only and does no SSH at render time.** Every check runs against
  the Kea HTTP API, the two databases, local files, or state Jen already
  persisted — never a live SSH command to a Kea host. This is what makes
  it safe for a `viewer` to open and safe to poll. It surfaces problems
  and links to the page that fixes them; it does not fix anything itself.
- **No DNS/BIND9 management.** Jen is DHCP-only.
- **No professional external security audit.** See `SECURITY.md` for
  the honest framing of what level of scrutiny this project has
  actually had.
- **The deployed application tree can no longer accrete stale files
  (v5.14.0).** Each release is a fresh directory built from that
  tarball's contents and switched in with one symlink flip, so a file
  dropped from a later release is simply absent from that release's
  `app/`. The *source repository* can still quietly carry a file that no
  clean-checkout tarball ever had (discovered in the v4.4.14 cleanup:
  the retired `jen.py` monolith and some relocated `docs/` files had
  persisted in the real repo for releases). The mitigation for that is
  still to periodically diff the published GitHub archive
  (`github.com/<repo>/archive/refs/tags/vX.Y.Z.tar.gz`) against the
  working tree that built it.
