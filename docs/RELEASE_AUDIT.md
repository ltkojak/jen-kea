# Auditing a release before a reviewer sees it

Every beta of investigation logging from 5.68.0-beta.21 to -28 went to an outside reviewer and came back with a defect that was a *sequence* nobody had named. This is the audit that is run on a
release candidate's diff **before** the tarball goes out, so the sequences are found by us. It is one pass of Fable's own time on the branch (no Sonnet round trip), then a second,
independent adversarial pass whose findings are reconciled against the first. The rules it checks are in [SAFETY_INVARIANTS.md](SAFETY_INVARIANTS.md); the audits that already run in CI are in
`tests/test_invariant_sweeps.py` (S1-S10), `tests/test_investigation_model.py` (the walk) and `tests/test_identity_guard.py`.

Set `PREV` to the previous release tag and `HEAD` to the candidate.

> **This document is Jen's adversarial review methodology** - how a release is investigated before and after it goes to a reviewer. Its companion is `docs/SAFETY_INVARIANTS.md`, the
> list of what Jen must never violate, each entry naming the choke point that enforces it and the tests that fail when it breaks. The methodology says HOW to look; the invariants say WHAT must
> hold. `docs/ADVERSARIAL_REVIEW_METHODOLOGY.md` is a pointer here, so that the name a reviewer expects resolves to one definition. (Adopted as the single methodology document 2026-10-24;
> the reviewer's own written method was compared against it the same day and the differences folded in below under "What the reviewer does".)

## The seven steps (first pass)

**(a) Read the diff in full.** Every changed function, not the summary.
```bash
git diff "$PREV"..HEAD --stat
git diff "$PREV"..HEAD -- jen/ jen-kea-helper install.sh tools/ templates/
```

**(b) Every new state, flag or field is a definition.** For each one, find every reader AND every writer of the object it lives on, and trace what the NEXT sweep, scheduler tick or page load does with
it (a state that nothing reads is a bug, a state that one reader forgot is the next review's finding).
```bash
git diff "$PREV"..HEAD -U0 | grep -E '^\+.*(entry\[|entry\.get\(|\["[a-z_]+"\] *=)' | sort -u
grep -rn "<the new key>" jen/ plugins/ templates/ tests/
```

**(c) Every new guard names its choke point.** Say which single function every write of the guarded thing ends in. If the answer is a list of callers, the guard is wrong (IDENT-001): move it to the
function the writes pass through, and add the whole-tree source test.
```bash
grep -rn "register_identity_guard\|investigation_writer\|file_write_refusal" jen/
```

**(d) Every call sequence, four cases.** For each new or changed multi-step operation: the *lost-reply* case (applied, no acknowledgement), the *silent* case (the peer does not answer), the *database-failed-
at-this-write* case, and the *reconfigured-mid-request* case (the settings changed between the check and the act).

**(e) Run the machines.**
```bash
JEN_MODEL_SEEDS=500 py -m pytest --noconftest tests/test_investigation_model.py -q -p no:cacheprovider
py -m pytest --noconftest tests/test_safety_invariants.py tests/test_invariant_sweeps.py -q -p no:cacheprovider
py -m ruff check . && py -m ruff format --check .
py -m pytest --collect-only -q          # must exit 0
```
A defect the walk finds is fixed and its sequence pinned by name beside it (`TestWhatTheWalkFound`); a new operation, state or fault is added to the walk in the same commit.

**(f) The six layers.** For each contract the release states, where is it true in: *live* (the running thing), *persisted* (what is stored), *derived* (what is computed from it), *delivered* (what a person or
channel was told), *restored* (after a recovery or restart), *exported* (backups, API, bundles) - and which test says so.

**(g) The registry.** List the ids in `docs/SAFETY_INVARIANTS.md` the release touches and confirm each still has its test (`test_safety_invariants.py` proves the references resolve). A new rule gets
an entry in the commit that adds its test.
```bash
grep -n "^### " docs/SAFETY_INVARIANTS.md
```

**(n) The credential matrix (v5.69.0-beta.11, Q180).** For any change under `jen/config.py`, `jen/services/credentials.py`, `kea._endpoint_for`, the settings forms or the setup wizard: the new
shape is a ROW of `tests/test_credential_destinations.py` BEFORE the fix (the parser as it was, the mutation as the route makes it through `mutate(..., typed=...)`, the expected `resolve(after)` per
endpoint, and whether the write is refused). A P1 or P2 the second pass finds in this class is handled in this order, and never by guarding a form: the row that fails; the fix in
`credentials.resolve` or `AppConfig._write_parser`; the registry line (CRED-004 / RBAC-004); the row green. Ask of every endpoint a change touches: which secret does `resolve` give it, from where, and
what does `destination_view` say about who may move it.

**An exemption is a row too (Q182).** An exemption in `credentials.move_refusal` (every `continue`), `credentials._user`, `credentials._inherit` or a route's `typed=` set is a row of the matrix that
uses it for a DIFFERENT purpose, BEFORE the exemption is code: the mode-switch skip was the whole flip until a review flipped the mode and moved the address in the same save (Q181's skip was
written for "direct -> CA re-points the daemons", and was used for "this daemon now has an address on another host"). Each `continue` in `move_refusal` carries `# row: <name>` and
`tests/test_credential_destinations.py::test_every_continue_in_move_refusal_names_the_row_that_uses_it` fails on one that names no row of the matrix. A route types the ONE endpoint it repoints, never the
server's three. Ask of every new exemption: what ELSE does this skip let through, and where is the row that says it is still refused? The row must REACH the `continue` that cites it
(`test_the_row_a_continue_names_reaches_that_continue` runs each through an instrumented `move_refusal`): a row that exists but is refused earlier proves nothing.

**The second pass EXECUTES (Q183).** The passes that found beta.12's findings, beta.13's and beta.14's did not read the credential rule, they ran it: the real writer, resolver and transport on
crafted configurations. That is now the procedure, and its instrument is `tests/probe/credential_probe.py` (a temporary jen.config, the real `AppConfig.mutate` / `write_values` /
`preflight_identity_change`, `kea_command` with a captured `post`, `materialise`, `config_merge.credential_refusal`; one function per scenario returning what it observed;
`tests/test_credential_probe.py` asserts them all). The second pass on any change to the credential rule EXECUTES: it extends `tests/probe/credential_probe.py` with one scenario per
exemption used for a purpose its comment does not state, runs it, and reports each finding with the executed input and the observed output; a finding reported from reading alone is a
hypothesis.

**(o) The inventory and the record (v5.69.0-beta.20, Q189).** Three questions, asked of every operation that acts on more than one host or keeps a local record of what a host holds.
1. **The SOURCE of the target set.** For every multi-host operation, name where its targets come from and EXECUTE the empty and the unreadable source. The rotation's targets came from a listing of local
   copy files (v5.29.0); a missing copy dropped a live endpoint and an unlistable directory read as "nothing to rotate" - a rotation that 'succeeded' cut Jen off from every daemon. Targets come from the
   configuration (what Jen dials); a record missing for one of them is a refusal.
2. **The record equals what the host was given, byte for byte, checked after EVERY scenario.** For every local record of remote state, an invariant over the harness's fake host (`Lab.check_invariants`, T1-T5
   in `tests/test_kea_tls_rotation.py`) - not an assertion someone thought to write. Q188 said ".prev is the host's truth" and let `commit_file_set` make `.prev` from the LIVE pair on the failing path.
3. **A register item is executed before it is registered.** An entry dismissed from reading is a hypothesis too: Q188's register item (f) ("the pre-rotation pair, same CA") was dismissed from reading and,
   executed, was the staged-CA pair - the opposite of what the marker promised. The register says which of its items were executed.

**(p) A classification is a row, everywhere (v5.69.0-beta.21, Q190).** Step (n) generalised from the credential rule. Any code that sorts targets into acted-on / left-alone / refused has a row
per CLASS, written before the classifier, and the left-alone class is proved by the invariant over the HOST (the daemon's own answer, its files, its trust relationship before and after), never by
the classifier's own word: beta.20's `_trust_is_jens` was a global path-string switch added by a second-pass fix, it made every Jen-issued endpoint 'the administrator's', and the invariant that
should have caught it only looked at a set the tests populated. Four rules follow.
1. **The second pass's FIX is a Q item.** A fixup that adds a class, an exemption, a switch or a short-circuit is written in the report as a row BEFORE it is code, and the release report lists each
   fixup with its row. A fixup is also a change (step (j)): the full harness runs after it so the invariants judge it.
2. **An invariant has no knob.** A `check_invariants` ranges over the simulated world; a test may not narrow it (no `managed` set, no `discard`). It is RELATIVE where a classification would be needed
   (a daemon that answered before answers after, or an incident names it), and judged by what the host holds, not by what Jen's files say.
3. **A path string is not an identity.** Whose CA a trust path is, which file is Jen's, what an address contains - are decided from the certificate or the parsed value, in ONE function, and a sweep
   (S13, S14) refuses the comparison anywhere else.
4. **An invariant needs its WORLDS (Q191).** Every configured input to an identity or a trust decision is enumerated as a SHAPE LIST in the Q (the CA bundle: Jen's file / alias / copy / bundle / other /
   empty / unreadable; the client pair: none / Jen's file / alias / copy / other / unreadable), and the harness builds one world per shape and crosses the lists: an invariant fires only in a world that has the
   shape, and beta.21's P1 lived in the one world no shipped test built (a client certificate that was a copy). A new input to the identity is a new list in the same commit.

**(q) A module's inputs are its worlds (v5.69.0-beta.23, Q192).** Step (p)4 for the code a diff did NOT touch. Three reviews in a row found v5.29 TLS functions (`ensure_ca`, `ca_present`, `client_cert_ok`)
by reading the whole archive while our own passes executed the diff. For a module that reads files or configuration into a decision, the Q lists EVERY input (each file, each configured path, each marker) and
EVERY state it can be in (absent, present-valid, malformed, unreadable, mismatched with its partner, alias, byte-copy, issued by an earlier CA, issued by another CA), and a test GENERATES the worlds - whether
or not the diff touched the module - and runs every ordinary action in each with the invariants after it. The enumeration is tied to the code (a test lists the module's path functions, suffixes, configured
inputs and reading functions and fails on one that is not a row), and the second pass executes the module's OLD functions in the worlds, not only the new ones. An invariant that a world BREAKS before any
action is made relative to the world (the world is the input; Health and the refusal say so) - never loosened for the action.

**(q), continued (v5.69.0-beta.25, Q194).** Two rules the matrix of beta.23 and the sentences of beta.24 each missed. **A file's states include its PURPOSE.** A certificate, a key, a config value is
enumerated by what it is FOR (CA / client / server; may it sign; is it valid now; does its signature verify) and not only by whether it parses and pairs: Q192's list was syntactic, and a `ca=False` pair, an
expired CA and a tampered self-signature were all `ok`. Every world list carries a `semantic` row set - the certificate parses, the key is its key, and it is wrong in ONE named way - for the live AND the
prepared copy. **A preflight proves by doing.** A check that guards a remote change performs the local action it guards (create the directory, write the file, take the lock) rather than inferring it, and
runs on EVERY path that will need it - Q193's "a directory that is not there yet is writable" was an inference that the real create contradicted under a read-only parent, and it was asked only when
listing raised. The second pass executes the storage worlds with the filesystem changed BETWEEN the preflight and the commit.

**(q), the terminal check (v5.69.0-beta.27, Q196).** When a review names the N-th property of an artifact that a verifier judges, the fix is the VERIFIER, not the N-th property. Since beta.19 the reviewer
found, one release at a time, the next semantic property of a certificate `ca_identity` did not check (the pair, then the purpose, then the Extended Key Usage), and each time the next Q specified the
next extension; X.509 has dozens (name constraints, policy constraints, path length, algorithm strength ...) and listing them is unbounded. Ask what TOOL the reviewer used to prove the finding
(`openssl verify -purpose sslserver`) and make that tool - or its library equivalent (`cryptography.x509.verification`) - the product's check, with the structural checks kept only for the sentence.
The second pass then executes every constraint the library can express, cross-checked against the reviewer's tool where it exists, and a disagreement between the two is a warning the operator sees.

## The second pass (adversarial)

Run as a separate subagent on the same diff, with the reviewer's method as its prompt, so that it does not inherit the first pass's assumptions. Its findings are reconciled against the first pass's
before anything goes out, and the final chart marks each finding by source.

**(h) Every entry point of each mutation the release touches.** The Settings UI, the REST API, a plugin route, the installer, a helper op, the direct-socket pages, config import, config-history
restore, recovery, the command line. Enumerate them from the tree (`grep` for the writer, not from memory) and check the invariant at each.

**(i) A failure matrix per multi-step operation.** Inject a failure: before the start; after authorization; after the first mutation; after the remote request is sent; after the remote commits but
before its reply; after local persistence; after remote persistence; during compensation; during the audit write; during final reporting. For each cell answer five questions: is the state known; is a
side effect outstanding; is responsibility kept (does something still own putting it right); is the user told the truth; is Health told.

**(j) Every fix is a change.** For every fix in the release: does it introduce a new failure path? (The question that would have caught the revert that itself could fail, and the rebuild that
wrote half a record.)

**(k) Interleavings.** List every check-then-mutate in the diff and name the concurrent operation that could change the checked state between the two - a second request, the sweep, the installer, a person
with an editor.

**(l) The negative questions.** Can the forbidden operation succeed through another route? Can an error become a success response? Can malformed or unavailable state read as safe? Can a partial
transaction become invisible? (`tests/test_invariant_sweeps.py` S10 lists the `except` sites on security and safety paths that return an empty value; a new one has to be argued onto its allowlist.)

**(m) Prove or keep apart.** A finding is *proved* when it has a `file:line`, the invariant it violates and the triggering sequence, ideally as a failing test. Anything less is a *hypothesis*, kept in a separate list
and never reported as a defect.

## The second pass, as the prompt

The author of a release candidate runs the second pass THEMSELVES, as a subagent (the Agent tool), after the code commits are pushed and CI is green, and before the release commit.
The prompt is below, verbatim; replace `<repo root>` and `<previous tag>` and change nothing else (the method is the prompt - a paraphrase loses the questions).

```
You are an independent adversarial release reviewer for Jen at <repo root>. Read-only: change no file; report findings only. Scope: `git diff <previous tag>..HEAD`
(run it). Read docs/RELEASE_AUDIT.md first and apply its steps (h)-(q). Read the WHOLE diff, then the CURRENT text of every changed function in full - never the hunk alone.
For every piece of evidence, guard or check the diff adds, ask what else could produce the same observation without the thing it is taken to prove; for every
check-then-act, name what could change between the two; for every except, say whether a failure reads as success; for every new state or field, find every reader and
writer; for every multi-step operation, inject a failure at each step and say what state is left and whether it is visible. Compare what the tests pin with what the
code does: name a test that pins a weak rule as desired and a behaviour no test asserts. Output a numbered list, most severe first, each with: severity (P1 = a scoped
or lower-role account reads or changes data it may not, auth or CSRF bypass, root reads or writes outside a wall, data loss, a daemon left in a wrong state, a loop
that dies silently, a 500 any user can trigger with ordinary input; P2 = wrong behaviour a user sees, a failure read as success, inconsistent answers, a missing
validation with no exploit; P3 = nit), the exact file:line in the CURRENT tree, a concrete triggering sequence, and whether a test pins the current behaviour. Then a
short list of what you checked and found correct. Keep hypotheses in a separate list. No padding: say so when nothing is at a severity.
On any change to the credential rule (credentials.py, AppConfig._write_parser, kea._endpoint_for, the connection forms, the wizard, the installer's merge) the pass EXECUTES: run
`py tests/probe/credential_probe.py`, extend it with one scenario per exemption used for a purpose its comment does not state, and report each finding with the executed input and the
observed output - a finding reported from reading alone is a hypothesis.
```

The author's rule: a P1 or P2 from the second pass is fixed in a fixup commit before the release commit (and CI is green again); a P3 is fixed when it is a one-liner, else added
to the register; the release report names the second pass's findings by number and says what was done with each. A finding that turns out wrong is said to be wrong, with the
`file:line` that refutes it - it is not silently dropped.

## The pre-reviewer executing pass (Fable, every tag)

Written after 5.69.0-beta.1…27 (2026-10-24). Twenty-seven betas for one minor release came from a loop with no exit condition - "a P1 in the review means another beta" - and from
passes that executed the DIFF while the reviewer read the whole archive and peeled one old module (`jen/services/kea_tls.py`, written in a day as v5.29.0) one layer per beta. This is
the procedure that replaces it. It runs on every tagged beta BEFORE the archive goes to the reviewer; a tag is never sent without it.

1. **Two independent agents, not one.** The first runs the executing harness lineage (the probe, the Lab, the fake daemons under the real transport and probe boundaries) extended for
   the Q. The second gets no harness, no earlier report and no hypothesis: a fresh adversarial read of every module the diff touched, every function, then its own execution. Two readers
   who do not share a starting point; the author's read is a third.
2. **The must-cover list is the MODULE, not the diff.** `git blame` every function of each module the diff touched - the ones older than the round included - and make each a named
   cell for both agents. The reviewer has never found a P1 outside the modules a diff touched; it has found most of them in the untouched functions of those modules.
3. **Every verdict is cross-checked against a real oracle, the ACCEPTED verdicts included.** A real TLS stack, `openssl verify`, the real writer, the real daemon's answer - never the
   route's words, never the fake's opinion. Worlds are enumerated from the library's or the format's own classes (every extension class, every file state, every topology the config can
   express), never from a list someone wrote: a list is the author's imagination, and the author's imagination is what the reviewer gets past.
4. **The Q's reported deviations and the author's own read are cells in the brief,** executed, not accepted.
5. **The two reports are reconciled against each other and the tree before anything is said:** each finding confirmed or refuted with `file:line`, by source; a clean pass is NECESSARY,
   not sufficient - the reviewer still reads.
6. **A review's findings become ONE Q,** with the class the findings belong to named and closed (see "the terminal check" under (q)), never one beta per finding.
7. **Enumerate VALUES, not only classes.** An extension class is built with EVERY distinct value family it has, never once with a default value. The first run of this pass (5.69.0-beta.27, two
   agents, ~1 400 cells over 135 CA shapes enumerated from the library's own extension classes) had no row for `anyExtendedKeyUsage` alone or for an AuthorityKeyIdentifier that names another key,
   because each class was built once with a default value - and both were shapes the daemon's library rejects and Jen's verifier accepted. `tests/_tls_worlds.py::EXTENSION_VALUE_FAMILIES` is the
   list for a CA certificate (the AKI and EKU families have at least three rows each, a test says so), and `TestTheValueFamiliesAgainstTheRealCli` runs every row against `openssl verify`: the one
   property that matters is that **a CA Jen calls healthy is never one the CLI rejects**; every shape where Jen is stricter is in the admin guide's table, and a new disagreement fails a test.
8. **When the two agents disagree, an independent reproduction decides** - never the more confident report and never a vote. In beta.27 the second agent found two shapes Jen called healthy while both
   real stacks rejected them; the first agent's table had no row for either, so its "the P1 class is empty" was refuted for those two and confirmed otherwise. The author executed both against
   `openssl verify` and a live handshake, and that, not either report, settled it.

**The exit rule.** Promotion is judged against Jen's threat model (`docs/ARCHITECTURE.md`): a P1 in a supported configuration blocks and gets a Q; a finding that requires the operator to
have hand-corrupted Jen's own identity or state files is a P2 in this model - registered, shipped as a stable PATCH if it proves to matter, never another beta. A finding after promotion
ships as `X.Y.Z+1` on the stable channel. The maintainer says "promote"; nothing about a promotion is written before that word.

## What the reviewer does (folded in 2026-10-24)

The external reviewer wrote down its own method after 5.69.0-beta.26. Compared against this document section by section, most of it was already here (the delta, the whole-archive read,
the complete-path trace, the failure matrix, the independent oracle, the "do not trust the changelog" rule). The differences that explain its streak of findings from beta.19 to beta.27, and
the parts of its report format we did not have, are adopted here as rules of both passes.

**(r) Defeat the fix.** For every fixup in a release and every previously reported finding, do not stop at confirming the guard exists: take the ORIGINAL reproduction and vary it through
the matrices below - an absent value, an empty one, an aliased one, a duplicated one, a contradictory one, the same change through another entry point, the same state after a reload or a
restart - and try to get past the fix with a slightly different input. This single step is where the reviewer found beta.20 (a path-string alias of the fixed check), beta.22 (the client half of
a fixed identity), beta.24 (the purpose of a fixed pair), beta.26 (the EKU of a fixed purpose). The second pass runs (r) on every fixup it or the author made; the pre-reviewer pass runs it on
every finding the previous review named.

**Evidence level is a second attribute on every finding, separate from severity.** `Reproduced` (the production function executed, the failure observed), `Integration-confirmed` (the whole
route executed), `Source-confirmed` (path and defect established by reading, not exercised), `Environment-dependent` (behaviour established; impact needs a particular deployment),
`Suspected` (a hypothesis). A chart row carries both. A `Suspected` item is never written as a defect, and a `Source-confirmed` one never as a reproduction - this document already said so in
(m); the five names make it checkable.

**Severity reflects realistic consequences under the supported deployment contract** - the reviewer's own words: "Do not automatically label an edge case P1 merely because it involves
cryptography or security-related code", and "A beta may be a strong release candidate even if lower-priority issues remain, provided the outstanding risks are understood, bounded and
explicitly accepted." That is the exit rule under "The pre-reviewer executing pass" and CLAUDE.md rule 11, stated by the reviewer; both sides now hold each other to it. Jen keeps three tiers
(P1 blocks, P2 is wrong behaviour or a dead end, P3 is a nit); a reviewer's P0 is a P1 that is also an incident.

**The matrices, as checklists** (the reviewer's lists, with Jen's stronger rule where it has one):
- *Input state*: absent · empty · normal · malformed · stale · contradictory (inherit selected with an explicit value) · unauthorised · duplicated (two records, one resource) · aliased
  (two paths or names, one resource) · inconsistent (a certificate without its key) · partially updated (remote changed, local not) · concurrent (two writers) · restored (database and
  configuration from different points in time).
- *Role*: anonymous · viewer · scoped admin · unrestricted admin · superadmin · superadmin past the step-up window · an API key · a background or non-interactive context - through the
  UI AND as a direct HTTP request (a hidden button is not a guard).
- *Topology*: one server · several independent servers · an HA pair · the first server unreachable · the second holding the newest evidence · two server ids for one endpoint · two names
  for one host · two daemons on one host · v4-only, v6-only, dual-stack · Control Agent mode, direct-socket mode · mixed authentication and TLS.
- *Certificate*: Jen's rule is stronger than a list - enumerate every extension class the library can build with EVERY distinct value family it has, every key type and curve, the validity
  edges, the name-constraint forms, the identifier mismatches - and judge every one with the library verifier, `openssl verify -purpose`, and a real handshake in both directions (see (q)).
- *Recovery*: inject at preflight · snapshot · local staging · remote file install · remote config write · validation · restart · probe · local commit · incident persistence · cleanup ·
  rollback · rollback restart · recovery verification - and at each ask: what changed before the failure, what should be rolled back, is the previous state still available, can the rollback
  itself fail, can Jen report success, can it be retried, will the next restart understand the state.

**Verify the archive, not only the tree.** Before the first pass on a release candidate: the archive's checksum recorded; `tar -tzf` read for paths outside the tree; `python -m compileall -q
jen plugins`; `bash -n install.sh` (and every shell script the archive ships); the six version spots checked inside the archive. A changelog entry is never evidence that a defect was fixed -
the implementation is the authority.

**Label test counts correctly.** Collected, executed, passed, failed, skipped - five different numbers, named. A statically counted `test_*` is not a passing test; a run under
`--noconftest` is not the suite; a collection failure is reported as such, never as a pass.

**The promotion gate, in the reviewer's terms and ours.** No unresolved P1 that applies under the supported contract; every previously confirmed blocker has a regression test that FAILS
against the vulnerable implementation; the full suite, the migrations, kea-compat and the system failure-injection scenarios green; known P2/P3 explicitly dispositioned (fixed / registered /
patch after promotion); a required test that cannot run is a documented risk decision, never a silently passed gate. The maintainer says "promote".

## The output

The chart Fable already produces - each finding **confirmed** or **refuted** with `file:line` - plus the registry ids touched, with the second pass's findings marked by source. A release goes to a reviewer
when the first pass is clean, the second pass has no unreconciled finding, (e) is green, AND the pre-reviewer executing pass above has reported on the tag.
