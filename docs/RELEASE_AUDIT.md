# Auditing a release before a reviewer sees it

Every beta of investigation logging from 5.68.0-beta.21 to -28 went to an outside reviewer and came back with a defect that was a *sequence* nobody had named. This is the audit that is run on a
release candidate's diff **before** the tarball goes out, so the sequences are found by us. It is one pass of Fable's own time on the branch (no Sonnet round trip), then a second,
independent adversarial pass whose findings are reconciled against the first. The rules it checks are in [SAFETY_INVARIANTS.md](SAFETY_INVARIANTS.md); the audits that already run in CI are in
`tests/test_invariant_sweeps.py` (S1-S10), `tests/test_investigation_model.py` (the walk) and `tests/test_identity_guard.py`.

Set `PREV` to the previous release tag and `HEAD` to the candidate.

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
(run it). Read docs/RELEASE_AUDIT.md first and apply its steps (h)-(n). Read the WHOLE diff, then the CURRENT text of every changed function in full - never the hunk alone.
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

## The output

The chart Fable already produces - each finding **confirmed** or **refuted** with `file:line` - plus the registry ids touched, with the second pass's findings marked by source. A release goes to a reviewer
when the first pass is clean, the second pass has no unreconciled finding, and (e) is green.
