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

## The output

The chart Fable already produces - each finding **confirmed** or **refuted** with `file:line` - plus the registry ids touched, with the second pass's findings marked by source. A release goes to a reviewer
when the first pass is clean, the second pass has no unreconciled finding, and (e) is green.
