# Adversarial review methodology

Jen's adversarial review methodology lives in **[`docs/RELEASE_AUDIT.md`](RELEASE_AUDIT.md)** - one document, so that the method has one definition. Its companion is
**[`docs/SAFETY_INVARIANTS.md`](SAFETY_INVARIANTS.md)**: the methodology says how to investigate a release; the invariants say what Jen must never violate, each with the choke point
that enforces it and the tests that fail when it breaks (`tests/test_safety_invariants.py` parses it).

Section map of `RELEASE_AUDIT.md`:

- **The seven steps (first pass)** - the author's own audit of a release candidate's diff, steps (a)-(g), then the rules learned since: (h)-(m) the adversarial second pass's questions,
  (n) the credential matrix, (p) a classification is a row everywhere, (q) a module's inputs are its worlds, a file's states include its purpose, a preflight proves by doing, the terminal check.
- **The second pass (adversarial)** and **The second pass, as the prompt** - the independent pass the author runs as a subagent before the release commit, verbatim.
- **The pre-reviewer executing pass** - every tag, two independent agents, the whole module by `git blame`, every verdict against a real oracle, values enumerated not only classes;
  and the exit rule for promotion (CLAUDE.md rule 11).
- **What the reviewer does** - the external reviewer's written method compared and folded in: (r) defeat the fix, evidence level as a second attribute, severity under the supported
  contract, the five matrices, archive verification, test-count labelling, the promotion gate.
- **The output** - the chart: every finding confirmed or refuted with `file:line`, by source, with its evidence level.

The lessons that produced these rules are kept by the maintainer outside the repository (`LESSONS.md`, git-ignored) and are quoted into this document as they become rules.
