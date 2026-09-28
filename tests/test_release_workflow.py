"""
tests/test_release_workflow.py
───────────────────────────────
v5.66.0 (Q103) — text assertions on .github/workflows/release.yml, pinning the shape of
the Kea host helper's release-time signing: it never becomes a signature that could be
replayed as the checksum file's own (SHA256SUMS.sig, namespace "jen-release"), and it is
computed against the exact bytes the tag's tarball ships, not the checkout that built it.
No YAML-semantic test runner exists in this repo for "did step X run before step Y with
argument Z" — this reads the workflow as plain text and checks ordering/content directly,
the way jen-sudoers and the Dockerfile are pinned elsewhere in the suite.
"""

import pathlib

_WORKFLOW = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"


def _text():
    return _WORKFLOW.read_text(encoding="utf-8")


class TestReleaseWorkflowExists:
    def test_file_exists(self):
        assert _WORKFLOW.is_file()

    def test_no_tabs(self):
        # YAML is indentation-sensitive; a stray tab is a common, easy-to-miss break.
        assert "\t" not in _text()


class TestKeaHelperSigningStep:
    """v5.66.0 (Q103) — the helper is extracted from the TAG's own tarball (never the
    checkout — the same reason the tarball itself is built from the tag, not HEAD),
    signed under a namespace distinct from the checksum file's, and published as a
    release asset that jen-update-root.py fetches and jen-kea-helper's own `update` op
    later verifies against."""

    def test_helper_is_extracted_from_the_built_tarball_not_the_checkout(self):
        text = _text()
        assert "tar xzf jen-v" in text
        assert "jen/jen-kea-helper -O > jen-kea-helper" in text

    def test_extraction_happens_before_signing(self):
        text = _text()
        assert text.index("Extract jen-kea-helper from the tarball") < text.index("Sign the Kea host helper")

    def test_checksums_are_generated_before_the_helper_is_extracted(self):
        # Generate checksums -> Extract jen-kea-helper -> Sign checksums -> Sign the helper:
        # the helper extraction doesn't depend on the checksum step, but keeping it right
        # after "Generate checksums" (both read the freshly-built dist/ tree) is deliberate.
        text = _text()
        assert text.index("Generate checksums") < text.index("Extract jen-kea-helper from the tarball")

    def test_helper_signature_uses_a_distinct_namespace_from_the_checksum_signature(self):
        text = _text()
        assert 'ssh-keygen -Y sign -f "$key_file" -n jen-release SHA256SUMS' in text
        assert 'ssh-keygen -Y sign -f "$key_file" -n jen-kea-helper jen-kea-helper' in text

    def test_both_signing_steps_use_the_same_signing_key_secret(self):
        assert _text().count('printf \'%s\\n\' "${{ secrets.RELEASE_SIGNING_KEY }}" > "$key_file"') == 2

    def test_helper_signing_step_uses_the_same_throwaway_key_file_dance(self):
        """The private key never touches disk longer than the checksum-signing step already
        keeps it for: a fresh 0600 mktemp file, removed by a trap on exit."""
        text = _text()
        helper_step = text[text.index("Sign the Kea host helper") : text.index("Extract release notes")]
        assert 'key_file="$(mktemp)"' in helper_step
        assert 'chmod 600 "$key_file"' in helper_step
        assert "trap 'rm -f \"$key_file\"' EXIT" in helper_step

    def test_helper_signature_is_published_as_a_release_asset(self):
        text = _text()
        assert "dist/jen-kea-helper.sig" in text

    def test_signing_happens_before_the_release_is_created(self):
        text = _text()
        assert text.index("Sign the Kea host helper") < text.index("Create GitHub Release")

    def test_release_assets_carry_every_expected_file_exactly_once(self):
        text = _text()
        files_block = text[text.index("files: |") : text.index("draft: false")]
        lines = [line.strip() for line in files_block.splitlines() if line.strip().startswith("dist/")]
        assert lines == [
            "dist/jen-v${{ steps.version.outputs.version }}.tar.gz",
            "dist/SHA256SUMS",
            "dist/SHA256SUMS.sig",
            "dist/jen-kea-helper.sig",
        ]
