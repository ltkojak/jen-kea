"""
tests/test_release_workflow.py
───────────────────────────────
v5.66.0 (Q103) — text assertions on .github/workflows/release.yml, pinning the shape of
the Kea host helper's release-time signing: it never becomes a signature that could be
replayed as the checksum file's own (SHA256SUMS.sig, namespace "jen-release"), and it is
computed against the exact bytes the tag's tarball ships, not the checkout that built it.

v5.66.0-beta.2 (Q104, items e/f/h) — the release job now tests, archives, signs and
extracts release notes from the SAME ref (never a workflow_dispatch's default branch
diverging from the tag it names), the helper's signature is appended INSIDE the tarball
before it's ever gzipped (so a tarball install has it with no separate fetch), and the
release job verifies both signatures it just produced against the tarball's own embedded
RELEASE_SIGNERS before ever creating the release — a release job that signs but never
re-checks its own output could otherwise publish a mis-signed release undetected.

No YAML-semantic test runner exists in this repo for "did step X run before step Y with
argument Z" — this reads the workflow(s) as plain text and checks ordering/content
directly, the way jen-sudoers and the Dockerfile are pinned elsewhere in the suite.
"""

import pathlib

_WORKFLOWS_DIR = pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows"
_RELEASE = _WORKFLOWS_DIR / "release.yml"
_TESTS = _WORKFLOWS_DIR / "tests.yml"
_CI = _WORKFLOWS_DIR / "ci.yml"


def _text():
    return _RELEASE.read_text(encoding="utf-8")


def _tests_text():
    return _TESTS.read_text(encoding="utf-8")


class TestReleaseWorkflowExists:
    def test_file_exists(self):
        assert _RELEASE.is_file()

    def test_no_tabs(self):
        # YAML is indentation-sensitive; a stray tab is a common, easy-to-miss break.
        assert "\t" not in _text()


class TestTagResolvedOnceToOneSHA:
    """v5.66.0-beta.7 (Q109, item d) — a tag name is a mutable pointer. release.yml used to
    resolve it THREE separate times (its own checkout, the called tests.yml's checkout, and
    the git-archive step) via the same textual expression — safe only as long as nothing moved
    the tag in between. A `resolve` job now runs first, resolves the tag to ONE commit SHA via
    `git rev-parse "<tag>^{commit}"`, and every later job/step uses that SHA; the tag name is
    looked at again only once more, immediately before publishing, to refuse a tag that has
    moved since resolution. Invariant: the SHA tested is the SHA archived, signed and
    published."""

    def test_resolve_job_exists_and_runs_before_test_and_release(self):
        text = _text()
        assert "resolve:" in text
        assert text.index("resolve:") < text.index("\n  test:")
        assert text.index("\n  test:") < text.index("\n  release:")

    def test_resolve_job_outputs_sha_and_tag(self):
        text = _text()
        resolve_block = text[text.index("resolve:") : text.index("\n  test:")]
        assert "outputs:" in resolve_block
        assert "sha: ${{ steps.resolve.outputs.sha }}" in resolve_block
        assert "tag: ${{ steps.resolve.outputs.tag }}" in resolve_block

    def test_resolve_step_uses_rev_parse_commit_peel(self):
        text = _text()
        resolve_block = text[text.index("resolve:") : text.index("\n  test:")]
        assert 'git rev-parse "${TAG}^{commit}"' in resolve_block
        assert 'echo "sha=$SHA" >> "$GITHUB_OUTPUT"' in resolve_block

    def test_tests_workflow_call_declares_a_ref_input_defaulting_to_empty(self):
        text = _tests_text()
        assert "workflow_call:" in text
        assert "ref:" in text
        assert "default: ''" in text

    def test_every_checkout_in_tests_workflow_uses_the_ref_input(self):
        text = _tests_text()
        checkouts = text.count("uses: actions/checkout@")
        assert checkouts >= 1
        assert text.count("ref: ${{ inputs.ref || github.ref }}") == checkouts

    def test_ci_workflow_passes_no_ref_and_is_otherwise_untouched(self):
        # ci.yml never needs to pin a ref — github.ref is already the commit it's testing.
        text = _CI.read_text(encoding="utf-8")
        assert "ref:" not in text

    def test_test_job_needs_resolve_and_uses_its_sha(self):
        text = _text()
        test_job_block = text[text.index("\n  test:") : text.index("\n  release:")]
        assert "needs: resolve" in test_job_block
        assert "with:" in test_job_block
        assert "ref: ${{ needs.resolve.outputs.sha }}" in test_job_block

    def test_release_job_needs_resolve_and_test(self):
        text = _text()
        release_start = text.index("\n  release:")
        release_header = text[release_start : text.index("steps:", release_start)]
        assert "needs: [resolve, test]" in release_header

    def test_release_job_checkout_uses_the_resolved_sha(self):
        text = _text()
        checkout_block = text[text.index("\n  release:") : text.index("Extract version info")]
        assert "ref: ${{ needs.resolve.outputs.sha }}" in checkout_block

    def test_archive_uses_the_resolved_sha_not_the_tag_name(self):
        text = _text()
        assert 'git archive --format=tar --prefix=jen/ "${{ needs.resolve.outputs.sha }}"' in text

    def test_tag_is_reresolved_and_compared_immediately_before_publishing(self):
        text = _text()
        assert "Confirm the tag has not moved" in text
        confirm_step = text[text.index("Confirm the tag has not moved") : text.index("Extract release notes")]
        assert 'git rev-parse "${{ needs.resolve.outputs.tag }}^{commit}"' in confirm_step
        assert "exit 1" in confirm_step
        assert text.index("Confirm the tag has not moved") < text.index("Create GitHub Release")

    def test_the_confirm_step_runs_after_both_signatures_are_verified(self):
        text = _text()
        assert text.index("Verify both signatures") < text.index("Confirm the tag has not moved")


class TestKeaHelperSigningStep:
    """v5.66.0 (Q103) — the helper is extracted from the TAG's own tarball (never the
    checkout — the same reason the tarball itself is built from the tag, not HEAD),
    signed under a namespace distinct from the checksum file's, and published as a
    release asset that jen-update-root.py fetches and jen-kea-helper's own `update` op
    later verifies against."""

    def test_helper_is_extracted_from_the_built_tarball_not_the_checkout(self):
        # v5.66.0-beta.2 (Q104, item h) — extracted from the uncompressed .tar now (the
        # signature is appended into it before it's ever gzipped), not the .tar.gz.
        text = _text()
        assert "tar xf jen-v" in text
        assert "jen/jen-kea-helper -O > jen-kea-helper" in text

    def test_extraction_happens_before_signing(self):
        text = _text()
        assert text.index("Extract jen-kea-helper from the tarball") < text.index("Sign the Kea host helper")

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
        helper_step = text[text.index("Sign the Kea host helper") : text.index("Append the helper signature")]
        assert 'key_file="$(mktemp)"' in helper_step
        assert 'chmod 600 "$key_file"' in helper_step
        assert "trap 'rm -f \"$key_file\"' EXIT" in helper_step

    def test_helper_signature_is_published_as_a_release_asset(self):
        text = _text()
        assert "dist/jen-kea-helper.sig" in text

    def test_the_helper_itself_is_also_published_as_a_release_asset(self):
        # v5.66.0-beta.2 (Q104, item b) — the ONE by-hand fallback (_helper_download_command())
        # fetches the helper from this exact release asset, not raw.githubusercontent.com.
        text = _text()
        files_block = text[text.index("files: |") : text.index("draft: false")]
        assert "dist/jen-kea-helper\n" in files_block or files_block.rstrip().endswith("dist/jen-kea-helper")

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
            "dist/jen-kea-helper",
            "dist/jen-kea-helper.sig",
        ]


class TestHelperSignatureAppendedIntoTarball:
    """v5.66.0-beta.2 (Q104, item h) — every tarball install now has jen-kea-helper.sig
    sitting right next to jen-kea-helper, no separate fetch needed (kea_host.py's
    fetch-the-asset path stays, for Docker images built from source instead of the
    tarball)."""

    def test_tar_is_built_uncompressed_first(self):
        # v5.66.0-beta.7 (Q109, item d) — archived from the resolve() job's SHA now, not the
        # tag name; see TestTagResolvedOnceToOneSHA.
        text = _text()
        assert 'git archive --format=tar --prefix=jen/ "${{ needs.resolve.outputs.sha }}"' in text

    def test_the_signature_is_appended_before_gzipping(self):
        text = _text()
        append_step = text[text.index("Append the helper signature") : text.index("Generate checksums")]
        assert "tar --append" in append_step
        assert "jen/jen-kea-helper.sig" in append_step
        assert "gzip" in append_step

    def test_append_step_stages_the_file_root_owned_and_world_readable(self):
        text = _text()
        append_step = text[text.index("Append the helper signature") : text.index("Generate checksums")]
        assert "--owner=0" in append_step
        assert "--group=0" in append_step
        assert "--mode=0644" in append_step

    def test_ordering_is_extract_sign_append_gzip_checksum_sign_verify_release(self):
        text = _text()
        order = [
            "Build tarball",
            "Extract jen-kea-helper from the tarball",
            "Sign the Kea host helper",
            "Append the helper signature into the tarball",
            "Generate checksums",
            "Sign checksums",
            "Verify both signatures before publishing",
            "Extract release notes from CHANGELOG",
            "Create GitHub Release",
        ]
        indices = [text.index(step) for step in order]
        assert indices == sorted(indices)


class TestReleaseVerifiesItsOwnSignatures:
    """v5.66.0-beta.2 (Q104, item f) — signing without ever verifying the result again
    means a broken key, a wrong namespace, or a corrupted intermediate file could publish
    a release that fails on every box that installs it. Verify both signatures against
    the tarball's OWN RELEASE_SIGNERS before "Create GitHub Release" ever runs."""

    def test_signers_are_extracted_from_the_tarballs_own_update_root(self):
        text = _text()
        verify_step = text[text.index("Verify both signatures") : text.index("Extract release notes")]
        assert "jen/jen-update-root.py" in verify_step
        assert "RELEASE_SIGNERS" in verify_step

    def test_both_signatures_are_verified_under_their_own_namespace(self):
        text = _text()
        verify_step = text[text.index("Verify both signatures") : text.index("Extract release notes")]
        assert "-n jen-release" in verify_step
        assert "-n jen-kea-helper" in verify_step
        assert "-s SHA256SUMS.sig" in verify_step
        assert "-s jen-kea-helper.sig" in verify_step

    def test_verification_happens_after_both_signing_steps_and_before_the_release(self):
        text = _text()
        assert text.index("Sign checksums") < text.index("Verify both signatures")
        assert text.index("Verify both signatures") < text.index("Create GitHub Release")

    def test_a_missing_signers_line_fails_the_job(self):
        text = _text()
        verify_step = text[text.index("Verify both signatures") : text.index("Extract release notes")]
        assert "exit 1" in verify_step
