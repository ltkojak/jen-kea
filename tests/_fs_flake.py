"""
tests/_fs_flake.py
──────────────────
v5.69.0-beta.20 (Q189) - TEST HELPER ONLY. On Windows an indexer or a virus scanner can hold a file that was just read or written for a few milliseconds, and an `os.replace` over it raises
PermissionError (a sharing violation). Linux has no such thing. The tests that drive the REAL `commit_file_set` over real temporary certificate files (`test_kea_tls_rotation`,
`test_direct_socket_lock`) read more files than they used to (Jen's record of what a host holds is read before every operation), so the platform's flake showed up there. This retries a
PermissionError a few times so a flake of the platform is not mistaken for a failure the test injected on purpose. The product's `commit_file_set` has no such retry and must not: a refusal to
replace is a real failure there.
"""

import os
import time

import pytest


def retrying_replace(real):
    def call(src, dst, *a, **k):
        for attempt in range(8):
            try:
                return real(src, dst, *a, **k)
            except PermissionError:
                if attempt == 7:
                    raise
                time.sleep(0.05)

    return call


@pytest.fixture(autouse=True)
def retry_transient_replace(monkeypatch):
    monkeypatch.setattr(os, "replace", retrying_replace(os.replace))
    yield
