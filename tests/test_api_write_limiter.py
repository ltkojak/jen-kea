"""
tests/test_api_write_limiter.py
──────────────────────────────────
v5.65.10 (Q99 j) — the per-key write limiter is mutated by every request thread (`--threads N`), so its
read-filter-append runs under a lock. The count must be exact under contention, and a malformed write
still counts (by design: the budget is on calls).
"""

import threading

from jen.services import api_auth


def test_the_limit_is_exact_under_contention(monkeypatch):
    monkeypatch.setattr(api_auth, "WRITE_RATE_PER_MINUTE", 50)
    api_auth._write_hits.clear()
    results = []

    def hammer():
        for _ in range(20):
            results.append(api_auth.write_rate_limited("k-contended"))

    threads = [threading.Thread(target=hammer) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    api_auth._write_hits.clear()
    assert len(results) == 400
    assert results.count(False) == 50 and results.count(True) == 350


def test_one_keys_budget_is_not_anothers(monkeypatch):
    monkeypatch.setattr(api_auth, "WRITE_RATE_PER_MINUTE", 2)
    api_auth._write_hits.clear()
    assert [api_auth.write_rate_limited("a") for _ in range(3)] == [False, False, True]
    assert api_auth.write_rate_limited("b") is False
    api_auth._write_hits.clear()


def test_the_lock_exists_and_guards_the_function():
    import inspect

    assert isinstance(api_auth._write_lock, type(threading.Lock()))
    assert "with _write_lock" in inspect.getsource(api_auth.write_rate_limited)
