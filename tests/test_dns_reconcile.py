"""
tests/test_dns_reconcile.py
─────────────────────────────
v5.47.0 (Q48) — jen.services.dns_reconcile: pure, no DB, no resolver —
`resolve` is injected so every verdict, the row cap, and a genuinely
timing-out lookup can all be exercised deterministically.
"""

import socket
import time

import pytest

from jen.services import dns_reconcile as dr


def _resolver(responses):
    """`responses` maps fqdn -> the dict `resolve(name, ip)` should
    return, mirroring ddns._run_verify's shape."""

    def resolve(name, ip):
        return responses.get(name, {})

    return resolve


class TestQualify:
    def test_bare_name_gets_suffix_appended(self):
        assert dr._qualify("host1", "lan.example.com") == "host1.lan.example.com"

    def test_already_qualified_name_is_untouched(self):
        assert dr._qualify("host1.lan.example.com", "lan.example.com") == "host1.lan.example.com"

    def test_name_equal_to_suffix_is_untouched(self):
        assert dr._qualify("lan.example.com", "lan.example.com") == "lan.example.com"

    def test_blank_suffix_leaves_name_bare(self):
        assert dr._qualify("host1", "") == "host1"

    def test_trailing_dots_stripped(self):
        assert dr._qualify("host1.", "lan.example.com.") == "host1.lan.example.com"


class TestClassify:
    """Every verdict in dr.VERDICTS, reachable by construction."""

    def test_ok(self):
        observed = {"forward_ips": ["10.0.0.5"], "reverse_name": "host1.lan"}
        assert dr._classify(observed, "10.0.0.5", "host1.lan", set()) == "ok"

    def test_missing_forward(self):
        observed = {"forward_error": "nodename nor servname provided"}
        assert dr._classify(observed, "10.0.0.5", "host1.lan", set()) == "missing-forward"

    def test_wrong_forward(self):
        observed = {"forward_ips": ["10.0.0.9"], "reverse_name": "host1.lan"}
        assert dr._classify(observed, "10.0.0.5", "host1.lan", set()) == "wrong-forward"

    def test_missing_ptr(self):
        observed = {"forward_ips": ["10.0.0.5"], "reverse_error": "unknown host"}
        assert dr._classify(observed, "10.0.0.5", "host1.lan", set()) == "missing-ptr"

    def test_wrong_ptr(self):
        observed = {"forward_ips": ["10.0.0.5"], "reverse_name": "somebody-else.lan"}
        assert dr._classify(observed, "10.0.0.5", "host1.lan", set()) == "wrong-ptr"

    def test_stale_ptr_when_reverse_name_belongs_to_an_expired_host(self):
        observed = {"forward_ips": ["10.0.0.5"], "reverse_name": "old-laptop.lan"}
        assert dr._classify(observed, "10.0.0.5", "host1.lan", {"old-laptop.lan"}) == "stale-ptr"

    def test_stale_ptr_matches_on_bare_name_too(self):
        observed = {"forward_ips": ["10.0.0.5"], "reverse_name": "old-laptop.lan.example.com"}
        assert dr._classify(observed, "10.0.0.5", "host1.lan.example.com", {"old-laptop"}) == "stale-ptr"

    def test_multiple_a(self):
        observed = {"forward_ips": ["10.0.0.5", "10.0.0.9"], "reverse_name": "host1.lan"}
        assert dr._classify(observed, "10.0.0.5", "host1.lan", set()) == "multiple-a"

    def test_multiple_a_takes_priority_over_wrong_forward(self):
        # two A records, neither of which happens to be the expected IP —
        # still "two IPs claim the name", not "wrong-forward".
        observed = {"forward_ips": ["10.0.0.8", "10.0.0.9"], "reverse_name": "host1.lan"}
        assert dr._classify(observed, "10.0.0.5", "host1.lan", set()) == "multiple-a"

    def test_reverse_case_insensitive_match_is_ok(self):
        observed = {"forward_ips": ["10.0.0.5"], "reverse_name": "HOST1.LAN"}
        assert dr._classify(observed, "10.0.0.5", "host1.lan", set()) == "ok"

    def test_no_reverse_name_and_no_reverse_error_is_ok(self):
        # expected_ip wasn't given (blank), forward is fine, nothing to
        # compare on the reverse side.
        observed = {"forward_ips": ["10.0.0.5"]}
        assert dr._classify(observed, "10.0.0.5", "host1.lan", set()) == "ok"


class TestReconcile:
    def test_every_verdict_reachable_through_reconcile(self):
        rows = [
            {"name": "ok1", "ip": "10.0.0.1", "source": "reservation"},
            {"name": "miss-fwd", "ip": "10.0.0.2", "source": "lease"},
            {"name": "wrong-fwd", "ip": "10.0.0.3", "source": "reservation"},
            {"name": "miss-ptr", "ip": "10.0.0.4", "source": "lease"},
            {"name": "wrong-ptr", "ip": "10.0.0.5", "source": "reservation"},
            {"name": "stale-ptr", "ip": "10.0.0.6", "source": "lease"},
            {"name": "dup-a", "ip": "10.0.0.7", "source": "reservation"},
        ]
        responses = {
            "ok1": {"forward_ips": ["10.0.0.1"], "reverse_name": "ok1"},
            "miss-fwd": {"forward_error": "NXDOMAIN"},
            "wrong-fwd": {"forward_ips": ["10.0.0.99"], "reverse_name": "wrong-fwd"},
            "miss-ptr": {"forward_ips": ["10.0.0.4"], "reverse_error": "no PTR"},
            "wrong-ptr": {"forward_ips": ["10.0.0.5"], "reverse_name": "unrelated"},
            "stale-ptr": {"forward_ips": ["10.0.0.6"], "reverse_name": "retired-host"},
            "dup-a": {"forward_ips": ["10.0.0.7", "10.0.0.70"], "reverse_name": "dup-a"},
        }
        results = dr.reconcile(rows, _resolver(responses), expired_names={"retired-host"})
        by_name = {r["name"]: r["verdict"] for r in results}
        assert by_name == {
            "ok1": "ok",
            "miss-fwd": "missing-forward",
            "wrong-fwd": "wrong-forward",
            "miss-ptr": "missing-ptr",
            "wrong-ptr": "wrong-ptr",
            "stale-ptr": "stale-ptr",
            "dup-a": "multiple-a",
        }
        # Every result row carries the full column set the page renders.
        for r in results:
            assert set(r.keys()) == {
                "name",
                "ip",
                "source",
                "expected_a",
                "observed_a",
                "expected_ptr",
                "observed_ptr",
                "verdict",
            }

    def test_suffix_applied_before_resolving(self):
        rows = [{"name": "host1", "ip": "10.0.0.1", "source": "reservation"}]
        seen = {}

        def resolve(name, ip):
            seen["name"] = name
            return {"forward_ips": [ip], "reverse_name": name}

        results = dr.reconcile(rows, resolve, suffix="lan.example.com")
        assert seen["name"] == "host1.lan.example.com"
        assert results[0]["name"] == "host1.lan.example.com"
        assert results[0]["verdict"] == "ok"

    def test_limit_caps_rows_and_preserves_order(self):
        rows = [{"name": f"h{i}", "ip": f"10.0.0.{i}", "source": "lease"} for i in range(10)]
        results = dr.reconcile(rows, _resolver({}), limit=3)
        assert [r["name"] for r in results] == ["h0", "h1", "h2"]

    def test_empty_rows_returns_empty(self):
        assert dr.reconcile([], _resolver({})) == []

    def test_timing_out_resolver_is_scored_not_raised(self, monkeypatch):
        monkeypatch.setattr(dr, "LOOKUP_TIMEOUT_SECONDS", 0.05)

        def slow_resolve(name, ip):
            time.sleep(0.3)
            return {"forward_ips": [ip], "reverse_name": name}  # never actually returned in time

        rows = [{"name": "slow-host", "ip": "10.0.0.1", "source": "reservation"}]
        results = dr.reconcile(rows, slow_resolve)
        assert len(results) == 1
        assert results[0]["verdict"] == "lookup-failed"

    def test_resolver_exception_is_scored_not_raised(self):
        def flaky_resolve(name, ip):
            raise RuntimeError("resolver exploded")

        rows = [{"name": "flaky", "ip": "10.0.0.1", "source": "lease"}]
        results = dr.reconcile(rows, flaky_resolve)
        assert results[0]["verdict"] == "lookup-failed"

    def test_observed_a_joins_multiple_forward_ips(self):
        rows = [{"name": "dup", "ip": "10.0.0.1", "source": "reservation"}]
        responses = {"dup": {"forward_ips": ["10.0.0.2", "10.0.0.1"], "reverse_name": "dup"}}
        results = dr.reconcile(rows, _resolver(responses))
        assert results[0]["observed_a"] == "10.0.0.1, 10.0.0.2"

    def test_source_carried_through(self):
        rows = [{"name": "h", "ip": "10.0.0.1", "source": "lease"}]
        results = dr.reconcile(rows, _resolver({"h": {"forward_ips": ["10.0.0.1"], "reverse_name": "h"}}))
        assert results[0]["source"] == "lease"


class TestSummarize:
    def test_every_verdict_present_even_at_zero(self):
        counts = dr.summarize([])
        assert set(counts.keys()) == set(dr.VERDICTS)
        assert all(v == 0 for v in counts.values())

    def test_counts_match(self):
        results = [{"verdict": "ok"}, {"verdict": "ok"}, {"verdict": "wrong-ptr"}]
        counts = dr.summarize(results)
        assert counts["ok"] == 2
        assert counts["wrong-ptr"] == 1
        assert counts["missing-forward"] == 0


class TestResolverOutageIsNotAMissingRecord:
    """v5.49.0-beta.2 (audit G) - only a DEFINITIVE "no such record" scores
    missing-*; a resolver that could not answer scores lookup-failed."""

    def test_nxdomain_errno_is_missing_forward(self):
        observed = {"forward_error": "Name or service not known", "forward_errno": socket.EAI_NONAME}
        assert dr._classify(observed, "10.0.0.5", "h.lan", set()) == "missing-forward"

    def test_eai_again_is_lookup_failed_not_missing(self):
        observed = {"forward_error": "Temporary failure", "forward_errno": socket.EAI_AGAIN}
        assert dr._classify(observed, "10.0.0.5", "h.lan", set()) == "lookup-failed"

    def test_reverse_herror_not_found_is_missing_ptr_but_try_again_is_lookup_failed(self):
        base = {"forward_ips": ["10.0.0.5"]}
        assert (
            dr._classify({**base, "reverse_error": "x", "reverse_errno": 1}, "10.0.0.5", "h.lan", set())
            == "missing-ptr"
        )
        assert (
            dr._classify({**base, "reverse_error": "x", "reverse_errno": 2}, "10.0.0.5", "h.lan", set())
            == "lookup-failed"
        )

    def test_hung_resolver_returns_at_the_budget_not_when_the_thread_finishes(self, monkeypatch):
        monkeypatch.setattr(dr, "LOOKUP_TIMEOUT_SECONDS", 0.3)

        def hung(name, ip):
            time.sleep(3)
            return {"forward_ips": [ip], "reverse_name": name}

        rows = [{"name": f"h{i}", "ip": f"10.0.0.{i}", "source": "lease"} for i in range(3)]
        t0 = time.monotonic()
        results = dr.reconcile(rows, hung)
        elapsed = time.monotonic() - t0
        assert elapsed < 1.5, elapsed
        assert [r["verdict"] for r in results] == ["lookup-failed"] * 3

    def test_summarize_and_verdicts_know_the_new_names(self):
        assert "multiple-a" in dr.VERDICTS and "lookup-failed" in dr.VERDICTS
        assert "duplicate-a" not in dr.VERDICTS
        assert dr.summarize([{"verdict": "lookup-failed"}])["lookup-failed"] == 1

    def test_run_verify_passes_the_errno_through(self, monkeypatch):
        from jen.routes import ddns

        def again(*a, **k):
            raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")

        monkeypatch.setattr(ddns.socket, "getaddrinfo", again)
        monkeypatch.setattr(
            ddns.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(socket.herror(1, "Unknown host"))
        )
        out = ddns._run_verify("h.lan", "10.0.0.5")
        assert out["forward_errno"] == socket.EAI_AGAIN
        assert out["reverse_errno"] == 1
        assert dr._classify(out, "10.0.0.5", "h.lan", set()) == "lookup-failed"


class TestBoundedPoolAndSingleFlight:
    """v5.49.0-beta.4 (Q55-D) - one module pool of eight threads and one run at a time."""

    ROWS = [{"name": f"h{i}", "ip": f"10.0.0.{i}", "source": "lease"} for i in range(1, 5)]

    def test_overlapping_runs_the_second_is_refused_without_work(self):
        import threading

        gate = threading.Event()
        called = []

        def blocking(name, ip):
            called.append(name)
            gate.wait(2)
            return {"forward_ips": [ip], "reverse_name": name}

        first = threading.Thread(target=lambda: dr.reconcile(self.ROWS[:1], blocking))
        first.start()
        try:
            time.sleep(0.2)  # the first run is holding the single-flight lock
            with pytest.raises(dr.ReconcileBusy):
                dr.reconcile(self.ROWS[:1], lambda n, i: called.append("SECOND") or {})
            assert "SECOND" not in called
        finally:
            gate.set()
            first.join(5)
        # and the lock is released afterwards
        assert dr.reconcile(self.ROWS[:1], lambda n, i: {"forward_ips": [i], "reverse_name": n})[0]["verdict"] == "ok"

    def test_threads_never_exceed_the_pool_across_repeated_runs_against_a_hung_resolver(self, monkeypatch):
        import threading

        monkeypatch.setattr(dr, "LOOKUP_TIMEOUT_SECONDS", 0.1)

        def sleeping(name, ip):
            time.sleep(0.6)
            return {"forward_ips": [ip], "reverse_name": name}

        for _ in range(3):
            results = dr.reconcile(self.ROWS, sleeping)
            assert all(r["verdict"] == "lookup-failed" for r in results)
            n = sum(1 for t in threading.enumerate() if t.name.startswith("dns-reconcile"))
            assert n <= dr.POOL_WORKERS, n
        time.sleep(0.8)  # let the abandoned lookups drain before other tests run
