"""
tests/test_log_tail.py
──────────────────────
v5.68.0-beta.17 (Q152, item f) - the live watch on Trace was one SSH tail per watcher per three seconds, so two admins watching the same
server doubled the load on the Kea host. `jen.services.log_tail` keeps one read per (server, path) for `WATCH_STEP_S` and makes a reader that
arrives mid-read wait for it. No database: `kea_host.tail_log` is a stand-in. `pytest --noconftest tests/test_log_tail.py`.
"""

import threading
import time

import pytest

from jen.services import kea_host, log_tail

SERVER = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5"}
LINES = [f"line {i}" for i in range(1000)]


@pytest.fixture(autouse=True)
def fake(monkeypatch):
    log_tail.clear()
    calls = []

    def tail_log(server, path, lines=200, timeout=None, helper_only=False):
        calls.append((server["id"], path, lines, timeout, helper_only))
        return {"ok": True, "code": "ok", "lines": LINES[-lines:], "via": "helper"}

    monkeypatch.setattr(kea_host, "tail_log", tail_log)
    yield calls
    log_tail.clear()


class TestOneReadPerStep:
    def test_two_watch_polls_inside_the_step_make_one_tail(self, fake):
        a = log_tail.tail(SERVER, "/var/log/kea.log", 1000, timeout=15)
        b = log_tail.tail(SERVER, "/var/log/kea.log", 1000, timeout=15)
        assert len(fake) == 1 and a["lines"] == b["lines"] == LINES

    def test_it_is_the_helper_only_call_the_callers_made(self, fake):
        log_tail.tail(SERVER, "/p", 1000, timeout=15)
        assert fake == [(1, "/p", 1000, 15, True)]

    def test_a_poll_after_the_window_reads_again(self, fake, monkeypatch):
        monkeypatch.setattr(log_tail, "TTL_S", 0.05)
        log_tail.tail(SERVER, "/p", 1000)
        time.sleep(0.08)
        log_tail.tail(SERVER, "/p", 1000)
        assert len(fake) == 2

    def test_eight_readers_at_once_cost_one_tail(self, fake, monkeypatch):
        def slow(server, path, lines=200, timeout=None, helper_only=False):
            fake.append(1)
            time.sleep(0.2)
            return {"ok": True, "code": "ok", "lines": ["x"], "via": "helper"}

        monkeypatch.setattr(kea_host, "tail_log", slow)
        out = []
        threads = [threading.Thread(target=lambda: out.append(log_tail.tail(SERVER, "/p", 1000))) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        assert len(fake) == 1 and len(out) == 8 and all(r["lines"] == ["x"] for r in out)

    def test_the_explain_pages_log_read_and_the_watch_share_the_one_read(self, fake):
        from jen.services import explain_context as ctx  # reads with TAIL_LINES, as Trace's default does

        assert ctx.TAIL_LINES == 1000
        log_tail.tail(SERVER, "/var/log/kea.log", ctx.TAIL_LINES, timeout=ctx.TAIL_TIMEOUT_S)
        log_tail.tail(SERVER, "/var/log/kea.log", 1000, timeout=15)
        assert len(fake) == 1


class TestWhatIsShared:
    def test_different_servers_and_paths_are_read_separately(self, fake):
        log_tail.tail(SERVER, "/a", 100)
        log_tail.tail({**SERVER, "id": 2}, "/a", 100)
        log_tail.tail(SERVER, "/b", 100)
        assert len(fake) == 3

    def test_a_smaller_request_gets_the_newest_lines_of_the_cached_read(self, fake):
        log_tail.tail(SERVER, "/p", 1000)
        small = log_tail.tail(SERVER, "/p", 50)
        assert len(fake) == 1 and small["lines"] == LINES[-50:]

    def test_the_cached_read_is_not_cut_by_a_smaller_request(self, fake):
        log_tail.tail(SERVER, "/p", 1000)
        log_tail.tail(SERVER, "/p", 50)
        assert len(log_tail.tail(SERVER, "/p", 1000)["lines"]) == 1000

    def test_a_larger_request_than_the_cached_one_reads_again(self, fake):
        log_tail.tail(SERVER, "/p", 50)
        big = log_tail.tail(SERVER, "/p", 1000)
        assert len(fake) == 2 and len(big["lines"]) == 1000

    def test_a_failure_is_kept_for_the_window_too(self, fake, monkeypatch):
        def failing(server, path, lines=200, timeout=None, helper_only=False):
            fake.append(1)
            return {"ok": False, "code": "error", "detail": "ssh timed out"}

        monkeypatch.setattr(kea_host, "tail_log", failing)
        first = log_tail.tail(SERVER, "/p", 1000)
        second = log_tail.tail(SERVER, "/p", 1000)
        assert len(fake) == 1 and first["code"] == second["code"] == "error"

    def test_the_problems_sweep_does_not_go_through_it(self):
        import pathlib

        src = pathlib.Path("jen/services/client_problems.py").read_text(encoding="utf-8")
        assert "log_tail" not in src and "_host.tail_log(" in src
