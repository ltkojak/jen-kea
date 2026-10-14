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
_REAL_READ = (
    log_tail._read_server_config
)  # tests/conftest.py replaces the seam for every test; the ones that test it use the function as imported
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
        # Q175 adjustment: the sweep now asks `log_tail.path_for` WHERE the log is (the one definition), but still never reads it through the coalescing cache
        assert "_log_tail.tail(" not in src and "log_tail.tail(" not in src
        assert "_host.tail_log(" in src and "_log_tail.path_for(" in src


class TestPathForIsWhereTheServersOwnLoggerWrites:
    """v5.69.0-beta.6 (Q175): `path_for` is the server-level form of `kea_log_trace.log_path_for` - the file the server's own kea-dhcp4 logger writes, else `[kea] dhcp4_log_path` -
    read once per server per `PATH_TTL_S`. The sweep, Trace and Explain all ask it; the config read is a seam (`_read_server_config`) so no test opens SSH."""

    CFG_FILE = {"Dhcp4": {"loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "/var/log/kea/dhcp4.log"}]}]}}
    CFG_STDOUT = {"Dhcp4": {"loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "stdout"}]}]}}

    @pytest.fixture(autouse=True)
    def _configured(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "DHCP4_LOG", "/var/log/kea/kea-dhcp4.log")

    def test_the_servers_own_logger_file_wins(self, monkeypatch):
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: self.CFG_FILE)
        assert log_tail.path_for(SERVER) == "/var/log/kea/dhcp4.log"

    def test_stdout_is_the_configured_path(self, monkeypatch):
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: self.CFG_STDOUT)
        assert log_tail.path_for(SERVER) == "/var/log/kea/kea-dhcp4.log"

    def test_a_config_that_cannot_be_read_is_the_configured_path(self, monkeypatch):
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: None)
        assert log_tail.path_for(SERVER) == "/var/log/kea/kea-dhcp4.log"

    def test_a_config_read_that_raises_is_the_configured_path_and_never_raises(self, monkeypatch):
        def boom(server):
            raise OSError("ssh timed out")

        monkeypatch.setattr(log_tail, "_read_server_config", boom)
        assert log_tail.path_for(SERVER) == "/var/log/kea/kea-dhcp4.log"

    def test_one_read_serves_every_caller_inside_the_window(self, monkeypatch):
        reads = []
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: reads.append(server["id"]) or self.CFG_FILE)
        for _ in range(5):
            log_tail.path_for(SERVER)
        assert reads == [1]

    def test_a_failed_read_is_kept_for_the_window_too(self, monkeypatch):
        reads = []
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: reads.append(1))  # returns None
        log_tail.path_for(SERVER)
        log_tail.path_for(SERVER)
        assert reads == [1]

    def test_the_read_is_per_server(self, monkeypatch):
        reads = []
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: reads.append(server["id"]) or None)
        log_tail.path_for(SERVER)
        log_tail.path_for({"id": 2, "name": "kea-b", "ssh_host": "10.0.0.6"})
        assert sorted(reads) == [1, 2]

    def test_a_read_after_the_window_asks_again_and_sees_a_changed_logger(self, monkeypatch):
        answers = [self.CFG_STDOUT, self.CFG_FILE]
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: answers.pop(0))
        monkeypatch.setattr(log_tail, "PATH_TTL_S", 0.05)
        assert log_tail.path_for(SERVER) == "/var/log/kea/kea-dhcp4.log"
        time.sleep(0.08)
        assert log_tail.path_for(SERVER) == "/var/log/kea/dhcp4.log"

    def test_clear_forgets_the_paths(self, monkeypatch):
        answers = [self.CFG_STDOUT, self.CFG_FILE]
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: answers.pop(0))
        log_tail.path_for(SERVER)
        log_tail.clear()
        assert log_tail.path_for(SERVER) == "/var/log/kea/dhcp4.log"

    def test_a_host_recorded_as_having_no_helper_is_not_asked_for_its_config(self, monkeypatch):
        from types import SimpleNamespace

        from jen.services import capabilities

        monkeypatch.setattr(
            capabilities, "for_server", lambda sid, **k: SimpleNamespace(helper_known=True, helper=False)
        )
        asked = []
        monkeypatch.setattr(
            kea_host, "read_config", lambda server, service, **k: asked.append(service) or self.CFG_FILE
        )
        assert _REAL_READ(SERVER) is None
        assert asked == []

    def test_a_host_with_a_helper_is_asked_for_its_dhcp4_config(self, monkeypatch):
        from types import SimpleNamespace

        from jen.services import capabilities

        monkeypatch.setattr(
            capabilities, "for_server", lambda sid, **k: SimpleNamespace(helper_known=True, helper=True)
        )
        asked = []
        monkeypatch.setattr(
            kea_host, "read_config", lambda server, service, **k: asked.append(service) or self.CFG_FILE
        )
        assert _REAL_READ(SERVER) == self.CFG_FILE
        assert asked == ["dhcp4"]

    def test_a_host_never_seen_is_asked_once_to_learn_what_it_has(self, monkeypatch):
        from types import SimpleNamespace

        from jen.services import capabilities

        monkeypatch.setattr(
            capabilities, "for_server", lambda sid, **k: SimpleNamespace(helper_known=False, helper=False)
        )
        monkeypatch.setattr(kea_host, "read_config", lambda server, service, **k: self.CFG_FILE)
        assert _REAL_READ(SERVER) == self.CFG_FILE


class TestPathForSecondPassFixes:
    """The adversarial pass of Q175: a page that only shows the path never opens a session, a changed host is not answered from the old one's cache, a failed read is not kept
    for two minutes, a clear() during a read keeps the stale answer out, and the config read is helper-only, bounded and records no revision."""

    CFG_FILE = TestPathForIsWhereTheServersOwnLoggerWrites.CFG_FILE

    @pytest.fixture(autouse=True)
    def _configured(self, monkeypatch):
        from jen import extensions

        monkeypatch.setattr(extensions, "DHCP4_LOG", "/var/log/kea/kea-dhcp4.log")

    def test_read_false_never_reads_and_gives_the_configured_path(self, monkeypatch):
        monkeypatch.setattr(
            log_tail, "_read_server_config", lambda server: (_ for _ in ()).throw(AssertionError("read"))
        )
        assert log_tail.path_for(SERVER, read=False) == "/var/log/kea/kea-dhcp4.log"

    def test_read_false_returns_a_cached_answer_when_there_is_one(self, monkeypatch):
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: self.CFG_FILE)
        log_tail.path_for(SERVER)
        monkeypatch.setattr(
            log_tail, "_read_server_config", lambda server: (_ for _ in ()).throw(AssertionError("read"))
        )
        assert log_tail.path_for(SERVER, read=False) == "/var/log/kea/dhcp4.log"

    def test_a_server_edited_to_point_elsewhere_is_not_answered_from_the_old_hosts_cache(self, monkeypatch):
        answers = {"10.0.0.5": self.CFG_FILE, "10.0.0.9": None}
        reads = []
        monkeypatch.setattr(
            log_tail, "_read_server_config", lambda server: reads.append(server) or answers[server["ssh_host"]]
        )
        assert log_tail.path_for(SERVER) == "/var/log/kea/dhcp4.log"
        moved = {**SERVER, "ssh_host": "10.0.0.9"}
        assert log_tail.path_for(moved) == "/var/log/kea/kea-dhcp4.log"
        log_tail.path_for({**SERVER, "kea_conf": "/etc/kea/other.conf"})
        assert len(reads) == 3, "a changed host and a changed config path each read again"

    def test_a_failed_read_is_kept_for_the_short_window_only(self, monkeypatch):
        answers = [None, self.CFG_FILE]
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: answers.pop(0))
        monkeypatch.setattr(log_tail, "FAIL_TTL_S", 0.05)
        assert log_tail.path_for(SERVER) == "/var/log/kea/kea-dhcp4.log"
        time.sleep(0.08)
        assert log_tail.path_for(SERVER) == "/var/log/kea/dhcp4.log", (
            "an SSH blip did not choose the file for two minutes"
        )

    def test_a_clear_while_a_read_is_in_flight_keeps_its_answer_out_of_the_cache(self, monkeypatch):
        def read_then_clear(server):
            log_tail.clear()  # the configuration changed while the read was on the wire
            return self.CFG_FILE

        monkeypatch.setattr(log_tail, "_read_server_config", read_then_clear)
        assert log_tail.path_for(SERVER) == "/var/log/kea/dhcp4.log", "the caller still gets what it read"
        calls = []
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: calls.append(1) or None)
        assert log_tail.path_for(SERVER) == "/var/log/kea/kea-dhcp4.log" and calls == [1], "but it was not kept"

    def test_the_real_read_is_helper_only_bounded_and_records_nothing(self, monkeypatch):
        from types import SimpleNamespace

        from jen.services import capabilities

        monkeypatch.setattr(
            capabilities, "for_server", lambda sid, **k: SimpleNamespace(helper_known=True, helper=True)
        )
        seen = []
        monkeypatch.setattr(kea_host, "read_config", lambda server, service, **k: seen.append((service, k)) or {})
        _REAL_READ(SERVER)
        assert seen == [("dhcp4", {"timeout": log_tail.READ_TIMEOUT_S, "helper_only": True, "capture": False})]
        assert log_tail.READ_TIMEOUT_S <= 15


class TestAReadBelongsToItsEndpoint:
    """v5.69.0-beta.8 (Q177, LOG-IDENTITY-001): the 3 s read cache was keyed by (server id, path) while `path_for` keyed by the server's identity; an endpoint changed under the same id
    (save_extra_servers) was answered with the old host's lines."""

    P = "/var/log/kea/kea-dhcp4.log"

    @pytest.fixture(autouse=True)
    def _count(self, monkeypatch):
        self.calls = []

        def tail_log(server, path, lines=200, timeout=None, helper_only=False):
            self.calls.append((server["ssh_host"], path))
            return {"ok": True, "code": "ok", "lines": [f"from:{server['ssh_host']}"]}

        monkeypatch.setattr(kea_host, "tail_log", tail_log)
        log_tail.clear()
        yield
        log_tail.clear()

    def _server(self, **over):
        return {
            "id": 1,
            "name": "kea",
            "ssh_host": "old",
            "ssh_user": "u",
            "kea_conf": "/etc/kea/kea-dhcp4.conf",
            **over,
        }

    def test_a_changed_host_under_the_same_id_is_a_new_read_and_says_so(self):
        first = log_tail.tail(self._server(), self.P, 10)
        second = log_tail.tail(self._server(ssh_host="new"), self.P, 10)
        assert len(self.calls) == 2
        assert first["lines"] == ["from:old"] and second["lines"] == ["from:new"]

    def test_the_same_server_twice_is_one_read(self):
        log_tail.tail(self._server(), self.P, 10)
        log_tail.tail(self._server(), self.P, 10)
        assert len(self.calls) == 1

    @pytest.mark.parametrize("over", [{"ssh_user": "other-user"}, {"kea_conf": "/etc/kea/kea-dhcp4-prod.conf"}])
    def test_a_different_user_or_config_path_is_a_new_read(self, over):
        log_tail.tail(self._server(), self.P, 10)
        log_tail.tail(self._server(**over), self.P, 10)
        assert len(self.calls) == 2

    def test_a_different_path_is_a_new_read(self):
        log_tail.tail(self._server(), self.P, 10)
        log_tail.tail(self._server(), "/var/log/kea/other.log", 10)
        assert len(self.calls) == 2

    def test_only_the_display_name_changed_is_no_new_read(self):
        log_tail.tail(self._server(), self.P, 10)
        log_tail.tail(self._server(name="renamed"), self.P, 10)
        assert len(self.calls) == 1

    def test_the_identity_is_one_helper_for_both_caches(self):
        import inspect

        assert log_tail._identity is log_tail.identity
        assert "identity(server)" in inspect.getsource(log_tail.tail) and "_identity(server)" not in inspect.getsource(
            log_tail.tail
        )
        assert "identity(server)" in inspect.getsource(log_tail.path_for) or "_identity(server)" in inspect.getsource(
            log_tail.path_for
        )


class TestTheGatesAreBounded:
    """v5.69.0-beta.9 (Q178, LOG-CACHE-002): the gates that make a second reader wait for the first one's read are a fixed set, striped by key - not one Lock per distinct key
    for the life of the process."""

    @pytest.fixture(autouse=True)
    def _fresh(self, monkeypatch):
        log_tail.clear()
        self.calls = []

        def tail_log(server, path, lines=200, timeout=None, helper_only=False):
            self.calls.append((server["ssh_host"], path))
            return {"ok": True, "code": "ok", "lines": [f"from:{server['ssh_host']}"]}

        monkeypatch.setattr(kea_host, "tail_log", tail_log)
        yield
        log_tail.clear()

    def test_a_thousand_distinct_keys_leave_nothing_behind(self):
        # (Q178: the entry asked for 64 striped locks; striping let a hung host's read hold an UNRELATED server's inside Explain's one budget - the model walk's E1 failed in CI -
        # so the table of in-flight reads is bounded by what is in flight instead, and an unrelated key never waits)
        for n in range(1000):
            log_tail.tail(
                {"id": n, "ssh_host": f"h{n}", "ssh_user": "u", "kea_conf": "/etc/kea/kea-dhcp4.conf"},
                f"/var/log/kea/{n}.log",
                10,
            )
        assert log_tail._flying == {} and log_tail._flying_paths == {}
        assert len(log_tail._cache) <= 65
        assert (
            not hasattr(log_tail, "_per_key")
            and not hasattr(log_tail, "_path_gates")
            and not hasattr(log_tail, "_GATES")
        )

    def test_path_for_does_not_grow_either(self, monkeypatch):
        monkeypatch.setattr(log_tail, "_read_server_config", lambda server: None)
        for n in range(300):
            log_tail.path_for({"id": n, "ssh_host": f"h{n}"})
        assert log_tail._flying_paths == {} and len(log_tail._paths) <= 65

    def test_an_unrelated_key_never_waits_for_a_slow_read(self, monkeypatch):
        started = threading.Event()
        release = threading.Event()

        def slow_or_fast(server, path, lines=200, timeout=None, helper_only=False):
            if server["ssh_host"] == "hung":
                started.set()
                release.wait(5)
            return {"ok": True, "code": "ok", "lines": [server["ssh_host"]]}

        monkeypatch.setattr(kea_host, "tail_log", slow_or_fast)
        hung = {"id": 1, "ssh_host": "hung", "ssh_user": "u", "kea_conf": "/c.conf"}
        t = threading.Thread(target=lambda: log_tail.tail(hung, "/var/log/kea/k.log", 10))
        t.start()
        started.wait(5)
        began = time.monotonic()
        for n in range(200):  # any number of unrelated keys: none of them may share anything with the hung read
            assert log_tail.tail(
                {"id": 100 + n, "ssh_host": f"ok{n}", "ssh_user": "u", "kea_conf": "/c.conf"}, "/var/log/kea/k.log", 10
            )["ok"]
        assert time.monotonic() - began < 2.0
        release.set()
        t.join(5)

    def test_one_key_from_two_threads_is_one_read_of_the_host(self, monkeypatch):
        started = threading.Event()
        release = threading.Event()

        def slow(server, path, lines=200, timeout=None, helper_only=False):
            self.calls.append(server["ssh_host"])
            started.set()
            release.wait(5)
            return {"ok": True, "code": "ok", "lines": ["x"]}

        monkeypatch.setattr(kea_host, "tail_log", slow)
        server = {"id": 1, "ssh_host": "h", "ssh_user": "u", "kea_conf": "/c.conf"}
        out = []
        t1 = threading.Thread(target=lambda: out.append(log_tail.tail(server, "/var/log/kea/k.log", 10)))
        t2 = threading.Thread(target=lambda: out.append(log_tail.tail(server, "/var/log/kea/k.log", 10)))
        t1.start()
        started.wait(5)
        t2.start()
        time.sleep(0.1)
        release.set()
        t1.join(5)
        t2.join(5)
        assert len(out) == 2 and self.calls == ["h"]

    def test_a_clear_while_a_read_is_in_flight_keeps_its_answer_out_of_the_cache(self, monkeypatch):
        server = {"id": 1, "ssh_host": "h", "ssh_user": "u", "kea_conf": "/c.conf"}

        def read_then_clear(srv, path, lines=200, timeout=None, helper_only=False):
            self.calls.append(srv["ssh_host"])
            log_tail.clear()  # the configuration changed while the read was on the wire
            return {"ok": True, "code": "ok", "lines": ["stale"]}

        monkeypatch.setattr(kea_host, "tail_log", read_then_clear)
        first = log_tail.tail(server, "/var/log/kea/k.log", 10)
        assert first["lines"] == ["stale"], "the caller that asked still gets what it read"
        monkeypatch.setattr(
            kea_host,
            "tail_log",
            lambda srv, path, lines=200, timeout=None, helper_only=False: {
                "ok": True,
                "code": "ok",
                "lines": ["fresh"],
            },
        )
        assert log_tail.tail(server, "/var/log/kea/k.log", 10)["lines"] == ["fresh"], (
            "but it was not served to the next one"
        )
