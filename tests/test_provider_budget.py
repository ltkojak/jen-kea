"""
tests/test_provider_budget.py
──────────────────────────────
v5.68.0-beta.11 (Q146) — the one-second budget for investigation and search providers is a bound, not a log line. A provider that
hangs must not hold the page: the request stops waiting at the budget and shows "unavailable (over 1 s)"; the calls that can be
outstanding are capped and a new one is turned away at once instead of queueing; a call still running after its budget is logged
once and counted; and a provider still answers for the caller who asked, from the pool's thread. No database: the providers are
fakes. `pytest --noconftest tests/test_provider_budget.py`.
"""

import logging
import threading
import time

import pytest
from flask import Flask, g
from flask import request as flask_request
from flask_login import LoginManager, UserMixin, current_user, login_user

from jen.services import client_subject as cs
from jen.services import investigation_providers as ip
from jen.services import provider_budget as pb
from jen.services import search_providers as sp


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    before_ip, before_sp = dict(ip._PROVIDERS), dict(sp._PROVIDERS)
    ip._PROVIDERS.clear()
    sp._PROVIDERS.clear()
    # a private pool for each test, so a hung fake never starves the next test's calls; the module's own pair is put back after
    monkeypatch.setattr(pb, "_executor", pb.ThreadPoolExecutor(max_workers=pb.MAX_WORKERS))
    monkeypatch.setattr(pb, "_slots", threading.BoundedSemaphore(pb.MAX_OUTSTANDING))
    monkeypatch.setattr(pb, "_stats", {"overruns": 0, "refused": 0})
    yield
    pb._executor.shutdown(wait=False, cancel_futures=True)
    ip._PROVIDERS.clear()
    sp._PROVIDERS.clear()
    ip._PROVIDERS.update(before_ip)
    sp._PROVIDERS.update(before_sp)


def _subject():
    return cs.ClientSubject(kind="mac", identifier="aa:bb:cc:dd:ee:01", mac="aa:bb:cc:dd:ee:01", ip="10.0.0.5")


class Hang:
    """A provider that does not answer until released. `started` counts the calls that actually began."""

    def __init__(self):
        self.release = threading.Event()
        self.started = 0
        self.lock = threading.Lock()

    def __call__(self, *args):
        with self.lock:
            self.started += 1
        self.release.wait(10)
        return None


def _register(kind, plugin_id, fn):
    if kind == "investigation":
        ip.register_investigation_provider(plugin_id, title=plugin_id.title(), fn=fn)
    else:
        sp.register_search_provider(plugin_id, title=plugin_id.title(), fn=fn)


def _run(kind):
    if kind == "investigation":
        return ip.run_investigation_providers(_subject(), {1}, True)
    return sp.run_search_providers("q", [1], True)


def _good(kind, text="fine"):
    if kind == "investigation":
        return lambda s, a, al: {"summary": text}
    return lambda q, a, al: [{"title": text, "subtitle": "", "href": "/x", "subnet_id": 1}]


@pytest.fixture(params=["investigation", "search"])
def kind(request, monkeypatch):
    monkeypatch.setattr(ip, "BUDGET_SECONDS", 0.2)
    monkeypatch.setattr(sp, "BUDGET_SECONDS", 0.2)
    return request.param


class TestTheBudgetIsABound:
    def test_a_hung_provider_costs_the_budget_and_the_others_still_answer(self, kind):
        hang = Hang()
        _register(kind, "hung", hang)
        _register(kind, "good", _good(kind))
        started = time.monotonic()
        try:
            out = _run(kind)
        finally:
            hang.release.set()
        elapsed = time.monotonic() - started
        assert elapsed < 1.5, f"the page waited {elapsed:.2f}s for a provider that never answers"
        by_id = {r["plugin_id"]: r for r in out}
        assert by_id["hung"]["unavailable"] is True and by_id["hung"]["reason"] == "over 0.2 s"
        assert by_id["good"]["unavailable"] is False and by_id["good"]["reason"] == ""
        assert (
            by_id["good"]["card"]["summary"] if kind == "investigation" else by_id["good"]["rows"][0]["title"]
        ) == "fine"

    def test_several_hung_providers_cost_one_budget_not_one_each(self, kind):
        hang = Hang()
        for name in ("a", "b", "c"):
            _register(kind, name, hang)
        started = time.monotonic()
        try:
            out = _run(kind)
        finally:
            hang.release.set()
        elapsed = time.monotonic() - started
        assert [r["unavailable"] for r in out] == [True, True, True]
        assert elapsed < 0.2 * 3, f"three hung providers took {elapsed:.2f}s: they were waited for one after the other"

    def test_registration_order_is_kept_whatever_order_they_finish_in(self, kind):
        def slow_good(*args):
            time.sleep(0.08)
            return _good(kind, "slow")(*args)

        _register(kind, "first", slow_good)
        _register(kind, "second", _good(kind, "quick"))
        assert [r["plugin_id"] for r in _run(kind)] == ["first", "second"]

    def test_a_provider_that_finishes_inside_the_budget_is_not_called_slow(self, kind):
        def ok(*args):
            time.sleep(0.05)
            return _good(kind)(*args)

        _register(kind, "ok", ok)
        out = _run(kind)
        assert out[0]["unavailable"] is False and pb.stats() == {"overruns": 0, "refused": 0}

    def test_a_provider_still_running_after_its_budget_is_logged_once_and_counted(self, kind, caplog):
        hang = Hang()
        _register(kind, "hung", hang)
        try:
            with caplog.at_level(logging.WARNING):
                _run(kind)
            time.sleep(0.05)
        finally:
            hang.release.set()
        assert caplog.text.count("still running after its") == 1
        assert pb.stats()["overruns"] == 1

    def test_a_raising_provider_is_still_just_unavailable_with_no_reason(self, kind):
        def boom(*args):
            raise RuntimeError("paramiko exploded")

        _register(kind, "bad", boom)
        out = _run(kind)
        assert out[0]["unavailable"] is True and out[0]["reason"] == ""


class TestOutstandingCalls:
    def _capped(self, monkeypatch, n):
        monkeypatch.setattr(pb, "_slots", threading.BoundedSemaphore(n))

    def test_when_every_slot_is_taken_a_new_call_waits_and_is_busy_only_when_the_deadline_passes(
        self, kind, monkeypatch, caplog
    ):
        self._capped(monkeypatch, 2)
        hang = Hang()
        for name in ("a", "b", "c"):
            _register(kind, name, hang)
        started = time.monotonic()
        try:
            with caplog.at_level(logging.WARNING):
                out = _run(kind)
        finally:
            hang.release.set()
        assert [(r["unavailable"], r["reason"]) for r in out] == [
            (True, "over 0.2 s"),
            (True, "over 0.2 s"),
            (True, "busy"),
        ]
        assert hang.started <= 2, "the third provider must never have been started"
        assert time.monotonic() - started < 0.2 * 3
        assert pb.stats()["refused"] == 1 and "already outstanding" in caplog.text

    def test_abandoned_calls_keep_their_slot_until_they_really_end(self, kind, monkeypatch):
        self._capped(monkeypatch, 2)
        hang = Hang()
        _register(kind, "a", hang)
        _register(kind, "b", hang)
        _run(kind)  # both abandoned at the budget, both still running
        _register(kind, "c", _good(kind))
        busy = _run(kind)
        assert busy[-1]["plugin_id"] == "c" and busy[-1]["reason"] == "busy", (
            "calls the page stopped waiting for are still running: their slots are not free"
        )
        hang.release.set()
        time.sleep(0.2)  # they end; the slots come back
        for registry in (ip._PROVIDERS, sp._PROVIDERS):
            registry.pop("a", None)
            registry.pop("b", None)
        assert _run(kind)[0]["unavailable"] is False

    def test_a_call_that_never_started_is_cancelled_not_left_to_run_later(self, kind, monkeypatch):
        monkeypatch.setattr(pb, "_executor", pb.ThreadPoolExecutor(max_workers=1))
        hang = Hang()
        ran = []
        _register(kind, "hung", hang)
        _register(kind, "queued", lambda *a: ran.append(1))
        try:
            out = _run(kind)
        finally:
            hang.release.set()
        time.sleep(0.2)
        assert [r["unavailable"] for r in out] == [True, True]
        assert ran == [], "a provider that was still queued when its budget ended must not run afterwards"

    def test_a_call_waiting_for_a_slot_gets_one_that_frees_inside_the_budget(self, kind, monkeypatch):
        """Q152: the ceiling no longer turns a call away on arrival. A slot that comes back before the page's deadline is used."""
        self._capped(monkeypatch, 1)
        gate = threading.Event()

        def first(*args):
            gate.wait(5)
            return _good(kind, "first")(*args)

        _register(kind, "a", first)
        _register(kind, "b", _good(kind, "second"))
        threading.Timer(0.05, gate.set).start()
        out = _run(kind)
        assert [r["unavailable"] for r in out] == [False, False], (
            "the second call waited 50 ms for the first one's slot"
        )
        assert pb.stats()["refused"] == 0

    def test_the_real_module_limits_are_the_documented_ones(self):
        assert (pb.MAX_WORKERS, pb.MIN_OUTSTANDING) == (8, 16)
        assert ip.BUDGET_SECONDS == 1.0 and sp.BUDGET_SECONDS == 1.0


class TestThePoolIsSizedForTheServer:
    """v5.68.0-beta.17 (Q152): seven providers per page and a ceiling of 8 meant the second page opened during the first got one slot
    and six 'busy' cards. The ceiling is max(16, 2 x threads x providers) and the workers follow [server] threads."""

    @pytest.mark.parametrize(
        "threads,providers,expected",
        [(8, 7, (8, 112)), (1, 0, (1, 16)), (2, 7, (2, 28)), (64, 7, (64, 896)), (0, 3, (1, 16))],
    )
    def test_sizing_rule(self, threads, providers, expected):
        assert pb.sizing(threads, providers) == expected

    def test_configure_replaces_the_pool_and_the_ceiling(self, monkeypatch):
        monkeypatch.setattr(pb, "MAX_WORKERS", pb.MAX_WORKERS)
        monkeypatch.setattr(pb, "MAX_OUTSTANDING", pb.MAX_OUTSTANDING)
        pb.configure(3, 7)
        assert (pb.MAX_WORKERS, pb.MAX_OUTSTANDING) == (3, 42)
        assert pb._executor._max_workers == 3
        assert all(pb._slots.acquire(blocking=False) for _ in range(42)) and not pb._slots.acquire(blocking=False)

    def test_two_pages_of_seven_providers_at_once_are_fourteen_ok_cards(self, kind, monkeypatch):
        monkeypatch.setattr(ip, "BUDGET_SECONDS", 1.0)
        monkeypatch.setattr(sp, "BUDGET_SECONDS", 1.0)
        pb.configure(8, 7)

        def slowish(*args):
            time.sleep(0.15)  # long enough that both pages' calls overlap
            return _good(kind)(*args)

        for n in range(7):
            _register(kind, f"p{n}", slowish)
        results = []

        def page():
            results.append(_run(kind))

        threads = [threading.Thread(target=page) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        cards = [r for page_ in results for r in page_]
        assert len(cards) == 14 and all(r["unavailable"] is False and r["reason"] == "" for r in cards)
        assert pb.stats()["refused"] == 0


class TestAProviderStillAnswersForTheCaller:
    """The pool's threads have no request of their own: a provider that reads `current_user`, `request` or `g` must see the page's."""

    class _User(UserMixin):
        def __init__(self, uid, all_subnets):
            self.id = uid
            self.all_subnets = all_subnets

    def _app(self):
        app = Flask("budget-test")
        app.secret_key = "x"
        manager = LoginManager(app)
        manager.user_loader(lambda uid: None)
        return app

    def test_current_user_request_and_g_are_the_pages_own(self, kind):
        seen = {}

        def probe(*args):
            seen.update(
                user=current_user.id,
                scoped=current_user.all_subnets is False,
                path=flask_request.path,
                flag=g.get("flag"),
            )
            return None

        _register(kind, "probe", probe)
        app = self._app()
        with app.test_request_context("/client?q=x"):
            g.flag = "set-on-the-request"  # the app context's g is NOT carried over - a provider must not rely on it
            login_user(self._User("admin-A", False))
            out = _run(kind)
        assert out == [] or out[0]["unavailable"] is False
        assert seen == {"user": "admin-A", "scoped": True, "path": "/client", "flag": None}

    def test_the_user_is_the_one_the_page_loaded_for_each_caller(self, kind):
        who = []
        _register(kind, "probe", lambda *a: who.append(current_user.id))
        app = self._app()
        for uid in ("one", "two"):
            with app.test_request_context("/"):
                login_user(self._User(uid, True))
                _run(kind)
        assert who == ["one", "two"]

    def test_outside_a_request_a_provider_simply_runs(self, kind):
        ran = []
        _register(kind, "bare", lambda *a: ran.append(1))
        _run(kind)
        assert ran == [1]
