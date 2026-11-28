"""
tests/test_the_wait_is_roomy.py
───────────────────────────────
Q254 - the timing family. Twelve test files set `kea_api_config.COMMAND_TIMEOUT` to 0.4 or 0.6 s for every command they sent to a real local server, so a runner that held one handler thread for that
long turned a working change into "Kea API request timed out." and reddened a tag (the pass on v7.1.0-beta.8). The wait is now set in ONE place, `tests/_kea_api_world.py::install_wait`: roomy for a
command no test hangs, short only for a command a test made the fake hang on. These tests hold that place, against a real local server and the product's own sender.
"""

import copy
import pathlib
import re
import time

import pytest

from jen import extensions
from jen.services import kea_api_config as api
from tests import _kea_api_world as world
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer

TESTS = pathlib.Path(__file__).resolve().parent
STALL = 1.0  # seconds a handler is held: longer than every wait the family used to set (0.4, 0.6), shorter than the roomy one


@pytest.fixture
def fake(monkeypatch):
    f = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
    f.hang_seconds = 1.2
    f.start()
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
    yield f
    f.stop()


def _server(f, name="kea-a"):
    return {"id": 7, "name": name, "api_url": f.url, "api_user": "", "api_pass": ""}


def _stall(f):
    f.on_command = lambda fake, command, arguments: time.sleep(STALL)


class TestOnePlaceSetsTheWait:
    def test_no_test_file_sets_the_wait_itself(self):
        """Whole tree, never a file list: a thirteenth file that sets a wait of its own is the family coming back."""
        mine = {"_kea_api_world.py", pathlib.Path(__file__).name}
        found = sorted(
            p.name
            for p in TESTS.rglob("*.py")
            if p.name not in mine and "COMMAND_TIMEOUT" in p.read_text(encoding="utf-8")
        )
        assert found == []

    def test_the_family_goes_through_it(self):
        users = sorted(
            p.name
            for p in TESTS.glob("test_*.py")
            if p.name != pathlib.Path(__file__).name
            and re.search(r"world\.install_wait\(", p.read_text(encoding="utf-8"))
        )
        assert len(users) == 12, users

    def test_the_two_numbers(self):
        assert world.HUNG_WAIT < 1.2 < world.ROOMY_WAIT
        assert world.ROOMY_WAIT <= api.COMMAND_TIMEOUT  # never roomier than the product's own wait


class TestAStalledRunnerIsNotATimeout:
    def test_the_old_wait_called_a_stall_a_timeout(self, fake, monkeypatch):
        """The control: the wait the family used to set, against the same stall."""
        monkeypatch.setattr(api, "COMMAND_TIMEOUT", 0.4)
        _stall(fake)
        reply = api._cmd(_server(fake), "dhcp4", "config-hash-get")
        assert "transport" in reply and "timed out" in reply.get("text", "")

    def test_the_roomy_wait_gets_the_answer(self, fake, monkeypatch):
        world.install_wait(monkeypatch, fake)
        _stall(fake)
        reply = api._cmd(_server(fake), "dhcp4", "config-hash-get")
        assert reply.get("result") == 0 and "transport" not in reply


class TestAHungCommandStillTimesOut:
    @pytest.mark.parametrize("when", ["before", "after"])
    def test_and_does_so_in_the_short_wait(self, fake, monkeypatch, when):
        world.install_wait(monkeypatch, fake)
        fake.hang = {"config-hash-get": when}
        started = time.monotonic()
        reply = api._cmd(_server(fake), "dhcp4", "config-hash-get")
        assert "timed out" in reply.get("text", "")
        assert time.monotonic() - started < fake.hang_seconds

    def test_a_command_that_is_not_the_hung_one_keeps_the_roomy_wait(self, fake, monkeypatch):
        world.install_wait(monkeypatch, fake)
        fake.hang = {"config-write": "before"}
        _stall(fake)
        assert api._cmd(_server(fake), "dhcp4", "config-hash-get").get("result") == 0

    def test_a_wait_the_product_passed_is_left_alone(self, fake, monkeypatch):
        """`hash(..., timeout=)` and `_get(..., timeout=)` carry a caller's own deadline; the helper never replaces one."""
        world.install_wait(monkeypatch, fake)
        fake.hang = {"config-hash-get": "after"}
        reply = api._cmd(_server(fake), "dhcp4", "config-hash-get", timeout=5)
        assert reply.get("result") == 0

    def test_a_hang_on_one_server_does_not_shorten_the_other(self, fake, monkeypatch):
        second = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
        second.start()
        try:
            world.install_wait(monkeypatch, fake, second)
            fake.hang = {"config-hash-get": "before"}
            _stall(second)
            assert api._cmd(_server(second, "kea-z"), "dhcp4", "config-hash-get").get("result") == 0
        finally:
            second.stop()

    def test_with_no_fake_named_only_the_number_is_set(self, monkeypatch):
        send = api._cmd
        world.install_wait(monkeypatch)
        assert api._cmd is send and api.COMMAND_TIMEOUT == world.ROOMY_WAIT
