"""v7.0.0-beta.6 (Q220) - the Getting-started nav pill and the unit suite.

The pill is cached for 300 s per (role, scope) and a miss runs the whole Health check set, which is Kea traffic. `TestTheMechanism` proves that with the
real pill (a cold render sends Kea commands a warm one does not); `TestThePillIsInertInTheUnitSuite` proves `tests/conftest.py::_nav_pill_is_inert` takes
it away from every test that did not ask for it. v7.0.0-beta.5's release run failed when that refresh landed in a test that asserted no Kea command was sent."""

import pytest

from jen.services import onboarding

PAGE = "/users"


def _recorder(monkeypatch):
    sent = []
    monkeypatch.setattr(
        "jen.services.kea.kea_command",
        lambda *a, **k: sent.append(a[0] if a else k.get("command", "?")) or {"result": 0},
    )
    return sent


def _cold_and_warm(client, sent):
    assert client.get(PAGE).status_code == 200
    cold = len(sent)
    assert client.get(PAGE).status_code == 200
    return cold, len(sent) - cold


@pytest.mark.real_nav_pill
class TestTheMechanism:
    def test_a_cold_pill_refresh_sends_kea_commands_from_a_page_render(self, logged_in_client, monkeypatch):
        onboarding._pill_cache.clear()
        sent = _recorder(monkeypatch)
        cold, warm = _cold_and_warm(logged_in_client, sent)
        assert cold > warm, (
            f"the cold render sent {cold} Kea commands and the warm one {warm}: the pill's refresh is Kea traffic ({sent})"
        )
        assert onboarding._pill_cache, "the cold render filled the pill's cache"


class TestThePillIsInertInTheUnitSuite:
    def test_a_page_render_sends_the_same_commands_cold_and_warm(self, logged_in_client, monkeypatch):
        sent = _recorder(monkeypatch)
        cold, warm = _cold_and_warm(logged_in_client, sent)
        assert cold == warm, f"an inert pill sends nothing of its own: cold {cold}, warm {warm} ({sent})"
        assert onboarding._pill_cache == {}

    def test_the_pill_answers_nothing_here(self):
        assert onboarding.cached_pill(object(), True) is None
