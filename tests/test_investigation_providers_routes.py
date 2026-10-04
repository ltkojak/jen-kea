"""
tests/test_investigation_providers_routes.py
─────────────────────────────────────────────
v5.68.0-beta.4 (Q139) — what the Investigation page's Overview does with the cards a plugin contributes: "What else Jen knows"
under the core facts, the warn summaries in the one-line answer, "unavailable" for a provider that raises, and — the part that
matters — that a provider is only ever asked about a client the caller may see, with the caller's own scope, and that a client
outside that scope is the same "No client matched" answer as one that does not exist.
"""

import pytest

from jen.services import investigation_providers as ip

MAC = "aa:bb:cc:dd:ef:39"
MAC_HEX = "AABBCCDDEF39"
IP = "10.45.9.5"


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM devices WHERE mac=%s", (MAC,))
        cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (MAC_HEX,))
    db.commit()


@pytest.fixture
def seeded(db):
    _clean(db)
    with db.cursor() as cur:
        cur.execute("INSERT INTO devices (mac, last_ip, last_subnet_id) VALUES (%s, %s, 1)", (MAC, IP))
        cur.execute(
            "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state) VALUES "
            "(inet_aton(%s), UNHEX(%s), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)",
            (IP, MAC_HEX),
        )
    db.commit()
    yield
    _clean(db)


@pytest.fixture
def providers():
    """Register fakes for the test and put the registry back afterwards; `calls` records what each was asked."""
    before = dict(ip._PROVIDERS)
    ip._PROVIDERS.clear()
    calls = []

    def add(plugin_id, title, answer):
        def fn(subject, accessible, all_subnets):
            calls.append((plugin_id, subject.mac, set(accessible), all_subnets))
            if isinstance(answer, Exception):
                raise answer
            return answer

        ip.register_investigation_provider(plugin_id, title=title, fn=fn)

    add.calls = calls
    yield add
    ip._PROVIDERS.clear()
    ip._PROVIDERS.update(before)


CARD = {
    "summary": "On sw1 port 3",
    "status": "ok",
    "href": "/plugin/fake/client",
    "rows": [{"label": "Switch", "value": "sw1", "href": "/plugin/fake/switch/1"}, {"label": "VLAN", "value": "20"}],
}


class TestTheCardsOnTheOverview:
    def test_a_card_appears_under_what_else_jen_knows_after_the_core_facts(self, logged_in_client, seeded, providers):
        providers("fake", "Fake Plugin", CARD)
        body = logged_in_client.get(f"/client?q={MAC}").data.decode()
        assert "What else Jen knows" in body and "Fake Plugin" in body and "On sw1 port 3" in body
        assert 'href="/plugin/fake/client"' in body and 'href="/plugin/fake/switch/1"' in body
        assert body.index('card-title">Reservations') < body.index("What else Jen knows"), "after the core facts"

    def test_nothing_to_say_renders_no_heading_at_all(self, logged_in_client, seeded, providers):
        providers("quiet", "Quiet", None)
        assert "What else Jen knows" not in logged_in_client.get(f"/client?q={MAC}").data.decode()

    def test_a_provider_that_raises_is_unavailable_and_says_nothing_of_why(self, logged_in_client, seeded, providers):
        providers("bad", "Bad Plugin", RuntimeError("secret at 10.9.9.9"))
        providers("good", "Good Plugin", CARD)
        r = logged_in_client.get(f"/client?q={MAC}")
        body = r.data.decode()
        assert r.status_code == 200 and "Bad Plugin is unavailable right now" in body and "10.9.9.9" not in body
        assert "Good Plugin" in body

    def test_a_warn_card_gets_a_needs_a_look_label_and_goes_into_the_one_line_answer(
        self, logged_in_client, seeded, providers
    ):
        providers("wd", "Host Watchdog", {"summary": "down for 4 checks", "status": "warn", "rows": []})
        body = logged_in_client.get(f"/client?q={MAC}").data.decode()
        assert "Worth a look:" in body and "Host Watchdog — down for 4 checks" in body
        assert "Needs a look:" in body

    def test_an_ok_card_is_not_in_the_one_line_answer(self, logged_in_client, seeded, providers):
        providers("fake", "Fake Plugin", CARD)
        assert "Worth a look:" not in logged_in_client.get(f"/client?q={MAC}").data.decode()

    def test_a_link_that_leaves_jen_is_not_rendered(self, logged_in_client, seeded, providers):
        providers(
            "evil",
            "Evil",
            {
                "summary": "x",
                "href": "https://evil.example/",
                "rows": [{"label": "L", "value": "v", "href": "//evil.example"}],
            },
        )
        assert "evil.example" not in logged_in_client.get(f"/client?q={MAC}").data.decode()

    def test_the_cards_are_on_the_overview_only(self, logged_in_client, seeded, providers):
        providers("fake", "Fake Plugin", CARD)
        body = logged_in_client.get(f"/client?q={MAC}&tab=timeline").data.decode()
        assert "What else Jen knows" not in body and providers.calls == []

    def test_a_provider_is_handed_the_resolved_client_and_the_callers_scope(self, logged_in_client, seeded, providers):
        providers("fake", "Fake Plugin", None)
        logged_in_client.get(f"/client?q={IP}")
        (plugin_id, mac, _accessible, all_subnets) = providers.calls[0]
        assert (plugin_id, mac, all_subnets) == ("fake", MAC, True)


class TestWhoseClientItIs:
    """The core's check: a provider sees only a client the caller may see, and asks about it with the caller's own scope."""

    def test_a_restricted_viewer_inside_the_subnet_sees_the_card_and_is_called_with_their_scope(
        self, client, db, seeded, providers
    ):
        from tests.conftest import restricted_client

        providers("fake", "Fake Plugin", CARD)
        restricted_client(client, db, allowed_subnets=[1], role="viewer", username="_inv_prov_in")
        body = client.get(f"/client?q={MAC}").data.decode()
        assert "Fake Plugin" in body
        (_pid, _mac, accessible, all_subnets) = providers.calls[0]
        assert accessible == {1} and all_subnets is False

    def test_a_restricted_viewer_outside_the_subnet_gets_no_card_and_no_provider_call(
        self, client, db, seeded, providers
    ):
        from tests.conftest import restricted_client

        providers("fake", "Fake Plugin", CARD)
        restricted_client(client, db, allowed_subnets=[999], role="viewer", username="_inv_prov_out")
        body = client.get(f"/client?q={MAC}").data.decode()
        # the same answer as a client that does not exist - the page is not an existence oracle
        assert "No client matched that identifier" in body
        assert "Fake Plugin" not in body and "On sw1 port 3" not in body
        assert providers.calls == [], "a provider is never asked about a client the caller cannot see"

    def test_an_unknown_client_is_the_same_answer_and_asks_no_provider(self, logged_in_client, db, providers):
        _clean(db)
        providers("fake", "Fake Plugin", CARD)
        body = logged_in_client.get("/client?q=aa:bb:cc:dd:ef:98").data.decode()
        assert "No client matched" in body and "Fake Plugin" not in body and providers.calls == []
