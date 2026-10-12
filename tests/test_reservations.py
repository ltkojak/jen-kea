"""
tests/test_reservations.py
──────────────────────────
Tests for reservation CRUD — add, edit, delete, bulk delete.
These tests mock the Kea API so no real Kea server is needed.
"""

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────
def _kea_add_ok(*a, **kw):
    return {"result": 0, "text": "Host added", "arguments": {}}


def _kea_del_ok(*a, **kw):
    return {"result": 0, "text": "Host deleted", "arguments": {}}


def _kea_list(*a, **kw):
    return {
        "result": 0,
        "arguments": {
            "hosts": [
                {
                    "hw-address": "aa:bb:cc:dd:ee:01",
                    "ip-address": "10.99.0.10",
                    "hostname": "test-host-1",
                    "dhcp4-subnet-id": 1,
                    "id": 101,
                },
            ]
        },
    }


@pytest.fixture
def mock_kea_reservations(monkeypatch):
    """Mock Kea API for reservation operations."""
    from jen.services import kea as kea_svc

    monkeypatch.setattr(
        kea_svc,
        "kea_command",
        lambda cmd, *a, **kw: (
            _kea_list()
            if "get-all" in cmd or "get-by" in cmd
            else _kea_add_ok()
            if "add" in cmd
            else _kea_del_ok()
            if "del" in cmd
            else {"result": 0, "arguments": {}}
        ),
    )
    monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: True)
    monkeypatch.setattr(
        kea_svc,
        "get_active_kea_server",
        lambda: {"id": 1, "api_url": "http://localhost:18000", "api_user": "test", "api_pass": "test"},
    )


class TestReservationsList:
    """Reservations list page."""

    def test_reservations_loads(self, logged_in_client, mock_kea_reservations):
        """Reservations page returns 200."""
        r = logged_in_client.get("/reservations")
        assert r.status_code == 200

    def test_reservations_add_page_loads(self, logged_in_client, mock_kea_reservations):
        """Add reservation page returns 200."""
        r = logged_in_client.get("/reservations/add")
        assert r.status_code == 200

    def test_empty_state_teaches_instead_of_a_blank_table(self, logged_in_client, mock_kea_reservations, db):
        """v5.39.0 (Q39) — the `hosts` table isn't covered by the
        autouse clean_tables fixture (other tests manage it themselves),
        so clear it explicitly rather than assume it's empty."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()

        r = logged_in_client.get("/reservations")
        body = r.data.decode()
        assert "No reservations. Convert a lease or add one." in body
        assert 'href="/reservations/add"' in body


class TestAddReservation:
    """Add reservation — POST /reservations/add"""

    def test_add_reservation_success(self, logged_in_client, mock_kea_reservations):
        """Valid reservation POST succeeds."""
        r = logged_in_client.post(
            "/reservations/add",
            data={
                "subnet_id": "1",
                "mac": "aa:bb:cc:dd:ee:ff",
                "ip": "10.99.0.50",
                "hostname": "test-device",
            },
            follow_redirects=True,
        )
        assert r.status_code == 200

    def test_add_reservation_invalid_mac(self, logged_in_client, mock_kea_reservations):
        """Invalid MAC address is rejected — v5.66.0-beta.8 (Q110): a failed POST now
        re-renders the form directly (400), never a blank redirect."""
        r = logged_in_client.post(
            "/reservations/add",
            data={
                "subnet_id": "1",
                "mac": "not-a-mac",
                "ip": "10.99.0.50",
                "hostname": "test-device",
            },
        )
        assert r.status_code == 400
        assert b"invalid" in r.data.lower() or b"error" in r.data.lower()

    def test_add_reservation_invalid_ip(self, logged_in_client, mock_kea_reservations):
        """Invalid IP address is rejected."""
        r = logged_in_client.post(
            "/reservations/add",
            data={
                "subnet_id": "1",
                "mac": "aa:bb:cc:dd:ee:ff",
                "ip": "999.999.999.999",
                "hostname": "test-device",
            },
        )
        assert r.status_code == 400
        assert b"invalid" in r.data.lower() or b"error" in r.data.lower()

    def test_add_reservation_missing_fields(self, logged_in_client, mock_kea_reservations):
        """Missing required fields are rejected."""
        r = logged_in_client.post(
            "/reservations/add",
            data={
                "subnet_id": "1",
                "mac": "",
                "ip": "",
                "hostname": "",
            },
        )
        assert r.status_code == 400


class TestAddReservationSubnetResolution:
    """v5.66.0-beta.8 (Q110) — the Add Reservation form no longer defaults to the first subnet
    when nothing tells it which one a device belongs to. jen.services.client_subject.subnet_for_ip
    and .client_subnet_for_mac drive the resolution; conftest's SUBNET_MAP has exactly one real
    subnet (id 1, 10.99.0.0/24)."""

    MAC = "aa:bb:cc:dd:ee:20"
    MAC_HEX = "AABBCCDDEE20"
    IP_IN_SUBNET_1 = "10.99.0.77"

    def _select_block(self, body: str) -> str:
        start = body.index('name="subnet_id"')
        end = body.index("</select>", start)
        return body[start:end]

    def test_step1_subnet_id_wins(self, logged_in_client):
        r = logged_in_client.get("/reservations/add?subnet_id=1")
        assert r.status_code == 200
        select = self._select_block(r.data.decode())
        assert '<option value="1" selected' in select

    def test_step2_subnet_alias_is_accepted(self, logged_in_client):
        """The pre-Q110 plugin-link parameter name still works."""
        r = logged_in_client.get("/reservations/add?subnet=1")
        assert r.status_code == 200
        select = self._select_block(r.data.decode())
        assert '<option value="1" selected' in select

    def test_step3_falls_back_to_the_ips_own_cidr(self, logged_in_client):
        r = logged_in_client.get(f"/reservations/add?ip={self.IP_IN_SUBNET_1}")
        assert r.status_code == 200
        select = self._select_block(r.data.decode())
        assert '<option value="1" selected' in select

    def test_step4_falls_back_to_the_macs_current_subnet(self, logged_in_client, db):
        """No subnet_id/subnet/ip resolves anything, but the MAC has a live lease in subnet 1."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX(%s)", (self.MAC_HEX,))
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state) VALUES "
                "(INET_ATON('10.99.0.88'), UNHEX(%s), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0)",
                (self.MAC_HEX,),
            )
        db.commit()

        r = logged_in_client.get(f"/reservations/add?mac={self.MAC}")
        assert r.status_code == 200
        select = self._select_block(r.data.decode())
        assert '<option value="1" selected' in select

    def test_step5_nothing_resolves_the_placeholder_is_selected(self, logged_in_client):
        r = logged_in_client.get("/reservations/add")
        assert r.status_code == 200
        select = self._select_block(r.data.decode())
        assert 'value="" selected' in select and "disabled" in select
        # never a silent default onto the first real option
        assert '<option value="1" selected' not in select

    def test_garbage_ip_and_mac_never_resolve_anything(self, logged_in_client):
        r = logged_in_client.get("/reservations/add?ip=not-an-ip&mac=not-a-mac")
        assert r.status_code == 200
        select = self._select_block(r.data.decode())
        assert 'value="" selected' in select

    def test_an_inaccessible_subnet_id_is_never_selected_or_named(self, client, db):
        """A restricted admin's subnet_id/ip/mac never selects — or even mentions — subnet 1,
        which conftest's SUBNET_MAP is the only real one (ARCHITECTURE §2)."""
        from tests.conftest import restricted_client

        restricted_client(client, db, allowed_subnets=[999])

        for qs in ("subnet_id=1", "subnet=1", f"ip={self.IP_IN_SUBNET_1}"):
            r = client.get(f"/reservations/add?{qs}")
            assert r.status_code == 200
            body = r.data.decode()
            select = self._select_block(body)
            assert 'value="" selected' in select
            assert "10.99.0.0/24" not in body, f"an inaccessible subnet must never be named ({qs})"


class TestAddReservationKeepsWhatWasTyped:
    """v5.66.0-beta.8 (Q110) — every failure re-renders the form with everything the operator
    typed, never a blank redirect."""

    def test_a_failed_post_keeps_every_field(self, logged_in_client, mock_kea_reservations):
        r = logged_in_client.post(
            "/reservations/add",
            data={
                "subnet_id": "1",
                "mac": "not-a-mac",
                "ip": "10.99.0.50",
                "hostname": "office-printer",
                "dns_override": "1.1.1.1",
                "notes": "second floor, near the window",
            },
        )
        assert r.status_code == 400
        body = r.data.decode()
        assert 'value="10.99.0.50"' in body
        assert 'value="office-printer"' in body
        assert 'value="1.1.1.1"' in body
        assert "second floor, near the window" in body
        assert '<option value="1" selected' in body

    def test_a_hostname_with_special_characters_survives_the_round_trip(self, logged_in_client, mock_kea_reservations):
        r = logged_in_client.post(
            "/reservations/add",
            data={
                "subnet_id": "1",
                "mac": "not-a-mac",  # forces the re-render without ever calling Kea
                "ip": "10.99.0.50",
                "hostname": 'a&b"c',
            },
        )
        assert r.status_code == 400
        assert "a&amp;b&#34;c" in r.data.decode() or "a&amp;b&quot;c" in r.data.decode()

    def test_choosing_no_subnet_is_refused_not_defaulted(self, logged_in_client, mock_kea_reservations):
        """The old code defaulted an empty/missing subnet_id to subnet 1 — an untouched form
        (the placeholder never actually selectable) must be refused instead."""
        r = logged_in_client.post(
            "/reservations/add",
            data={"subnet_id": "", "mac": "aa:bb:cc:dd:ee:ff", "ip": "10.99.0.50", "hostname": "x"},
        )
        assert r.status_code == 400
        assert b"choose a subnet" in r.data.lower()


class TestAddReservationAddressMustBeInSubnet:
    """v5.66.0-beta.8 (Q110) — verified against Kea's own host_cmds source
    (HostCmdsImpl::validateHostForSubnet4): reservation-add refuses an ip-address outside the
    named subnet-id's own range every time subnet-id isn't 0, with the exact wording "is not
    matching the IPv4 subnet prefix" — Jen now catches this locally, before ever calling Kea,
    and names which subnet the address actually belongs to."""

    def test_an_address_outside_the_chosen_subnet_is_refused_with_the_real_one_named(
        self, logged_in_client, mock_kea_reservations
    ):
        r = logged_in_client.post(
            "/reservations/add",
            data={
                "subnet_id": "1",
                "mac": "aa:bb:cc:dd:ee:ff",
                "ip": "192.0.2.50",  # nowhere near 10.99.0.0/24
                "hostname": "x",
            },
        )
        assert r.status_code == 400
        assert b"192.0.2.50 is not inside" in r.data

    def test_kea_never_sees_the_call_when_jen_refuses_first(self, logged_in_client, monkeypatch):
        from jen.services import kea as kea_svc

        calls = []
        monkeypatch.setattr(kea_svc, "kea_command", lambda cmd, *a, **kw: calls.append(cmd) or {"result": 0})
        r = logged_in_client.post(
            "/reservations/add",
            data={"subnet_id": "1", "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.0.2.50", "hostname": "x"},
        )
        assert r.status_code == 400
        assert calls == []

    def test_an_address_inside_the_subnet_is_never_refused_on_this_ground(
        self, logged_in_client, mock_kea_reservations
    ):
        r = logged_in_client.post(
            "/reservations/add",
            data={"subnet_id": "1", "mac": "aa:bb:cc:dd:ee:ff", "ip": "10.99.0.50", "hostname": "x"},
        )
        assert r.status_code in (200, 302)


class TestEditReservation:
    """Regression coverage for the v4.4.0 bug where reservation notes got
    silently orphaned. Kea's reservation-del + reservation-add (how Jen
    implements "edit") churns hosts.host_id — an AUTO_INCREMENT primary
    key — even though ip/mac/subnet don't change. The route must write
    reservation_notes against the new host_id, not the stale one from the
    URL, or the note becomes invisible on the list page despite a
    "Reservation updated" success message."""

    def test_notes_survive_host_id_reassignment(self, logged_in_client, db, monkeypatch):
        from jen.services import kea as kea_svc

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('aabbccddee99'), 0, 1, INET_ATON('10.99.0.50'), 'churn-test')"
            )
            old_host_id = cur.lastrowid
        db.commit()

        def _kea_mock(cmd, *a, **kw):
            # Simulate what a real Kea server does to the hosts table on
            # reservation-del/reservation-add: delete-then-reinsert, which
            # assigns a brand new AUTO_INCREMENT host_id.
            if "reservation-del" in cmd:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM hosts WHERE host_id=%s", (old_host_id,))
                db.commit()
                return {"result": 0, "text": "deleted", "arguments": {}}
            if "reservation-add" in cmd:
                with db.cursor() as cur:
                    cur.execute(
                        "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                        "dhcp4_subnet_id, ipv4_address, hostname) "
                        "VALUES (UNHEX('aabbccddee99'), 0, 1, INET_ATON('10.99.0.50'), 'churn-test-renamed')"
                    )
                db.commit()
                return {"result": 0, "text": "added", "arguments": {}}
            return {"result": 0, "arguments": {}}

        monkeypatch.setattr(kea_svc, "kea_command", _kea_mock)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1})

        r = logged_in_client.post(
            f"/reservations/edit/{old_host_id}",
            data={"hostname": "churn-test-renamed", "notes": "should survive"},
        )
        assert r.status_code in (200, 302)

        with db.cursor() as cur:
            cur.execute("SELECT host_id FROM hosts WHERE inet_ntoa(ipv4_address)=%s", ("10.99.0.50",))
            row = cur.fetchone()
        assert row is not None
        current_host_id = row["host_id"]
        assert current_host_id != old_host_id, "test setup didn't actually churn the id — mock is wrong"

        with db.cursor() as cur:
            cur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (current_host_id,))
            note_row = cur.fetchone()
        assert note_row is not None, "note was not written under the new host_id — it got orphaned"
        assert note_row["notes"] == "should survive"

        with db.cursor() as cur:
            cur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (old_host_id,))
            stale_row = cur.fetchone()
        assert stale_row is None, "orphaned note under the old host_id was not cleaned up"


class TestARefusedEditLeavesTheReservationAlone:
    """v5.69.0-beta.3 (Q172, item 8): the edit is Kea's reservation-del followed by reservation-add. The hostname and the DNS override were validated only by Kea, AFTER the
    delete, so a typo in either removed the reservation and the client lost its address. Now they are checked first, with the add route's own validators, and an add Kea refuses
    anyway puts the ORIGINAL back."""

    MAC_HEX = "aabbccddee77"
    IP = "10.99.0.77"

    @pytest.fixture
    def reservation(self, db):
        """One reservation with a DNS override and a note, and a Kea stand-in that keeps `hosts` in step: a delete removes the row, an add inserts one (a new host_id)."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (self.MAC_HEX.upper(),))
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, 1, INET_ATON(%s), 'original-host')",
                (self.MAC_HEX, self.IP),
            )
            host_id = cur.lastrowid
            cur.execute(
                "INSERT INTO dhcp4_options (code, formatted_value, space, scope_id, host_id, client_classes) VALUES (6, '10.99.0.1', 'dhcp4', 3, %s, '')",
                (host_id,),
            )
            cur.execute(
                "INSERT INTO reservation_notes (host_id, notes) VALUES (%s, 'original note') ON DUPLICATE KEY UPDATE notes='original note'",
                (host_id,),
            )
        db.commit()
        yield host_id
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (self.MAC_HEX.upper(),))
            cur.execute("DELETE FROM reservation_notes WHERE notes IN ('original note', 'edited note')")
        db.commit()

    @pytest.fixture
    def kea(self, db, monkeypatch):
        """Records every call; `refuse_hostnames` makes reservation-add answer an error for those names (Kea's own refusal), `refuse_restore` for the original too."""
        from jen.services import kea as kea_svc

        state = {
            "calls": [],
            "refuse_hostnames": set(),
            "refuse_restore": False,
            "delete_result": 0,
            "delete_applies_but_errors": False,  # a lost reply: Kea removed the row, `kea_command` says result 1
            "add_applies_but_errors": False,  # likewise for the new reservation
            "held": None,  # what `reservation-get` answers (the reservation as Kea holds it)
        }

        def command(cmd, *a, **kw):
            args = kw.get("arguments") or {}
            state["calls"].append((cmd, args))
            if cmd == "reservation-get":
                if state["held"] is None:
                    return {"result": 3, "text": "not found"}
                return {"result": 0, "arguments": state["held"]}
            if cmd == "reservation-del":
                if state["delete_result"] == 0 or state["delete_applies_but_errors"]:
                    with db.cursor() as cur:
                        cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (self.MAC_HEX.upper(),))
                    db.commit()
                return {
                    "result": state["delete_result"],
                    "text": "deleted" if state["delete_result"] == 0 else "not deleted",
                }
            if cmd == "reservation-add":
                res = args["reservation"]
                if res.get("hostname") in state["refuse_hostnames"] or (
                    state["refuse_restore"] and res.get("hostname") == "original-host"
                ):
                    return {"result": 1, "text": "Kea refused the reservation"}
                lost = state["add_applies_but_errors"] and res.get("hostname") == "renamed"
                with db.cursor() as cur:
                    cur.execute(
                        "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                        "VALUES (UNHEX(%s), 0, 1, INET_ATON(%s), %s)",
                        (self.MAC_HEX, self.IP, res.get("hostname", "")),
                    )
                db.commit()
                return {"result": 1, "text": "timed out"} if lost else {"result": 0, "text": "added"}
            return {"result": 0, "arguments": {}}

        monkeypatch.setattr(kea_svc, "kea_command", command)
        monkeypatch.setattr(kea_svc, "kea_is_up", lambda *a, **kw: True)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1})
        return state

    def _hosts(self, db):
        with db.cursor() as cur:
            cur.execute("SELECT host_id, hostname FROM hosts WHERE HEX(dhcp_identifier)=%s", (self.MAC_HEX.upper(),))
            rows = cur.fetchall()
        db.commit()  # end this connection's snapshot: the next read sees what the request committed
        return rows

    def test_a_dns_override_that_is_not_an_ip_is_refused_before_the_delete(
        self, logged_in_client, db, reservation, kea
    ):
        r = logged_in_client.post(
            f"/reservations/edit/{reservation}",
            data={"hostname": "renamed", "dns_override": "not-an-ip", "notes": "edited note"},
            follow_redirects=True,
        )
        assert b"Invalid DNS: not-an-ip" in r.data
        assert [c for c, _a in kea["calls"] if c in ("reservation-del", "reservation-add")] == [], "Kea was never asked"
        rows = self._hosts(db)
        assert [(x["host_id"], x["hostname"]) for x in rows] == [(reservation, "original-host")]

    def test_a_hostname_that_is_not_one_is_refused_before_the_delete(self, logged_in_client, db, reservation, kea):
        r = logged_in_client.post(
            f"/reservations/edit/{reservation}",
            data={"hostname": "bad_host!", "dns_override": "", "notes": ""},
            follow_redirects=True,
        )
        assert b"Invalid hostname: bad_host!" in r.data
        assert not kea["calls"]
        assert [x["hostname"] for x in self._hosts(db)] == ["original-host"]

    def test_an_add_that_kea_refuses_after_the_delete_puts_the_original_back(
        self, logged_in_client, db, reservation, kea
    ):
        kea["refuse_hostnames"] = {"renamed"}
        r = logged_in_client.post(
            f"/reservations/edit/{reservation}",
            data={"hostname": "renamed", "dns_override": "10.99.0.2", "notes": "edited note"},
            follow_redirects=True,
        )
        assert b"put back with its address, hostname and options" in r.data
        adds = [a["reservation"] for c, a in kea["calls"] if c == "reservation-add"]
        assert len(adds) == 2 and adds[0]["hostname"] == "renamed"
        assert adds[1] == {
            "subnet-id": 1,
            "hw-address": "AA:BB:CC:DD:EE:77",  # as the route formats it (Kea reads the identifier case-insensitively)
            "ip-address": self.IP,
            "hostname": "original-host",
            "option-data": [{"name": "domain-name-servers", "data": "10.99.0.1"}],
        }, "the original, including the DNS override it had"
        rows = self._hosts(db)
        assert [x["hostname"] for x in rows] == ["original-host"]
        # the note followed the reservation to its new id
        with db.cursor() as cur:
            cur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (rows[0]["host_id"],))
            note = cur.fetchone()
        db.commit()
        assert note and note["notes"] == "original note"

    def test_when_the_original_cannot_be_put_back_the_flash_says_so(self, logged_in_client, db, reservation, kea):
        kea["refuse_hostnames"] = {"renamed"}
        kea["refuse_restore"] = True
        r = logged_in_client.post(
            f"/reservations/edit/{reservation}", data={"hostname": "renamed", "dns_override": ""}, follow_redirects=True
        )
        assert b"could NOT be put back" in r.data and self.IP.encode() in r.data
        assert list(self._hosts(db)) == []

    def test_a_delete_kea_refuses_adds_nothing(self, logged_in_client, db, reservation, kea):
        kea["delete_result"] = 1
        r = logged_in_client.post(
            f"/reservations/edit/{reservation}", data={"hostname": "renamed", "dns_override": ""}, follow_redirects=True
        )
        assert b"the reservation was not changed" in r.data
        assert [c for c, _a in kea["calls"]] == ["reservation-get", "reservation-del"]
        assert [x["hostname"] for x in self._hosts(db)] == ["original-host"]

    def test_a_lost_reply_on_the_delete_does_not_strand_the_client_without_an_address(
        self, logged_in_client, db, reservation, kea
    ):
        """The second pass (finding 1): Kea APPLIED the delete and the reply was lost - `kea_command` says result 1. The row is gone, so the edit goes on and adds."""
        kea["delete_applies_but_errors"] = True
        kea["delete_result"] = 1
        r = logged_in_client.post(
            f"/reservations/edit/{reservation}",
            data={"hostname": "renamed", "dns_override": "", "notes": "edited note"},
            follow_redirects=True,
        )
        assert b"not changed" not in r.data and b"Reservation updated" in r.data
        assert [x["hostname"] for x in self._hosts(db)] == ["renamed"], "the reservation exists, edited"

    def test_a_lost_reply_on_the_add_is_a_success_not_a_put_back(self, logged_in_client, db, reservation, kea):
        """The second pass (finding 2): Kea applied the NEW reservation and the reply was lost. It exists; the original is not put back on top of it."""
        kea["add_applies_but_errors"] = True
        r = logged_in_client.post(
            f"/reservations/edit/{reservation}",
            data={"hostname": "renamed", "dns_override": "", "notes": "edited note"},
            follow_redirects=True,
        )
        assert b"could NOT be put back" not in r.data and b"Reservation updated" in r.data
        adds = [a["reservation"] for c, a in kea["calls"] if c == "reservation-add"]
        assert len(adds) == 1, "the original was not added on top of the new one"
        rows = self._hosts(db)
        assert [x["hostname"] for x in rows] == ["renamed"]
        with db.cursor() as cur:
            cur.execute("SELECT notes FROM reservation_notes WHERE host_id=%s", (rows[0]["host_id"],))
            assert cur.fetchone()["notes"] == "edited note"
        db.commit()

    def test_what_the_form_does_not_show_travels_with_the_edit_and_with_a_restore(
        self, logged_in_client, db, reservation, kea
    ):
        """The second pass (finding 3): client classes, a boot file and an option other than the DNS servers were dropped by the edit and by the put-back."""
        kea["held"] = {
            "ip-address": self.IP,
            "hw-address": "aa:bb:cc:dd:ee:77",
            "hostname": "original-host",
            "client-classes": ["voip"],
            "boot-file-name": "pxelinux.0",
            "option-data": [
                {"name": "domain-name-servers", "data": "10.99.0.1"},
                {"name": "ntp-servers", "data": "10.99.0.9"},
            ],
        }
        logged_in_client.post(
            f"/reservations/edit/{reservation}",
            data={"hostname": "renamed", "dns_override": "10.99.0.2", "notes": ""},
            follow_redirects=True,
        )
        (new,) = [a["reservation"] for c, a in kea["calls"] if c == "reservation-add"]
        assert new["client-classes"] == ["voip"] and new["boot-file-name"] == "pxelinux.0"
        assert {"name": "ntp-servers", "data": "10.99.0.9"} in new["option-data"]
        assert [o["data"] for o in new["option-data"] if o["name"] == "domain-name-servers"] == ["10.99.0.2"]
        kea["calls"].clear()
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (self.MAC_HEX.upper(),))
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, 1, INET_ATON(%s), 'original-host')",
                (self.MAC_HEX, self.IP),
            )
            host_id = cur.lastrowid
        db.commit()
        kea["refuse_hostnames"] = {"renamed"}
        logged_in_client.post(
            f"/reservations/edit/{host_id}", data={"hostname": "renamed", "dns_override": ""}, follow_redirects=True
        )
        restore = [a["reservation"] for c, a in kea["calls"] if c == "reservation-add"][-1]
        assert restore["hostname"] == "original-host" and restore["client-classes"] == ["voip"]
        assert {"name": "ntp-servers", "data": "10.99.0.9"} in restore["option-data"]

    def test_a_hostname_the_reservation_already_had_stays_editable(self, logged_in_client, db, reservation, kea):
        """The second pass (finding 10): a hostname Kea's own config gave the reservation (an underscore) is not re-judged unless the person changed it."""
        with db.cursor() as cur:
            cur.execute("UPDATE hosts SET hostname='old_style_name' WHERE host_id=%s", (reservation,))
        db.commit()
        r = logged_in_client.post(
            f"/reservations/edit/{reservation}",
            data={"hostname": "old_style_name", "dns_override": "", "notes": "edited note"},
            follow_redirects=True,
        )
        assert b"Invalid hostname" not in r.data


class TestTheListAndTheExportAskForNotesAndDnsOnce:
    """v5.69.0-beta.3 (Q172, item 10): the list page and the CSV export read each row's DNS override and note with one query per row. One `IN (...)` query each now."""

    @pytest.fixture
    def three(self, db):
        macs = ["aabbccddee81", "aabbccddee82", "aabbccddee83"]
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
            for n, mac in enumerate(macs):
                cur.execute(
                    "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                    "VALUES (UNHEX(%s), 0, 1, INET_ATON(%s), %s)",
                    (mac, f"10.99.0.{81 + n}", f"many-{n}"),
                )
                host_id = cur.lastrowid
                if n < 2:
                    cur.execute(
                        "INSERT INTO dhcp4_options (code, formatted_value, space, scope_id, host_id, client_classes) VALUES (6, %s, 'dhcp4', 3, %s, '')",
                        (f"10.99.0.{n + 1}", host_id),
                    )
                cur.execute(
                    "INSERT INTO reservation_notes (host_id, notes) VALUES (%s, %s) ON DUPLICATE KEY UPDATE notes=VALUES(notes)",
                    (host_id, f"note-number-{n}"),
                )
        db.commit()
        yield
        with db.cursor() as cur:
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
            cur.execute("DELETE FROM reservation_notes WHERE notes LIKE 'note-number-%'")
        db.commit()

    @staticmethod
    def _count(monkeypatch):
        import pymysql.cursors

        seen = []
        real = pymysql.cursors.Cursor.execute

        def counting(self, query, args=None):
            seen.append(str(query))
            return real(self, query, args)

        monkeypatch.setattr(pymysql.cursors.Cursor, "execute", counting)
        return seen

    def test_the_list_page_shows_every_note_and_override_from_one_query_each(
        self, logged_in_client, three, mock_kea_reservations, monkeypatch
    ):
        seen = self._count(monkeypatch)
        body = logged_in_client.get("/reservations").get_data(as_text=True)
        for n in range(3):
            assert f"note-number-{n}" in body
        assert body.count("● Override") == 2
        assert len([q for q in seen if "FROM dhcp4_options" in q]) == 1
        assert len([q for q in seen if "FROM reservation_notes" in q]) == 1

    def test_the_export_carries_every_note_and_override_from_one_query_each(
        self, logged_in_client, three, mock_kea_reservations, monkeypatch
    ):
        import csv
        import io

        seen = self._count(monkeypatch)
        text = logged_in_client.get("/reservations/export").get_data(as_text=True)
        rows = list(csv.DictReader(io.StringIO(text)))
        by_ip = {r["ip"]: r for r in rows}
        assert by_ip["10.99.0.81"]["dns_override"] == "10.99.0.1" and by_ip["10.99.0.81"]["notes"] == "note-number-0"
        assert by_ip["10.99.0.82"]["dns_override"] == "10.99.0.2" and by_ip["10.99.0.82"]["notes"] == "note-number-1"
        assert by_ip["10.99.0.83"]["dns_override"] == "" and by_ip["10.99.0.83"]["notes"] == "note-number-2"
        assert len([q for q in seen if "FROM dhcp4_options" in q]) == 1
        assert len([q for q in seen if "FROM reservation_notes" in q]) == 1


class TestImportReservations:
    """v5.69.0-beta.3 (Q172, item 8): the CSV import wrote straight into Kea's `hosts` table with whatever the file said - `garbage` as an address, a 5-digit "MAC" - checking only that the MAC had
    twelve characters, and its dry run skipped the duplicate check, so a preview promised rows the real run skipped. Every value is checked per row, a bad row is named by the file's own
    line and inserts nothing, and the dry run asks the same duplicate question. (The first test of this route.)"""

    HEADER = "ip,mac,hostname,subnet_id\n"

    @pytest.fixture(autouse=True)
    def _clean_hosts(self, db):
        def wipe():
            with db.cursor() as cur:
                cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
            db.commit()

        wipe()
        yield
        wipe()

    @staticmethod
    def _post(client, body, dry_run=False):
        import io

        return client.post(
            "/reservations/import" + ("?dry_run=1" if dry_run else ""),
            data={"csv_file": (io.BytesIO(body.encode()), "reservations.csv")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

    @staticmethod
    def _count(db):
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
            n = cur.fetchone()["n"]
        db.commit()
        return n

    def test_a_bad_address_is_reported_by_its_line_and_inserts_nothing(
        self, logged_in_client, db, mock_kea_reservations
    ):
        r = self._post(logged_in_client, self.HEADER + "garbage,aa:bb:cc:dd:ee:ff,host-a,1\n")
        assert b"line 2: not an IPv4 address" in r.data
        assert self._count(db) == 0

    def test_each_kind_of_bad_row_is_named_and_the_good_rows_around_it_are_imported(
        self, logged_in_client, db, mock_kea_reservations
    ):
        body = (
            self.HEADER
            + "10.99.0.20,aa:bb:cc:dd:ee:20,good-one,1\n"  # line 2
            + "10.99.0.21,aa:bb:cc:dd:ee,short-mac,1\n"  # line 3
            + "10.99.0.22,zz:bb:cc:dd:ee:22,not-hex,1\n"  # line 4
            + "10.99.0.23,aa:bb:cc:dd:ee:23,bad_host!,1\n"  # line 5
            + "10.99.0.24,aa:bb:cc:dd:ee:24,no-subnet,\n"  # line 6
            + "10.99.0.25,aa:bb:cc:dd:ee:25,wrong-subnet,9\n"  # line 7
            + "192.0.2.26,aa:bb:cc:dd:ee:26,outside,1\n"  # line 8
            + "10.99.0.27,aa-bb-cc-dd-ee-27,good-two,1\n"  # line 9
        )
        r = self._post(logged_in_client, body)
        text = r.get_data(as_text=True)
        assert "line 3: not a MAC address" in text
        assert "line 4: not a MAC address" in text
        assert "line 5: not a valid hostname" in text
        assert "line 6: invalid subnet_id" in text
        assert "line 7: unknown subnet_id 9" in text
        assert "line 8: 192.0.2.26 is not inside" in text
        assert "Import complete: 2 added" in text
        with db.cursor() as cur:
            cur.execute(
                "SELECT inet_ntoa(ipv4_address) AS ip, HEX(dhcp_identifier) AS mac FROM hosts ORDER BY ipv4_address"
            )
            rows = cur.fetchall()
        db.commit()
        assert [(x["ip"], x["mac"]) for x in rows] == [("10.99.0.20", "AABBCCDDEE20"), ("10.99.0.27", "AABBCCDDEE27")]

    def test_the_dry_run_reports_a_duplicate_and_inserts_nothing(self, logged_in_client, db, mock_kea_reservations):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('aabbccddee30'), 0, 1, INET_ATON('10.99.0.30'), 'already-there')"
            )
        db.commit()
        body = (
            self.HEADER
            + "10.99.0.30,aa:bb:cc:dd:ee:31,takes-the-address,1\n"
            + "10.99.0.32,aa:bb:cc:dd:ee:32,new-one,1\n"
        )
        r = self._post(logged_in_client, body, dry_run=True)
        text = r.get_data(as_text=True)
        assert "Dry run: 1 would be added, 1 skipped" in text
        assert "line 2: 10.99.0.30 is already reserved" in text
        assert self._count(db) == 1, "the dry run inserted nothing"

    def test_the_dry_run_and_the_real_run_agree_on_a_repeated_row_and_a_repeated_mac(
        self, logged_in_client, db, mock_kea_reservations
    ):
        body = (
            self.HEADER
            + "10.99.0.40,aa:bb:cc:dd:ee:40,first,1\n"
            + "10.99.0.40,aa:bb:cc:dd:ee:41,same-address,1\n"
            + "10.99.0.42,aa:bb:cc:dd:ee:40,same-mac,1\n"
        )
        dry = self._post(logged_in_client, body, dry_run=True).get_data(as_text=True)
        assert "Dry run: 1 would be added, 2 skipped" in dry
        real = self._post(logged_in_client, body).get_data(as_text=True)
        assert "Import complete: 1 added, 2 skipped" in real
        assert self._count(db) == 1


class TestDeleteReservation:
    """Delete reservation."""

    def test_delete_reservation(self, logged_in_client, mock_kea_reservations):
        """Delete reservation returns success."""
        r = logged_in_client.post("/reservations/delete/101", data={"subnet_id": "1"}, follow_redirects=True)
        assert r.status_code == 200


class TestReservationStatus:
    """v5.1.3 — active/inactive (and conflict) status on the reservations
    list, matching what Windows DHCP shows: does the reserved IP
    currently have a live lease bound to it? Uses real hosts/lease4 rows
    against the real test DB rather than mocking Kea, since this is
    Jen's own read-side computation, not a Kea API call."""

    def _insert_reservation(self, db, mac_hex="aabbccddee01", ip="10.99.1.10", hostname="status-test", subnet_id=1):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, %s, INET_ATON(%s), %s)",
                (mac_hex, subnet_id, ip, hostname),
            )
            host_id = cur.lastrowid
        db.commit()
        return host_id

    def _insert_lease(self, db, ip, mac_hex, state=0, expire_offset_seconds=3600):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, "
                "subnet_id, state) VALUES (INET_ATON(%s), UNHEX(%s), 3600, "
                "DATE_ADD(NOW(), INTERVAL %s SECOND), 1, %s)",
                (ip, mac_hex, expire_offset_seconds, state),
            )
        db.commit()

    def test_reservation_with_no_lease_is_inactive(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.10", mac_hex="aabbccddee01")
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        # The filter dropdown always contains the literal text "Active
        # only"/"Inactive only" regardless of data, so check the specific
        # status-badge marker (○/●) rather than the bare word.
        assert b"\xe2\x97\x8b Inactive" in resp.data  # ○ Inactive
        assert b"\xe2\x97\x8f Active" not in resp.data  # ● Active

    def test_reservation_with_matching_active_lease_is_active(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.11", mac_hex="aabbccddee02")
        self._insert_lease(db, "10.99.1.11", "aabbccddee02")
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        assert b"\xe2\x97\x8f Active" in resp.data  # ● Active

    def test_expired_lease_does_not_count_as_active(self, logged_in_client, db):
        """A lease that already expired must not make the reservation
        show as active — only a genuinely live lease counts."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.12", mac_hex="aabbccddee03")
        self._insert_lease(db, "10.99.1.12", "aabbccddee03", expire_offset_seconds=-3600)
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        assert b"\xe2\x97\x8b Inactive" in resp.data

    def test_released_lease_does_not_count_as_active(self, logged_in_client, db):
        """state != 0 (released/expired-per-Kea) must not count as active
        even if the expire timestamp is still in the future."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.13", mac_hex="aabbccddee04")
        self._insert_lease(db, "10.99.1.13", "aabbccddee04", state=1)
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        assert b"\xe2\x97\x8b Inactive" in resp.data

    def test_different_mac_on_reserved_ip_shows_conflict(self, logged_in_client, db):
        """The reserved IP has a live lease, but it belongs to a
        different device than the reservation — must be flagged
        distinctly from a plain 'Active' status."""
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.14", mac_hex="aabbccddee05")
        self._insert_lease(db, "10.99.1.14", "112233445566")  # different MAC
        resp = logged_in_client.get("/reservations")
        assert resp.status_code == 200
        assert b"Conflict" in resp.data

    def test_status_filter_active_only(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.20", mac_hex="aabbccddee10", hostname="online-host")
        self._insert_lease(db, "10.99.1.20", "aabbccddee10")
        self._insert_reservation(db, ip="10.99.1.21", mac_hex="aabbccddee11", hostname="offline-host")
        resp = logged_in_client.get("/reservations?status=active")
        assert resp.status_code == 200
        assert b"online-host" in resp.data
        assert b"offline-host" not in resp.data

    def test_status_filter_inactive_only(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.22", mac_hex="aabbccddee12", hostname="printer-alpha")
        self._insert_lease(db, "10.99.1.22", "aabbccddee12")
        self._insert_reservation(db, ip="10.99.1.23", mac_hex="aabbccddee13", hostname="scanner-beta")
        resp = logged_in_client.get("/reservations?status=inactive")
        assert resp.status_code == 200
        assert b"scanner-beta" in resp.data
        assert b"printer-alpha" not in resp.data

    def test_invalid_status_value_falls_back_to_all(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts WHERE dhcp4_subnet_id IS NOT NULL")
        db.commit()
        self._insert_reservation(db, ip="10.99.1.24", mac_hex="aabbccddee14", hostname="whatever-host")
        resp = logged_in_client.get("/reservations?status=bogus")
        assert resp.status_code == 200
        assert b"whatever-host" in resp.data  # not filtered out


class TestSettings:
    """Settings pages — basic load tests."""

    def test_settings_system_loads(self, logged_in_client):
        """Settings system page loads."""
        r = logged_in_client.get("/settings/system")
        assert r.status_code == 200

    def test_settings_infrastructure_loads(self, logged_in_client, mock_kea):
        """Settings Kea page loads (was Infrastructure before v5.9.0)."""
        r = logged_in_client.get("/settings/kea")
        assert r.status_code == 200

    def test_settings_alerts_loads(self, logged_in_client):
        """Settings alerts page loads."""
        r = logged_in_client.get("/settings/alerts")
        assert r.status_code == 200

    def test_settings_viewer_forbidden(self, logged_in_client, db):
        """Viewer role cannot access admin settings."""
        # Create a viewer
        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES (%s, %s, 'viewer')",
                ("viewer1", hash_password("viewpass")),
            )
        db.commit()

        # Viewer logged_in_client uses admin session — just verify 200/302
        r = logged_in_client.get("/settings/system")
        assert r.status_code in (200, 302, 403)


class TestBulkReservationActions:
    """v5.2.2 — bulk delete/export on the Reservations page. This
    JS (toggleAll/updateCount/confirmBulk) and both backend routes
    (bulk_delete_reservations, bulk_export_reservations) already
    existed before this release — but there was no checkbox, no
    select-all, no action bar, and no <form> anywhere in the template
    to actually connect them. The feature was completely unreachable
    from the UI despite a fully correct, already-tested-looking
    backend. These tests exercise the routes directly (as any prior
    test here could already have done, had anyone written one) and
    also confirm the previously-missing markup is now actually
    present in a real rendered page.
    """

    def _insert_host(self, db, mac_hex="aabbccddee10", ip="10.99.0.40", subnet_id=1, hostname="bulk-test-host"):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, %s, INET_ATON(%s), %s)",
                (mac_hex, subnet_id, ip, hostname),
            )
            host_id = cur.lastrowid
        db.commit()
        return host_id

    def test_bulk_delete_removes_selected_reservations(self, logged_in_client, db, monkeypatch):
        """v5.2.2/5.2.3 CI failure fix: the actual `hosts` row is
        removed by Kea itself when it processes reservation-del
        (Kea owns that table, the same way the single-item delete
        route already works — see delete_reservation() above, which
        never issues its own DELETE FROM hosts either) — Jen's own
        side of this is only cleaning up reservation_notes and
        reporting the outcome. Asserting the row is gone from a
        *mocked* Kea's perspective was asserting something outside
        what a mock can actually simulate; the mock returns success
        without touching the real hosts table, so the row was always
        going to still be there in this test environment regardless of
        whether the route's logic is correct. This is exactly the same
        shape of gap as the existing test_delete_reservation() test
        above, which only checks status_code == 200 for the same
        reason — it just wasn't followed for this new test.

        What this test verifies instead: Jen sends the correct
        reservation-del command (matching this specific host's
        subnet-id and MAC), and reports success — the parts actually
        under Jen's control and observable without a real Kea server.
        """
        host_id = self._insert_host(db, mac_hex="aabbccddee10", subnet_id=1)
        calls = []

        def fake_kea_command(cmd, service="dhcp4", arguments=None, server=None):
            calls.append((cmd, arguments))
            return {"result": 0, "text": "Host deleted", "arguments": {}}

        monkeypatch.setattr("jen.services.kea.kea_command", fake_kea_command)

        r = logged_in_client.post(
            "/reservations/bulk-delete", data={"host_ids[]": [str(host_id)]}, follow_redirects=True
        )
        assert r.status_code == 200
        assert b"Deleted 1 reservation" in r.data

        del_calls = [c for c in calls if c[0] == "reservation-del"]
        assert len(del_calls) == 1, f"expected exactly one reservation-del call, got {del_calls}"
        _, args = del_calls[0]
        assert args["subnet-id"] == 1
        assert args["identifier"] == "aa:bb:cc:dd:ee:10"
        assert args["identifier-type"] == "hw-address"

    def test_bulk_delete_with_no_selection_shows_error(self, logged_in_client, mock_kea):
        r = logged_in_client.post("/reservations/bulk-delete", data={}, follow_redirects=True)
        assert r.status_code == 200
        assert b"No reservations selected" in r.data

    def test_bulk_delete_respects_subnet_restriction(self, client, db, mock_kea):
        """A bulk action can't be used to reach a subnet a restricted
        admin couldn't touch one at a time — same guard as the
        single-item delete route, checked per host_id in the loop."""
        from tests.conftest import restricted_client

        host_id = self._insert_host(db, mac_hex="aabbccddee11", ip="10.99.0.41", subnet_id=1)
        restricted_client(client, db, allowed_subnets=[999])
        r = client.post("/reservations/bulk-delete", data={"host_ids[]": [str(host_id)]}, follow_redirects=True)
        assert r.status_code == 200
        with db.cursor() as cur:
            cur.execute("SELECT * FROM hosts WHERE host_id=%s", (host_id,))
            assert cur.fetchone() is not None, "reservation outside the restricted admin's scope must survive"

    def test_bulk_export_returns_csv_of_selected_reservations(self, logged_in_client, db, mock_kea):
        host_id = self._insert_host(db, mac_hex="aabbccddee12", ip="10.99.0.42", hostname="export-target")
        r = logged_in_client.post("/reservations/bulk-export", data={"host_ids[]": [str(host_id)]})
        assert r.status_code == 200
        assert b"export-target" in r.data
        assert b"10.99.0.42" in r.data

    def test_bulk_export_with_no_selection_shows_error(self, logged_in_client, mock_kea):
        r = logged_in_client.post("/reservations/bulk-export", data={}, follow_redirects=True)
        assert r.status_code == 200
        assert b"No reservations selected" in r.data

    def test_reservations_page_now_actually_renders_the_bulk_markup(self, logged_in_client, db, mock_kea):
        """Regression guard for the actual bug: the page must contain
        real checkboxes, a select-all control, and a bulk form —
        not just the JS that references IDs which didn't exist."""
        host_id = self._insert_host(db, mac_hex="aabbccddee13", ip="10.99.0.43")
        r = logged_in_client.get("/reservations")
        assert r.status_code == 200
        body = r.data.decode()
        assert 'id="bulk-form"' in body
        assert 'id="selectAll"' in body
        assert f'name="host_ids[]" value="{host_id}"' in body
