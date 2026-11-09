"""v7.0.0-beta.11 (Q225) - the DB-backed rows of the pass on 7.0.0-beta.10.

AK1  a subnet-restricted admin's alert channel never stores NULL (every subnet): a selection that names none of their subnets - the untouched form - refuses the form, as the API-key route's does.
AK21 a `users.subnet_access` value that is not a JSON list is NO subnets, never every subnet: such an admin is refused the Logs page, where NULL would have read it.
AK22 the stored subnet list carries each id once, in order.

Needs the database (the `client`, `db` and `logged_in_client` fixtures of tests/conftest.py)."""

import json

import pytest

from tests.conftest import restricted_client

SAVE = "/settings/alerts/save-channel"


def _channel(db, name):
    with db.cursor() as cur:
        cur.execute("SELECT subnet_scope FROM alert_channels WHERE channel_name=%s", (name,))
        return cur.fetchone()


def _drop(db, name):
    with db.cursor() as cur:
        cur.execute("DELETE FROM alert_channels WHERE channel_name=%s", (name,))
    db.commit()


def _form(name, **subnets):
    data = {
        "channel_type": "webhook",
        "channel_name": name,
        "enabled": "on",
        "webhook_url": "https://hooks.example.test/x",
        "alert_types[]": ["new_lease"],
    }
    data.update(subnets)
    return data


class TestARestrictedAdminsChannelCoversItsSubnets:
    """AK1."""

    @pytest.mark.parametrize("selection", [{}, {"subnet_ids": []}, {"subnet_ids": ["424242"]}, {"subnet_ids": ["all"]}])
    def test_a_selection_that_names_none_of_their_subnets_refuses_the_form(self, client, db, selection):
        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="admin", username="_ch_scoped")
        name = "_ch_none"
        _drop(db, name)
        r = c.post(SAVE, data=_form(name, **selection), follow_redirects=True)
        assert r.status_code == 200 and b"Select at least one subnet this channel should cover" in r.data, selection
        assert _channel(db, name) is None, "nothing was written"

    def test_one_of_their_subnets_is_stored_as_the_scope(self, client, db):
        c, _uid = restricted_client(client, db, allowed_subnets=[1], role="admin", username="_ch_scoped_ok")
        name = "_ch_one"
        _drop(db, name)
        try:
            r = c.post(SAVE, data=_form(name, subnet_ids=["1", "1", "424242"]), follow_redirects=True)
            assert r.status_code == 200 and b"Select at least one subnet" not in r.data
            row = _channel(db, name)
            assert row is not None and json.loads(row["subnet_scope"]) == [1], row
        finally:
            _drop(db, name)

    def test_the_control_an_unrestricted_admin_may_still_scope_a_channel_to_every_subnet(self, logged_in_client, db):
        name = "_ch_all"
        _drop(db, name)
        try:
            r = logged_in_client.post(SAVE, data=_form(name), follow_redirects=True)
            assert r.status_code == 200 and b"Select at least one subnet" not in r.data
            row = _channel(db, name)
            assert row is not None and row["subnet_scope"] is None
        finally:
            _drop(db, name)


class TestAnUnreadableScopeIsNoSubnets:
    """AK21: the consequence at a page. NULL reads the Logs page; a row that is not a JSON list used to be read as NULL (or to raise)."""

    def test_an_admin_whose_stored_scope_is_not_a_list_is_refused_the_logs_page(self, client, db):
        from datetime import datetime, timezone

        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role, subnet_access) VALUES (%s, %s, 'admin', %s)",
                (
                    "_garbage_scope",
                    hash_password("testpass123"),
                    '"abc"',
                ),  # valid JSON that is not a list: what a JSON column lets through
            )
            uid = cur.lastrowid
        db.commit()
        with client.session_transaction() as sess:
            sess["_user_id"] = str(uid)
            sess["_fresh"] = True
            now = datetime.now(timezone.utc).isoformat()
            sess["last_active"] = now
            sess["auth_at"] = now
        r = client.get("/settings/logs")
        assert r.status_code == 302 and "/servers" in r.headers["Location"], (r.status_code, r.headers.get("Location"))
        assert client.get("/servers").status_code == 200, "the account itself is not broken: it is scoped to nothing"


class TestTheStoredListCarriesEachIdOnce:
    """AK22."""

    def _access(self, db, uid):
        with db.cursor() as cur:
            cur.execute("SELECT subnet_access FROM users WHERE id=%s", (uid,))
            return cur.fetchone()["subnet_access"]

    def test_set_user_subnets_dedupes_and_orders(self, logged_in_client, db):
        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role, subnet_access) VALUES (%s, %s, 'admin', '[1]')",
                ("_dedupe_set", hash_password("x" * 12)),
            )
            uid = cur.lastrowid
        db.commit()
        logged_in_client.post(f"/users/set-subnets/{uid}", data={"subnet_ids": ["2", "2", "1"]}, follow_redirects=True)
        assert json.loads(self._access(db, uid)) == [1, 2]

    def test_edit_user_dedupes_and_orders(self, logged_in_client, db):
        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role, subnet_access) VALUES (%s, %s, 'admin', '[1]')",
                ("_dedupe_edit", hash_password("x" * 12)),
            )
            uid = cur.lastrowid
        db.commit()
        logged_in_client.post(
            f"/users/edit/{uid}",
            data={"role": "admin", "timeout": "", "subnet_ids": ["2", "1", "2"]},
            follow_redirects=True,
        )
        assert json.loads(self._access(db, uid)) == [1, 2]
