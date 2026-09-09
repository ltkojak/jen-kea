"""
tests/test_api_key_authorization.py
──────────────────────────────────────
v5.2.10 — SECURITY FIX. Third-party review finding: the API key
listing query loaded every key regardless of who created it, and the
revoke/delete routes checked only `role in (superadmin, admin)` — no
ownership check, no scope check. A subnet-restricted plain admin could
view metadata for, revoke, or delete a superadmin's unrestricted API
key just by knowing or guessing its (small, sequential) id.

Fix: a plain admin now only ever sees, and can only ever act on, API
keys they created themselves. Superadmins continue to see and manage
everything, consistent with how superadmin access works everywhere
else in the app. The revoke/delete routes give the same generic
"API key not found" message whether a key genuinely doesn't exist or
exists but isn't the caller's — distinguishing the two would let
someone confirm a specific key id exists even though they can't act
on it either way.

Also covers three related fixes bundled into the same pass since they
touch the same file: no leaking raw exception text to the user in the
API key routes, a floor on the REST API's `limit` parameter (previously
only capped at 1000 with no lower bound), and `_api_auth()`'s
last_used write throttled to once per 5-minute window instead of every
single authenticated request.
"""

import json
from datetime import datetime, timezone

from jen.models.user import hash_password


def _insert_api_key(db, name, created_by, subnet_access=None, active=1):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, subnet_access, active) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (
                name,
                f"hash_{name}",
                name[:8],
                created_by,
                json.dumps(subnet_access) if subnet_access is not None else None,
                active,
            ),
        )
        return cur.lastrowid


def _insert_admin_user(db, username, role="admin"):
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
            (username, hash_password("testpass123"), role),
        )
        return cur.lastrowid


def _login_as(client, user_id, username, role):
    with client.session_transaction() as sess:
        sess["_user_cache"] = {
            "id": user_id,
            "username": username,
            "role": role,
            "session_timeout": None,
            "subnet_access": None,
        }
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True
        sess["last_active"] = datetime.now(timezone.utc).isoformat()


class TestApiKeyListingScope:
    def test_superadmin_sees_keys_created_by_other_admins(self, logged_in_client, db):
        other_admin_id = _insert_admin_user(db, "other_admin_1")
        db.commit()
        _insert_api_key(db, "othersUnrestrictedKey", other_admin_id)
        db.commit()

        r = logged_in_client.get("/settings/api-keys")
        assert r.status_code == 200
        assert b"othersUnrestrictedKey" in r.data

    def test_plain_admin_does_not_see_keys_created_by_others(self, client, db):
        admin_a = _insert_admin_user(db, "admin_a")
        admin_b = _insert_admin_user(db, "admin_b")
        db.commit()
        _insert_api_key(db, "adminBsSecretKey", admin_b)
        db.commit()

        _login_as(client, admin_a, "admin_a", "admin")
        r = client.get("/settings/api-keys")
        assert r.status_code == 200
        assert b"adminBsSecretKey" not in r.data

    def test_plain_admin_sees_their_own_keys(self, client, db):
        admin_a = _insert_admin_user(db, "admin_c")
        db.commit()
        _insert_api_key(db, "adminCsOwnKey", admin_a)
        db.commit()

        _login_as(client, admin_a, "admin_c", "admin")
        r = client.get("/settings/api-keys")
        assert r.status_code == 200
        assert b"adminCsOwnKey" in r.data


class TestApiKeyRevokeAuthorization:
    def test_superadmin_can_revoke_any_key(self, logged_in_client, db):
        other_admin_id = _insert_admin_user(db, "other_admin_2")
        db.commit()
        key_id = _insert_api_key(db, "revokeMeSuperadmin", other_admin_id)
        db.commit()

        r = logged_in_client.post(f"/settings/api-keys/revoke/{key_id}", follow_redirects=True)
        assert r.status_code == 200
        assert b"revoked" in r.data

        with db.cursor() as cur:
            cur.execute("SELECT active FROM api_keys WHERE id=%s", (key_id,))
            assert cur.fetchone()["active"] == 0

    def test_admin_can_revoke_their_own_key(self, client, db):
        admin_id = _insert_admin_user(db, "admin_d")
        db.commit()
        key_id = _insert_api_key(db, "myOwnKeyToRevoke", admin_id)
        db.commit()

        _login_as(client, admin_id, "admin_d", "admin")
        r = client.post(f"/settings/api-keys/revoke/{key_id}", follow_redirects=True)
        assert r.status_code == 200
        assert b"revoked" in r.data

        with db.cursor() as cur:
            cur.execute("SELECT active FROM api_keys WHERE id=%s", (key_id,))
            assert cur.fetchone()["active"] == 0

    def test_admin_cannot_revoke_another_admins_key(self, client, db):
        """The actual reported vulnerability: a restricted admin
        revoking a key they didn't create, including one with
        unrestricted (all-subnets) access."""
        admin_a = _insert_admin_user(db, "admin_e")
        admin_b = _insert_admin_user(db, "admin_f")
        db.commit()
        key_id = _insert_api_key(db, "unrestrictedKeyOfAdminF", admin_b, subnet_access=None)
        db.commit()

        _login_as(client, admin_a, "admin_e", "admin")
        r = client.post(f"/settings/api-keys/revoke/{key_id}", follow_redirects=True)
        assert r.status_code == 200
        assert b"API key not found" in r.data

        with db.cursor() as cur:
            cur.execute("SELECT active FROM api_keys WHERE id=%s", (key_id,))
            assert cur.fetchone()["active"] == 1, "key must remain active — the revoke must not have happened"

    def test_nonexistent_key_and_not_owned_key_give_the_same_message(self, client, db):
        """Deliberately no distinction between the two cases — telling
        them apart would let someone confirm a specific key id exists
        even though they can't act on it either way."""
        admin_a = _insert_admin_user(db, "admin_g")
        admin_b = _insert_admin_user(db, "admin_h")
        db.commit()
        key_id = _insert_api_key(db, "adminHsKey", admin_b)
        db.commit()

        _login_as(client, admin_a, "admin_g", "admin")
        r1 = client.post(f"/settings/api-keys/revoke/{key_id}", follow_redirects=True)
        r2 = client.post("/settings/api-keys/revoke/999999", follow_redirects=True)

        assert b"API key not found" in r1.data
        assert b"API key not found" in r2.data


class TestApiKeyDeleteAuthorization:
    def test_superadmin_can_delete_any_key(self, logged_in_client, db):
        other_admin_id = _insert_admin_user(db, "other_admin_3")
        db.commit()
        key_id = _insert_api_key(db, "deleteMeSuperadmin", other_admin_id)
        db.commit()

        r = logged_in_client.post(f"/settings/api-keys/delete/{key_id}", follow_redirects=True)
        assert r.status_code == 200
        assert b"deleted" in r.data

        with db.cursor() as cur:
            cur.execute("SELECT * FROM api_keys WHERE id=%s", (key_id,))
            assert cur.fetchone() is None

    def test_admin_cannot_delete_another_admins_key(self, client, db):
        admin_a = _insert_admin_user(db, "admin_i")
        admin_b = _insert_admin_user(db, "admin_j")
        db.commit()
        key_id = _insert_api_key(db, "adminJsKeyNotDeletable", admin_b)
        db.commit()

        _login_as(client, admin_a, "admin_i", "admin")
        r = client.post(f"/settings/api-keys/delete/{key_id}", follow_redirects=True)
        assert r.status_code == 200
        assert b"API key not found" in r.data

        with db.cursor() as cur:
            cur.execute("SELECT * FROM api_keys WHERE id=%s", (key_id,))
            assert cur.fetchone() is not None, "key must still exist — the delete must not have happened"

    def test_admin_can_delete_their_own_key(self, client, db):
        admin_id = _insert_admin_user(db, "admin_k")
        db.commit()
        key_id = _insert_api_key(db, "myOwnKeyToDelete", admin_id)
        db.commit()

        _login_as(client, admin_id, "admin_k", "admin")
        r = client.post(f"/settings/api-keys/delete/{key_id}", follow_redirects=True)
        assert r.status_code == 200
        assert b"deleted" in r.data


class TestApiKeyRoutesDoNotLeakExceptions:
    def test_revoke_error_does_not_leak_raw_exception_text(self, logged_in_client, monkeypatch):
        import jen.routes.api as api_module

        def fake_jen_db():
            raise RuntimeError("Table 'jen.api_keys' doesn't exist — internal schema detail")

        monkeypatch.setattr(api_module, "jen_db", fake_jen_db)
        r = logged_in_client.post("/settings/api-keys/revoke/1", follow_redirects=True)
        assert r.status_code == 200
        assert b"internal schema detail" not in r.data
        assert b"Error revoking key" in r.data

    def test_delete_error_does_not_leak_raw_exception_text(self, logged_in_client, monkeypatch):
        import jen.routes.api as api_module

        def fake_jen_db():
            raise RuntimeError("Connection refused to 10.10.11.250:3306 — internal host detail")

        monkeypatch.setattr(api_module, "jen_db", fake_jen_db)
        r = logged_in_client.post("/settings/api-keys/delete/1", follow_redirects=True)
        assert r.status_code == 200
        assert b"10.10.11.250" not in r.data
        assert b"Error deleting key" in r.data

    def test_listing_error_does_not_leak_raw_exception_text(self, logged_in_client, monkeypatch):
        import jen.routes.api as api_module

        def fake_jen_db():
            raise RuntimeError("Access denied for user 'jen'@'localhost' — internal credential detail")

        monkeypatch.setattr(api_module, "jen_db", fake_jen_db)
        r = logged_in_client.get("/settings/api-keys")
        assert r.status_code == 200
        assert b"internal credential detail" not in r.data
        assert b"Could not load API keys" in r.data

    def test_create_error_does_not_leak_raw_exception_text(self, logged_in_client, monkeypatch):
        import jen.routes.api as api_module

        def fake_jen_db():
            raise RuntimeError("Duplicate entry 'secretname' for key 'PRIMARY' — internal detail")

        monkeypatch.setattr(api_module, "jen_db", fake_jen_db)
        r = logged_in_client.post(
            "/settings/api-keys/create", data={"name": "test key", "subnet_ids": ["all"]}, follow_redirects=True
        )
        assert r.status_code == 200
        assert b"internal detail" not in r.data
        assert b"Error creating key" in r.data


class TestLimitParameterFloor:
    """The negative-limit test in particular requires a genuinely valid
    API key — with an invalid one, _api_auth() returns 401 before the
    limit parameter is ever parsed at all, which would make the test
    pass without actually exercising the code it's meant to test."""

    def _insert_valid_key_and_get_raw(self, db, admin_id):
        """v5.2.11 fix — this used to build the raw key from a fixed
        literal string, so every call within this test class produced
        the exact same key_hash. api_keys.key_hash has a UNIQUE
        constraint, so the second test in this class to call this
        helper failed with a duplicate-key IntegrityError, not because
        of anything wrong in the limit-clamping logic being tested —
        a bug in the test's own fixture data, not the application.
        Each call now gets its own unique raw key via secrets."""
        import hashlib
        import secrets

        raw_key = "jen_" + secrets.token_hex(20)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, subnet_access, active) "
                "VALUES (%s, %s, %s, %s, NULL, 1)",
                ("limit-floor-test-key", key_hash, raw_key[:8], admin_id),
            )
        db.commit()
        return raw_key

    def test_negative_limit_does_not_reach_the_database_unclamped(self, logged_in_client, db, mock_kea):
        """?limit=-1 must not produce a negative LIMIT clause — MySQL
        rejects LIMIT with a negative value outright, which previously
        surfaced as a raw SQL error (a 500) rather than being clamped
        to a valid, safe value."""
        admin_id = _insert_admin_user(db, "admin_limit_test1")
        db.commit()
        raw_key = self._insert_valid_key_and_get_raw(db, admin_id)

        r = logged_in_client.get("/api/v1/leases?limit=-1", headers={"Authorization": f"Bearer {raw_key}"})
        assert r.status_code == 200, f"expected a clamped, successful response, got {r.status_code}: {r.data}"

    def test_zero_limit_does_not_crash(self, logged_in_client, db, mock_kea):
        admin_id = _insert_admin_user(db, "admin_limit_test2")
        db.commit()
        raw_key = self._insert_valid_key_and_get_raw(db, admin_id)

        r = logged_in_client.get("/api/v1/leases?limit=0", headers={"Authorization": f"Bearer {raw_key}"})
        assert r.status_code == 200, f"expected a clamped, successful response, got {r.status_code}: {r.data}"


class TestApiKeySubnetScope:
    """v5.8.4 — docs/ARCHITECTURE.md §3.4 says a subnet-scoped key gets
    the same subnet restriction as the human UI on every /api/v1 route.
    Nothing tested that until now: only key *ownership* and the limit
    clamp were covered. These seed one row per subnet in each table and
    assert a key scoped to subnet 1 never sees subnet 2's row — list
    routes and by-MAC routes alike (the latter must 404, not 403, so the
    key can't probe whether a MAC exists outside its scope)."""

    def _scoped_key(self, db, admin_id, subnet_ids):
        import hashlib
        import secrets

        raw_key = "jen_" + secrets.token_hex(20)
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, subnet_access, active) "
                "VALUES (%s, %s, %s, %s, %s, 1)",
                (
                    f"scope-key-{raw_key[-6:]}",
                    hashlib.sha256(raw_key.encode()).hexdigest(),
                    raw_key[:8],
                    admin_id,
                    json.dumps(subnet_ids),
                ),
            )
        db.commit()
        return {"Authorization": f"Bearer {raw_key}"}

    def _seed(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4")
            cur.execute("DELETE FROM hosts")
            cur.execute("DELETE FROM devices")
            for sid, ip, mac in ((1, "10.10.1.50", "aa1111111101"), (2, "10.10.2.50", "aa2222222202")):
                cur.execute(
                    "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
                    "VALUES (INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), %s, 0, %s)",
                    (ip, mac, sid, f"scope-lease-{sid}"),
                )
                cur.execute(
                    "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                    "VALUES (UNHEX(%s), 0, %s, INET_ATON(%s), %s)",
                    (mac, sid, ip.replace(".50", ".60"), f"scope-res-{sid}"),
                )
                mac_colon = ":".join(mac[i : i + 2] for i in range(0, 12, 2))
                cur.execute(
                    "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, first_seen, last_seen) "
                    "VALUES (%s, %s, %s, %s, NOW(), NOW())",
                    (mac_colon, ip, f"scope-dev-{sid}", sid),
                )
        db.commit()

    def test_list_routes_only_return_in_scope_subnet(self, client, db, mock_kea):
        admin_id = _insert_admin_user(db, "scope_admin_1")
        db.commit()
        self._seed(db)
        headers = self._scoped_key(db, admin_id, [1])

        leases = client.get("/api/v1/leases", headers=headers).get_json()["leases"]
        assert {lease["subnet_id"] for lease in leases} == {1}

        res = client.get("/api/v1/reservations", headers=headers).get_json()["reservations"]
        assert {r["subnet_id"] for r in res} == {1}

        devs = client.get("/api/v1/devices", headers=headers).get_json()["devices"]
        assert [d["last_hostname"] for d in devs] == ["scope-dev-1"]

    def test_explicit_out_of_scope_subnet_filter_is_still_clamped(self, client, db, mock_kea):
        """?subnet=2 on a key scoped to [1] must not widen the scope."""
        admin_id = _insert_admin_user(db, "scope_admin_2")
        db.commit()
        self._seed(db)
        headers = self._scoped_key(db, admin_id, [1])
        leases = client.get("/api/v1/leases?subnet=2", headers=headers).get_json()["leases"]
        assert leases == []

    def test_by_mac_routes_404_outside_scope(self, client, db, mock_kea):
        admin_id = _insert_admin_user(db, "scope_admin_3")
        db.commit()
        self._seed(db)
        headers = self._scoped_key(db, admin_id, [1])
        assert client.get("/api/v1/leases/aa:22:22:22:22:02", headers=headers).status_code == 404
        assert client.get("/api/v1/devices/aa:22:22:22:22:02", headers=headers).status_code == 404
        # …and the in-scope twin works, so the 404 above is scope, not data.
        assert client.get("/api/v1/leases/aa:11:11:11:11:01", headers=headers).status_code == 200
        assert client.get("/api/v1/devices/aa:11:11:11:11:01", headers=headers).status_code == 200

    def test_unrestricted_key_sees_both(self, client, db, mock_kea):
        admin_id = _insert_admin_user(db, "scope_admin_4")
        db.commit()
        self._seed(db)
        headers = self._scoped_key(db, admin_id, [1, 2])
        leases = client.get("/api/v1/leases", headers=headers).get_json()["leases"]
        assert {lease["subnet_id"] for lease in leases} == {1, 2}


class TestLastUsedThrottling:
    def test_last_used_not_updated_within_five_minutes_of_previous_update(self, db):
        """Direct DB-level test of the throttling SQL itself — avoids
        needing to fake the passage of real time to test the 'still
        within the window' branch, which is the one that actually
        prevents the write."""
        admin_id = _insert_admin_user(db, "admin_throttle_test")
        db.commit()
        key_id = _insert_api_key(db, "throttleTestKey", admin_id)
        with db.cursor() as cur:
            cur.execute("UPDATE api_keys SET last_used=NOW() WHERE id=%s", (key_id,))
        db.commit()

        with db.cursor() as cur:
            cur.execute("SELECT last_used FROM api_keys WHERE id=%s", (key_id,))
            before = cur.fetchone()["last_used"]

        # Run the exact conditional UPDATE _api_auth() uses.
        with db.cursor() as cur:
            cur.execute(
                "UPDATE api_keys SET last_used=NOW() WHERE id=%s "
                "AND (last_used IS NULL OR last_used < NOW() - INTERVAL 5 MINUTE)",
                (key_id,),
            )
        db.commit()

        with db.cursor() as cur:
            cur.execute("SELECT last_used FROM api_keys WHERE id=%s", (key_id,))
            after = cur.fetchone()["last_used"]

        assert before == after, "last_used should not change again within the 5-minute throttle window"

    def test_last_used_updated_when_null(self, db):
        admin_id = _insert_admin_user(db, "admin_throttle_test2")
        db.commit()
        key_id = _insert_api_key(db, "throttleTestKeyNull", admin_id)
        db.commit()

        with db.cursor() as cur:
            cur.execute("SELECT last_used FROM api_keys WHERE id=%s", (key_id,))
            assert cur.fetchone()["last_used"] is None

        with db.cursor() as cur:
            cur.execute(
                "UPDATE api_keys SET last_used=NOW() WHERE id=%s "
                "AND (last_used IS NULL OR last_used < NOW() - INTERVAL 5 MINUTE)",
                (key_id,),
            )
        db.commit()

        with db.cursor() as cur:
            cur.execute("SELECT last_used FROM api_keys WHERE id=%s", (key_id,))
            assert cur.fetchone()["last_used"] is not None, "a NULL last_used must always be updated on first use"

    def test_last_used_updated_when_outside_throttle_window(self, db):
        admin_id = _insert_admin_user(db, "admin_throttle_test3")
        db.commit()
        key_id = _insert_api_key(db, "throttleTestKeyOld", admin_id)
        with db.cursor() as cur:
            cur.execute("UPDATE api_keys SET last_used = NOW() - INTERVAL 10 MINUTE WHERE id=%s", (key_id,))
        db.commit()

        with db.cursor() as cur:
            cur.execute("SELECT last_used FROM api_keys WHERE id=%s", (key_id,))
            before = cur.fetchone()["last_used"]

        with db.cursor() as cur:
            cur.execute(
                "UPDATE api_keys SET last_used=NOW() WHERE id=%s "
                "AND (last_used IS NULL OR last_used < NOW() - INTERVAL 5 MINUTE)",
                (key_id,),
            )
        db.commit()

        with db.cursor() as cur:
            cur.execute("SELECT last_used FROM api_keys WHERE id=%s", (key_id,))
            after = cur.fetchone()["last_used"]

        assert after > before, "last_used should update once the throttle window has passed"
