"""
tests/test_support_bundle.py
────────────────────────────
v5.33.0 (Q32) — the diagnostic support bundle.

The guarantee that matters is redaction, and it is a TEST, not a
promise: `TestNoSecretSurvives` seeds every secret-bearing place the
bundle reads from with a distinctive sentinel, builds the archive from
that raw data, unzips it, and asserts no sentinel appears in ANY member.
The pure builders run without a database
(`python -m pytest --noconftest tests/test_support_bundle.py -k "Redact or Scrub or Build or Cap"`);
the route test at the bottom exercises the live collectors through the
app.
"""

import io
import json
import zipfile
from datetime import datetime, timezone

import pytest

from jen.services import support_bundle as sb

NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)

SENTINELS = {
    "jen_db_password": "SENTINEL_JEN_DB_PASS_7f3a",
    "kea_db_password": "SENTINEL_KEA_DB_PASS_8b21",
    "kea_api_pass": "SENTINEL_KEA_API_PASS_91cc",
    "oidc_client_secret": "SENTINEL_OIDC_SECRET_4d0e",
    "metrics_token": "SENTINEL_METRICS_TOKEN_a55f",
    "kea_basic_auth": "SENTINEL_KEA_BASIC_AUTH_c2b9",
    "kea_db_in_config": "SENTINEL_KEA_HOSTSDB_PASS_e17d",
    "ha_peer_password": "SENTINEL_HA_PEER_PASS_0c4a",
    "bearer_in_log": "SENTINEL_BEARER_TOKEN_6e8d",
    "password_in_log": "SENTINEL_LOG_PASSWORD_b3f0",
    "api_key_in_log": "jen_SENTINELAPIKEYVALUE0123456789abcdefghijklmnopqrstuvwxyz",
}

CONFIG_INI = f"""[kea]
api_url = http://10.0.0.5:8000
api_user = jen
api_pass = {SENTINELS["kea_api_pass"]}
api_client_key = /etc/jen/ssl/kea-client.key
[kea_db]
host = db
user = kea
password = {SENTINELS["kea_db_password"]}
database = kea
[jen_db]
host = db
user = jen
password = {SENTINELS["jen_db_password"]}
database = jen
[oidc]
client_id = jen
client_secret = {SENTINELS["oidc_client_secret"]}
[server]
metrics_token = {SENTINELS["metrics_token"]}
log_file = /var/log/jen/jen.log
[kea_ssh]
key_path = /etc/jen/ssh/jen_rsa
[updates]
channel = beta
"""

KEA_CONFIG = {
    "Dhcp4": {
        "control-sockets": [
            {
                "socket-type": "https",
                "socket-address": "10.0.0.5",
                "socket-port": 8000,
                "authentication": {
                    "type": "basic",
                    "clients": [{"user": "jen", "password": SENTINELS["kea_basic_auth"]}],
                },
                "trust-anchor": "/etc/kea/tls/dhcp4/ca.crt",
                "key-file": "/etc/kea/tls/dhcp4/server.key",
            }
        ],
        "hosts-database": {"type": "mysql", "name": "kea", "user": "kea", "password": SENTINELS["kea_db_in_config"]},
        "hooks-libraries": [
            {
                "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
                "parameters": {
                    "high-availability": [
                        {
                            "peers": [
                                {
                                    "name": "s2",
                                    "url": "http://10.0.0.6:8000/",
                                    "basic-auth-password": SENTINELS["ha_peer_password"],
                                }
                            ]
                        }
                    ]
                },
            }
        ],
        "subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}],
    }
}

LOG_TEXT = "\n".join(
    [
        "2026-09-14T11:59:00Z INFO jen.routes.api: GET /api/v1/leases",
        f"2026-09-14T11:59:01Z DEBUG urllib3: Authorization: Bearer {SENTINELS['bearer_in_log']}",
        f"2026-09-14T11:59:02Z WARNING jen.services.kea: login failed password={SENTINELS['password_in_log']} for jen",
        f"2026-09-14T11:59:03Z INFO jen.routes.api: key {SENTINELS['api_key_in_log']} created",
        "2026-09-14T11:59:04Z INFO jen: plain line that must survive intact",
    ]
)


def _collected(**overrides):
    base = {
        "notes": [],
        "jen": {"version": "5.33.0-beta.1", "channel": "beta", "hostname": "jen-box"},
        "config_text": CONFIG_INI,
        "servers": [
            {"id": 1, "name": "Primary", "api_url": "http://10.0.0.5:8000", "ssh_key_path": "/etc/jen/ssh/jen_rsa"}
        ],
        "health": {"summary": {"ok": 1}, "checks": [{"id": "kea_reachable", "status": "ok"}]},
        "drift": [],
        "kea_configs": [
            {
                "server_id": 1,
                "server": "Primary",
                "service": "dhcp4",
                "revision_id": 7,
                "sha256": "abc",
                "config": KEA_CONFIG,
            }
        ],
        "plugins": [{"id": "ipam", "version": "1.5.0"}],
        "db": {"schema_latest": 24},
        "audit": [{"id": 1, "action": "LOGIN", "details": "User admin logged in"}],
        "alerts": [],
        "lease_history": [],
        "log_text": LOG_TEXT,
    }
    base.update(overrides)
    return base


def _unzip(data: bytes) -> dict[str, str]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return {n: zf.read(n).decode("utf-8") for n in zf.namelist()}


class TestRedactIni:
    def test_secret_values_masked_paths_kept(self):
        out = sb.redact_ini_text(CONFIG_INI)
        for s in SENTINELS.values():
            assert s not in out
        assert "api_client_key = /etc/jen/ssl/kea-client.key" in out
        assert "key_path = /etc/jen/ssh/jen_rsa" in out
        assert "api_url = http://10.0.0.5:8000" in out
        assert "channel = beta" in out
        assert out.count(sb.MASK) == 5

    @pytest.mark.parametrize(
        "key,secret",
        [
            ("password", True),
            ("api_pass", True),
            ("client_secret", True),
            ("metrics_token", True),
            ("smtp_password", True),
            ("api_key", True),
            ("key_path", False),
            ("api_url", False),
            ("user", False),
            ("token_lifetime", False),
            ("ssl_key", False),
        ],
    )
    def test_is_secret_key(self, key, secret):
        assert sb.is_secret_key(key) is secret

    def test_unparsable_ini_becomes_a_note_not_an_echo(self):
        out = sb.redact_ini_text("not = an [ini\n[[[")
        assert "could not be parsed" in out and "not = an" not in out


class TestScrubLog:
    def test_credentials_scrubbed_plain_lines_kept(self):
        out = sb.scrub_log_text(LOG_TEXT)
        for key in ("bearer_in_log", "password_in_log", "api_key_in_log"):
            assert SENTINELS[key] not in out, key
        assert "plain line that must survive intact" in out
        assert "GET /api/v1/leases" in out

    def test_tail_is_bounded(self):
        text = "\n".join(f"line {i}" for i in range(5000))
        out = sb.scrub_log_text(text, max_lines=10)
        assert out.count("\n") == 10 and "line 4999" in out and "line 4989" not in out


class TestBuildBundle:
    def test_member_set_is_exactly_the_documented_one(self):
        data, names = sb.build_bundle(_collected(), now=NOW)
        assert names == [
            "README.txt",
            "alerts-tail.json",
            "audit-tail.json",
            "config.ini.redacted",
            "db.json",
            "drift.json",
            "health.json",
            "jen.json",
            "kea/1-dhcp4.json",
            "lease-history-7d.json",
            "logs/jen.log.tail",
            "plugins.json",
            "servers.json",
        ]
        assert set(_unzip(data)) == set(names)

    def test_journald_note_when_no_log_file(self):
        data, names = sb.build_bundle(_collected(log_text=None, log_note="journald here\n"), now=NOW)
        assert "logs/README.txt" in names and "logs/jen.log.tail" not in names
        assert _unzip(data)["logs/README.txt"] == "journald here\n"

    def test_readme_carries_version_channel_and_notes(self):
        data, _ = sb.build_bundle(_collected(notes=["health: TimeoutError: kea"]), now=NOW)
        readme = _unzip(data)["README.txt"]
        assert "v5.33.0-beta.1 (beta channel)" in readme and "jen-box" in readme
        assert "health: TimeoutError: kea" in readme

    def test_bundle_is_deterministic_for_the_same_input(self):
        a, _ = sb.build_bundle(_collected(), now=NOW)
        b, _ = sb.build_bundle(_collected(), now=NOW)
        assert a == b

    def test_filename(self):
        assert sb.bundle_filename("jen box/1", NOW) == "jen-support-jen-box-1-20260914-1200.zip"
        assert sb.bundle_filename("", NOW) == "jen-support-jen-20260914-1200.zip"


class TestSizeCap:
    def test_droppable_members_go_largest_first(self):
        members = {
            "README.txt": b"r",
            "logs/jen.log.tail": b"x" * 100,
            "audit-tail.json": b"y" * 50,
            "health.json": b"h" * 30,
        }
        kept, dropped = sb.apply_size_cap(dict(members), cap=90)
        assert dropped == ["logs/jen.log.tail"]  # 181 → 81 ≤ 90, stop
        assert "audit-tail.json" in kept and "health.json" in kept

    def test_never_drops_the_core_members(self):
        members = {"health.json": b"h" * 1000, "jen.json": b"j" * 1000}
        kept, dropped = sb.apply_size_cap(dict(members), cap=10)
        assert dropped == [] and set(kept) == {"health.json", "jen.json"}

    def test_cap_is_recorded_in_the_readme(self):
        # Distinct short lines: one long run would be scrubbed as base64 and shrink.
        big = _collected(log_text="\n".join(f"line {i} ok" for i in range(600)))
        data, names = sb.build_bundle(big, now=NOW, cap=4000)
        assert "logs/jen.log.tail" not in names
        assert "dropped to stay under" in _unzip(data)["README.txt"]


class TestNoSecretSurvives:
    """THE guarantee. Every secret-bearing input seeded, nothing leaks."""

    def test_every_sentinel_is_absent_from_every_member(self):
        data, names = sb.build_bundle(_collected(), now=NOW)
        members = _unzip(data)
        leaks = [(name, key) for name, body in members.items() for key, s in SENTINELS.items() if s in body]
        assert not leaks, f"secrets leaked into the bundle: {leaks}"
        # And the redaction was real, not an accident of the inputs:
        kea = json.loads(members["kea/1-dhcp4.json"])
        clients = kea["config"]["Dhcp4"]["control-sockets"][0]["authentication"]["clients"]
        assert clients[0]["password"] == "********"
        assert kea["config"]["Dhcp4"]["hosts-database"]["password"] == "********"
        assert (
            kea["config"]["Dhcp4"]["control-sockets"][0]["key-file"] == "/etc/kea/tls/dhcp4/server.key"
        )  # a path, kept

    def test_key_file_contents_are_never_read(self, tmp_path, monkeypatch):
        """The collectors must not open any private key even if the
        config points at one that exists."""
        from jen import extensions

        key = tmp_path / "jen_rsa"
        key.write_text("SENTINEL_PRIVATE_KEY_BODY")
        cfg = tmp_path / "jen.config"
        cfg.write_text(f"[kea_ssh]\nkey_path = {key}\n[server]\nlog_file = {tmp_path / 'jen.log'}\n")
        (tmp_path / "jen.log").write_text("hello\n")
        monkeypatch.setattr(extensions, "CONFIG_FILE", str(cfg))
        opened = []
        real_open = open

        def spy(path, *a, **k):
            opened.append(str(path))
            return real_open(path, *a, **k)

        monkeypatch.setattr("builtins.open", spy)
        text = sb._collect_config_text()
        log = sb._collect_log_text()
        assert "SENTINEL_PRIVATE_KEY_BODY" not in text and "SENTINEL_PRIVATE_KEY_BODY" not in (log or "")
        assert str(key) not in opened


class TestRoute:
    def test_superadmin_downloads_a_real_bundle(self, logged_in_client, db):
        r = logged_in_client.get("/settings/system/support-bundle")
        assert r.status_code == 200, r.data[:200]
        assert r.headers["Content-Type"].startswith("application/zip")
        assert r.headers["Content-Disposition"].startswith("attachment; filename=jen-support-")
        members = _unzip(r.data)
        assert "README.txt" in members and "health.json" in members and "config.ini.redacted" in members
        assert (
            "jen_test" not in members["config.ini.redacted"] or "password = ********" in members["config.ini.redacted"]
        )
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) c FROM audit_log WHERE action='SUPPORT_BUNDLE'")
            assert cur.fetchone()["c"] >= 1

    def test_admin_is_refused(self, client, db):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=None, role="admin", username="_bundle_admin")
        r = c.get("/settings/system/support-bundle", follow_redirects=True)
        assert b"superadmin access required" in r.data.lower()

    def test_system_page_offers_the_button(self, logged_in_client):
        page = logged_in_client.get("/settings/system").get_data(as_text=True)
        assert "/settings/system/support-bundle" in page and "Support bundle" in page
