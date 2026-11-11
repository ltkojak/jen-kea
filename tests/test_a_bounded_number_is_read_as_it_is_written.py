"""
tests/test_a_bounded_number_is_read_as_it_is_written.py
───────────────────────────────────────────────────────
7.0.0-beta.12 (Q226): the pure half of the pass on 7.0.0-beta.11 (Opus, AL1-AL32). Each class names its rows. The database-backed half - the Alerts page as a
restricted admin, the kept secret across a changed server, the Security page's printed numbers - is `tests/test_the_alerts_page_keeps_its_secrets.py`.

Pure: no database (`--noconftest` runs it on the Windows box), the real `StatefulKeaServer` for the write-path rows.
"""

import ast
import copy
import pathlib
import re
from contextlib import contextmanager

import pytest

from jen import extensions
from jen.services import kea_api_config as api
from jen.services import kea_changeset as cs
from jen.services import kea_transport_switch as sw
from jen.services.secret_keys import is_secret_key
from tests import _kea_api_world as world
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
SID = 7


def _bounds():
    """The table module, imported when a test asks: the file collects on a tree that lacks it (the control run against the previous tag), and those tests fail there as they should."""
    from jen.services import setting_bounds

    return setting_bounds


@pytest.fixture
def store(monkeypatch):
    return world.install_store(monkeypatch)


@pytest.fixture(autouse=True)
def probes(monkeypatch):
    return world.install_probes(monkeypatch)


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: "")
    monkeypatch.setattr("jen.services.investigation_logging.restore_window", lambda server, now=None: "")
    monkeypatch.setattr(cs, "record_outcome", lambda *a, **k: None)
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
    monkeypatch.setattr(api, "COMMAND_TIMEOUT", 0.6)


@pytest.fixture
def fake():
    f = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
    f.hang_seconds = 1.2
    f.start()
    yield f
    f.stop()


@pytest.fixture
def w(fake, store, monkeypatch):
    server = {"id": SID, "name": "kea-a", "api_url": fake.url, "ssh_host": "10.0.0.9", "config_transport": "api"}
    out = world.ProofWorld(fake, server, store, monkeypatch)
    out.start(copy.deepcopy(TWO_SUBNET_DHCP4))
    return out


def _settings(monkeypatch, **rows):
    monkeypatch.setattr("jen.models.user.get_global_setting", lambda k, d=None: rows.get(k, d))


class _Principal:
    """`current_user` for the route module's pure helpers."""

    def __init__(self, all_subnets: bool, ids=()):
        self.all_subnets = all_subnets
        self._ids = list(ids)

    def accessible_subnet_ids(self, subnet_map):
        return list(self._ids)


# ── the bounds ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestOneTableOfBounds:
    """AL5, AL8, AL9, AL11: one table, one reader, and every form reads the same table."""

    def test_the_table_has_the_ten_keys(self):
        assert set(_bounds().SETTING_BOUNDS) == {
            "rl_max_attempts",
            "rl_lockout_minutes",
            "audit_retention_days",
            "history_retention_days",
            "events_retention_days",
            "alert_log_retention_days",
            "snapshot_interval_minutes",
            "stale_device_days",
            "alert_threshold_pct",
            "pool_exhaustion_free",
        }

    @pytest.mark.parametrize(
        "key,raw,applied",
        [
            ("rl_max_attempts", "5000", 1000),
            ("rl_max_attempts", "00", 0),
            ("rl_max_attempts", "abc", 10),
            ("rl_lockout_minutes", "999999", 10080),
            ("audit_retention_days", "0", 0),
            ("audit_retention_days", "99999", 3650),
            ("history_retention_days", "0", 1),
            ("history_retention_days", "4000", 365),
            ("events_retention_days", "0", 1),
            ("alert_log_retention_days", "0", 1),
            ("alert_log_retention_days", "-7", 180),
            ("snapshot_interval_minutes", "1", 5),
            ("snapshot_interval_minutes", "99999", 1440),
            ("stale_device_days", "0", 1),
            ("stale_device_days", "9999", 365),
            ("alert_threshold_pct", "250", 100),
            ("alert_threshold_pct", "²", 80),
            ("pool_exhaustion_free", "999999999999", 1_000_000),
            ("pool_exhaustion_free", "0", 1),
        ],
    )
    def test_clamp(self, key, raw, applied):
        assert _bounds().clamp(key, raw) == applied

    def test_in_bounds_is_the_forms_test(self):
        assert _bounds().in_bounds("pool_exhaustion_free", "1000000") and not _bounds().in_bounds(
            "pool_exhaustion_free", "1000001"
        )
        assert _bounds().in_bounds("audit_retention_days", "0") and not _bounds().in_bounds(
            "history_retention_days", "0"
        )
        assert not _bounds().in_bounds("stale_device_days", "²") and not _bounds().in_bounds("stale_device_days", " 7")

    def test_an_unknown_key_is_an_error_not_a_guess(self):
        with pytest.raises(KeyError):
            _bounds().clamp("no_such_setting", "1")

    def test_the_constants_are_the_tables(self):
        from jen.services import alerts, auth

        assert (
            auth.MAX_ATTEMPTS_BOUND == 1000 and auth.MAX_LOCKOUT_MINUTES == 10080 and alerts.MAX_RETENTION_DAYS == 3650
        )
        assert auth.MAX_ATTEMPTS_BOUND is _bounds().bounds("rl_max_attempts")[2]

    @pytest.mark.parametrize(
        "rel,key",
        [
            ("jen/routes/settings/alerts.py", "pool_exhaustion_free"),
            ("jen/routes/settings/alerts.py", "alert_threshold_pct"),
            ("jen/routes/reports.py", "snapshot_interval_minutes"),
            ("jen/routes/reports.py", "history_retention_days"),
            ("jen/routes/devices.py", "stale_device_days"),
        ],
    )
    def test_every_form_asks_the_table(self, rel, key):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert re.search(rf'in_bounds\(\s*"{key}"', src), (rel, key)

    def test_the_readers_ask_the_table(self, monkeypatch):
        from jen.models import user
        from jen.services import alerts

        _settings(
            monkeypatch,
            stale_device_days="9999",
            alert_threshold_pct="250",
            pool_exhaustion_free="0",
            snapshot_interval_minutes="1",
            alert_log_retention_days="0",
        )
        assert user.get_stale_device_days() == 365
        assert alerts._int_setting("alert_threshold_pct", 80) == 100
        assert alerts._int_setting("pool_exhaustion_free", 5) == 1
        assert alerts._int_setting("snapshot_interval_minutes", 30) == 5
        assert alerts.alert_log_retention_days() == 1

    def test_no_reader_under_jen_reads_a_bounded_key_raw(self):
        """Every `get_global_setting("<key>"` of a table key under `jen/` is inside `setting_bounds` itself. (Q227, AM10) The Alerts and Reports pages were listed here as "the stored
        text beside its form": they printed a stored 0 or 5000 that the server never applies, and they read the table's reader now. A new raw reader is a finding."""
        allowed = {"jen/services/setting_bounds.py"}
        hits = []
        for path in (ROOT / "jen").rglob("*.py"):
            rel = path.relative_to(ROOT).as_posix()
            text = path.read_text(encoding="utf-8")
            for key in _bounds().SETTING_BOUNDS:
                for m in re.finditer(rf'get_global_setting\(\s*"{key}"', text):
                    if rel not in allowed:
                        hits.append(f"{rel}:{text[: m.start()].count(chr(10)) + 1} {key}")
        assert not hits, hits


class TestAZeroRetentionNeverEmptiesATable:
    """AL11: `purge_history` keyed "0 = keep forever" to the audit table's NAME; a stored 0 on a history key deleted the whole table on every pass."""

    def _purge(self, monkeypatch, **rows):
        from jen.services import alerts

        _settings(monkeypatch, **rows)
        seen: list[tuple] = []

        class _Cur:
            rowcount = 0

            def execute(self, sql, params=()):
                seen.append((sql, tuple(params)))

        class _Db:
            def cursor(self):
                @contextmanager
                def c():
                    yield _Cur()

                return c()

            def commit(self):
                pass

        @contextmanager
        def ctx():
            yield _Db()

        monkeypatch.setattr(alerts, "__jen_db_ctx", ctx, raising=False)
        monkeypatch.setattr(alerts, "_purge_old_alert_log", lambda: 0, raising=False)
        alerts.purge_history()
        return {sql.split("FROM ")[1].split(" ")[0]: params[0] for sql, params in seen}

    def test_zero_on_a_history_key_prunes_at_one_day_never_zero(self, monkeypatch):
        kept = self._purge(monkeypatch, history_retention_days="0", events_retention_days="0")
        assert (
            kept["lease_history"] == 1
            and kept["lease6_history"] == 1
            and kept["server_stats"] == 1
            and kept["events"] == 1
        )
        assert 0 not in kept.values()

    def test_zero_on_the_audit_log_still_keeps_forever(self, monkeypatch):
        kept = self._purge(monkeypatch, audit_retention_days="0")
        assert "audit_log" not in kept


class TestTheLockoutSentinelAndTheWindow:
    """AL12: 999 minutes was the sentinel for "until cleared" and any lockout of 999 minutes or more read as permanent at `/login`. AL18: the detection window for a lockout of 0 was 24
    hours while the ratchet called 0 the longest lockout; it is the longest lockout the page accepts."""

    def test_the_sentinel_is_named_and_no_route_tests_a_magnitude(self):
        from jen.services import auth

        assert auth.PERMANENT_LOCKOUT == -1
        for rel in ("jen/routes/auth.py", "jen/services/auth.py"):
            src = (ROOT / rel).read_text(encoding="utf-8")
            assert ">= 999" not in src and "= 999" not in src.replace("PERMANENT_LOCKOUT", ""), rel
        assert (ROOT / "jen/routes/auth.py").read_text(encoding="utf-8").count("== __auth.PERMANENT_LOCKOUT") == 3

    def test_a_permanent_lockout_answers_the_sentinel_writes_its_row_and_counts_a_week(self, monkeypatch):
        from jen.services import auth

        _settings(monkeypatch, rl_mode="ip", rl_max_attempts="3", rl_lockout_minutes="0")
        cur = _Cursor(
            ip=[3 * 86400, 2 * 86400, 60]
        )  # three failures spread over three days: inside a week, outside 24 hours
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        assert auth.is_locked_out("10.0.0.1", "admin") == (True, auth.PERMANENT_LOCKOUT)
        counts = [p for q, p in zip(cur.queries, cur.params, strict=True) if "COUNT(*)" in q]
        assert counts == [("10.0.0.1", auth.MAX_LOCKOUT_MINUTES)], (
            "the window for 0 is the longest lockout, not 24 hours"
        )
        assert ("ip", "10.0.0.1") in cur.locked, "the permanent lockout is a ROW from this moment"

    def test_a_long_timed_lockout_is_timed(self, monkeypatch):
        from jen.services import auth

        _settings(monkeypatch, rl_mode="ip", rl_max_attempts="3", rl_lockout_minutes="10080")
        cur = _Cursor(ip=[90, 60, 30])
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        locked, minutes = auth.is_locked_out("10.0.0.1", "admin")
        assert locked and minutes == 10079 and minutes != auth.PERMANENT_LOCKOUT
        assert not cur.locked


class TestAPermanentLockoutIsARow:
    """The beta.11 review's P2 #3: a "permanent" lockout was the rolling window alone, and the attempts it was counted from were pruned after 24 hours, so it ended within a day with nobody
    clearing it. A permanent lockout is a row in `login_lockouts` (migration 39), read before the count, written when a bucket crosses the line under a lockout of 0, deleted by clear-lockouts."""

    def test_a_row_locks_before_any_attempt_is_counted(self, monkeypatch):
        from jen.services import auth

        _settings(monkeypatch, rl_mode="both", rl_max_attempts="3", rl_lockout_minutes="15")
        cur = _Cursor(locked=[("username", "admin")])
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        assert auth.is_locked_out("10.0.0.1", "admin") == (True, auth.PERMANENT_LOCKOUT)
        assert not [q for q in cur.queries if "COUNT(*)" in q], (
            "the row answers; no attempt is counted (and the pruned table cannot end it)"
        )

    def test_a_row_for_another_bucket_than_the_mode_counts_does_not_lock(self, monkeypatch):
        from jen.services import auth

        _settings(monkeypatch, rl_mode="ip", rl_max_attempts="3", rl_lockout_minutes="15")
        cur = _Cursor(locked=[("username", "admin")])
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        assert auth.is_locked_out("10.0.0.1", "admin") == (False, 0)

    def test_the_prune_keeps_a_week(self):
        from jen.services import auth

        seen = []

        class _Cur:
            def execute(self, sql, params=()):
                seen.append((sql, tuple(params)))

        auth._last_prune = 0.0
        assert auth._maybe_prune_login_attempts(_Cur(), now=10_000.0)
        assert seen == [
            (
                "DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL %s MINUTE)",
                (auth.MAX_LOCKOUT_MINUTES,),
            )
        ]

    def test_clear_lockouts_deletes_both_tables(self):
        src = (ROOT / "jen/routes/settings/security.py").read_text(encoding="utf-8")
        assert 'cur.execute("DELETE FROM login_attempts")' in src and '"DELETE FROM login_lockouts"' in src

    def test_migration_39_is_registered_with_one_guarded_statement(self):
        from jen.models.migrations import MIGRATIONS, _m039_login_lockouts

        by_version = {v: fn.__name__ for v, _d, fn in MIGRATIONS}
        assert by_version[39] == "_m039_login_lockouts" and MIGRATIONS[-1][0] == 39
        src = (ROOT / "jen/models/migrations.py").read_text(encoding="utf-8")
        body = src.split("def _m039_login_lockouts", 1)[1].split("\n\n\n", 1)[0]
        assert body.count("cur.execute(") == 1 and "CREATE TABLE IF NOT EXISTS login_lockouts" in body
        assert _m039_login_lockouts.__doc__ and "Q226" in _m039_login_lockouts.__doc__


class TestAPolicyIsSavedWholeOrNotAtAll:
    """The beta.11 review's P2 #5: `set_global_setting` answers False on a failed write and the routes said "saved" anyway, in three commits per policy."""

    def test_set_global_settings_is_one_statement_in_one_transaction(self, monkeypatch):
        from jen.models import user

        seen = []

        class _Cur:
            def executemany(self, sql, rows):
                seen.append(("many", sql, list(rows)))

        class _Db:
            committed = 0

            def cursor(self):
                @contextmanager
                def c():
                    yield _Cur()

                return c()

            def commit(self):
                _Db.committed += 1

        @contextmanager
        def ctx():
            yield _Db()

        monkeypatch.setattr("jen.models.db.jen_db", ctx)
        assert user.set_global_settings({"rl_max_attempts": "5", "rl_lockout_minutes": "30", "rl_mode": "both"}) is True
        assert len(seen) == 1 and seen[0][2] == [
            ("rl_max_attempts", "5"),
            ("rl_lockout_minutes", "30"),
            ("rl_mode", "both"),
        ]
        assert _Db.committed == 1

    def test_a_failed_write_answers_false_and_raises_nothing(self, monkeypatch):
        from jen.models import user

        @contextmanager
        def ctx():
            raise RuntimeError("the database is gone")
            yield

        monkeypatch.setattr("jen.models.db.jen_db", ctx)
        assert user.set_global_settings({"rl_mode": "both"}) is False
        assert user.set_global_settings({}) is True, "nothing to write is written"

    @pytest.mark.parametrize(
        "rel,fn",
        [
            ("jen/routes/settings/security.py", "save_rate_limit"),
            ("jen/routes/settings/security.py", "save_session_settings"),
            ("jen/routes/settings/alerts.py", "save_alert_global"),
            ("jen/routes/reports.py", "save_report_settings"),
            ("jen/routes/devices.py", "save_device_settings"),
            ("jen/routes/settings/__init__.py", "save_audit_retention"),
        ],
    )
    def test_every_policy_route_uses_the_answer(self, rel, fn):
        """No bare `set_global_setting(...)` statement: the answer is tested, and a policy of several rows goes through `set_global_settings`."""
        src = (ROOT / rel).read_text(encoding="utf-8")
        tree = ast.parse(src)
        f = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == fn)
        bare = [
            n.lineno
            for n in ast.walk(f)
            if isinstance(n, ast.Expr)
            and isinstance(n.value, ast.Call)
            and getattr(n.value.func, "attr", "") in ("set_global_setting", "set_global_settings")
        ]
        assert not bare, (rel, fn, bare)
        calls = [
            n for n in ast.walk(f) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "set_global_setting"
        ]
        assert len(calls) <= 1, "several rows of one policy are one `set_global_settings` call"


class TestADamagedScopeDeliversNoSubnetSpecificAlert:
    """The beta.11 review's P1 #2 (Fable: P2 - a hand-edited row, since no form writes an empty or unreadable scope; the fix is the reader's). NULL stays the one deliberate "every subnet"."""

    @pytest.mark.parametrize("scope", ["[]", "not json", "{}", "[true]", '["1"]', "5"])
    def test_a_damaged_scope_is_no_subnet(self, scope):
        from jen.services import alerts

        assert alerts.channel_allows_subnet({"subnet_scope": scope}, 2) is False
        assert alerts.channel_allows_subnet({"subnet_scope": scope}, None, scoped=True) is False
        assert alerts.channel_allows_subnet({"subnet_scope": scope}, None) is True, (
            "a server-level alert still goes through"
        )

    def test_null_is_every_subnet_and_a_list_is_itself(self):
        from jen.services import alerts

        assert alerts.channel_allows_subnet({"subnet_scope": None}, 2) is True
        assert (
            alerts.channel_allows_subnet({"subnet_scope": "[1, 2]"}, 2) is True
            and alerts.channel_allows_subnet({"subnet_scope": "[1, 2]"}, 3) is False
        )


from tests.test_the_mode_is_part_of_the_strictness import (  # noqa: E402  (the shared fakes: a table of attempt ages and a permanent-row table)
    _ctx,
    _Cursor,
)

# ── the Alerts page's pure half ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestAChannelsSecretIsWriteOnly:
    """AL2: the page carried every channel's decrypted config into a `<script>` block; AL3: a blank secret was kept across a changed SMTP host (CRED-002)."""

    def test_every_type_names_its_write_only_keys_and_the_form_marks_the_inputs(self):
        from jen.routes.settings import alerts as route

        assert set(route.WRITE_ONLY_KEYS) == set(route.CHANNEL_TYPES)
        html = (ROOT / "templates/settings_alerts.html").read_text(encoding="utf-8")
        for (ctype, key), field in route.WRITE_ONLY_FIELDS.items():
            assert key in route.WRITE_ONLY_KEYS[ctype], (ctype, key)
            tag = re.search(rf'<input[^>]*name="{field}"[^>]*>', html)
            assert tag and 'data-secret="1"' in tag.group(0) and 'type="password"' in tag.group(0), field
        assert len(route.WRITE_ONLY_FIELDS) == sum(len(v) for v in route.WRITE_ONLY_KEYS.values())

    def test_shown_carries_the_named_keys_and_nothing_else(self):
        """(Q227, AM1, AM7) `_shown` is an allowlist. It used to blank the declared type's write-only keys and print every key it did not know."""
        from jen.routes.settings import alerts as route

        assert route._shown("telegram", {"token": "111:abc", "chat_id": "9"}) == {"chat_id": "9"}
        assert route._shown("email", {"smtp_host": "m", "smtp_pass": "p", "use_tls": "false"}) == {
            "smtp_host": "m",
            "use_tls": "false",
        }
        assert route._shown("slack", {"webhook_url": "https://hooks.slack.com/x"}) == {}
        assert route._shown(
            "webhook",
            {
                "webhook_url": "https://h/x?k=t",
                "header_name": "Authorization",
                "header_value": "Bearer t",
                "payload_type": "json",
            },
        ) == {"header_name": "Authorization", "payload_type": "json"}
        assert route._shown("pushover", {"user_key": "u", "api_token": "t"}) == {}

    def test_a_row_whose_type_does_not_describe_its_config_shows_no_secret(self):
        """(Q227, AM1) an edit before 5.69.0 wrote the form's config and left the row's type: a Telegram config under `webhook`, a Slack URL under `telegram`."""
        from jen.routes.settings import alerts as route

        assert route._shown("webhook", {"token": "111:abc", "chat_id": "9"}) == {}
        assert route._shown("telegram", {"webhook_url": "https://hooks.slack.com/x"}) == {}
        assert route._shown("email", {"user_key": "u", "api_token": "t", "token": "n"}) == {}

    def test_an_extra_key_and_an_unknown_type_show_nothing(self):  # AM7
        from jen.routes.settings import alerts as route

        assert route._shown("telegram", {"chat_id": "9", "bot_secret": "s"}) == {"chat_id": "9"}
        assert route._shown("matrix", {"homeserver": "https://m", "access_token": "t"}) == {}
        assert route._shown("telegram", None) == {} and route._shown("", {"token": "t"}) == {}

    def test_no_shown_key_is_write_only_under_any_type(self):
        """(Q227, AM1) the two tables cannot disagree: a key the page may carry is a secret under NO type, so a config stored under the wrong type has nothing to show."""
        from jen.routes.settings import alerts as route

        assert set(route.SHOWN_KEYS) == set(route.CHANNEL_TYPES) == set(route.WRITE_ONLY_KEYS)
        secret = {k for keys in route.WRITE_ONLY_KEYS.values() for k in keys}
        shown = {k for keys in route.SHOWN_KEYS.values() for k in keys}
        assert not secret & shown, sorted(secret & shown)
        assert "webhook_url" in route.WRITE_ONLY_KEYS["webhook"], "AM1, AM23: a generic webhook's URL carries its token"

    def test_the_route_sends_the_page_only_what_shown_gives(self):
        src = (ROOT / "jen/routes/settings/alerts.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "settings_alerts")
        assigns = [
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.Assign)
            and any(
                isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) and t.slice.value == "config"
                for t in n.targets
            )
        ]
        assert assigns and all(
            isinstance(a.value, ast.Call) and getattr(a.value.func, "id", "") == "_shown" for a in assigns
        )

    def _kept(self, monkeypatch, channel_type, new, old, old_type=None):
        from jen.routes.settings import alerts as route

        monkeypatch.setattr(route.__alerts, "get_channel_config", lambda row: dict(old)) if False else None
        monkeypatch.setattr("jen.services.alerts.get_channel_config", lambda row: dict(old))
        stored = {"id": 4, "channel_type": old_type or channel_type, "config": "x"}
        return route._kept_secrets(4, channel_type, dict(new), stored)

    def test_a_blank_password_is_kept_for_the_same_server_port_and_wire(self, monkeypatch):
        old = {"smtp_host": "mail.example.test", "smtp_port": "587", "smtp_pass": "s3cret", "use_tls": "true"}
        new = {"smtp_host": "mail.example.test", "smtp_port": "587", "smtp_pass": "", "use_tls": "true"}
        assert self._kept(monkeypatch, "email", new, old)["smtp_pass"] == "s3cret"

    @pytest.mark.parametrize(
        "change",
        [
            {"smtp_host": "other.example.test"},
            {"smtp_port": "25"},
            {"use_tls": "false"},
            {"smtp_host": "MAIL.example.test:2525"},
        ],
    )
    def test_a_blank_password_for_a_changed_place_is_refused_and_names_the_field(self, monkeypatch, change):
        old = {"smtp_host": "mail.example.test", "smtp_port": "587", "smtp_pass": "s3cret", "use_tls": "true"}
        new = {**old, "smtp_pass": "", **change}
        from jen.routes.settings import alerts as route

        assert self._kept(monkeypatch, "email", new, old) == ("smtp_pass", route.DESTINATION_CHANGED)

    def test_a_typed_password_is_taken_whatever_the_place(self, monkeypatch):
        old = {"smtp_host": "mail.example.test", "smtp_port": "587", "smtp_pass": "s3cret", "use_tls": "true"}
        new = {**old, "smtp_host": "other.example.test", "smtp_pass": "new"}
        assert self._kept(monkeypatch, "email", new, old)["smtp_pass"] == "new"

    def test_a_webhooks_header_is_bound_to_its_url_and_a_providers_token_to_nothing(self, monkeypatch):
        from jen.routes.settings import alerts as route

        # (Q228, the beta.13 review's #2) this cell kept the value across a changed PATH and said "a path is not a place". For a webhook it is: two paths of one host are two
        # receivers (`auth.same_destination`). The same address still keeps it
        assert self._kept(
            monkeypatch,
            "webhook",
            {"webhook_url": "https://h/x", "header_value": ""},
            {"webhook_url": "https://h/y", "header_value": "B"},
        ) == ("header_value", route.DESTINATION_CHANGED)
        assert (
            self._kept(
                monkeypatch,
                "webhook",
                {"webhook_url": "https://h/y/", "header_value": ""},
                {"webhook_url": "https://h/y", "header_value": "B"},
            )["header_value"]
            == "B"
        )
        assert self._kept(
            monkeypatch,
            "webhook",
            {"webhook_url": "https://h2/x", "header_value": ""},
            {"webhook_url": "https://h/x", "header_value": "B"},
        ) == ("header_value", route.DESTINATION_CHANGED)
        assert (
            self._kept(monkeypatch, "telegram", {"token": "", "chat_id": "9"}, {"token": "T", "chat_id": "1"})["token"]
            == "T"
        )
        assert self._kept(
            monkeypatch, "pushover", {"user_key": "", "api_token": ""}, {"user_key": "U", "api_token": "A"}
        ) == {"user_key": "U", "api_token": "A"}

    def test_a_channel_whose_type_changed_keeps_nothing(self, monkeypatch):
        from jen.routes.settings import alerts as route

        # (Q228, the beta.13 review's #3) nothing is kept: Telegram's `token` is not ntfy's. An ntfy token is one the channel works without, so the blank is "none" and the
        # channel is saved; a blank secret the new type NEEDS is still refused
        assert self._kept(
            monkeypatch,
            "ntfy",
            {"url": "https://ntfy.sh", "topic": "t", "token": ""},
            {"token": "T"},
            old_type="telegram",
        ) == {"url": "https://ntfy.sh", "topic": "t", "token": ""}
        assert self._kept(
            monkeypatch, "slack", {"webhook_url": ""}, {"token": "T", "chat_id": "9"}, old_type="telegram"
        ) == ("slack_webhook", route.DESTINATION_CHANGED)

    def test_a_stored_config_that_cannot_be_read_is_refused_and_says_why(self, monkeypatch):
        """(Q227, AM6) `get_channel_config` answers {} for a row whose config cannot be decrypted. A provider's token was then "kept" as "" and the page said saved."""
        from jen.routes.settings import alerts as route

        for ctype, new, field in (
            ("telegram", {"token": "", "chat_id": "9"}, "token"),
            ("pushover", {"user_key": "", "api_token": ""}, "pushover_user_key"),
            ("webhook", {"webhook_url": "", "header_value": ""}, "webhook_url"),
        ):
            assert self._kept(monkeypatch, ctype, new, {}) == (field, route.STORED_UNREADABLE), ctype
        # (Q228, the beta.13 review's #3) an SMTP password is a secret the channel works without: over a row that cannot be read it is stored as none, and the save names it
        mail = {"smtp_host": "m", "smtp_port": "587", "smtp_pass": "", "use_tls": "true"}
        assert self._kept(monkeypatch, "email", mail, {}) == mail
        assert route._emptied("email", mail, {"id": 4, "channel_type": "email", "config": "x"}) == ["the SMTP password"]
        # a typed secret needs nothing of the stored row
        assert self._kept(monkeypatch, "telegram", {"token": "T2", "chat_id": "9"}, {}) == {
            "token": "T2",
            "chat_id": "9",
        }

    def test_a_channel_with_no_stored_secret_may_change_its_place(self, monkeypatch):
        """(Q227) only a key that HAS a stored value is kept, so only such a key is refused. A webhook with no authorization header could not change its URL: its always-blank
        header was "a secret for a changed place". The same for SMTP with no password and ntfy with no token."""
        assert self._kept(
            monkeypatch,
            "webhook",
            {"webhook_url": "https://h2/x", "header_name": "", "header_value": ""},
            {"webhook_url": "https://h/x", "header_name": "", "header_value": ""},
        ) == {"webhook_url": "https://h2/x", "header_name": "", "header_value": ""}
        old = {"smtp_host": "relay.example.test", "smtp_port": "25", "smtp_pass": "", "use_tls": "false"}
        new = {**old, "smtp_host": "relay2.example.test"}
        assert self._kept(monkeypatch, "email", new, old) == new
        assert self._kept(
            monkeypatch,
            "ntfy",
            {"url": "https://ntfy2.example.test", "topic": "t", "token": ""},
            {"url": "https://ntfy.sh"},
        ) == {"url": "https://ntfy2.example.test", "topic": "t", "token": ""}

    def test_a_blank_webhook_url_is_the_stored_one_and_its_header_stays_with_it(self, monkeypatch):
        """(Q227, AM1) the URL is write-only now: the edit form posts it blank, the stored one is taken BEFORE the place is compared, and the header beside it is kept."""
        old = {"webhook_url": "https://h/x?k=t", "header_name": "Authorization", "header_value": "B"}
        assert self._kept(
            monkeypatch, "webhook", {"webhook_url": "", "header_name": "Authorization", "header_value": ""}, old
        ) == {"webhook_url": "https://h/x?k=t", "header_name": "Authorization", "header_value": "B"}
        assert self._kept(
            monkeypatch, "webhook", {"webhook_url": "", "header_name": "Authorization", "header_value": "B2"}, old
        ) == {"webhook_url": "https://h/x?k=t", "header_name": "Authorization", "header_value": "B2"}

    def test_a_new_channel_keeps_nothing(self):
        from jen.routes.settings import alerts as route

        cfg = {"smtp_host": "m", "smtp_port": "587", "smtp_pass": "", "use_tls": "true"}
        assert route._kept_secrets("", "email", dict(cfg), None) == cfg


class TestARestrictedAdminSeesOnlyChannelsInsideTheirScope:
    """AL24 (and AL2's reach): a restricted admin reads, edits, tests and deletes only a channel whose scope lies inside their own; AL1: a channel for every subnet says so."""

    def test_may_act_on(self, monkeypatch):
        from jen.routes.settings import alerts as route

        monkeypatch.setattr(route, "current_user", _Principal(False, [1, 2]))
        assert route._may_act_on({"subnet_scope": "[1]"}) and route._may_act_on({"subnet_scope": "[1, 2]"})
        assert not route._may_act_on({"subnet_scope": None}), "every subnet is wider than theirs"
        assert not route._may_act_on({"subnet_scope": "[1, 3]"}) and not route._may_act_on({"subnet_scope": "[]"})
        assert not route._may_act_on({"subnet_scope": "not json"}) and not route._may_act_on({"subnet_scope": "[true]"})
        monkeypatch.setattr(route, "current_user", _Principal(True))
        assert route._may_act_on({"subnet_scope": None}) and route._may_act_on({"subnet_scope": "[3]"})

    def test_the_three_acting_routes_read_the_row_first(self):
        src = (ROOT / "jen/routes/settings/alerts.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        for name in ("save_alert_channel", "delete_alert_channel", "test_alert_channel"):
            fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
            calls = [n.func.id for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
            assert "_may_act_on" in calls and "_stored_channel" in calls, name

    def test_the_card_prints_a_scope_for_every_channel(self):
        html = (ROOT / "templates/settings_alerts.html").read_text(encoding="utf-8")
        assert "Subnet-specific alerts for all subnets" in html and "Subnet-specific alerts limited to:" in html


# ── OIDC ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestAMalformedSubnetMapNamesNoDefault:
    """AL4: a segment with no colon or no group name was skipped, and under `subnet_map_default = all` the login it was meant to scope came in unrestricted."""

    def test_the_errors_are_named(self):
        from jen.services import oidc

        assert oidc.subnet_map_errors("eng 1,2;:3;ok:4;;") == ["'eng 1,2' has no colon", "':3' has no group name"]
        assert oidc.subnet_map_errors("ok:1;all:*") == [] and oidc.subnet_map_errors("") == []

    @pytest.mark.parametrize("default", ["all", "none"])
    def test_a_login_under_a_malformed_map_is_scoped_to_nothing(self, monkeypatch, default):
        from jen.services import oidc

        monkeypatch.setattr(extensions, "OIDC_SUBNET_MAP", "eng 1,2;net:3", raising=False)
        monkeypatch.setattr(extensions, "OIDC_SUBNET_MAP_DEFAULT", default, raising=False)
        monkeypatch.setattr(extensions, "OIDC_ROLE_CLAIM", "groups", raising=False)
        assert oidc.map_subnet_access({"groups": ["eng"]}) == "[]"
        assert oidc.map_subnet_access({"groups": ["net"]}) == "[3]"

    def test_a_well_formed_map_keeps_the_default(self, monkeypatch):
        from jen.services import oidc

        monkeypatch.setattr(extensions, "OIDC_SUBNET_MAP", "net:3", raising=False)
        monkeypatch.setattr(extensions, "OIDC_SUBNET_MAP_DEFAULT", "all", raising=False)
        monkeypatch.setattr(extensions, "OIDC_ROLE_CLAIM", "groups", raising=False)
        assert oidc.map_subnet_access({"groups": ["nobody"]}) is None

    def test_the_form_refuses_a_malformed_map(self):
        src = (ROOT / "jen/routes/settings/security.py").read_text(encoding="utf-8")
        assert "__oidc.subnet_map_errors(subnet_map)" in src and re.search(r'flash_field\(\s*"subnet_map"', src)


class TestAnOidcLoginRefreshesTheOtherSessions:
    """AL7: the login rewrote `role` and `subnet_access` without `token_version`, alone among six writers. AL21: the scope was compared as text."""

    def test_both_statements_move_token_version(self):
        src = (ROOT / "jen/services/oidc.py").read_text(encoding="utf-8")
        updates = re.findall(r"UPDATE users SET (role|subnet_access)=%s[^\"]*", src)
        assert len(updates) == 2
        assert src.count("token_version=token_version+1 WHERE id=%s") == 2

    def test_the_scope_is_compared_as_a_value(self):
        from jen.services import oidc

        assert oidc._scope_json("[1, 2]") == oidc._scope_json("[1,2]") == [1, 2]
        assert oidc._scope_json(None) is None and oidc._scope_json(b"[3]") == [3]
        assert oidc._scope_json("not json") == "not json"


# ── stored scopes and secret names ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestAScopeListWithABadElementIsNoSubnets:
    """AL20."""

    @pytest.mark.parametrize("stored", ['[1, "abc"]', "[[1], 2]", "[true]", "[1.5]", '["1"]'])
    def test_no_subnets(self, stored):
        from jen.models.user import User

        u = User(1, "x", "admin", subnet_access=stored)
        assert u.all_subnets is False and u.can_access_subnet(1) is False, stored

    def test_a_list_of_ids_is_kept(self):
        from jen.models.user import User

        assert User(1, "x", "admin", subnet_access="[1, 2]").can_access_subnet(2) is True


class TestASecretNamesPluralAndNumber:
    """AL17."""

    @pytest.mark.parametrize(
        "name", ["secrets", "tokens", "api_keys", "apikeys", "password2", "smtp_password1", "hook-tokens"]
    )
    def test_a_secret(self, name):
        assert is_secret_key(name), name

    @pytest.mark.parametrize(
        "name", ["keys", "tokens-per-second", "mypassword", "bypass", "keyboard", "token_lifetime", "DBPASSWORD"]
    )
    def test_not_a_secret(self, name):
        assert not is_secret_key(name), name


# ── the write path ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestASectionIsAnObject:
    """AL29, AL30: `_section` collapsed the falsy shapes and a truthy non-dict fell through to `running == candidate`; two equal scalars answered True from both functions."""

    @pytest.mark.parametrize("value", ["text", 3, 1.5, True, ["a"]])
    def test_two_equal_non_objects_mirror_nothing(self, value):
        assert api.file_in_daemon({"Dhcp4": value}, {"Dhcp4": value}, "dhcp4") is False
        assert api.mirrors({"Dhcp4": value}, {"Dhcp4": value}, "dhcp4") is False

    def test_an_object_against_a_non_object_is_false_both_ways(self):
        live = {"Dhcp4": copy.deepcopy(TWO_SUBNET_DHCP4)}
        assert (
            api.mirrors({"Dhcp4": "text"}, live, "dhcp4") is False
            and api.mirrors(live, {"Dhcp4": "text"}, "dhcp4") is False
        )
        assert api.file_in_daemon(live, {"Dhcp4": 3}, "dhcp4") is False

    def test_the_controls_still_hold(self):
        live = {"Dhcp4": copy.deepcopy(TWO_SUBNET_DHCP4)}
        assert (
            api.mirrors(copy.deepcopy(live), live, "dhcp4") is True
            and api.file_in_daemon(copy.deepcopy(live), live, "dhcp4") is True
        )
        assert (
            api.mirrors({"Dhcp4": {}}, {"Dhcp4": {}}, "dhcp4") is False
            and api.mirrors(live, {"Dhcp4": {}}, "dhcp4") is False
        )


class TestTheRollbackRefusalNamesItsCause:
    """AL31: with the file untouched and the DAEMON answering an empty section, the refusal blamed the file and pointed at a Config-history row holding an unedited file."""

    def test_an_empty_daemon_answer_is_the_daemons_doing(self, w, fake, store, monkeypatch):
        cfg, digest = api.read(w.server, "dhcp4", capture=False)
        plan = api.file_proof(w.server, "dhcp4")
        candidate = copy.deepcopy(cfg)
        candidate["Dhcp4"]["valid-lifetime"] = 7200
        out = api.apply(w.server, "dhcp4", candidate, digest, "x", before_cfg=cfg, planned_sha=plan["sha256"])
        assert out["ok"], out
        fake.set_running({})  # the daemon now answers {"Dhcp4": {}}
        back = api.revert(w.server, "dhcp4", cfg, out["sha256"], "rollback: x", before_cfg=candidate)
        assert not back["ok"] and back["code"] == "guard", back
        assert (
            "came back empty; the file was not judged" in back["detail"]
            and "edited since Kea wrote it" not in back["detail"]
        ), back["detail"]


class TestARefusalBeforeTheSendSaysSo:
    """AL27: a `pending_block` refusal carries `needs_hands` (for the EARLIER change) and sends nothing; the change set's bucket reads `sent`."""

    def test_pending_block_carries_sent_false(self, w, fake, store, monkeypatch):
        cfg, digest = api.read(w.server, "dhcp4", capture=False)
        monkeypatch.setattr(
            api, "pending_block", lambda server, service: "an earlier change is unresolved - Settle it now"
        )
        fake.commands.clear()
        out = api.apply(w.server, "dhcp4", copy.deepcopy(cfg), digest, "x", before_cfg=cfg)
        assert out["needs_hands"] is True and out["sent"] is False and out["code"] == "unverified", out
        assert "config-set" not in fake.commands

    def test_the_bucket_reads_sent(self):
        src = (ROOT / "jen/services/kea_changeset.py").read_text(encoding="utf-8")
        assert 'if not rres.get("needs_hands") or rres.get("sent") is False:' in src


class TestTheAuditLineNamesADiscardOnlyWhenOneWasMade:
    """AL28: `file -> api` and `off -> api` always write a file, and the result's `consents` named the discard whether or not the write discarded anything."""

    FACTS = {
        "config_api": True,
        "test_ok": True,
        "include": [],
        "agree": False,
        "write": {"may_write": True, "account": "_kea", "mode": "0644"},
        "auth": "basic",
    }

    def test_a_proved_file_discards_nothing_and_the_consents_say_so(self, w, store, fake, monkeypatch):
        monkeypatch.setattr(api, "probe", lambda server, service="dhcp4", **k: dict(self.FACTS))
        monkeypatch.setattr(api, "file_proof", lambda *a, **k: api._proof(True, "loaded", sha256="f" * 64))
        monkeypatch.setattr(api, "record_rendering_after_write", lambda *a, **k: True)
        out = sw._to_api(w.server, "file", {"consent_rendering", "discard_file_edit"}, "me")
        assert out["ok"], out
        assert "discard_file_edit" not in out["consents"] and "consent_rendering" in out["consents"], out

    def test_the_control_an_edit_is_discarded_and_named(self, w, store, fake, monkeypatch):
        monkeypatch.setattr(api, "probe", lambda server, service="dhcp4", **k: dict(self.FACTS))
        monkeypatch.setattr(api, "file_proof", lambda *a, **k: api._proof(False, "none", why="edited"))
        monkeypatch.setattr(api, "record_rendering_after_write", lambda *a, **k: True)
        out = sw._to_api(w.server, "file", {"consent_rendering", "discard_file_edit"}, "me")
        assert out["ok"] and "discard_file_edit" in out["consents"], out

    def test_write_file_reports_the_discard(self, w, fake, monkeypatch):
        monkeypatch.setattr(api, "file_proof", lambda *a, **k: api._proof(False, "none", why="edited"))
        assert api.write_file(w.server, "dhcp4", discard=True)["discarded"] is True
        monkeypatch.setattr(api, "file_proof", lambda *a, **k: api._proof(True, "loaded", sha256="f" * 64))
        assert api.write_file(w.server, "dhcp4", discard=True)["discarded"] is False


# ── the tree ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestTheTreesSmallerRows:
    def test_no_exception_text_in_the_switchs_lines(self):  # AL25
        src = (ROOT / "jen/services/kea_transport_switch.py").read_text(encoding="utf-8")
        assert "({e})" not in src

    def test_the_dead_helpers_are_gone(self):  # AL26
        from jen.services import auth

        assert not hasattr(auth, "valid_positive_int")
        assert "_write_atomically" not in (ROOT / "jen/routes/settings/security.py").read_text(encoding="utf-8")

    def test_the_stale_days_statement_is_parameterized(self):  # AL10
        src = (ROOT / "jen/routes/devices.py").read_text(encoding="utf-8")
        assert "INTERVAL {stale_days}" not in src and "INTERVAL %s DAY" in src

    def test_the_log_page_number_is_whole(self):  # AL14
        src = (ROOT / "jen/routes/users.py").read_text(encoding="utf-8")
        assert '__text.whole(request.args.get("page", "1"), 1)' in src and 'int(request.args.get("page"' not in src

    def test_the_security_form_bounds_are_the_servers(self):  # AL6
        html = (ROOT / "templates/settings_security.html").read_text(encoding="utf-8")
        assert 'name="max_attempts" value="{{ rl.max_attempts }}" min="0" max="1000"' in html
        assert 'name="lockout_minutes" value="{{ rl.lockout_minutes }}" min="0" max="10080"' in html

    def test_the_security_page_prints_what_the_server_applies(self):  # AL5
        src = (ROOT / "jen/routes/settings/__init__.py").read_text(encoding="utf-8")
        assert "applied = __auth.get_rate_limit_settings()" in src and 'get_global_setting("rl_max_attempts"' not in src

    def test_the_api_key_scope_has_the_whole_shape(self):  # AL19
        src = (ROOT / "jen/routes/api.py").read_text(encoding="utf-8")
        assert "sorted({int(s) for s in subnet_ids_raw})" in src and src.count("Subnet ids must be numbers.") == 1

    def test_the_compat_rows_sentence_is_true(self):  # AL32
        src = (ROOT / "tests/kea_compat/test_config_write.py").read_text(encoding="utf-8")
        assert "written back as root afterward, as row 13 leaves it" not in src
        assert 'facts["mirrors_a_changed_key_reads_as"]' in src


class TestNoTestPatchesOneNameBothWays:
    """AL16: pytest undoes every `setattr` before every `setitem`, so a test that patches one name with both leaves the setattr's stub behind for the next test. Q225's fixup fixed the one
    instance; this refuses the class over every file under `tests/`."""

    def test_no_function_patches_one_name_with_setattr_and_setitem(self):
        hits = []
        for path in (ROOT / "tests").rglob("test_*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for fn in ast.walk(tree):
                if not isinstance(fn, ast.FunctionDef):
                    continue
                by_kind = {"setattr": set(), "setitem": set()}
                for call in ast.walk(fn):
                    if (
                        isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and call.func.attr in by_kind
                        and call.args
                    ):
                        target = call.args[0]
                        if isinstance(target, ast.Constant) and isinstance(target.value, str):
                            by_kind[call.func.attr].add(target.value.rsplit(".", 1)[-1])
                        elif (
                            len(call.args) > 1
                            and isinstance(call.args[1], ast.Constant)
                            and isinstance(call.args[1].value, str)
                        ):
                            by_kind[call.func.attr].add(call.args[1].value)
                both = by_kind["setattr"] & by_kind["setitem"]
                if both:
                    hits.append(f"{path.relative_to(ROOT)}::{fn.name} {sorted(both)}")
        assert not hits, hits


class TestTheRegistryCarriesThisReleasesRules:
    """AL15: five rules of beta.11 had no entry or an entry that was not updated; this release's are asked for in the other direction."""

    @pytest.mark.parametrize(
        "rid,test",
        [
            ("RBAC-001", "TestARestrictedAdminSeesOnlyChannelsInsideTheirScope"),
            ("RBAC-001", "TestARestrictedAdminsChannelCoversItsSubnets"),
            ("FAIL-001", "TestAnUnreadableScopeIsNoSubnets"),
            ("FAIL-001", "TestAScopeListWithABadElementIsNoSubnets"),
            ("CRED-002", "TestAChannelsSecretIsWriteOnly"),
            ("LEAK-001", "TestAChannelsSecretIsWriteOnly"),
            ("BOUND-001", "TestOneTableOfBounds"),
            ("BOUND-001", "TestAZeroRetentionNeverEmptiesATable"),
            ("DEF-003", "TestTheTreesSmallerRows"),
            ("CFG-002", "test_14_the_file_kea_wrote_mirrors_config_get"),
            ("CFG-004", "TestASectionIsAnObject"),
            ("CFG-005", "TestADiscardOverAnUnreadableFileIsRefused"),
            ("RBAC-003", "TestTheLockoutSentinelAndTheWindow"),
            ("RBAC-003", "TestAPermanentLockoutIsARow"),
            ("RBAC-003", "TestTheRemainingTimeIsTheNthMostRecentAttempt"),
            ("RBAC-001", "TestADamagedScopeDeliversNoSubnetSpecificAlert"),
            ("MIG-001", "TestMigration39LoginLockouts"),
            ("STORE-001", "TestAPolicyIsSavedWholeOrNotAtAll"),
            ("STORE-001", "TestAPolicySaveThatFailsSaysSo"),
        ],
    )
    def test_the_entry_names_the_test(self, rid, test):
        text = (ROOT / "docs/SAFETY_INVARIANTS.md").read_text(encoding="utf-8")
        section = text.split(f"### {rid} ")[1].split("\n### ")[0]
        assert test in section, (rid, test)
