"""
tests/test_alert_channel_encryption.py
──────────────────────────────────────
v5.7.0 — `alert_channels.config` (Telegram bot tokens, SMTP passwords,
Pushover keys, ntfy tokens, Slack/Discord/webhook URLs) is encrypted at
rest with the same Fernet key as the TOTP secrets (jen/services/crypto.py).

Covers the encode/decode helpers, migration 18 (wraps pre-existing
plaintext blobs), the save-route wiring, and the fail-soft behaviour when
a blob can't be decrypted (a DB restored without its /etc/jen key — a
channel goes quiet rather than crashing alert dispatch).

conftest repoints extensions.MFA_KEY_PATH at /tmp for the whole suite.
"""

import json

import pytest

from jen.models.db import jen_db
from jen.services import alerts, crypto


@pytest.fixture(autouse=True)
def _fresh_key_cache():
    crypto.reset_key_cache()
    yield
    crypto.reset_key_cache()


# ── encode/decode helpers ──────────────────────────────────────────────────
class TestChannelConfigCodec:
    def test_round_trip_and_ciphertext_hides_token(self):
        cfg = {"token": "123456:AAExampleBotToken", "chat_id": "-1001234"}
        blob = alerts.encode_channel_config(cfg)
        # stored as a JSON string literal so the JSON column stays valid
        assert blob.startswith('"v1:')
        assert json.loads(blob).startswith("v1:")
        assert "AAExampleBotToken" not in blob
        assert alerts.get_channel_config({"config": blob}) == cfg

    def test_legacy_plaintext_json_still_parses(self):
        cfg = {"smtp_host": "mail.example.com", "smtp_pass": "hunter2"}
        assert alerts.get_channel_config({"config": json.dumps(cfg)}) == cfg

    def test_dict_passthrough(self):
        cfg = {"webhook_url": "https://hooks.example.com/xyz"}
        assert alerts.get_channel_config({"config": cfg}) is cfg

    def test_empty_config_is_empty_dict(self):
        assert alerts.get_channel_config({"config": None}) == {}
        assert alerts.get_channel_config({"config": ""}) == {}
        assert alerts.get_channel_config({}) == {}

    def test_undecryptable_blob_is_soft_empty_not_raise(self):
        """A ciphertext this key can't open (DB moved without /etc/jen)
        yields {} so dispatch skips the channel, never throws."""
        out = alerts.get_channel_config({"config": '"v1:gAAAAABmangled"', "channel_name": "x"})
        assert out == {}
        # a genuinely corrupt (non-JSON) column value is also soft-empty
        assert alerts.get_channel_config({"config": "not json at all", "channel_name": "x"}) == {}

    def test_wrong_key_does_not_silently_pass_through(self, tmp_path, monkeypatch):
        from jen import extensions

        blob = alerts.encode_channel_config({"token": "secret-value"})
        monkeypatch.setattr(extensions, "MFA_KEY_PATH", str(tmp_path / "other_key"))
        crypto.reset_key_cache()
        assert alerts.get_channel_config({"config": blob}) == {}


# ── Migration 18 ───────────────────────────────────────────────────────────
class TestMigration18:
    def test_in_registry_and_applied(self):
        from jen.models.migrations import MIGRATIONS, applied_versions

        assert 18 in [v for v, _, _ in MIGRATIONS]
        assert 18 in applied_versions()

    def test_encrypts_plaintext_blob_preserves_content_and_is_idempotent(self):
        from jen.models.migrations import _m018_encrypt_alert_channel_config

        cfg = {"token": "999:PlainBotToken", "chat_id": "42"}
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM alert_channels WHERE channel_name='_enc_probe'")
                cur.execute(
                    "INSERT INTO alert_channels (channel_type, channel_name, enabled, config, alert_types) "
                    "VALUES ('telegram', '_enc_probe', 0, %s, %s)",
                    (json.dumps(cfg), json.dumps(["kea_down"])),
                )
            db.commit()
        try:
            with jen_db() as db:
                _m018_encrypt_alert_channel_config(db)
                db.commit()
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT config FROM alert_channels WHERE channel_name='_enc_probe'")
                after_first = cur.fetchone()["config"]
            assert after_first.startswith('"v1:')
            assert "PlainBotToken" not in after_first
            assert alerts.get_channel_config({"config": after_first}) == cfg

            # Re-run: already-encrypted row left byte-for-byte alone
            with jen_db() as db:
                _m018_encrypt_alert_channel_config(db)
                db.commit()
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT config FROM alert_channels WHERE channel_name='_enc_probe'")
                assert cur.fetchone()["config"] == after_first
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM alert_channels WHERE channel_name='_enc_probe'")
                db.commit()


# ── Dispatch reads the decrypted token ─────────────────────────────────────
class TestDispatchUsesDecryptedConfig:
    def test_get_active_channels_config_decrypts_for_senders(self):
        cfg = {"token": "555:DispatchToken", "chat_id": "7"}
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM alert_channels WHERE channel_name='_disp_probe'")
                cur.execute(
                    "INSERT INTO alert_channels (channel_type, channel_name, enabled, config, alert_types) "
                    "VALUES ('telegram', '_disp_probe', 1, %s, %s)",
                    (alerts.encode_channel_config(cfg), json.dumps(["kea_down"])),
                )
            db.commit()
        try:
            channel = next(c for c in alerts.get_active_channels() if c["channel_name"] == "_disp_probe")
            assert alerts.get_channel_config(channel) == cfg
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM alert_channels WHERE channel_name='_disp_probe'")
                db.commit()


# ── Save route stores ciphertext, not the submitted token ──────────────────
class TestSaveChannelRoute:
    def test_save_channel_persists_encrypted_config(self, logged_in_client):
        resp = logged_in_client.post(
            "/settings/alerts/save-channel",
            data={
                "channel_type": "telegram",
                "channel_name": "_save_probe",
                "enabled": "on",
                "token": "111:SubmittedBotToken",
                "chat_id": "123",
                "alert_types[]": ["kea_down"],
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200
        try:
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT config FROM alert_channels WHERE channel_name='_save_probe'")
                row = cur.fetchone()
            assert row is not None, "channel did not persist"
            assert row["config"].startswith('"v1:')
            assert "SubmittedBotToken" not in row["config"]
            assert alerts.get_channel_config({"config": row["config"]}) == {
                "token": "111:SubmittedBotToken",
                "chat_id": "123",
            }
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM alert_channels WHERE channel_name='_save_probe'")
                db.commit()

    def test_blank_secret_on_edit_keeps_the_stored_one(self, logged_in_client):
        """The 'leave blank to keep existing' path must decrypt the old
        row to recover the token, not write an empty one."""
        with jen_db() as db:
            with db.cursor() as cur:
                cur.execute("DELETE FROM alert_channels WHERE channel_name='_blank_probe'")
                cur.execute(
                    "INSERT INTO alert_channels (channel_type, channel_name, enabled, config, alert_types) "
                    "VALUES ('email', '_blank_probe', 1, %s, %s)",
                    (
                        alerts.encode_channel_config(
                            {"smtp_host": "mail.example.com", "smtp_pass": "keepme", "smtp_port": "587"}
                        ),
                        json.dumps(["kea_down"]),
                    ),
                )
            db.commit()
            with db.cursor() as cur:
                cur.execute("SELECT id FROM alert_channels WHERE channel_name='_blank_probe'")
                cid = cur.fetchone()["id"]
        try:
            resp = logged_in_client.post(
                "/settings/alerts/save-channel",
                data={
                    "channel_id": str(cid),
                    "channel_type": "email",
                    "channel_name": "_blank_probe",
                    "enabled": "on",
                    "smtp_host": "mail.example.com",
                    "smtp_port": "587",
                    "smtp_pass": "",
                    "alert_types[]": ["kea_down"],
                },
                follow_redirects=True,
            )
            assert resp.status_code == 200
            with jen_db() as db, db.cursor() as cur:
                cur.execute("SELECT config FROM alert_channels WHERE id=%s", (cid,))
                cfg = alerts.get_channel_config({"config": cur.fetchone()["config"]})
            assert cfg["smtp_pass"] == "keepme"
        finally:
            with jen_db() as db:
                with db.cursor() as cur:
                    cur.execute("DELETE FROM alert_channels WHERE channel_name='_blank_probe'")
                db.commit()
