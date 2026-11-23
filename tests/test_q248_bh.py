"""
tests/test_q248_bh.py
─────────────────────
v7.2.0-beta.6 (Q248) - the core rows of the executing pass on v7.2.0-beta.5.

* BH1  an account that sees every subnet and ticks nothing gets no API key (it got an unrestricted one).
* BH2  "all" beside a subnet id is refused (it made an unrestricted key).
* BH7  the email channel's plain-text part and subject are unescaped, like every other text-only channel.
* BH4  the image ships `ip`, so Jen can read the container's own addresses.
"""

import email
import pathlib
import re

import pytest

from jen.services import alerts

ROOT = pathlib.Path(__file__).resolve().parent.parent
KEY = "q248-bh-key"


def _stored(name):
    """(found, subnet_access) of the API key `name`."""
    from jen.models.db import jen_db

    with jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT subnet_access FROM api_keys WHERE name=%s", (name,))
        row = cur.fetchone()
    if row is None:
        return False, None
    return True, (row["subnet_access"] if isinstance(row, dict) else row[0])


@pytest.fixture
def no_key():
    from jen.models.db import jen_db

    def clean():
        with jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE name=%s", (KEY,))

    clean()
    yield
    clean()


class TestAnApiKeyIsNeverWiderThanTheBoxesTicked:
    """The account here is the suite's superadmin, which sees every subnet: the branch BH1 and BH2 are in."""

    def _subnet_id(self, client):
        html = client.get("/settings/api-keys").get_data(as_text=True)
        ids = re.findall(r'name="subnet_ids" value="(\d+)"', html)
        assert ids, "the test configuration has no subnet to tick"
        return ids[0]

    def test_nothing_ticked_makes_no_key(self, logged_in_client, no_key):
        r = logged_in_client.post("/settings/api-keys/create", data={"name": KEY}, follow_redirects=True)
        assert r.status_code == 200
        assert _stored(KEY) == (False, None), "a key was created with nothing ticked"
        assert "Tick All Subnets or at least one subnet. No key was created." in r.get_data(as_text=True)

    def test_all_beside_a_subnet_makes_no_key(self, logged_in_client, no_key):
        sid = self._subnet_id(logged_in_client)
        r = logged_in_client.post(
            "/settings/api-keys/create", data={"name": KEY, "subnet_ids": ["all", sid]}, follow_redirects=True
        )
        assert r.status_code == 200
        assert _stored(KEY) == (False, None), "a key was created from All Subnets beside a subnet"
        assert "Tick All Subnets or named subnets, not both. No key was created." in r.get_data(as_text=True)

    def test_all_alone_is_the_one_way_to_an_unrestricted_key(self, logged_in_client, no_key):
        r = logged_in_client.post(
            "/settings/api-keys/create", data={"name": KEY, "subnet_ids": ["all"]}, follow_redirects=True
        )
        assert r.status_code == 200
        assert _stored(KEY) == (True, None)

    def test_a_subnet_alone_is_that_subnet(self, logged_in_client, no_key):
        sid = self._subnet_id(logged_in_client)
        r = logged_in_client.post(
            "/settings/api-keys/create", data={"name": KEY, "subnet_ids": [sid]}, follow_redirects=True
        )
        assert r.status_code == 200
        found, access = _stored(KEY)
        assert found and re.findall(r"\d+", str(access)) == [sid], access

    def test_the_page_says_what_the_route_does(self, logged_in_client):
        html = logged_in_client.get("/settings/api-keys").get_data(as_text=True)
        assert "With nothing ticked no key is created." in html
        assert (
            "<select"
            not in (ROOT / "jen" / "routes" / "api.py")
            .read_text(encoding="utf-8")
            .split("def api_keys_create", 1)[1]
            .split("\ndef ", 1)[0]
        ), "the comment still describes the select the form no longer has (BH12)"


class TestTheEmailPlainPartIsUnescaped:
    def _send(self, monkeypatch, message):
        import smtplib

        sent = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=0):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def starttls(self, context=None):
                pass

            def login(self, *a):
                pass

            def sendmail(self, frm, to, body):
                sent["body"] = body

        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        cfg = {"smtp_host": "h", "smtp_port": 587, "from_addr": "jen@x.test", "to_addr": "a@x.test"}
        assert alerts._send_email_channel(message, "kea_down", cfg) is True
        msg = email.message_from_string(sent["body"])
        parts = {
            p.get_content_type(): p.get_payload(decode=True).decode("utf-8") for p in msg.walk() if not p.is_multipart()
        }
        return msg, parts

    def test_an_escaped_value_reads_as_typed_in_the_plain_part_and_stays_escaped_in_the_html_part(self, monkeypatch):
        msg, parts = self._send(monkeypatch, "<b>Conflict</b> in Lab &amp; &lt;one&gt;\nhost AT&amp;T &lt;hotspot&gt;")
        assert "Lab & <one>" in parts["text/plain"] and "AT&T <hotspot>" in parts["text/plain"]
        assert "&amp;" not in parts["text/plain"] and "&lt;" not in parts["text/plain"]
        assert "Lab &amp; &lt;one&gt;" in parts["text/html"]
        assert msg["Subject"] == "Jen Alert: Conflict in Lab & <one>"

    def test_an_entity_that_is_a_line_break_cannot_start_a_second_header(self, monkeypatch):
        msg, _parts = self._send(monkeypatch, "Down &#13;&#10;Bcc: x@y.test\nsecond line")
        assert msg["Bcc"] is None
        assert "\n" not in msg["Subject"] and "\r" not in msg["Subject"]
        assert msg["Subject"] == "Jen Alert: Down Bcc: x@y.test"


class TestTheImageShipsIp:
    def test_iproute2_is_installed_in_the_image(self):
        apt_block = re.search(
            r"apt-get install.*?apt-get clean", (ROOT / "Dockerfile").read_text(encoding="utf-8"), re.S
        )
        assert re.search(r"^\s*iproute2\b", apt_block.group(0), re.M), (
            "iproute2 (the `ip` command) is not installed in the image"
        )

    def test_the_docker_guide_says_so(self):
        assert "iproute2" in (ROOT / "docs" / "docker.md").read_text(encoding="utf-8")
