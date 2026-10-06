"""
tests/test_client_page_labels.py
─────────────────────────────────
v5.68.0-beta.11 (Q146 e) — the freshness line under the Investigation page's facts names each thing it timestamps once. The first
item (when the device row was read) was labelled "Config", and the config's own SHA, further along the same line, was labelled
"Config" too: two different things under one word. The device fetch is "Device"; the SHA keeps "Config". No database: the line is
read from the template source.
`pytest --noconftest tests/test_client_page_labels.py`.
"""

import pathlib
import re

TEMPLATE = (pathlib.Path(__file__).resolve().parent.parent / "templates" / "client.html").read_text(encoding="utf-8")


def _freshness_line() -> str:
    start = TEMPLATE.index("fetched_at.get('device')")
    return TEMPLATE[TEMPLATE.rindex("<div", 0, start) : TEMPLATE.index("</div>", start)]


class TestTheFreshnessLine:
    def test_the_device_fetch_is_labelled_device(self):
        line = _freshness_line()
        assert re.search(r"Device \{\{ view\.fetched_at\.get\('device'\)", line)
        assert not re.search(r"Config \{\{ view\.fetched_at", line)

    def test_every_label_on_the_line_appears_once_and_the_sha_keeps_config(self):
        labels = re.findall(r"(?:^|\s)(Device|Leases|Reservations|Config)\s+(?:\{\{|\{%)", _freshness_line())
        # the Device, Leases and Reservations timestamps, then "Config <sha>" inside the config_sha condition
        assert labels == ["Device", "Leases", "Reservations", "Config"], labels
        assert "Config {{ config_sha[:8] }}" in _freshness_line()
