"""
tests/test_problems_templates.py
─────────────────────────────────
v5.68.0-beta.5 (Q140) — the Servers page's NAK and drop counters link to the Problems inbox filtered to that server; no database needed
(`pytest --noconftest tests/test_problems_templates.py`).
"""

import pathlib

from jinja2 import Environment, FileSystemLoader

from jen.services.icons import icon

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _render(named):
    env = Environment(loader=FileSystemLoader(str(ROOT / "templates")), autoescape=True)
    env.globals["icon"] = icon
    s = {
        "server": {"id": 7, "name": "kea-a"},
        "up": True,
        "packet_health": {"status": "ok", "notes": [], "window_minutes": 60, "named": named, "other_counters": []},
    }
    return env.get_template("_packet_health_block.html").render(s=s)


def _n(key, label, total):
    return {"key": key, "label": label, "total": total}


class TestTheCountersLinkToTheInbox:
    def test_naked_and_dropped_link_to_this_servers_problems_when_there_are_some(self):
        html = _render([_n("pkt4-nak-sent", "Naked", 12), _n("pkt4-receive-drop", "Dropped", 3)])
        assert html.count('href="/problems?server=7"') == 2
        assert ">12</a>" in html and ">3</a>" in html

    def test_a_zero_is_not_a_link(self):
        html = _render([_n("pkt4-nak-sent", "Naked", 0), _n("pkt4-receive-drop", "Dropped", 0)])
        assert "/problems" not in html

    def test_the_other_counters_are_plain_numbers(self):
        html = _render([_n("pkt4-received", "Received", 500), _n("pkt4-ack-sent", "Acked", 400)])
        assert "/problems" not in html and ">500<" in html
