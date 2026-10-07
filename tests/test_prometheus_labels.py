"""
tests/test_prometheus_labels.py
───────────────────────────────
v5.68.0-beta.19 (Q154) - every label value on /metrics goes through `_prom_label`. Subnet and server names are operator-typed free text; they were
interpolated raw (a quote or a backslash in one broke the whole scrape) and server names had their quotes STRIPPED (silently renaming the series).
The exposition is parsed with the real parser (`prometheus_client.parser`) so "valid" is not our own opinion.
"""

import pathlib

import pytest

from jen import extensions
from jen.routes import dashboard

BS = chr(92)  # a backslash, spelled so no layer of quoting can eat it
NL = chr(10)
DQ = chr(34)

NAMES = [
    f"He said {DQ}hi{DQ}",
    f"back{BS}slash",
    f"new{NL}line",
    "Ünïcødé — ☃",
    f"all {DQ}of{BS}it{DQ}{NL}",
]


class TestTheEscape:
    @pytest.mark.parametrize(
        "raw,escaped",
        [
            ("plain", "plain"),
            (f"a{DQ}b", f"a{BS}{DQ}b"),
            (f"a{BS}b", f"a{BS}{BS}b"),
            (f"a{NL}b", f"a{BS}nb"),
            (f"{BS}{DQ}", f"{BS}{BS}{BS}{DQ}"),
            ("Ünï ☃", "Ünï ☃"),
            (5, "5"),
        ],
    )
    def test_the_three_characters_the_format_requires(self, raw, escaped):
        assert dashboard._prom_label(raw) == escaped

    def test_nothing_is_stripped(self):
        assert dashboard._prom_label(f"a{DQ}b") != "ab"

    def test_no_label_site_still_strips_or_interpolates_raw(self):
        src = (pathlib.Path(__file__).resolve().parent.parent / "jen" / "routes" / "dashboard.py").read_text(
            encoding="utf-8"
        )
        assert ".replace('" + DQ + "', " + DQ + DQ + ")" not in src, "a label value is escaped, never stripped"
        assert '{info["name"]}' not in src and '{info["cidr"]}' not in src


class TestTheExpositionParses:
    @pytest.fixture
    def metrics_open(self, monkeypatch):
        import configparser

        cfg = configparser.ConfigParser()
        cfg.read_dict({s: dict(extensions.cfg.items(s)) for s in extensions.cfg.sections()})
        if "server" not in cfg:
            cfg["server"] = {}
        cfg["server"]["metrics_open"] = "true"
        monkeypatch.setattr(extensions, "cfg", cfg)

    def test_names_with_quotes_backslashes_newlines_and_unicode_survive_a_round_trip(
        self, client, db, mock_kea, metrics_open, monkeypatch
    ):
        parser = pytest.importorskip("prometheus_client.parser")
        monkeypatch.setattr(
            extensions, "SUBNET_MAP", {i + 1: {"name": n, "cidr": f"10.1.{i}.0/24"} for i, n in enumerate(NAMES)}
        )
        text = client.get("/metrics").get_data(as_text=True)
        seen = set()
        for family in parser.text_string_to_metric_families(text):
            for sample in family.samples:
                if "subnet" in sample.labels:
                    seen.add(sample.labels["subnet"])
        assert seen == set(NAMES), "every subnet name comes back exactly as typed"

    def test_a_server_name_with_a_quote_is_not_renamed(self, client, db, mock_kea, metrics_open, monkeypatch):
        parser = pytest.importorskip("prometheus_client.parser")
        from jen.services import kea as kea_svc

        name = f"Kea {DQ}primary{DQ}{BS}1"
        monkeypatch.setattr(
            kea_svc,
            "get_all_server_status",
            lambda: [
                {"server": {"id": 1, "name": name}, "up": True, "ha_state": None, "version": "3.0", "role": "primary"}
            ],
        )
        text = client.get("/metrics").get_data(as_text=True)
        names = {
            s.labels["server"]
            for fam in parser.text_string_to_metric_families(text)
            for s in fam.samples
            if "server" in s.labels
        }
        assert name in names
