"""
tests/test_q57_quickwins.py
───────────────────────────
v5.50.0 (Q57) — the standard alert glyph set and the five quick wins.

Pure (no DB): `py -m pytest --noconftest tests/test_q57_quickwins.py`.
"""

import pathlib

from jen.services import alerts, config_doctor, kea_host

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


class TestAlertGlyphs:
    def test_every_default_opens_with_one_standard_glyph(self):
        glyphs = {g for g, _, _ in alerts.GLYPH_LEGEND}
        assert len(glyphs) == len(alerts.GLYPH_LEGEND) == 4
        for atype, text in alerts.DEFAULT_TEMPLATES.items():
            lead = text.split(" ", 1)[0]
            assert lead in glyphs, (atype, lead)

    def test_recoveries_are_green_and_outages_are_critical(self):
        t = alerts.DEFAULT_TEMPLATES
        ok = alerts.GLYPH_LEGEND[2][0]
        crit = alerts.GLYPH_LEGEND[0][0]
        for k in ("kea_up", "utilization_ok", "packet_health_ok", "config_drift_resolved"):
            assert t[k].startswith(ok), k
        for k in ("kea_down", "pool_exhaustion", "rogue_device"):
            assert t[k].startswith(crit), k

    def test_legend_is_rendered_from_data_not_literals(self):
        html = _read("templates/settings_alerts.html")
        assert "glyph_legend" in html
        assert 'id="al-glyph-legend"' in html


class TestHelperVersionPhrasing:
    def test_label(self):
        assert kea_host.helper_version_label(4, 5) == "v4 (v5 available)"
        assert kea_host.helper_version_label(5, 5) == "v5"
        assert kea_host.helper_version_label(None, 5) == "not recorded"

    def test_fleet_phrase(self):
        assert kea_host.helper_version_phrase([4], 5) == "1/1 host(s) on helper v4 (v5 available)"
        assert kea_host.helper_version_phrase([5, 5], 5) == "2/2 host(s) on helper v5"
        assert kea_host.helper_version_phrase([4, 5, None], 5) == (
            "1/3 host(s) on helper v4 (v5 available); 1/3 host(s) on helper v5; 1/3 host(s) with no helper recorded"
        )
        assert kea_host.helper_version_phrase([], 5) == ""

    def test_health_and_ssh_card_use_it(self):
        assert "helper_version_phrase" in _read("jen/services/health.py")
        assert "s.helper_label" in _read("templates/settings_kea.html")


def _f(fid, sev, where, detail="d"):
    return {"id": fid, "severity": sev, "title": fid, "why": "why", "fix_url": "/x", "where": where, "detail": detail}


class TestDoctorGrouping:
    def test_same_kind_collapses_and_keeps_order(self):
        findings = [_f("a", "warn", "one"), _f("b", "info", "x")] + [_f("a", "warn", f"r{i}") for i in range(3)]
        groups = config_doctor.group_findings(findings)
        assert [g["id"] for g in groups] == ["a", "b"]
        assert groups[0]["count"] == 4 and len(groups[0]["items"]) == 4
        assert groups[1]["count"] == 1

    def test_same_id_different_severity_stays_apart(self):
        groups = config_doctor.group_findings([_f("a", "warn", "1"), _f("a", "info", "2")])
        assert len(groups) == 2

    def test_empty(self):
        assert config_doctor.group_findings([]) == []


class TestLayoutQuickWins:
    def test_packet_counters_wrap(self):
        html = _read("templates/_packet_health_block.html")
        assert "repeat(auto-fit,minmax(96px,1fr))" in html and "for n in ph.named" in html

    def test_subnets_header_uses_the_action_bar(self):
        assert 'class="action-bar"' in _read("templates/subnets.html")
        assert ".action-bar" in _read("templates/base.html")

    def test_dashboard_header_stays_on_one_row(self):
        html = _read("templates/dashboard.html")
        assert 'aria-label="Auto-refresh"' in html and "flex-wrap:nowrap" in html
