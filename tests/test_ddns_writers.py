"""
tests/test_ddns_writers.py
──────────────────────────
v5.69.0-beta.7 (Q176) - jen/services/ddns_writers.py is pure: when a run_script hook is loaded, whether dhcp4 sends updates, and which DNS provider Jen looks names up on
(`effective_provider`: no Technitium DEFAULT, but a hand-written config that has a provider's URL or token and no `dns_provider` key still reads as the Technitium it was written
for, so an upgrade does not silently turn its lookups off). No DB: `pytest --noconftest tests/test_ddns_writers.py`.
"""

import configparser

import pytest

from jen.services import ddns_writers as w


def _cfg(**ddns):
    cfg = configparser.ConfigParser()
    if ddns:
        cfg["ddns"] = ddns
    return cfg


class TestHookLoaded:
    @pytest.mark.parametrize(
        "library",
        [
            "libdhcp_run_script.so",
            "/x/libdhcp_run_script.so",
            "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_run_script.so",
            " /x/libdhcp_run_script.so ",
        ],
    )
    def test_the_library_by_any_path(self, library):
        assert w.hook_loaded({"hooks-libraries": [{"library": library}]})

    @pytest.mark.parametrize(
        "library",
        [
            "/x/notlibdhcp_run_script.so",
            "/x/libdhcp_run_script.so.bak",
            "/x/libdhcp_run_script.sox",
            "/x/libdhcp_run_script.so/",
            "",
            None,
            5,
            ["a"],
        ],
    )
    def test_a_look_alike_is_not_the_library(self, library):
        assert not w.hook_loaded({"hooks-libraries": [{"library": library}]})

    @pytest.mark.parametrize(
        "dhcp4",
        [
            None,
            "x",
            {},
            {"hooks-libraries": "x"},
            {"hooks-libraries": [None, 3, "y"]},
            {"hooks-libraries": {"library": "a"}},
        ],
    )
    def test_malformed_shapes_are_not_loaded_and_never_raise(self, dhcp4):
        assert w.hook_loaded(dhcp4) is False


class TestUpdatesEnabled:
    def test_the_switch(self):
        assert w.updates_enabled({"dhcp-ddns": {"enable-updates": True}})
        assert not w.updates_enabled({"dhcp-ddns": {"enable-updates": False}})
        assert not w.updates_enabled({"dhcp-ddns": {}}) and not w.updates_enabled({}) and not w.updates_enabled(None)
        assert not w.updates_enabled({"dhcp-ddns": "x"})


class TestEffectiveProvider:
    def test_a_fresh_install_has_no_provider(self):
        assert w.effective_provider(_cfg()) == "none"

    def test_the_key_is_what_it_says(self):
        assert w.effective_provider(_cfg(dns_provider="pihole")) == "pihole"
        assert w.effective_provider(_cfg(dns_provider="none", api_url="http://x")) == "none", (
            "an explicit none is never overridden"
        )

    def test_an_upgraded_hand_written_config_keeps_the_technitium_it_was_written_for(self):
        assert w.effective_provider(_cfg(api_url="http://dns:5380")) == "technitium"
        assert w.effective_provider(_cfg(api_token="t")) == "technitium"
        assert w.effective_provider(_cfg(log_path="/var/log/kea/kea-ddns.log")) == "none", (
            "a log path alone is not a provider"
        )

    def test_a_blank_key_is_absent(self):
        assert w.effective_provider(_cfg(dns_provider="  ")) == "none"
