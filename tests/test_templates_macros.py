"""
tests/test_templates_macros.py
──────────────────────────────
v5.69.0-beta.5 (Q174): three blocks of markup that had been pasted into several templates are macros now - the DDNS sub-tab row (ddns.html, ddns_reconcile.html), the IPv4 / IPv6
switch (leases, reservations, devices) and the two base64url helpers of the WebAuthn pages (mfa_enroll, mfa_challenge, reauth). Each test renders the markup the macro replaced (kept
here, verbatim) and the macro, and compares them byte for byte; a second test fails if a template grows its own copy again. Pure Jinja: no app, no database.
"""

import pathlib
from types import SimpleNamespace

import pytest
from jinja2 import DictLoader, Environment, FileSystemLoader

TEMPLATES = pathlib.Path("templates")


def _env(extra=None):
    from jinja2 import ChoiceLoader

    return Environment(
        loader=ChoiceLoader([DictLoader(extra or {}), FileSystemLoader(str(TEMPLATES))]), autoescape=True
    )


OLD_DDNS_TABS = """{% from '_settings_subtabs.html' import subtabs %}
{% set ddns_tabs = [{'id': 'status', 'label': 'Status', 'url': '/ddns?tab=status'}] %}
{% if current_user.role != 'viewer' %}
{% set ddns_tabs = ddns_tabs + [
    {'id': 'naming', 'label': 'Naming (dhcp4)', 'url': '/ddns?tab=naming'},
    {'id': 'd2config', 'label': 'D2 Configuration', 'url': '/ddns?tab=d2config'},
] + ([{'id': 'verify', 'label': 'Verify', 'url': '/ddns?tab=verify'}] if current_user.all_subnets else []) + [
    {'id': 'reconcile', 'label': 'Reconcile', 'url': '/ddns/reconcile'},
] %}
{% endif %}
{% if ddns_tabs|length > 1 %}{{ subtabs(ddns_tabs, tab) }}{% endif %}
"""

NEW_DDNS_TABS = "{% from '_ddns_tabs.html' import ddns_tabs with context %}{{ ddns_tabs(tab) }}"


@pytest.mark.parametrize(
    "role,all_subnets",
    [("viewer", True), ("viewer", False), ("admin", True), ("admin", False), ("superadmin", True)],
)
@pytest.mark.parametrize("tab", ["status", "naming", "d2config", "verify", "reconcile"])
def test_the_ddns_tabs_macro_renders_what_the_pasted_list_rendered(role, all_subnets, tab):
    ctx = {"current_user": SimpleNamespace(role=role, all_subnets=all_subnets), "tab": tab}
    env = _env()
    old = env.from_string(OLD_DDNS_TABS).render(**ctx)
    new = env.from_string(NEW_DDNS_TABS).render(**ctx)
    assert new.strip() == old.strip()
    if role == "viewer":
        assert new.strip() == ""  # Status alone is no row at all


OLD_IP_SWITCH = """{% if ipv6_enabled and subnet6_map %}
<div class="segmented-control segmented">
    <a href="/PATH?view=v4" class="btn btn-sm {{ 'btn-primary' if view_mode != 'v6' else 'btn-secondary' }}">IPv4</a>
    <a href="/PATH?view=v6" class="btn btn-sm {{ 'btn-primary' if view_mode == 'v6' else 'btn-secondary' }}">IPv6</a>
</div>
{% endif %}
"""


@pytest.mark.parametrize("path", ["leases", "reservations", "devices"])
@pytest.mark.parametrize(
    "ctx",
    [
        {"ipv6_enabled": False, "subnet6_map": {}, "view_mode": "v4"},
        {"ipv6_enabled": True, "subnet6_map": {}, "view_mode": "v4"},
        {"ipv6_enabled": True, "subnet6_map": {1: {}}, "view_mode": "v4"},
        {"ipv6_enabled": True, "subnet6_map": {1: {}}, "view_mode": "v6"},
    ],
)
def test_the_ip_version_switch_macro_renders_what_the_pasted_block_rendered(path, ctx):
    env = _env()
    old = env.from_string(OLD_IP_SWITCH.replace("PATH", path)).render(**ctx)
    new = env.from_string(
        "{% from '_ip_version_control.html' import ip_version_control with context %}{{ ip_version_control('/"
        + path
        + "') }}"
    ).render(**ctx)
    assert new.strip() == old.strip()


OLD_PASSKEY_B64 = """    function b64urlToBytes(s) {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        var bin = atob(s), out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out.buffer;
    }
    function bytesToB64url(buf) {
        var bytes = new Uint8Array(buf), bin = '';
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
    }
"""


def test_the_passkey_helper_macro_renders_the_twelve_lines_it_replaced():
    out = _env().from_string("    {% from '_passkey_b64.html' import passkey_b64 %}{{ passkey_b64() }}\n").render()
    assert out + "\n" == OLD_PASSKEY_B64  # the call line's own indent + the macro's lines = the lines it replaced


class TestNoTemplateGrowsItsOwnCopyAgain:
    def test_the_base64url_helpers_live_in_one_file(self):
        owners = [
            p.name
            for p in sorted(TEMPLATES.glob("*.html"))
            if "function b64urlToBytes" in p.read_text(encoding="utf-8")
        ]
        assert owners == ["_passkey_b64.html"], owners

    def test_the_ddns_tab_list_lives_in_one_file(self):
        owners = [
            p.name for p in sorted(TEMPLATES.glob("*.html")) if "'/ddns/reconcile'" in p.read_text(encoding="utf-8")
        ]
        assert owners == ["_ddns_tabs.html"], owners

    def test_the_version_switch_lives_in_one_file(self):
        owners = [
            p.name
            for p in sorted(TEMPLATES.glob("*.html"))
            if "segmented-control segmented" in p.read_text(encoding="utf-8")
        ]
        assert owners == ["_ip_version_control.html"], owners
