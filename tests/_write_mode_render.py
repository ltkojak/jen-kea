"""
tests/_write_mode_render.py
───────────────────────────
Q217 - the Write mode card, rendered WITHOUT a server: `infrastructure._config_cards()` (the real builder) feeds the card block of `templates/settings_kea.html` through a plain Jinja
`Environment` with `StrictUndefined`, so an undefined variable in the template fails here, on any box. The only things stood in are the box's own state: the server list, the stored probe, the
helper's recorded builds, the revision store and the signed-in role.
"""

import copy
import pathlib
import re
import types

from jinja2 import DictLoader, Environment, StrictUndefined

ROOT = pathlib.Path(__file__).resolve().parent.parent
NOW = "2026-11-04T10:00:00+00:00"

GOOD = {
    "at": NOW,
    "config_api": True,
    "test_ok": True,
    "include": [],
    "agree": True,
    "write": {"may_write": True, "account": "_kea", "mode": "0660", "daemon_is_root": False},
    "auth": "password",
    "tls": False,
    "authored": True,
    "consented_at": NOW,
    "consents": ["consent_rendering"],
    "bound": "x",
}
HELPER_OK = {"1": {"build": 20, "version": 7}, "2": {"build": 20, "version": 7}, "3": {"build": 20, "version": 7}}
S_FILE = {"id": 1, "name": "kea-a", "api_url": "http://x", "ssh_host": "10.0.0.1", "config_transport": "file"}
S_API = {"id": 2, "name": "kea-b", "api_url": "http://y", "ssh_host": "10.0.0.2", "config_transport": "api"}
S_API_NOSSH = {"id": 3, "name": "kea-c", "api_url": "http://z", "config_transport": "api"}
S_OFF = {"id": 4, "name": "kea-d", "api_url": "http://w", "config_transport": "off"}


def card_block() -> str:
    src = (ROOT / "templates" / "settings_kea.html").read_text(encoding="utf-8")
    a = src.index("<!-- Write mode (Q217)")
    b = src.index("<!-- SSH — host/user/path AND the key")
    return src[a:b]


def _env() -> Environment:
    env = Environment(loader=DictLoader({"card": card_block()}), undefined=StrictUndefined, autoescape=True)
    env.globals["icon"] = lambda n, *a, **k: f"<svg data-icon='{n}'></svg>"
    env.globals["csrf_token"] = lambda: "T"
    env.filters["utcfmt"] = lambda v: str(v)
    return env


def render(monkeypatch, servers, probes=None, helper=None, superadmin=True, gate=""):
    """(cards, html) for `servers`; `probes` is {server_id: stored probe}."""
    from jen import extensions
    from jen.routes.settings import infrastructure as infra
    from jen.services import config_revisions as rev
    from jen.services import kea_api_config as api
    from jen.services import kea_host

    probes = probes or {}
    user = types.SimpleNamespace(is_superadmin=superadmin, role="superadmin" if superadmin else "admin")
    monkeypatch.setattr(extensions, "KEA_SERVERS", servers)
    monkeypatch.setattr(infra, "current_user", user)
    monkeypatch.setattr(api, "stored_probe", lambda sid: copy.deepcopy(probes.get(sid)))
    monkeypatch.setattr(api, "probe_gate", lambda srv, source="jen": gate)
    monkeypatch.setattr(kea_host, "helper_status", lambda: helper if helper is not None else HELPER_OK)
    monkeypatch.setattr(rev, "pending", lambda sid, svc: None)
    cards = infra._config_cards()
    html = _env().get_template("card").render(config_cards=cards, current_user=user)
    return cards, html


def checked_modes(html: str) -> list[str]:
    radios = re.findall(r'<input type="radio"[^>]*>', html)
    return [re.search(r'value="(\w+)"', r).group(1) for r in radios if " checked" in r]


def consent_names(html: str) -> list[str]:
    return re.findall(r'name="(consent_\w+|confirm_\w+|discard_\w+)"', html)


def api_consent_names(html: str) -> list[str]:
    """The consent inputs of the Live API panel only (row 3) - File over SSH has its own discard box."""
    start = html.index('data-mode-panel="api"')
    end = html.find('data-mode-panel="file"', start)
    return consent_names(html[start : end if end != -1 else len(html)])
