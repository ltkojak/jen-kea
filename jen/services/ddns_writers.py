"""
jen/services/ddns_writers.py
────────────────────────────
v5.69.0-beta.7 (Q176) - who writes DNS names, as far as Jen can see it. Jen never writes a DNS record itself. On the Kea host a name is written by one of two things:
D2 (kea-dhcp-ddns, when dhcp4's `dhcp-ddns.enable-updates` is on) or a hook script of the operator's own, loaded through Kea's `libdhcp_run_script.so`. Jen cannot know what
a hook script does, but it can see that one is loaded - and when both are on, every lease may be written twice by two writers that do not know each other. That is a warning
in three places (Doctor, the DDNS Status tab, the Naming tab), never a block: an operator who runs both on purpose is not stopped.

Pure - no I/O. The callers hand in the `Dhcp4` section of a config-get or of the config file.

(The optional Local DNS Sync plugin is the one further thing that writes DNS - rewrites to Pi-hole or AdGuard Home from its own target list - and is not what this module
is about: it is a Jen plugin the operator installs and configures, not something that runs on the Kea host beside D2.)
"""

from __future__ import annotations

RUN_SCRIPT_LIBRARY = "libdhcp_run_script.so"

TWO_WRITERS_SENTENCE = (
    "dhcp4 sends updates to D2 and a run_script hook is loaded: if the hook also updates DNS, every lease is written twice by two writers that do not know each other - "
    "turn one off."
)


def hook_loaded(dhcp4) -> bool:
    """True when `Dhcp4.hooks-libraries` has an entry whose `library` ends in `libdhcp_run_script.so` (any path to it)."""
    libraries = dhcp4.get("hooks-libraries") if isinstance(dhcp4, dict) else None
    for entry in libraries if isinstance(libraries, list) else []:
        library = entry.get("library") if isinstance(entry, dict) else None
        # the file name, not a suffix: `/x/notlibdhcp_run_script.so` is a different library
        if isinstance(library, str) and library.strip().rsplit("/", 1)[-1] == RUN_SCRIPT_LIBRARY:
            return True
    return False


def updates_enabled(dhcp4) -> bool:
    """True when dhcp4 sends updates to D2 (`dhcp-ddns.enable-updates`)."""
    block = dhcp4.get("dhcp-ddns") if isinstance(dhcp4, dict) else None
    return bool(block.get("enable-updates")) if isinstance(block, dict) else False


def effective_provider(cfg) -> str:
    """The DNS provider Jen looks names up on, from a ConfigParser: `[ddns] dns_provider` when it is set; when the key is absent but an `api_url` or `api_token` is - a
    hand-written config from the years when an absent key meant Technitium - `technitium`, so an upgrade does not silently turn that box's lookups off and make its next
    save of the form clear the URL and zone; else `none`. A fresh install has neither and reads `none` (v5.69.0-beta.7, Q176)."""
    provider = cfg.get("ddns", "dns_provider", fallback="").strip()
    if provider:
        return provider
    if cfg.get("ddns", "api_url", fallback="").strip() or cfg.get("ddns", "api_token", fallback="").strip():
        return "technitium"
    return "none"
