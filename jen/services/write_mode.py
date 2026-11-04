"""
jen/services/write_mode.py
──────────────────────────
Q217 (7.0.0-beta.3) - the words of Write mode. A server's `config_transport` (`api | file | off`) never changes; this is what the operator is told it is, in ONE place, used wherever a mode is
named: the Settings card, the Servers page badge and its title, `capabilities.transport_why`, the Doctor, the change set's lines, the audit rows and both guides. No imports: everything may import it.
"""

MODE_ORDER = ("api", "file", "off")  # the fixed order of the card's radios

MODE_WORDS = {"api": "Live API", "file": "File over SSH", "off": "Read-only"}

MODE_SENTENCES = {
    "api": "Jen sends changes to the running daemon. Live at once, no restart, no SSH needed.",
    "file": "Jen rewrites kea-dhcp4.conf over SSH, validates it, and restarts Kea. The 5.x way.",
    "off": "Jen monitors this server and never changes its configuration.",
}

# What the operator accepts, once each (the card's row 3 and the switch's consents).
CONSENT_TEXTS = {
    "consent_rendering": "Kea will rewrite its config file in its own format; comments and key order are lost",
    "consent_unauthenticated": "This API has no authentication; anything that reaches it can change this daemon",
    "discard_file_edit": "The config file has an edit the daemon never loaded; discard it",
    "confirm_no_include": "This server has no SSH host, so Jen cannot see its file: it has no include and no unloaded edit",
}


def mode_word(transport: str) -> str:
    """The word for a config value; anything that is not one of the three reads as Read-only (as `declared_transport` reads it)."""
    return MODE_WORDS.get(transport, MODE_WORDS["off"])
