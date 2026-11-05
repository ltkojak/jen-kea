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


# The ONE value a consent checkbox carries (Q219 BI3 d, AD15): the card writes `value="{{ c.consent_value }}"` and the route reads it back with this constant, so the two cannot drift apart unseen.
CONSENT_VALUE = "1"

# What the readiness check says about the file on a Live API server's host (Q219 BI1 f): ONE table for the card, the support bundle and Health, keyed by what `file_proof` found (`how`). `none` has three
# readings - both times known, only the file's, and no clock at all (a helper below build 22) - and `{written}` / `{loaded}` are times the caller has already formatted.
PROOF_SENTENCES = {
    "loaded": "one the daemon has loaded (written {written}, loaded {loaded})",
    "rendering": "Jen's own rendering of what the daemon runs (see Config history)",
    "planned": "the file the unfinished change was planned over",
    "none": "written at {written}, after the daemon's last load at {loaded} - the daemon has not loaded that edit",
    "none-before": "written at {written}, before the daemon's last load at {loaded}, but the daemon does not run it",
    "no-daemon": "written at {written}; the daemon's own load time could not be read",
    "no-clock": "cannot be proved: helper build 22 needed for the daemon's own load time (press Update helper)",
    "unreadable": "the file on the host could not be read",
    "no-file": "no SSH host: there is no file to prove",
}


def proof_sentence(how, written="", loaded="", after=True):
    """The sentence for a stored proof (`how`, the two preformatted times, and whether the file is the NEWER of the two); "" for a result that records none (one stored before the proof existed)."""
    if not how:
        return ""
    key = how
    if how == "none":
        key = ("none" if after else "none-before") if written and loaded else ("no-daemon" if written else "no-clock")
    return PROOF_SENTENCES.get(key, "").format(written=written, loaded=loaded)


def mode_word(transport: str) -> str:
    """The word for a config value; anything that is not one of the three reads as Read-only (as `declared_transport` reads it)."""
    return MODE_WORDS.get(transport, MODE_WORDS["off"])
