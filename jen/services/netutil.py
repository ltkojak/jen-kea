"""
jen/services/netutil.py
───────────────────────
v5.69.0-beta.5 (Q174): the one place an IPv4 address becomes an integer. Eleven route modules, `alerts.py` and `config_doctor.py` each carried their own copy (twelve of
them dead, and four different bodies: one raised on a bad address, one stripped, one answered None); this is the body `config_doctor` had, the strictest of them, and
`tests/test_source_hygiene.py` fails CI if a second `ip_to_int` appears anywhere under `jen/`.

Pure: no Flask, no database.
"""

from __future__ import annotations

import ipaddress


def ip_to_int(ip: str) -> int | None:
    """The IPv4 address `ip` as an integer, or None when it is not one (None, empty, an IPv6 address, text)."""
    try:
        return int(ipaddress.IPv4Address((ip or "").strip()))
    except ValueError:
        return None
