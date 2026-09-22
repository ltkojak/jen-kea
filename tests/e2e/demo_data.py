"""
tests/e2e/demo_data.py
────────────────────────
v5.54.0-era (Q62) — a fictional-by-construction homelab dataset for the docs
screenshot pass (tests/e2e/test_docs_screenshots.py). Selected with
JEN_E2E_DATASET=demo (tests/e2e/conftest.py); the default e2e run never
imports this module, so the 22 existing journeys — which depend on
E2E_SUBNETS' ids 1/2 and the Office/Guest names — never see it.

Every function here is pure (returns rows; takes a seeded `random.Random` so
the pictures come out the same run to run — seed 20260921, this Q's date).
`seed(conn)` is the one function with a side effect: it writes the rows this
module builds into an already-connected, already-migrated jen_test database
(jen_test serves as both jen_db and kea_db in tests — see CLAUDE.md).

Nothing here is a real network. Hostnames are things, never people
(`living-room-tv`, not a name); FORBIDDEN below is what
test_docs_screenshots.py's leak guard checks every captured page's text
against — every marker the maintainer gave as identifying their own network.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

# ── Subnets — obviously not the maintainer's (10.20.x.0/24, not their real
# range), named for what they are rather than copying Office/Guest. ─────────
SUBNETS = {
    10: {"name": "Production", "cidr": "10.20.10.0/24"},
    30: {"name": "IoT", "cidr": "10.20.30.0/24"},
    50: {"name": "Guest", "cidr": "10.20.50.0/24"},
    90: {"name": "Lab", "cidr": "10.20.90.0/24"},
}
SUBNET_ROUTERS = {sid: f"{info['cidr'].rsplit('.', 1)[0]}.1" for sid, info in SUBNETS.items()}
SUBNET_DNS = dict.fromkeys(SUBNETS, "10.20.10.53,9.9.9.9")
SUBNET_POOL_RANGE = dict.fromkeys(SUBNETS, (100, 220))
# 1 day / 7 days / 8 hours / 1 day, in seconds — Production/Lab renew daily,
# IoT (rarely moves) gets a week, Guest (turns over fast) gets 8 hours.
SUBNET_VALID_LIFETIME = {10: 86400, 30: 604800, 50: 28800, 90: 86400}

# Active-lease counts per subnet — about 45 total, Production heaviest.
LEASE_COUNTS = {10: 22, 30: 14, 50: 5, 90: 4}

# Real, public OUI prefixes — verified present in jen/services/oui_db.json
# (grep it before changing any of these; swap in another vendor's real
# prefix from that file if one of these is ever removed from it). Apple,
# Samsung, Amazon and Intel's prefixes named in the original spec weren't in
# the bundled DB, so these are different real prefixes for the same vendors.
VENDOR_PREFIXES = {
    "Apple": "00:03:93",
    "Samsung": "00:00:f0",
    "Raspberry Pi": "b8:27:eb",
    "Espressif": "24:6f:28",
    "Amazon": "00:bb:3a",
    "Roku": "b0:a7:37",
    "Intel": "00:02:b3",
}
_VENDOR_NAMES = list(VENDOR_PREFIXES)

# Things, never people.
HOSTNAMES = [
    "living-room-tv",
    "kitchen-display",
    "hallway-thermostat",
    "printer-2f",
    "nas-01",
    "cam-driveway",
    "esp-garage-01",
    "pixel-guest",
    "lab-pve-01",
    "bedroom-speaker",
    "office-desktop",
    "kids-tablet",
    "garage-door",
    "doorbell-front",
    "patio-cam",
    "esp-mailbox",
    "shop-vac-plug",
    "guest-phone-1",
    "guest-laptop",
    "lab-switch-01",
    "lab-nas-backup",
    "office-laptop",
    "upstairs-ap",
    "downstairs-ap",
    "media-server",
    "printer-office",
    "esp-sensor-attic",
    "thermostat-upstairs",
    "cam-backyard",
    "roku-livingroom",
    "sonos-kitchen",
    "raspberrypi-dns",
    "vpn-router",
    "switch-core",
    "ups-monitor",
    "esp-plant-sensor",
    "office-phone",
    "lab-esxi-01",
    "lab-truenas",
    "kids-console",
    "work-laptop",
    "conference-cam",
    "printer-lab",
    "guest-tablet",
    "esp-doorlock",
]

RESERVATION_NOTES = [
    "Front desk printer",
    "Rack 1 U4",
    "Do not DHCP-expire — static service",
    "Conference room B",
    "Backup target",
    "Core switch mgmt",
    "Security cam PoE",
    "NAS — media share",
    "VPN gateway",
    "Lab hypervisor host",
    "Guest kiosk",
    "Reception display",
]

# The maintainer's real markers — every string the leak guard checks every
# captured screenshot's text against. Fail closed: if any of these appears,
# the dataset stopped being fictional somewhere and the run must not upload
# the picture.
FORBIDDEN = ("10.10.", "matthew", "laura", "micah", "lucia", "thibodeau", "constantping")

ALERT_KINDS = ("kea_up", "new_lease", "new_reservation", "new_device", "daily_summary", "kea_down")


def _mac(rng: random.Random, vendor: str) -> str:
    prefix = VENDOR_PREFIXES[vendor]
    tail = ":".join(f"{rng.randint(0, 255):02x}" for _ in range(3))
    return f"{prefix}:{tail}"


def _hex(mac: str) -> str:
    return mac.replace(":", "").upper()


def active_leases(rng: random.Random | None = None) -> list[dict]:
    """~45 active leases across the four subnets (LEASE_COUNTS), each a
    distinct fictional device with a hostname from HOSTNAMES, a vendor MAC,
    and an `obtained` timestamp within the subnet's own valid-lifetime."""
    rng = rng or random.Random(20260921)
    names = list(HOSTNAMES)
    rng.shuffle(names)
    rows = []
    name_i = 0
    for sid, count in LEASE_COUNTS.items():
        lo, _hi = SUBNET_POOL_RANGE[sid]
        base = SUBNETS[sid]["cidr"].rsplit(".", 1)[0]
        lifetime = SUBNET_VALID_LIFETIME[sid]
        for i in range(count):
            vendor = _VENDOR_NAMES[rng.randrange(len(_VENDOR_NAMES))]
            hostname = names[name_i % len(names)]
            name_i += 1
            age = rng.uniform(0.05, 0.9) * lifetime  # how far into its lease it already is
            rows.append(
                {
                    "ip": f"{base}.{lo + i}",
                    "mac": _mac(rng, vendor),
                    "vendor": vendor,
                    "hostname": hostname,
                    "subnet_id": sid,
                    "valid_lifetime": lifetime,
                    "age_seconds": int(age),
                }
            )
    return rows


def reservations(rng: random.Random | None = None, count: int = 30) -> list[dict]:
    """~30 reservations, spread across subnets in proportion to their lease
    counts, about a dozen carrying a `notes` value."""
    rng = rng or random.Random(20260921)
    names = [n for n in HOSTNAMES if n not in {r["hostname"] for r in active_leases(rng=random.Random(20260921))}]
    if not names:
        names = list(HOSTNAMES)
    weights = list(LEASE_COUNTS.values())
    subnet_ids = list(LEASE_COUNTS)
    total_weight = sum(weights)
    rows = []
    notes_left = 12
    for i in range(count):
        # proportional-to-lease-count subnet pick, deterministic under the seeded rng
        pick = rng.uniform(0, total_weight)
        acc = 0
        sid = subnet_ids[-1]
        for s, w in zip(subnet_ids, weights, strict=True):
            acc += w
            if pick <= acc:
                sid = s
                break
        lo, hi = SUBNET_POOL_RANGE[sid]
        base = SUBNETS[sid]["cidr"].rsplit(".", 1)[0]
        # reservations live past the dynamic pool's low end, out of the active-lease range above
        offset = hi - (i % (hi - lo - LEASE_COUNTS[sid] - 5)) if hi - lo > LEASE_COUNTS[sid] + 5 else lo + 40 + i
        vendor = _VENDOR_NAMES[rng.randrange(len(_VENDOR_NAMES))]
        has_notes = notes_left > 0 and rng.random() < 0.5
        if has_notes:
            notes_left -= 1
        rows.append(
            {
                "ip": f"{base}.{max(lo, min(offset, 253))}",
                "mac": _mac(rng, vendor),
                "hostname": names[i % len(names)],
                "subnet_id": sid,
                "notes": RESERVATION_NOTES[i % len(RESERVATION_NOTES)] if has_notes else "",
            }
        )
    return rows


def devices(rng: random.Random | None = None) -> list[dict]:
    """~40 devices (jen's own inventory table): every active-lease MAC plus a
    handful seen before but not currently leased, first_seen/last_seen spread
    over the last 30 days so Top Active Devices has something to rank."""
    from jen.services.fingerprint import lookup_oui

    rng = rng or random.Random(20260921)
    now = datetime.now(timezone.utc)
    seen: dict[str, dict] = {}
    for lease in active_leases(rng=random.Random(20260921)):
        mfr, dtype, dicon = lookup_oui(lease["mac"])
        last_seen = now - timedelta(minutes=rng.randint(0, 45))
        seen[lease["mac"]] = {
            "mac": lease["mac"],
            "device_name": lease["hostname"],
            "last_ip": lease["ip"],
            "last_hostname": lease["hostname"],
            "last_subnet_id": lease["subnet_id"],
            "manufacturer": mfr,
            "device_type": dtype,
            "device_icon": dicon,
            "first_seen": now - timedelta(days=rng.uniform(1, 29)),
            "last_seen": last_seen,
        }
    # a handful of "seen before, not leased right now" devices to round out to ~40
    extra_needed = max(0, 40 - len(seen))
    for i in range(extra_needed):
        vendor = _VENDOR_NAMES[rng.randrange(len(_VENDOR_NAMES))]
        mac = _mac(rng, vendor)
        sid = list(SUBNETS)[i % len(SUBNETS)]
        base = SUBNETS[sid]["cidr"].rsplit(".", 1)[0]
        mfr, dtype, dicon = lookup_oui(mac)
        seen[mac] = {
            "mac": mac,
            "device_name": HOSTNAMES[(i * 3 + 7) % len(HOSTNAMES)],
            "last_ip": f"{base}.{50 + i}",
            "last_hostname": HOSTNAMES[(i * 3 + 7) % len(HOSTNAMES)],
            "last_subnet_id": sid,
            "manufacturer": mfr,
            "device_type": dtype,
            "device_icon": dicon,
            "first_seen": now - timedelta(days=rng.uniform(2, 30)),
            "last_seen": now - timedelta(days=rng.uniform(1, 6)),
        }
    return list(seen.values())


def lease_history_rows(rng: random.Random | None = None, days: int = 30) -> list[dict]:
    """30 days x 4 subnets at the 30-minute snapshot interval Health/Reports
    read (jen.services.health.lease_history_window): a gentle daily sine plus
    seeded noise, IoT trending slowly upward so the pool-exhaustion forecast
    (Q35) has a real rising trend to draw a dashed projection for."""
    rng = rng or random.Random(20260921)
    now = datetime.now(timezone.utc)
    rows = []
    points_per_day = 48  # every 30 minutes
    for sid in SUBNETS:
        lo, hi = SUBNET_POOL_RANGE[sid]
        pool_size = hi - lo
        base_active = LEASE_COUNTS[sid]
        rising = sid == 30  # IoT
        for day in range(days, 0, -1):
            for p in range(points_per_day):
                ts = now - timedelta(days=day, minutes=(points_per_day - p) * 30)
                hour = ts.hour + ts.minute / 60.0
                daily = 1.0 + 0.35 * (0.5 - abs((hour - 12) / 24))  # busier at midday
                trend = 1.0 + (0.5 * (days - day) / days if rising else 0.0)
                noise = rng.uniform(-1, 1)
                active = max(1, int(base_active * daily * trend + noise))
                active = min(active, pool_size - 2)
                dynamic = max(0, active - max(1, active // 4))
                reserved = active - dynamic
                rows.append(
                    {
                        "subnet_id": sid,
                        "snapshot_time": ts,
                        "active_leases": active,
                        "dynamic_leases": dynamic,
                        "reserved_leases": reserved,
                        "pool_size": pool_size,
                    }
                )
    return rows


def alert_log_rows(rng: random.Random | None = None) -> list[dict]:
    """Ten rows over the last day: kea up, four new-lease, two
    new-reservation, one new-device, a daily summary, and a kea down->up
    pair — the standardised alert kinds (jen/services/alerts.py)."""
    rng = rng or random.Random(20260921)
    now = datetime.now(timezone.utc)
    kinds = (
        "kea_down",
        "kea_up",
        "new_lease",
        "new_lease",
        "new_lease",
        "new_lease",
        "reservation_added",
        "reservation_added",
        "new_device",
        "daily_summary",
    )
    rows = []
    for i, kind in enumerate(kinds):
        rows.append(
            {
                "channel_type": "telegram",
                "alert_type": kind,
                "message": f"{kind.replace('_', ' ').title()} alert",
                "status": "ok",
                "error": "",
                "sent_at": now - timedelta(minutes=rng.randint(5, 1400) + i),
            }
        )
    return rows


def server_stats_rows() -> list[dict]:
    """Two snapshots (the minimum the Q42 packet-health assessment needs for
    a delta), five minutes apart, with clean-looking climbing counters."""
    now = datetime.now(timezone.utc)
    early = {
        "pkt4-received": 4200,
        "pkt4-offer-sent": 2000,
        "pkt4-ack-sent": 4150,
        "pkt4-nak-sent": 3,
        "pkt4-receive-drop": 0,
        "pkt4-parse-failed": 0,
    }
    later = {k: v + int(v * 0.02) + 5 for k, v in early.items()}
    later["pkt4-nak-sent"] = early["pkt4-nak-sent"] + 1
    return [
        {"snapshot_time": now - timedelta(minutes=5), "stats": early},
        {"snapshot_time": now, "stats": later},
    ]


def dashboard_prefs_v2() -> dict:
    """The Q61 v2 shape: Total Summary first, then Subnet Statistics, the
    Forecast and Packet Health catalog widgets at half width, Recently
    Issued Leases, Server Status, Alert Summary; subnets in the order
    Production, IoT, Guest, Lab, nothing hidden."""
    return {
        "v": 2,
        "panels": [
            {"id": "totals", "w": "full"},
            {"id": "subnet_stats", "w": "full"},
            {"id": "forecast", "w": "half"},
            {"id": "packet_health", "w": "half"},
            {"id": "recent_leases", "w": "full"},
            {"id": "server_status", "w": "half"},
            {"id": "alert_summary", "w": "half"},
        ],
        "subnets": {"order": [10, 30, 50, 90], "pinned": [], "hidden": []},
        "compact": False,
    }


def seed(conn) -> None:
    """Write every row this module builds into `conn` (an already-connected,
    already-migrated jen_test database — jen_test serves as both jen_db and
    kea_db in tests, so one connection reaches every table here). Called
    from tests/e2e/conftest.py's live_server fixture, after _seed_users(),
    only when JEN_E2E_DATASET=demo."""
    import json as _json

    with conn.cursor() as cur:
        for lease in active_leases(random.Random(20260921)):
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, hostname, state) "
                "VALUES (INET_ATON(%s), UNHEX(%s), %s, DATE_ADD(NOW(), INTERVAL %s SECOND), %s, %s, 0)",
                (
                    lease["ip"],
                    _hex(lease["mac"]),
                    lease["valid_lifetime"],
                    lease["valid_lifetime"] - lease["age_seconds"],
                    lease["subnet_id"],
                    lease["hostname"],
                ),
            )
        for res in reservations(random.Random(20260921)):
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, %s, INET_ATON(%s), %s)",
                (_hex(res["mac"]), res["subnet_id"], res["ip"], res["hostname"]),
            )
            if res["notes"]:
                cur.execute(
                    "INSERT INTO reservation_notes (host_id, notes) VALUES (LAST_INSERT_ID(), %s)",
                    (res["notes"],),
                )
        for dev in devices(random.Random(20260921)):
            cur.execute(
                "INSERT INTO devices (mac, device_name, last_ip, last_hostname, last_subnet_id, "
                "manufacturer, device_type, device_icon, first_seen, last_seen) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    dev["mac"],
                    dev["device_name"],
                    dev["last_ip"],
                    dev["last_hostname"],
                    dev["last_subnet_id"],
                    dev["manufacturer"],
                    dev["device_type"],
                    dev["device_icon"],
                    dev["first_seen"],
                    dev["last_seen"],
                ),
            )
        # 30 days x 4 subnets x 48 snapshots/day (~5,760 rows) — one round trip via
        # executemany rather than one per row, which measurably slows the e2e job.
        history_rows = lease_history_rows(random.Random(20260921))
        cur.executemany(
            "INSERT INTO lease_history (subnet_id, snapshot_time, active_leases, dynamic_leases, "
            "reserved_leases, pool_size) VALUES (%s, %s, %s, %s, %s, %s)",
            [
                (
                    r["subnet_id"],
                    r["snapshot_time"],
                    r["active_leases"],
                    r["dynamic_leases"],
                    r["reserved_leases"],
                    r["pool_size"],
                )
                for r in history_rows
            ],
        )
        for row in alert_log_rows(random.Random(20260921)):
            cur.execute(
                "INSERT INTO alert_log (channel_type, alert_type, message, status, error, sent_at) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (row["channel_type"], row["alert_type"], row["message"], row["status"], row["error"], row["sent_at"]),
            )
        for row in server_stats_rows():
            cur.execute(
                "INSERT INTO server_stats (server_id, snapshot_time, stats) VALUES (1, %s, %s)",
                (row["snapshot_time"], _json.dumps(row["stats"])),
            )
        cur.execute("SELECT id FROM users WHERE username='admin'")
        admin_id = cur.fetchone()["id"]
        prefs = _json.dumps(dashboard_prefs_v2())
        cur.execute(
            "INSERT INTO dashboard_prefs (user_id, widgets) VALUES (%s, %s) ON DUPLICATE KEY UPDATE widgets=%s",
            (admin_id, prefs, prefs),
        )
    conn.commit()
