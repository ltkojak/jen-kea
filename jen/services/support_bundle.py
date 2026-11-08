"""
jen/services/support_bundle.py
──────────────────────────────
v5.33.0 (Q32) — the diagnostic support bundle: one zip an operator can
attach to a bug report instead of describing their install.

Two layers, kept apart on purpose:

* **Collectors** (`_collect_*`) read live state — config file, Health
  Center, database, GitHub-free — and each one is wrapped so that a
  failure becomes a note inside the bundle, never a missing bundle.
* **Builders** (`build_bundle`, `redact_ini_text`, `scrub_log_text`,
  …) are pure functions of the collected data. The tests feed them
  raw data seeded with sentinels and assert no sentinel survives into
  any member — that test is the redaction guarantee; this docstring
  is not.

What is NEVER read: the SSH key, the mTLS client key, the CA key,
the config dir's `mfa_key`, `mfa_methods`, `mfa_backup_codes`, `api_keys`,
`users`, `alert_channels` (their config blobs carry tokens), and the
config-revision *history* (only the latest revision per server and
service, and that one redacted). Paths to key files are included;
their contents are not.
"""

import configparser
import io
import json
import logging
import os
import platform
import re
import socket
import sys
import zipfile
from datetime import datetime, timezone

from jen import extensions
from jen.services import runtime
from jen.services.secret_keys import (
    is_secret_key,
    scrub_urls,
    without_userinfo,
)

logger = logging.getLogger(__name__)

# Members are added in this order; when the size cap is exceeded the
# droppable ones go first (largest first).
SIZE_CAP_BYTES = 20 * 1024 * 1024
DROPPABLE = ("logs/jen.log.tail", "audit-tail.json", "alerts-tail.json")

LOG_TAIL_LINES = 2000
_MEMBER_NAME_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*"
)  # (Q223, AH14) what a member of the archive may be called
NOTE_MAX_CHARS = 500  # (Q222, AG2) a collector's note in README.txt is cut here
AUDIT_TAIL_ROWS = 500
ALERT_TAIL_ROWS = 200
LEASE_HISTORY_DAYS = 7

# Which INI keys hold a secret is jen.services.secret_keys.is_secret_key - the one definition (Q204 AT4), shared with the Kea-config masker. A key that
# names a *path* to a secret (key_path, api_client_key, ssl_key) is kept BY NAME - the path is diagnostic, the file is never opened. The VALUE is never consulted (Q222, AG1): until
# 7.0.0-beta.8 a secret-named key whose value began with `/` or `X:\` was taken for a path and written in clear, and the name rule already excludes every path-naming key.
MASK = "********"

# Log scrubbing — anything that looks like a credential in a log line.
_LOG_SCRUBS = (
    (re.compile(r"(Bearer\s+)\S+", re.IGNORECASE), r"\1[redacted]"),
    (re.compile(r"(Authorization:\s*)\S+.*$", re.IGNORECASE), r"\1[redacted]"),
    (re.compile(r"(password|passwd|secret|token|api_pass|api_key)(\s*[=:]\s*)\S+", re.IGNORECASE), r"\1\2[redacted]"),
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "[redacted-hex]"),
    (re.compile(r"\b[A-Za-z0-9+/_\-]{40,}={0,2}\b"), "[redacted-b64]"),
)


# ── Pure builders ────────────────────────────────────────────────────────────


def redact_ini_text(text: str) -> str:
    """The INI re-emitted with every secret-looking value masked. Paths
    survive even under a secret-looking key (`ssl_key = /etc/…`). A
    file that doesn't parse is replaced by a note, never echoed."""
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str  # (Q223, AH13) the key as written: `configparser` would lower-case `clientSecret` to `clientsecret`, which the name rule cannot read as a secret
    try:
        parser.read_string(text or "")
    except configparser.Error as e:
        # The parser's message quotes the offending line — which could be a
        # secret — so only the error class is reported, never the text.
        return f"; jen.config could not be parsed ({type(e).__name__}) — not included\n"
    out = []
    for section in parser.sections():
        out.append(f"[{section}]")
        for key, value in parser.items(section):
            if is_secret_key(key) and value:
                value = MASK  # (Q222, AG1) by NAME only: a password that begins with `/` is a password
            else:
                value = without_userinfo(
                    value
                )  # (Q221, AE7; CRED-005) a legacy address keeps its host and port and never its user name or password
            out.append(f"{key} = {value}")
        out.append("")
    return "\n".join(out)


def _address_key(key) -> bool:
    """Is `key` one whose value is an address (`api_url`, `api6_url`, `api_d2_url`, a Kea `url`)? Such a value is split structurally; any other string is text."""
    return str(key if key is not None else "").lower().replace("-", "_").endswith("url")


def _is_secret_shape(value) -> bool:
    """Is `value` a thing that can CARRY a secret under a secret-named key? A non-empty string, bytes, or any container (a list of credentials, a dict of passwords - the value is masked whole,
    as `kea_authoring.redact_secrets` masks any shape). A bool, a number and None say that a secret exists or how long it is, never what it is: kept (Q223 AH7 decided; Q224 AJ12 the containers)."""
    if isinstance(value, (bool, int, float)) or value is None:
        return False
    if isinstance(value, str):
        return bool(value)
    return isinstance(value, (bytes, bytearray, dict, list, tuple, set, frozenset))


def _scrubbed(data, key=None):
    """`data` with no user-info left in any address, at any depth (Q221, AE7): THE pass every JSON member of the bundle goes through (`_json`), so a section added later is covered by being a
    member. A string under an address key is a value (`secret_keys.without_userinfo`); any other string is text (`secret_keys.scrub_urls`). Keys, numbers, booleans and None are untouched."""
    if isinstance(data, dict):
        return {
            (scrub_urls(k) if isinstance(k, str) else k): (
                MASK if is_secret_key(k) and _is_secret_shape(v) else _scrubbed(v, k)
            )
            for k, v in data.items()
        }  # (Q222, AG11) a key is text too; (Q223, AH7) a string under a secret-named key is masked here, in the pass every member goes through, whoever made the member
    if isinstance(data, (list, tuple)):
        return [_scrubbed(v, key) for v in data]
    if isinstance(data, str):
        return without_userinfo(data) if _address_key(key) else scrub_urls(data)
    if isinstance(data, (int, float, bool)) or data is None:
        return data
    return scrub_urls(
        str(data)
    )  # (Q222, AG11) an object the encoder would print with `default=str`: printed here, as text, so the pass covers it


def scrub_log_line(line: str) -> str:
    line = scrub_urls(line)  # (Q221, AE7) before the patterns: an address in a log line never keeps its user-info
    for rx, repl in _LOG_SCRUBS:
        line = rx.sub(repl, line)
    return line


def scrub_log_text(text: str, max_lines: int = LOG_TAIL_LINES) -> str:
    lines = (text or "").splitlines()[-max_lines:]
    return "\n".join(scrub_log_line(ln) for ln in lines) + ("\n" if lines else "")


def _json(data) -> str:
    return (
        json.dumps(_scrubbed(data), indent=2, sort_keys=True, default=lambda o: scrub_urls(str(o))) + "\n"
    )  # (Q222, AG11) what the encoder adds is scrubbed too


def readme_text(version: str, channel: str, hostname: str, when: str, notes: list[str]) -> str:
    body = [
        f"Jen support bundle — v{version} ({channel} channel) — {hostname} — {when}",
        "",
        "Attach this file to a bug report. It was produced by Settings → System →",
        "Support bundle and contains only diagnostic state:",
        "",
        "  jen.json                 version, channel, Python, serving mode, paths",
        "  config.ini.redacted      jen.config with every secret value masked",
        "  servers.json             each Kea server: URLs, write mode and readiness facts, helper version, TLS copies",
        "  health.json              Health Center results",
        "  drift.json               subnet-map drift",
        "  kea/<server>-<svc>.json  the LATEST config revision per server/daemon, secrets masked",
        "  plugins.json             installed plugins and their state",
        "  db.json                  schema versions, migrations, row counts, server version",
        "  audit-tail.json          last audit rows",
        "  alerts-tail.json         last alert-log rows",
        "  lease-history-7d.json    per-subnet utilization summary",
        "  logs/                    scrubbed tail of the Jen log, or a note if it goes to journald",
        "",
        "What is NOT here: passwords, API keys, TOTP secrets, alert-channel tokens,",
        "a user name or password inside an address (an address is host and port),",
        "the SSH / mTLS / CA private keys, users, or the config-revision history.",
        "Key FILE PATHS appear; key contents never do.",
    ]
    if notes:
        # (Q222, AG2) a note is a collector's exception message verbatim - a driver's error naming a user, a host and a port, a path - so it is scrubbed like a log line and cut: the
        # README is written after the size cap and must stay small on its own
        body += ["", "Sections that could not be collected:"] + [
            f"  - {scrub_log_line(str(n))[:NOTE_MAX_CHARS]}" for n in notes
        ]
    return "\n".join(body) + "\n"


def cap_text(cap: int) -> str:
    """The size cap as a person reads it (Q223, AH8): whole MB at or above 1 MiB, else KB - never "0 MB"."""
    return f"{cap // (1024 * 1024)} MB" if cap >= 1024 * 1024 else f"{max(1, cap // 1024)} KB"


def apply_size_cap(members: dict[str, bytes], cap: int = SIZE_CAP_BYTES) -> tuple[dict[str, bytes], list[str]]:
    """Drop the droppable members, largest first, until the raw total
    fits. Pure. Returns (members, dropped_names)."""
    dropped: list[str] = []
    total = sum(len(v) for v in members.values())
    for name in sorted(DROPPABLE, key=lambda n: -len(members.get(n, b""))):
        if total <= cap:
            break
        if name in members:
            total -= len(members[name])
            dropped.append(name)
            del members[name]
    return members, dropped


def build_bundle(collected: dict, *, now: datetime | None = None, cap: int = SIZE_CAP_BYTES) -> tuple[bytes, list[str]]:
    """Pure: `collected` is the dict `collect_all()` produces (raw data,
    NOT yet redacted). Returns (zip bytes, member names). Every
    redaction happens here so the tests can seed sentinels into
    `collected` and assert they never reach the archive."""
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%d %H:%M UTC")
    notes: list[str] = list(collected.get("notes") or [])
    members: dict[str, bytes] = {}

    def put(name: str, text: str):
        # (Q222, AG2; CRED-005) THE choke point: every member of the archive is written here and none keeps the user-info of an address, whoever made it. `scrub_urls` is idempotent, so a
        # member a stricter pass already made (`_json`, `redact_ini_text`, `scrub_log_text`) is unchanged; README.txt and logs/README.txt are covered by being members
        if not _MEMBER_NAME_RE.fullmatch(name):
            raise ValueError(
                f"a bundle member's name is a plain relative path: {name!r}"
            )  # (Q223, AH14) never `..`, never absolute, never a backslash: the archive an operator extracts stays in its folder
        members[name] = scrub_urls(str(text)).encode("utf-8")

    put("jen.json", _json(collected.get("jen") or {}))
    put("config.ini.redacted", redact_ini_text(collected.get("config_text") or ""))
    put("servers.json", _json(collected.get("servers") or []))
    put("health.json", _json(collected.get("health") or {}))
    put("drift.json", _json(collected.get("drift") or []))
    for entry in collected.get("kea_configs") or []:
        name = f"kea/{int(entry.get('server_id'))}-{entry.get('service')}.json"  # (Q223, AH14) the id is a number, as the producer's own database lookup already holds
        body = dict(entry)
        cfg = body.pop("config", None)
        if isinstance(cfg, dict):
            from jen.services.kea_authoring import redact_secrets

            body["config"] = redact_secrets(cfg)
        put(name, _json(body))
    put("plugins.json", _json(collected.get("plugins") or []))
    put("db.json", _json(collected.get("db") or {}))
    put("audit-tail.json", _json(collected.get("audit") or []))
    put("alerts-tail.json", _json(collected.get("alerts") or []))
    put("lease-history-7d.json", _json(collected.get("lease_history") or []))
    log_text = collected.get("log_text")
    if log_text is None:
        put(
            "logs/README.txt",
            scrub_log_line(
                str(
                    collected.get("log_note")
                    or "No log file configured — Jen logs to journald: `journalctl -u jen -n 500`.\n"
                )
            ),  # (Q222, AG2) a note is text that may name a path or an address
        )
    else:
        put("logs/jen.log.tail", scrub_log_text(log_text))

    members, dropped = apply_size_cap(members, cap)
    for d in dropped:
        notes.append(
            f"{d} dropped to stay under the {cap_text(cap)} size cap"
        )  # (Q223, AH8) the cap as it is, never "0 MB" for a cap below 1 MiB; it applies to the three tails, and README.txt is written after it
    jen_meta = collected.get("jen") or {}
    put(
        "README.txt",
        readme_text(
            str(jen_meta.get("version", "?")),
            str(jen_meta.get("channel", "?")),
            str(jen_meta.get("hostname", "?")),
            stamp,
            notes,
        ),
    )

    buf = io.BytesIO()
    # Fixed timestamps: the archive is a function of its inputs, nothing else.
    fixed = (now.year, now.month, now.day, now.hour, now.minute, 0)
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name in ["README.txt"] + sorted(n for n in members if n != "README.txt"):
            info = zipfile.ZipInfo(name, date_time=fixed)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, members[name])
    return buf.getvalue(), ["README.txt"] + sorted(n for n in members if n != "README.txt")


def bundle_filename(hostname: str, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", hostname or "jen").strip("-") or "jen"
    return f"jen-support-{safe}-{now.strftime('%Y%m%d-%H%M')}.zip"


# ── Collectors (live state; each failure becomes a note) ────────────────────


def _guard(notes: list[str], label: str, fn, default):
    try:
        return fn()
    except Exception as e:  # a diagnostic tool must not die on one bad section
        logger.warning(f"support bundle: {label} not collected: {e}")
        notes.append(f"{label}: {type(e).__name__}: {e}")
        return default


def _collect_jen() -> dict:
    from jen import JEN_VERSION

    return {
        "version": JEN_VERSION,
        "channel": extensions.UPDATE_CHANNEL,
        "hostname": socket.gethostname(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "in_venv": sys.prefix != sys.base_prefix,
        "jen_root": extensions.JEN_ROOT,
        "content_dir": extensions.CONTENT_DIR,
        "config_file": extensions.CONFIG_FILE,
        "docker": runtime.in_container(),
        "http_port": extensions.HTTP_PORT,
        "https_port": extensions.HTTPS_PORT,
        "worker_threads": extensions.WORKER_THREADS,
        "trusted_proxies": len(extensions.TRUSTED_PROXIES or []),
        "kea_connection_mode": extensions.KEA_CONNECTION_MODE,
        "oidc_enabled": bool(extensions.OIDC_ENABLED),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _collect_config_text() -> str:
    with open(extensions.CONFIG_FILE, encoding="utf-8") as f:
        return f.read()


#: The stored readiness facts of a server that a bundle carries (Q218 BH6 e, AC19): flags and strings, never a configuration body and never a value under a secret key. `agree_at` is the path the compare
#: named, redacted at the time it was written (`kea_api_config.difference_text`); `refused` is Kea's own text, cut to 300 characters when it was stored.
WRITE_MODE_FACT_KEYS = (
    "at",
    "bound",
    "config_api",
    "auth",
    "tls",
    "agree",
    "agree_at",
    "include",
    "include_unavailable",
    "write",
    "consents",
    "consented_at",
    "refused",
    "defaults",
    "test_ok",
    "test_detail",
    "read_error",
    "file_written_at",
    "daemon_loaded_at",
    "proof",
)


def _write_mode_of(server: dict) -> dict:
    """The write mode of a server, for `servers.json` (the exported layer of "the file is the daemon's configuration", Q154's six): the configured value, the word the operator reads, and the stored
    readiness facts. A stored result that cannot be read is named, never an empty object that reads as "never checked"."""
    from jen.services import capabilities, write_mode
    from jen.services import kea_api_config as api
    from jen.services import kea_changeset as changeset

    out = {
        "config_transport": server.get("config_transport"),
        "write_mode": write_mode.mode_word(changeset._transport(server, "dhcp4")),
    }
    try:
        probe = api.stored_probe(server.get("id")) or {}
        out["write_mode_facts"] = {k: probe[k] for k in WRITE_MODE_FACT_KEYS if k in probe}
        out["write_mode_checked"] = bool(probe)
        # (Q219 BI5 a, AD6) the gate's own state: whether it is closed and the sentence that says why. The bundle is a superadmin's download (`routes/settings/updates.py`: `@_superadmin_required`), so
        # it carries the full sentence the card prints to a superadmin - never a configuration body, never a secret
        caps = capabilities.write_gate_for(server)
        out["transport_blocked"] = bool(caps.transport_blocked)
        out["transport_why"] = caps.transport_why_for(True)
    except Exception as e:  # a settings row that cannot be read is said so, in words
        logger.warning(f"support bundle: the readiness facts of server {server.get('id')} were not read: {e}")
        out["write_mode_facts_error"] = type(e).__name__
    return out


def _collect_servers() -> list[dict]:
    from jen.services import kea_host, kea_tls

    helper = kea_host.helper_status() or {}
    try:
        copies = kea_tls.issued_server_copies() or []
    except Exception as e:
        logger.warning(f"support bundle: TLS copies not listed: {e}")
        copies = []
    out = []
    for s in extensions.KEA_SERVERS or []:
        sid = str(s.get("id"))
        row = {
            "id": s.get("id"),
            "name": s.get("name"),
            "api_url": s.get("api_url"),
            "api6_url": s.get("api6_url"),
            "api_d2_url": s.get("api_d2_url"),
            "ssh_host": s.get("ssh_host"),
            "ssh_user": s.get("ssh_user"),
            "ssh_key_path": s.get("ssh_key"),
            "kea_conf": s.get("kea_conf"),
            **_write_mode_of(s),
            "helper": helper.get(sid),
            "tls_copies": [
                {"service": c.get("service"), "path": c.get("path"), "days_left": c.get("days_left")}
                for c in copies
                if str(c.get("server_id")) == sid
            ],
        }
        out.append(row)
    return out


def _collect_health() -> dict:
    from jen.services import health

    checks = health.run_checks()
    return {"summary": health.summarize(checks), "checks": [c.as_dict() for c in checks]}


def _collect_drift() -> list:
    from jen.services.config_drift import check_config_drift

    return check_config_drift()


def _collect_kea_configs(notes: list[str]) -> list[dict]:
    from jen.services import config_revisions

    out = []
    for s in extensions.KEA_SERVERS or []:
        for service in ("dhcp4", "dhcp6", "d2"):
            try:
                row = config_revisions.latest(int(s.get("id")), service)
            except Exception as e:  # SecretDecryptError and friends
                notes.append(f"kea config {s.get('id')}-{service}: {type(e).__name__}: {e}")
                continue
            if not row:
                continue
            cfg = row.get("config")
            try:
                cfg = json.loads(cfg) if isinstance(cfg, str) else cfg
            except ValueError:
                cfg = {"_note": "revision body is not JSON"}
            out.append(
                {
                    "server_id": s.get("id"),
                    "server": s.get("name"),
                    "service": service,
                    "revision_id": row.get("id"),
                    "sha256": row.get("sha256"),
                    "summary": row.get("summary"),
                    "source": row.get("source"),
                    "created_at": row.get("created_at"),
                    "config": cfg,
                }
            )
    return out


def _collect_plugins() -> list[dict]:
    from jen.services.plugins import discover_plugins, missing_os_packages

    out = []
    for p in discover_plugins():
        out.append(
            {
                "id": p.get("id"),
                "version": p.get("version"),
                "requires_jen": p.get("requires_jen"),
                "enabled": p.get("enabled"),
                "version_ok": p.get("version_ok"),
                "bundled": p.get("bundled"),
                "root_owned": p.get("root_owned"),
                "path": p.get("path"),
                "os_packages": p.get("os_packages"),
                "missing_os_packages": missing_os_packages(p),
            }
        )
    return out


def _collect_db() -> dict:
    from jen.models import migrations
    from jen.models.db import jen_db
    from jen.services.dbexport import JEN_TABLES, _row_count

    out: dict = {"schema_latest": migrations.latest_version(), "schema_applied": sorted(migrations.applied_versions())}
    with jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT VERSION() AS v")
        out["server_version"] = (cur.fetchone() or {}).get("v")
        cur.execute("SELECT plugin_id, version, applied_at FROM plugin_schema_migrations ORDER BY plugin_id, version")
        out["plugin_migrations"] = list(cur.fetchall())
        counts = {}
        for table in JEN_TABLES:
            # dbexport's own counter (table names come from its fixed dict).
            try:
                counts[table] = _row_count(db, table)
            except Exception as e:
                counts[table] = f"error: {type(e).__name__}"
        out["row_counts"] = counts
    return out


def _collect_audit() -> list[dict]:
    from jen.models.db import jen_db

    with jen_db() as db, db.cursor() as cur:
        cur.execute(
            "SELECT id, username, action, entity, details, ip_address, created_at FROM audit_log ORDER BY id DESC LIMIT %s",
            (AUDIT_TAIL_ROWS,),
        )
        return list(cur.fetchall())


def _collect_alerts() -> list[dict]:
    from jen.models.db import jen_db

    with jen_db() as db, db.cursor() as cur:
        cur.execute(
            "SELECT id, channel_type, alert_type, status, error, sent_at FROM alert_log ORDER BY id DESC LIMIT %s",
            (ALERT_TAIL_ROWS,),
        )
        return list(cur.fetchall())


def _collect_lease_history() -> list[dict]:
    from jen.models.db import jen_db

    with jen_db() as db, db.cursor() as cur:
        cur.execute(
            """
            SELECT subnet_id, COUNT(*) AS snapshots, MIN(snapshot_time) AS first, MAX(snapshot_time) AS last,
                   MAX(active_leases) AS peak_active, MAX(pool_used) AS peak_pool_used, MAX(pool_size) AS pool_size
            FROM lease_history WHERE snapshot_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
            GROUP BY subnet_id ORDER BY subnet_id
            """,
            (LEASE_HISTORY_DAYS,),
        )
        rows = list(cur.fetchall())
    for r in rows:
        r["name"] = (extensions.SUBNET_MAP.get(r["subnet_id"]) or {}).get("name")
    return rows


def _log_file_path() -> str:
    try:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(extensions.CONFIG_FILE)
        return parser.get("server", "log_file", fallback="") or os.environ.get("JEN_LOG_FILE", "")
    except Exception:
        return os.environ.get("JEN_LOG_FILE", "")


def _collect_log_text() -> str | None:
    path = _log_file_path()
    if not path:
        return None
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def collect_all() -> dict:
    """Everything the bundle needs, RAW. Redaction is build_bundle's job."""
    notes: list[str] = []
    collected = {
        "notes": notes,
        "jen": _guard(notes, "jen", _collect_jen, {}),
        "config_text": _guard(notes, "config", _collect_config_text, ""),
        "servers": _guard(notes, "servers", _collect_servers, []),
        "health": _guard(notes, "health", _collect_health, {}),
        "drift": _guard(notes, "drift", _collect_drift, []),
        "kea_configs": _guard(notes, "kea configs", lambda: _collect_kea_configs(notes), []),
        "plugins": _guard(notes, "plugins", _collect_plugins, []),
        "db": _guard(notes, "db", _collect_db, {}),
        "audit": _guard(notes, "audit", _collect_audit, []),
        "alerts": _guard(notes, "alerts", _collect_alerts, []),
        "lease_history": _guard(notes, "lease history", _collect_lease_history, []),
    }
    log_text = _guard(notes, "log", _collect_log_text, None)
    collected["log_text"] = log_text
    if log_text is None:
        collected["log_note"] = (
            "No [server] log_file configured — Jen logs to journald on a systemd host: "
            "`journalctl -u jen -n 500 --no-pager`. Attach that output alongside this bundle.\n"
        )
    return collected


def make_bundle() -> tuple[bytes, str, list[str]]:
    """(zip bytes, filename, member names) for the route."""
    collected = collect_all()
    now = datetime.now(timezone.utc)
    data, names = build_bundle(collected, now=now)
    return data, bundle_filename((collected.get("jen") or {}).get("hostname", "jen"), now), names
