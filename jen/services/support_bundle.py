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
`/etc/jen/mfa_key`, `mfa_methods`, `mfa_backup_codes`, `api_keys`,
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

logger = logging.getLogger(__name__)

# Members are added in this order; when the size cap is exceeded the
# droppable ones go first (largest first).
SIZE_CAP_BYTES = 20 * 1024 * 1024
DROPPABLE = ("logs/jen.log.tail", "audit-tail.json", "alerts-tail.json")

LOG_TAIL_LINES = 2000
AUDIT_TAIL_ROWS = 500
ALERT_TAIL_ROWS = 200
LEASE_HISTORY_DAYS = 7

# INI keys whose VALUE is a secret. A key that names a *path* to a
# secret (key_path, api_client_key, ssl_key) is kept — the path is
# diagnostic, the file is never opened.
_SECRET_KEY_RE = re.compile(
    r"(^|_)(password|pass|passwd|secret|token|api_key|client_secret|metrics_token)$|_(pass|secret|token)$",
    re.IGNORECASE,
)
_PATH_VALUE_RE = re.compile(r"^(/|[A-Za-z]:\\)")
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


def is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEY_RE.search(key or ""))


def redact_ini_text(text: str) -> str:
    """The INI re-emitted with every secret-looking value masked. Paths
    survive even under a secret-looking key (`ssl_key = /etc/…`). A
    file that doesn't parse is replaced by a note, never echoed."""
    parser = configparser.ConfigParser(interpolation=None)
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
            if is_secret_key(key) and value and not _PATH_VALUE_RE.match(value):
                value = MASK
            out.append(f"{key} = {value}")
        out.append("")
    return "\n".join(out)


def scrub_log_line(line: str) -> str:
    for rx, repl in _LOG_SCRUBS:
        line = rx.sub(repl, line)
    return line


def scrub_log_text(text: str, max_lines: int = LOG_TAIL_LINES) -> str:
    lines = (text or "").splitlines()[-max_lines:]
    return "\n".join(scrub_log_line(ln) for ln in lines) + ("\n" if lines else "")


def _json(data) -> str:
    return json.dumps(data, indent=2, sort_keys=True, default=str) + "\n"


def readme_text(version: str, channel: str, hostname: str, when: str, notes: list[str]) -> str:
    body = [
        f"Jen support bundle — v{version} ({channel} channel) — {hostname} — {when}",
        "",
        "Attach this file to a bug report. It was produced by Settings → System →",
        "Support bundle and contains only diagnostic state:",
        "",
        "  jen.json                 version, channel, Python, serving mode, paths",
        "  config.ini.redacted      jen.config with every secret value masked",
        "  servers.json             each Kea server: URLs, mode, helper version, TLS copies",
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
        "the SSH / mTLS / CA private keys, users, or the config-revision history.",
        "Key FILE PATHS appear; key contents never do.",
    ]
    if notes:
        body += ["", "Sections that could not be collected:"] + [f"  - {n}" for n in notes]
    return "\n".join(body) + "\n"


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
        members[name] = text.encode("utf-8")

    put("jen.json", _json(collected.get("jen") or {}))
    put("config.ini.redacted", redact_ini_text(collected.get("config_text") or ""))
    put("servers.json", _json(collected.get("servers") or []))
    put("health.json", _json(collected.get("health") or {}))
    put("drift.json", _json(collected.get("drift") or []))
    for entry in collected.get("kea_configs") or []:
        name = f"kea/{entry.get('server_id')}-{entry.get('service')}.json"
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
            collected.get("log_note") or "No log file configured — Jen logs to journald: `journalctl -u jen -n 500`.\n",
        )
    else:
        put("logs/jen.log.tail", scrub_log_text(log_text))

    members, dropped = apply_size_cap(members, cap)
    for d in dropped:
        notes.append(f"{d} dropped to stay under the {cap // (1024 * 1024)} MB size cap")
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
        "docker": os.path.exists("/.dockerenv"),
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
    from jen.services.dbexport import JEN_TABLES

    out: dict = {"schema_latest": migrations.latest_version(), "schema_applied": sorted(migrations.applied_versions())}
    with jen_db() as db, db.cursor() as cur:
        cur.execute("SELECT VERSION() AS v")
        out["server_version"] = (cur.fetchone() or {}).get("v")
        cur.execute("SELECT plugin_id, version, applied_at FROM plugin_schema_migrations ORDER BY plugin_id, version")
        out["plugin_migrations"] = list(cur.fetchall())
        counts = {}
        for table in JEN_TABLES:
            try:
                cur.execute(f"SELECT COUNT(*) AS c FROM `{table}`")  # table names come from dbexport's fixed dict
                counts[table] = (cur.fetchone() or {}).get("c")
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
                   MAX(active_leases) AS peak_active, MAX(pool_size) AS pool_size
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
