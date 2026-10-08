"""
jen/config.py
─────────────
Single source of truth for jen.config: loading, validation, writing,
and derivation of all runtime configuration values.

Architecture (v4.0.0)
─────────────────────
The AppConfig class owns the entire config lifecycle. The module-level
globals in jen/extensions.py remain the read surface for the rest of
the application (so call sites stay simple), but they are written
ONLY by AppConfig.apply() — no other code may assign them.

Every write method reloads from disk and re-derives all values, so
the on-disk file, the parsed ConfigParser, and the derived globals
can never diverge. This eliminates the stale-config bug class fixed
piecemeal in v3.8.1.

The config file path is read dynamically from extensions.CONFIG_FILE
on every operation (never cached) so the test suite can repoint it.

Module-level functions (load_config, init_extensions_from_config,
write_config_value, write_subnets_config, load_kea_servers,
load_subnet_map) are preserved as thin wrappers for backward
compatibility with existing callers and plugins.
"""

import configparser
import contextlib
import errno
import functools
import ipaddress
import logging
import os
import re
import threading
import time

from jen import extensions

logger = logging.getLogger(__name__)


def _db_port(cfg, section: str, default: int) -> int:
    """`[kea_db] port` / `[kea6_db] port` → a TCP port (v5.67.0-beta.8, Q120, item g). Absent → `default`;
    a value that is not 1-65535 is logged and ignored rather than raised — apply() must not raise on a
    working config, and a typo here must not stop the app booting."""
    raw = cfg.get(section, "port", fallback="").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        logger.warning(f"[{section}] port: {raw!r} is not a valid port — using {default}")
        return default
    return port


def _parse_update_channel(raw: str) -> str:
    """`[updates] channel` → "stable" | "beta". Unknown → "stable" with a
    warning (v5.32.0, Q38)."""
    from jen.version import CHANNELS

    value = (raw or "").strip().lower()
    if value in CHANNELS:
        return value
    if value:
        logger.warning(f"[updates] channel: unknown value {raw!r} — using stable")
    return "stable"


def _parse_problem_threshold(raw: str) -> int:
    """`[alerts] client_problem_threshold` -> a whole number of at least 1; anything else -> 3 with a warning (v5.68.0-beta.5,
    Q140). Optional: the key's absence is the default and says nothing."""
    text = (raw or "").strip()
    if not text:
        return 3
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        logger.warning(f"[alerts] client_problem_threshold: {raw!r} is not a whole number of 1 or more - using 3")
        return 3
    return min(value, 1000)


def _parse_trusted_proxies(raw: str) -> list:
    """Parse `[server] trusted_proxies` (comma list of IPs / CIDRs) into a
    list of ip_network objects. A single host is accepted bare (`10.0.0.1`
    → `10.0.0.1/32`). Malformed entries are logged and skipped."""
    nets = []
    for tok in (raw or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            logger.warning(f"[server] trusted_proxies: ignoring invalid entry {tok!r}")
    return nets


# v5.67.0-beta.5 (Q117, item h) — write_subnets()/write_subnets6()'s own
# storage format is "name, cidr[, paired_v4_subnet_id]"; a name containing
# any of these breaks that split(",") on the next read (_parse_subnet_map,
# below) and the whole entry is silently dropped — not rejected at write
# time, just gone on the next reload with nothing but a log warning. `=`,
# `[` and `]` are refused too: ConfigParser's own INI syntax would read a
# `name = x` value fine today, but a name containing them is one format
# change away from the same silent-corruption class.
SUBNET_NAME_MAX_LEN = 64
SUBNET_NAME_FORBIDDEN_CHARS = ",=[]"


def invalid_subnet_name_reason(name: str) -> str | None:
    """None if `name` is safe to store, else a short, user-facing reason.
    write_subnets()/write_subnets6() call this for a NEW or CHANGED name
    before writing anything (v5.67.0-beta.7, Q119, item g — an untouched
    legacy name is never re-validated; see _reconcile_subnet_names()),
    so nothing bypasses it for the names that actually matter — a bad
    one always raises ValueError there at minimum. routes/subnets.py's
    add-subnet form also calls it directly first, for an inline refusal
    before Kea's own config is ever touched, rather than only finding
    out from the choke point after the fact; /setup's Found step relies
    on the choke point alone (jen.services.setup_wizard.save_subnets
    catches the ValueError and turns it into a flash message)."""
    if not name:
        return "Name is required"
    if len(name) > SUBNET_NAME_MAX_LEN:
        return f"Name must be at most {SUBNET_NAME_MAX_LEN} characters"
    if any(c in name for c in SUBNET_NAME_FORBIDDEN_CHARS):
        return "Name must not contain a comma, =, [ or ]"
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        return "Name must not contain a control character"
    return None


def _reconcile_subnet_names(subnet_dict: dict, stored: dict, raw_section: dict) -> dict:
    """v5.67.0-beta.7 (Q119, item g) — since Q117, write_subnets()/
    write_subnets6() validated EVERY name in the whole map on every
    write, including names that predate the validator and were never
    touched by this write at all: a single legacy name with an `=` or
    over 64 characters made every later add/delete/import raise
    ValueError — after Kea's own config had already been changed, since
    every caller writes Jen's map AFTER applying the real change.

    Refuses only a name that is NEW (`sid` not in `stored`) or CHANGED
    (`stored[sid]["name"] != info["name"]`) relative to what's already
    on disk — an untouched legacy name is written back exactly as it
    was, no re-validation.

    `raw_section` ({str(sid): raw stored value}) covers a sharper case:
    a comma in a name doesn't just make it "stored oddly," it corrupts
    the `"name, cidr"` line's own format — derive_subnet_map() splits on
    comma and discards such an entry as malformed, so it's invisible to
    `stored` (and to the running app's SUBNET_MAP) even though it's
    still physically sitting in the file. Without this, the very next
    unrelated write (rebuilding the section from `subnet_dict`, which
    never heard of an entry SUBNET_MAP never loaded) would silently
    DELETE it outright. Recovered here instead: the comma is replaced
    with a space (logged) and the repaired entry rejoins the map, where
    it's visible — and manageable — again from the next page load on.

    Returns a new dict in `subnet_dict`'s own shape (safe to write
    as-is); raises ValueError on the first new/changed name that fails
    validation, same as before — nothing is mutated or logged for a
    dict that ends up not being written at all."""
    reconciled = {}
    for sid, info in subnet_dict.items():
        name = info["name"]
        existing = stored.get(sid)
        if existing is None or existing["name"] != name:
            reason = invalid_subnet_name_reason(name)
            if reason:
                raise ValueError(f"subnet {sid}: {reason}")
        reconciled[sid] = dict(info)

    for key, raw in raw_section.items():
        try:
            sid = int(key)
        except ValueError:
            continue
        if sid in stored or sid in reconciled:
            continue  # cleanly parsed already, or this write already handles it
        parts = [p.strip() for p in raw.split(",")]
        if len(parts) < 2:
            continue  # genuinely unparseable — nothing left to recover
        *name_parts, cidr = parts
        name = ", ".join(name_parts)
        fixed = name.replace(",", " ")
        logger.warning(f"subnet {sid}: repairing a comma in its stored name ({name!r} -> {fixed!r})")
        reconciled[sid] = {"name": fixed, "cidr": cidr}
    return reconciled


try:  # advisory file locks are POSIX; the app itself only runs on Linux (the lock is skipped where `fcntl` does not exist)
    import fcntl
except ImportError:  # pragma: no cover - Windows dev boxes
    fcntl = None

#: v5.68.0-beta.18 (Q153) - how long a writer waits for the config file lock before giving up (an installer's `--configure` holds it for
#: the length of an interactive wizard, so a Settings save during it waits - and then says why - instead of overwriting the installer's copy).
FILE_LOCK_WAIT_S = 30.0

_writer_state = (
    threading.local()
)  # per thread: how many writers are open, and whether we are inside a `mutate` callback


class ConfigFileLocked(RuntimeError):
    """The config file's advisory lock (`<config>.lock`) is held by another process and did not come free in `FILE_LOCK_WAIT_S`."""


def _open_lock(lock_path):
    """Open `<config>.lock` for locking, FAILING CLOSED and NEVER BY REPLACEMENT.

    A lock is an INODE, not a name: `flock` is held on the file the descriptor points at. beta.19 (Q154) repaired an unopenable lock by renaming a fresh
    private file over it - and an installer that still held the OLD inode and Jen locking the NEW one both held "the" lock, so the lost update the
    lock exists to prevent was back. v5.68.0-beta.20 (Q155): there is no repair here. One `O_NOFOLLOW` open; a symlink is refused (never followed),
    and a file this account cannot open refuses the save with the reason and the exact fix - `chown <the Jen service user>; chmod 600` on the SAME
    inode, which `install.sh` does for you on every upgrade and `--configure` (a chown does not drop an flock)."""
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(lock_path, flags, 0o600)
    except OSError as e:
        if os.path.islink(lock_path):
            raise _refuse_lock(lock_path, "is a symlink - Jen never locks through one; remove it", e) from e
        if not os.path.lexists(lock_path):
            # v5.68.0-beta.22 (Q157): there is NO lock file - the open failed trying to CREATE it (ENOENT / EACCES / EROFS on the DIRECTORY). The fix
            # is not "chown the lock file" (nothing to chown): the config directory must exist and be writable by this account.
            directory = os.path.dirname(lock_path) or "."
            raise ConfigFileLocked(
                f"the config lock {lock_path} could not be created ({e.strerror or e}): the config directory {directory} must exist and be writable by the "
                f"Jen service user - sudo chown <the Jen service user> {directory}"
            ) from e
        raise _refuse_lock(lock_path, f"cannot be opened ({e.strerror or e})", e) from e


def _refuse_lock(lock_path, reason, cause):
    message = f"the config lock {lock_path} {reason} - fix its ownership and mode (sudo chown <the Jen service user> {lock_path}; chmod 600 {lock_path})"
    logger.error(message)
    return ConfigFileLocked(message)


@contextlib.contextmanager
def _file_lock(path):
    """An exclusive advisory `flock` on `<config>.lock`, held for the whole read-modify-replace of one writer.

    v5.68.0-beta.18 (Q153): `AppConfig._write_lock` serialises this PROCESS's threads, and the installer is another process - `install.sh
    --configure` runs its wizard and rewrites jen.config while Jen is running, so a Settings save made during the wizard was overwritten by the
    installer's older copy. The installer and `tools/private_write.py` take this same lock. Taken once per thread (a nested writer, which the
    RLock allows, must not queue behind its own thread on a second descriptor); the lock file is created 0600, never through a symlink."""
    depth = getattr(_writer_state, "lock_depth", 0)
    if fcntl is None or depth > 0:
        _writer_state.lock_depth = depth + 1
        try:
            yield
        finally:
            _writer_state.lock_depth = depth
        return
    lock_path = f"{path}.lock"
    fd = _open_lock(lock_path)
    try:
        deadline = time.monotonic() + FILE_LOCK_WAIT_S
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EAGAIN, errno.EACCES):
                    # v5.68.0-beta.22 (Q157): ENOLCK (NFS), EBADF, EINTR... escaped as a bare OSError and 500'd the save; it is a refusal with the reason
                    raise ConfigFileLocked(
                        f"the config lock {lock_path} could not be taken ({errno.errorcode.get(e.errno, e.errno)}: {e.strerror or e}) - "
                        "the file system does not support the advisory lock Jen's saves take; keep the config directory on a local file system"
                    ) from e
                if time.monotonic() >= deadline:
                    raise ConfigFileLocked(
                        f"{lock_path} is held by another process (the installer's --configure?) - try again when it has finished"
                    ) from e
                time.sleep(0.05)
        _writer_state.lock_depth = 1
        try:
            yield
        finally:
            _writer_state.lock_depth = 0
    finally:
        os.close(fd)  # closing the descriptor releases the flock


def _serialized(fn):
    """Run a writer while holding AppConfig's one lock - see AppConfig._write_lock - and the config file's advisory lock."""

    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        if getattr(_writer_state, "in_mutate", False):
            # v5.68.0-beta.18 (Q153): `mutate` hands its callback the parser to change and writes THAT parser when it returns, so a writer
            # called from inside it would write to disk and then be overwritten - silently - by the outer write of the parser read before.
            # The contract refuses what it cannot honour instead of advertising it.
            raise RuntimeError("mutate the parser you were given")
        with AppConfig._write_lock, _file_lock(self.path):
            return fn(self, *args, **kwargs)

    return wrapper


class AppConfig:
    """Owns loading, writing, and derivation of jen.config."""

    # v5.68.0-beta.17 (Q152) - ONE lock for every writer. Each writer is read-modify-write (read the file, change one thing, replace the
    # file), and gunicorn runs one worker with N threads, so two Settings saves at once - two admins, or a save racing the setup wizard
    # or Author Kea Config's `[subnets]` write - were a lost update: the second read missed the first write. The lock is held from the
    # read to the end of the reload, so what a writer reads is what is on disk when it replaces it and the globals follow the same
    # order as the file. It is an RLock because `mutate`'s callback may itself call a writer, and CLASS-level so every AppConfig
    # instance (the module's `app_config`, a test's own) serialises against every other. Readers (`load`, `reload`) take no lock:
    # `os.replace` means they see the old file or the new one, never half of one.
    _write_lock = threading.RLock()

    # ── Path (dynamic — tests repoint extensions.CONFIG_FILE) ────────────

    @property
    def path(self) -> str:
        return extensions.CONFIG_FILE

    # ── Loading ──────────────────────────────────────────────────────────

    def load(self) -> configparser.ConfigParser:
        """Read and validate jen.config. Raises on missing required values."""
        # interpolation=None (v4.4.8): DB/API passwords can legitimately
        # contain a literal '%' character. With default BasicInterpolation
        # enabled, configparser treats '%' specially and raises
        # InterpolationSyntaxError reading such a value back — Jen doesn't
        # use interpolation anywhere in its own config, so there's no
        # downside to disabling it outright.
        cfg = configparser.ConfigParser(interpolation=None)
        if not os.path.exists(self.path):
            raise FileNotFoundError(
                f"Config file not found: {self.path}\nCopy jen.config.example to {self.path} and fill in your values."
            )
        cfg.read(self.path)
        # v5.67.0 (Q115) — Kea's API/database are no longer required for Jen
        # to boot at all: a fresh install with none of that configured is
        # the whole point of the /setup wizard (jen.services.setup_wizard,
        # jen/routes/setup.py) — kea_connected() already treats a blank
        # KEA_API_URL/SUBNET_MAP as a legitimate, handled state everywhere
        # else in the app (dashboard, health checks, …). Jen's own database
        # is the one thing it genuinely cannot run without.
        required = [
            ("jen_db", "host"),
            ("jen_db", "user"),
            ("jen_db", "password"),
        ]
        missing = [(s, k) for s, k in required if not cfg.has_option(s, k) or not cfg.get(s, k).strip()]
        if missing:
            raise ValueError(f"Missing required config values: {missing}")
        return cfg

    # ── Derivation ───────────────────────────────────────────────────────

    def apply(self, cfg: configparser.ConfigParser) -> None:
        """
        Populate all extensions globals from a loaded ConfigParser.
        This is the ONLY place extensions config globals are assigned.
        """
        extensions.cfg = cfg
        # v5.65.2 (Q91 e): a saved configuration (a server, the connection mode) makes any cached
        # per-server capability stale; this is the one place every config write and reload passes.
        try:
            from jen.services import capabilities as _caps

            _caps.invalidate()
        except Exception:  # never let a cache drop break a config load
            pass

        extensions.KEA_API_URL = cfg.get("kea", "api_url")
        extensions.KEA_API_USER = cfg.get("kea", "api_user")
        extensions.KEA_API_PASS = cfg.get("kea", "api_pass")

        # v5.10.0 — Control-Agent-less mode. Default 'ca' = every prior
        # release's behavior, unchanged; an unrecognized value is treated
        # as 'ca' rather than raising (a typo mustn't break a working
        # install). See jen/services/kea.py::_endpoint_for().
        _mode = cfg.get("kea", "connection_mode", fallback="ca").strip().lower()
        extensions.KEA_CONNECTION_MODE = _mode if _mode in ("ca", "direct") else "ca"
        extensions.KEA_API_CA = cfg.get("kea", "api_ca", fallback="").strip()
        extensions.KEA_API_TLS_VERIFY = cfg.getboolean("kea", "api_tls_verify", fallback=True)
        # v5.10.2 — client certificate for Kea's default mTLS https socket.
        # A missing file is a save-time error (see save_infra_kea), never a
        # load-time one — apply() must not raise on a working config.
        extensions.KEA_API_CLIENT_CERT = cfg.get("kea", "api_client_cert", fallback="").strip()
        extensions.KEA_API_CLIENT_KEY = cfg.get("kea", "api_client_key", fallback="").strip()

        extensions.KEA_DB_HOST = cfg.get("kea_db", "host")
        extensions.KEA_DB_USER = cfg.get("kea_db", "user")
        extensions.KEA_DB_PASS = cfg.get("kea_db", "password")
        extensions.KEA_DB_NAME = cfg.get("kea_db", "database", fallback="kea")
        extensions.KEA_DB_PORT = _db_port(cfg, "kea_db", 3306)
        extensions.KEA_DB_SSL_CA = cfg.get("kea_db", "ssl_ca", fallback="")

        extensions.JEN_DB_HOST = cfg.get("jen_db", "host")
        extensions.JEN_DB_USER = cfg.get("jen_db", "user")
        extensions.JEN_DB_PASS = cfg.get("jen_db", "password")
        extensions.JEN_DB_NAME = cfg.get("jen_db", "database", fallback="jen")
        extensions.JEN_DB_SSL_CA = cfg.get("jen_db", "ssl_ca", fallback="")

        extensions.HTTP_PORT = cfg.getint("server", "http_port", fallback=5050)
        extensions.HTTPS_PORT = cfg.getint("server", "https_port", fallback=8443)

        # v5.5.0 — clamp to a sane range; a typo of 0 or 5000 shouldn't
        # translate straight into a gunicorn --threads argument.
        _threads = cfg.getint("server", "threads", fallback=8)
        extensions.WORKER_THREADS = max(1, min(_threads, 64))

        # v5.17.0 (Q6 6D) — reverse-proxy trust. A comma list of IPs or
        # CIDRs; when the request's peer is one of them, TrustedProxyMiddleware
        # rewrites REMOTE_ADDR from X-Forwarded-For and url_scheme from
        # X-Forwarded-Proto. A malformed entry is logged and skipped, not
        # fatal — a broken proxy line must not stop the app booting.
        extensions.TRUSTED_PROXIES = _parse_trusted_proxies(cfg.get("server", "trusted_proxies", fallback=""))

        # v5.32.0 (Q38) — release channel. Optional; anything but the two
        # known names is logged and treated as stable, never as beta — the
        # conservative reading of a typo.
        extensions.UPDATE_CHANNEL = _parse_update_channel(cfg.get("updates", "channel", fallback="stable"))

        extensions.KEA_SSH_HOST = cfg.get("kea_ssh", "host", fallback="")
        extensions.KEA_SSH_USER = cfg.get("kea_ssh", "user", fallback="")
        extensions.KEA_CONF = cfg.get("kea_ssh", "kea_conf", fallback="/etc/kea/kea-dhcp4.conf")
        extensions.SSH_KEY_PATH = cfg.get(
            "kea_ssh", "key_path", fallback=os.path.join(extensions.CONFIG_DIR, "ssh", "jen_rsa")
        )

        extensions.DDNS_LOG = cfg.get("ddns", "log_path", fallback="/var/log/kea/kea-ddns.log")
        extensions.DHCP4_LOG = cfg.get("kea", "dhcp4_log_path", fallback="/var/log/kea/kea-dhcp4.log").strip()
        extensions.CLIENT_PROBLEM_THRESHOLD = _parse_problem_threshold(
            cfg.get("alerts", "client_problem_threshold", fallback="")
        )

        # v5.0 Phase 1 — IPv6. Every [kea6]/[kea6_db] value falls back to its
        # v4 counterpart when absent, matching the common same-CA/same-DB Kea
        # deployment (confirmed against theelders' real kea-ctrl-agent.conf —
        # see the v5.0 plan doc). Reading these costs a v4-only install
        # nothing; they're simply never consulted unless ipv6_enabled (a
        # settings-table flag, not a config value) is true.
        # v5.10.0 — in ca mode [kea6] api_url falls back to the v4 CA URL
        # (one Control Agent proxies both families — the common case). In
        # direct mode there is NO fallback: kea-dhcp4 cannot answer dhcp6
        # commands, so an unset [kea6] api_url means v6 API calls return an
        # error dict rather than being misrouted to the v4 daemon.
        _kea6_url_fallback = extensions.KEA_API_URL if extensions.KEA_CONNECTION_MODE == "ca" else ""
        extensions.KEA6_API_URL = cfg.get("kea6", "api_url", fallback=_kea6_url_fallback)
        extensions.KEA6_API_USER = cfg.get("kea6", "api_user", fallback=extensions.KEA_API_USER)
        extensions.KEA6_API_PASS = cfg.get("kea6", "api_pass", fallback=extensions.KEA_API_PASS)

        extensions.KEA6_DB_HOST = cfg.get("kea6_db", "host", fallback=extensions.KEA_DB_HOST)
        extensions.KEA6_DB_USER = cfg.get("kea6_db", "user", fallback=extensions.KEA_DB_USER)
        extensions.KEA6_DB_PASS = cfg.get("kea6_db", "password", fallback=extensions.KEA_DB_PASS)
        extensions.KEA6_DB_NAME = cfg.get("kea6_db", "database", fallback=extensions.KEA_DB_NAME)
        extensions.KEA6_DB_PORT = _db_port(cfg, "kea6_db", extensions.KEA_DB_PORT)
        extensions.KEA6_DB_SSL_CA = cfg.get("kea6_db", "ssl_ca", fallback=extensions.KEA_DB_SSL_CA)

        # v5.23.0 (Q19) — D2's own control socket, same ca/direct fallback
        # shape as [kea6] above: in ca mode api_url defaults to the v4 CA
        # URL (one CA proxies D2 too); in direct mode there's no fallback,
        # since a bare CA connection_mode of "direct" means every daemon
        # (D2 included) has its own http control socket.
        _d2_url_fallback = extensions.KEA_API_URL if extensions.KEA_CONNECTION_MODE == "ca" else ""
        extensions.D2_API_URL = cfg.get("d2", "api_url", fallback=_d2_url_fallback)
        extensions.D2_API_USER = cfg.get("d2", "api_user", fallback=extensions.KEA_API_USER)
        extensions.D2_API_PASS = cfg.get("d2", "api_pass", fallback=extensions.KEA_API_PASS)

        # v5.25.0 (Q21) — [oidc] is entirely optional; apply() only reads
        # values, it never validates (a bad issuer/role_map here must not
        # stop a working install from booting — validation happens at
        # save time, in the settings route).
        extensions.OIDC_ENABLED = cfg.getboolean("oidc", "enabled", fallback=False)
        extensions.OIDC_ISSUER = cfg.get("oidc", "issuer", fallback="").strip()
        extensions.OIDC_CLIENT_ID = cfg.get("oidc", "client_id", fallback="").strip()
        extensions.OIDC_CLIENT_SECRET = cfg.get("oidc", "client_secret", fallback="")
        extensions.OIDC_SCOPES = cfg.get("oidc", "scopes", fallback="openid profile email")
        extensions.OIDC_USERNAME_CLAIM = cfg.get("oidc", "username_claim", fallback="preferred_username")
        extensions.OIDC_ROLE_CLAIM = cfg.get("oidc", "role_claim", fallback="groups")
        extensions.OIDC_ROLE_MAP = cfg.get(
            "oidc", "role_map", fallback="superadmin=jen-superadmin;admin=jen-admin;viewer=jen-viewer"
        )
        extensions.OIDC_DEFAULT_ROLE = cfg.get("oidc", "default_role", fallback="viewer").strip().lower()
        extensions.OIDC_AUTO_CREATE = cfg.getboolean("oidc", "auto_create", fallback=True)
        extensions.OIDC_BUTTON_LABEL = cfg.get("oidc", "button_label", fallback="Sign in with SSO")
        extensions.OIDC_REDIRECT_URI = cfg.get("oidc", "redirect_uri", fallback="").strip()
        extensions.OIDC_LOCAL_LOGIN = cfg.getboolean("oidc", "local_login", fallback=True)
        extensions.OIDC_SUBNET_MAP = cfg.get("oidc", "subnet_map", fallback="")
        extensions.OIDC_SUBNET_MAP_DEFAULT = cfg.get("oidc", "subnet_map_default", fallback="none").strip().lower()

        extensions.KEA_SERVERS = self.derive_kea_servers(cfg)
        extensions.SUBNET_MAP = self.derive_subnet_map(cfg)
        extensions.SUBNET6_MAP = self.derive_subnet_map(cfg, section="subnets6")

    def reload(self) -> configparser.ConfigParser:
        """Load from disk and re-derive everything. The single choke point."""
        cfg = self.load()
        self.apply(cfg)
        return cfg

    # ── Writing (every write reloads so memory always matches disk) ──────

    def _read_parser(self) -> configparser.ConfigParser:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(self.path)
        return parser

    def _write_parser(self, parser: configparser.ConfigParser) -> None:
        # v5.10.4 — write a sibling temp file and os.replace() it into
        # place, for two reasons:
        #   * an interrupted write can no longer truncate jen.config to
        #     nothing (the reader sees either the old file or the new one,
        #     never a half-written one);
        #   * os.replace() only needs write access to the *directory*
        #     (/etc/jen, owned by the service user), so a box whose
        #     jen.config was left root-owned by an older installer
        #     (5.9.0–5.10.3 fresh installs — see write_config in
        #     install.sh) self-heals on its first Settings save instead of
        #     failing every save with EACCES.
        # v5.68.0-beta.15 (Q150) - private from its FIRST BYTE: this file holds every database password and API credential, and
        # `open(tmp, "w")` created it with the process umask (world-readable under systemd's 0022) and tightened it afterwards. The
        # write goes through jen.services.private_files (unique O_EXCL 0600 temp in this directory, fsync, fchmod 0600 on the
        # descriptor, os.replace) - the same discipline as the helper's `_private_tempfile`.
        import io

        from jen.services.private_files import write_private_file

        buf = io.StringIO()
        parser.write(buf)
        write_private_file(self.path, buf.getvalue(), 0o600)

    @_serialized
    def write_value(self, section: str, key: str, value: str, reload: bool = True) -> None:
        """Update a single value on disk, then reload."""
        parser = self._read_parser()
        if not parser.has_section(section):
            parser.add_section(section)
        parser.set(section, key, value)
        self._write_parser(parser)
        if reload:
            self.reload()

    @_serialized
    def write_values(self, items, reload: bool = True) -> None:
        """Update multiple (section, key, value) tuples in one write+reload."""
        parser = self._read_parser()
        for section, key, value in items:
            if not parser.has_section(section):
                parser.add_section(section)
            parser.set(section, key, value)
        self._write_parser(parser)
        if reload:
            self.reload()

    @_serialized
    def write_subnets(self, subnet_dict: dict, reload: bool = True) -> None:
        """Rewrite the [subnets] section entirely, then reload.

        v5.67.0-beta.5 (Q117, item h) — every NEW or CHANGED name is
        validated BEFORE anything is written (never a partial write): a
        bad one raises ValueError rather than silently corrupting the
        stored line. v5.67.0-beta.7 (Q119, item g) — an untouched legacy
        name is no longer re-validated on every write; see
        _reconcile_subnet_names()."""
        parser = self._read_parser()
        stored = self.derive_subnet_map(parser, "subnets")
        raw_section = dict(parser.items("subnets")) if parser.has_section("subnets") else {}
        reconciled = _reconcile_subnet_names(subnet_dict, stored, raw_section)
        if parser.has_section("subnets"):
            parser.remove_section("subnets")
        parser.add_section("subnets")
        for sid, info in reconciled.items():
            parser.set("subnets", str(sid), f"{info['name']}, {info['cidr']}")
        self._write_parser(parser)
        if reload:
            self.reload()

    @_serialized
    def write_subnets6(self, subnet_dict: dict, reload: bool = True) -> None:
        """Rewrite the [subnets6] section entirely, then reload. Mirrors
        write_subnets() above (including the v5.67.0-beta.7, Q119, item g
        new-or-changed-only validation); includes the optional
        paired_subnet4_id third field when an entry has one set."""
        parser = self._read_parser()
        stored = self.derive_subnet_map(parser, "subnets6")
        raw_section = dict(parser.items("subnets6")) if parser.has_section("subnets6") else {}
        reconciled = _reconcile_subnet_names(subnet_dict, stored, raw_section)
        if parser.has_section("subnets6"):
            parser.remove_section("subnets6")
        parser.add_section("subnets6")
        for sid, info in reconciled.items():
            paired = info.get("paired_subnet4_id")
            line = f"{info['name']}, {info['cidr']}"
            if paired is not None:
                line += f", {paired}"
            parser.set("subnets6", str(sid), line)
        self._write_parser(parser)
        if reload:
            self.reload()

    @_serialized
    def mutate(self, fn, reload: bool = True) -> None:
        """
        Arbitrary structured edit: load the parser from disk, pass it to
        fn(parser) for mutation, write it back, reload. Used for edits
        that add/remove whole sections (e.g. extra Kea servers).
        """
        parser = self._read_parser()
        _writer_state.in_mutate = True
        try:
            fn(parser)
        finally:
            _writer_state.in_mutate = False
        self._write_parser(parser)
        if reload:
            self.reload()

    # ── Derived structures ───────────────────────────────────────────────

    @staticmethod
    def derive_kea_servers(cfg: configparser.ConfigParser) -> list:
        """Return list of server dicts from config."""
        primary_user = cfg.get("kea", "api_user")
        primary_pass = cfg.get("kea", "api_pass")
        servers = [
            {
                "id": 1,
                "name": cfg.get("kea", "name", fallback="Kea Server 1"),
                "api_url": cfg.get("kea", "api_url"),
                # v5.10.0 — the kea-dhcp6 control-socket URL for `direct`
                # mode. Blank on the primary means "use [kea6] api_url"
                # (jen/services/kea.py::_endpoint_for); v6 API is
                # primary-only, so extra servers rarely set this.
                "api6_url": cfg.get("kea6", "api_url", fallback=""),
                # v5.10.2 — per-daemon v6 credentials. The `or` chain in
                # _endpoint_for() (server.api6_* → KEA6_* → server.api_*)
                # encodes precedence, so these carry the RAW [kea6] value,
                # NOT a fallback — pre-filling would mask that chain.
                "api6_user": cfg.get("kea6", "api_user", fallback=""),
                "api6_pass": cfg.get("kea6", "api_pass", fallback=""),
                # v5.23.0 (Q19) — same shape as api6_* above: the raw
                # [d2] value, not a fallback (jen.services.kea._endpoint_for's
                # `or` chain does the ca-mode/primary-only fallback).
                "api_d2_url": cfg.get("d2", "api_url", fallback=""),
                "api_d2_user": cfg.get("d2", "api_user", fallback=""),
                "api_d2_pass": cfg.get("d2", "api_pass", fallback=""),
                "api_user": primary_user,
                "api_pass": primary_pass,
                "ssh_host": cfg.get("kea_ssh", "host", fallback=""),
                "ssh_user": cfg.get("kea_ssh", "user", fallback=""),
                "ssh_key": cfg.get(
                    "kea_ssh", "key_path", fallback=os.path.join(extensions.CONFIG_DIR, "ssh", "jen_rsa")
                ),
                "kea_conf": cfg.get("kea_ssh", "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
                "role": cfg.get("kea", "role", fallback="primary"),
            }
        ]
        # v5.19.1 — gap-tolerant: a `while has_section(kea_server_n): n +=
        # 1` loop stops at the first missing number, silently hiding every
        # server after a hand-made gap (e.g. kea_server_2 + kea_server_4
        # with no _3). Enumerate every matching section instead; a stray
        # kea_server_0/_1 (the primary is `[kea]`, id 1) is ignored with a
        # warning rather than colliding with the primary's id.
        nums = []
        for sec_name in cfg.sections():
            m = re.fullmatch(r"kea_server_(\d+)", sec_name)
            if not m:
                continue
            num = int(m.group(1))
            if num < 2:
                logging.getLogger(__name__).warning(f"ignoring [{sec_name}] — server ids start at 2 ([kea] is 1)")
                continue
            nums.append(num)
        for n in sorted(nums):
            sec = f"kea_server_{n}"
            servers.append(
                {
                    "id": n,
                    "name": cfg.get(sec, "name", fallback=f"Kea Server {n}"),
                    "api_url": cfg.get(sec, "api_url", fallback=""),
                    "api6_url": cfg.get(sec, "api6_url", fallback=""),
                    # v5.10.2 — raw per-server value, fallback "" (see the
                    # primary above); _endpoint_for()'s `or` chain does the
                    # rest.
                    "api6_user": cfg.get(sec, "api6_user", fallback=""),
                    "api6_pass": cfg.get(sec, "api6_pass", fallback=""),
                    "api_d2_url": cfg.get(sec, "api_d2_url", fallback=""),
                    "api_d2_user": cfg.get(sec, "api_d2_user", fallback=""),
                    "api_d2_pass": cfg.get(sec, "api_d2_pass", fallback=""),
                    "api_user": cfg.get(sec, "api_user", fallback=primary_user),
                    "api_pass": cfg.get(sec, "api_pass", fallback=primary_pass),
                    "ssh_host": cfg.get(sec, "ssh_host", fallback=""),
                    "ssh_user": cfg.get(sec, "ssh_user", fallback=""),
                    "ssh_key": cfg.get(sec, "ssh_key", fallback=os.path.join(extensions.CONFIG_DIR, "ssh", "jen_rsa")),
                    "kea_conf": cfg.get(sec, "kea_conf", fallback="/etc/kea/kea-dhcp4.conf"),
                    "role": cfg.get(sec, "role", fallback="standby"),
                }
            )
        return servers

    @staticmethod
    def derive_subnet_map(cfg: configparser.ConfigParser, section: str = "subnets") -> dict:
        """
        Parse a `[subnets]`-shaped section into {int_id: {"name": str, "cidr": str}}.

        v5.0: also used for the optional `[subnets6]` section (SUBNET6_MAP) —
        same "id = Friendly Name, CIDR" format, Kea's v6 subnet IDs just live
        in a separate numbering space from v4's. A v4-only install has no
        [subnets6] section at all, which is silent and expected here (unlike
        a missing [subnets], this never warns) — v6 is opt-in, not a
        misconfiguration.

        [subnets6] entries also accept an optional third field —
        "id = Name, CIDR, paired_v4_subnet_id" — so the Subnets page (Phase
        2) can render a paired v4/v6 subnet as one card with two detail
        blocks (plan doc recommendation: config-driven pairing, not
        auto-detected by name/VLAN matching, which is too easy to guess
        wrong). Every entry always carries a "paired_subnet4_id" key so
        callers don't need a .get() with a default; it's None when unset or
        when parsing [subnets], which never has a third field.
        """
        subnet_map = {}
        if not cfg.has_section(section):
            if section == "subnets":
                logger.warning("No [subnets] section found in config.")
            return subnet_map
        for key, val in cfg.items(section):
            try:
                parts = [p.strip() for p in val.split(",")]
                max_parts = 3 if section == "subnets6" else 2
                if len(parts) < 2 or len(parts) > max_parts:
                    expected = "Name, CIDR[, paired_v4_subnet_id]" if section == "subnets6" else "Name, CIDR"
                    logger.warning(f"Skipping malformed subnet '{key}' in [{section}]: expected '{expected}'")
                    continue
                name, cidr = parts[0], parts[1]
                ipaddress.ip_network(cidr, strict=False)
                entry = {"name": name, "cidr": cidr}
                if section == "subnets6":
                    # Only v6 entries carry this key — v4 SUBNET_MAP keeps
                    # its exact original two-key shape so nothing downstream
                    # of the v4 path (templates, other config writers, the
                    # existing test suite) sees any change at all.
                    paired_subnet4_id = None
                    if len(parts) == 3 and parts[2]:
                        paired_subnet4_id = int(parts[2])
                    entry["paired_subnet4_id"] = paired_subnet4_id
                subnet_map[int(key)] = entry
            except ValueError as e:
                logger.warning(f"Skipping invalid subnet '{key} = {val}' in [{section}]: {e}")
        if not subnet_map and section == "subnets":
            logger.warning("No valid subnets found in [subnets] config section.")
        return subnet_map


# ── Singleton ─────────────────────────────────────────────────────────────────

app_config = AppConfig()


# ── Backward-compatible wrappers ─────────────────────────────────────────────
# Existing callers and plugins import these names; they delegate to app_config.


def load_config() -> configparser.ConfigParser:
    return app_config.load()


def init_extensions_from_config(cfg: configparser.ConfigParser) -> None:
    app_config.apply(cfg)


def write_config_value(section: str, key: str, value: str) -> None:
    app_config.write_value(section, key, value)


def write_subnets_config(subnet_dict: dict) -> None:
    app_config.write_subnets(subnet_dict)


def write_subnets6_config(subnet_dict: dict) -> None:
    app_config.write_subnets6(subnet_dict)


def load_kea_servers(cfg: configparser.ConfigParser) -> list:
    return AppConfig.derive_kea_servers(cfg)


def load_subnet_map(cfg: configparser.ConfigParser) -> dict:
    return AppConfig.derive_subnet_map(cfg)


def ssl_configured() -> bool:
    """Return True if a usable SSL certificate + key are present.

    v4.4.9: previously required SSL_COMBINED to exist too — but that
    file is only guaranteed when certs are uploaded through Jen's own
    settings UI (upload_cert() always writes it). Anyone provisioning
    certs externally — mounting Let's Encrypt/cert-manager output into
    a Docker volume, for instance — would have a valid cert+key pair
    that this function refused to recognize, silently falling back to
    HTTP-only with no indication why. run.py already treats
    SSL_COMBINED as optional (falls back to SSL_CERT if absent); this
    now matches that.

    v5.9.1: run.py sets JEN_SSL_DISABLED=1 when the on-disk pair exists but
    cannot be loaded (a mismatched key, a truncated PEM) and it has fallen
    back to HTTP-only rather than crash-looping. Everything that keys on
    "is SSL on" — the HTTPS redirect, the Secure cookie flag, the settings
    badges — must agree with what's actually being served, so honor it
    here, at the one choke point.
    """
    if os.environ.get("JEN_SSL_DISABLED") == "1":
        return False
    return os.path.exists(extensions.SSL_CERT) and os.path.exists(extensions.SSL_KEY)
