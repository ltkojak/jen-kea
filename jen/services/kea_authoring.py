"""
jen/services/kea_authoring.py
──────────────────────────────
v5.1 — "Author a starting config" for kea-dhcp4.conf / kea-dhcp6.conf.

This is deliberately NOT the same operation as editing an existing
subnet (jen/routes/subnets.py's patch scripts, or kea6.py's
build_subnet6_patch_script()) — those touch one subnet block inside an
existing, working file whose interfaces/HA/hooks/lease-database Jen
never has to understand. This module writes a WHOLE new file, so it has
to get those things right itself, and gets them wrong more expensively
than a bad subnet edit does (kea-dhcp4/6 -t only proves the file
parses, not that it binds anything useful or that Jen's own commands
will work against it).

Design principle, per direct instruction: prefer pulling real values
from an already-working sibling config over autodetecting or asking —
if kea-dhcp4.conf already exists and is genuinely running, generating
kea-dhcp6.conf should reuse its interfaces and DB connection info
rather than re-guessing. Autodetection (reading live interface
addresses over SSH) is the fallback for a truly from-scratch host with
neither protocol configured yet, not the default path.

Deliberately excluded from generation, always:
  - HA peer configuration. A peer relationship encodes real state
    (which server is primary, heartbeat timing) that's much more
    expensive to get wrong than a subnet block — matches the
    "don't guess at things a bad guess is expensive for" principle
    already applied to SSH TOFU and subnet pairing elsewhere in Jen.
    If HA is wanted, add it to the generated file by hand afterward.
  - Anything beyond host_cmds/lease_cmds in hooks-libraries. These two
    are the ones Jen's own command usage actually depends on
    (reservation-add/del needs host_cmds; lease6-get-all style reads
    benefit from lease_cmds) — not a guess at what the operator's
    broader setup might want.
"""

import json
import logging
import os
import shlex

from jen import extensions

logger = logging.getLogger(__name__)

REQUIRED_HOOKS = ["host_cmds", "lease_cmds"]

# Kea's own documented defaults (see the ARM) — used only when nothing
# more specific (a sibling config, or the operator's own input) exists.
DEFAULT_TIMERS = {
    "dhcp4": {"valid-lifetime": 86400, "renew-timer": 43200, "rebind-timer": 75600},
    "dhcp6": {"preferred-lifetime": 3000, "valid-lifetime": 7200, "renew-timer": 1000, "rebind-timer": 2000},
}

SIBLING_SERVICE = {"dhcp4": "dhcp6", "dhcp6": "dhcp4"}
SIBLING_DHCP_KEY = {"dhcp4": "Dhcp6", "dhcp6": "Dhcp4"}
DHCP_KEY = {"dhcp4": "Dhcp4", "dhcp6": "Dhcp6"}


def conf_path_for(server: dict, service: str) -> str:
    """
    Derive the path for `service`'s config file from the server's known
    kea_conf (always the v4 path today — see jen/services/kea6.py's
    _kea6_conf_path(), same convention reused here for symmetry). Both
    protocols' config files live side-by-side in the same directory.
    """
    kea4_conf = server.get("kea_conf") or extensions.KEA_CONF
    dirname = os.path.dirname(kea4_conf)
    filename = "kea-dhcp4.conf" if service == "dhcp4" else "kea-dhcp6.conf"
    return os.path.join(dirname, filename)


def ca_conf_path_for(server: dict) -> str:
    """The Control Agent's own config file — conventionally sits next to
    kea-dhcp4.conf. Read (not written) to discover the control-socket
    path each service is expected to use, so a freshly-authored config
    is actually reachable through the same CA Jen already talks to."""
    kea4_conf = server.get("kea_conf") or extensions.KEA_CONF
    return os.path.join(os.path.dirname(kea4_conf), "kea-ctrl-agent.conf")


def read_remote_json(ssh, path: str):
    """cat a remote JSON file over SSH and parse it. Returns None if the
    file doesn't exist or isn't valid JSON — never raises, since "the
    file isn't there" is an expected, common outcome here (that's
    exactly the case this whole module exists to help with), not an
    error condition."""
    try:
        # path is validated on save (valid_remote_path) — quoted here too,
        # defense-in-depth, since it's interpolated into a remote shell.
        _, stdout, _ = ssh.exec_command(f"cat {shlex.quote(path)} 2>/dev/null")
        raw = stdout.read().decode()
        if not raw.strip():
            return None
        return json.loads(raw)
    except Exception as e:
        logger.warning(f"read_remote_json({path}): {e}")
        return None


def detect_ca_socket_path(ssh, server: dict, service: str):
    """
    Read the Control Agent's own config to find the control-socket path
    it expects for `service` — the CA proxies Jen's API commands to
    kea-dhcp4/6 over this exact unix socket, so a generated config must
    use the same path or Jen's own commands against the new service
    will silently fail to route anywhere. Returns None if the CA config
    isn't found or doesn't mention this service (both real, expected
    outcomes — the caller falls back to a conventional default path).
    """
    cfg = read_remote_json(ssh, ca_conf_path_for(server))
    if not cfg:
        return None
    try:
        sockets = cfg["Control-agent"]["control-sockets"]
        return sockets[service]["socket-name"]
    except (KeyError, TypeError):
        return None


def detect_sibling_config(ssh, server: dict, target_service: str) -> dict:
    """
    The preferred source of truth per the design principle above: if
    the OTHER protocol's config already exists and is real, pull
    interfaces and lease-database connection info from it rather than
    autodetecting or asking. Returns a dict with `found` (bool) plus
    whatever fields were actually extractable — always returns a valid
    dict shape, callers don't need to null-check individual keys.
    """
    result = {
        "found": False,
        "interfaces": [],
        "lease_db_type": "",
        "lease_db_host": "",
        "lease_db_name": "",
        "hooks": [],
    }
    sibling_service = SIBLING_SERVICE[target_service]
    sibling_path = conf_path_for(server, sibling_service)
    cfg = read_remote_json(ssh, sibling_path)
    if not cfg:
        return result
    try:
        section = cfg[SIBLING_DHCP_KEY[target_service]]
    except (KeyError, TypeError):
        return result

    result["found"] = True
    result["interfaces"] = section.get("interfaces-config", {}).get("interfaces", [])
    lease_db = section.get("lease-database", {})
    result["lease_db_type"] = lease_db.get("type", "")
    result["lease_db_host"] = lease_db.get("host", "")
    result["lease_db_name"] = lease_db.get("name", "")
    result["hooks"] = [
        os.path.basename(h.get("library", "")).replace("libdhcp_", "").replace(".so", "")
        for h in section.get("hooks-libraries", [])
        if isinstance(h, dict) and h.get("library")
    ]
    return result


def autodetect_interfaces(ssh, service: str) -> list:
    """
    Fallback ONLY — used when detect_sibling_config() found nothing to
    inherit from (a genuinely from-scratch host with neither protocol
    configured yet). Reads live interface addresses over SSH rather
    than asking blind. Returns interface names with a global-scope
    address in the relevant family, excluding loopback; never raises —
    an empty list just means the operator fills interfaces in by hand.
    """
    family = "-6" if service == "dhcp6" else "-4"
    try:
        _, stdout, _ = ssh.exec_command(f"ip {family} addr show scope global 2>/dev/null")
        out = stdout.read().decode()
        interfaces = []
        for line in out.splitlines():
            line = line.strip()
            if line and line[0].isdigit() and ":" in line:
                name = line.split(":")[1].strip().split("@")[0]
                if name and name != "lo" and name not in interfaces:
                    interfaces.append(name)
        return interfaces
    except Exception as e:
        logger.warning(f"autodetect_interfaces: {e}")
        return []


def autodetect_addresses(ssh) -> list:
    """v5.10.2 — global-scope IP addresses on the Kea host, for the
    'bind the control API here' picker in direct-mode authoring. One
    exec_command; never raises (`[]` on any failure, same contract as
    autodetect_interfaces). Loopback / link-local are dropped."""
    try:
        _, stdout, _ = ssh.exec_command(
            "ip -4 -o addr show scope global 2>/dev/null; ip -6 -o addr show scope global 2>/dev/null"
        )
        out = stdout.read().decode()
        addrs = []
        for line in out.splitlines():
            parts = line.split()
            # "2: eth0    inet 10.0.0.5/24 brd ..." → parts[2] == "inet", parts[3] == "10.0.0.5/24"
            if len(parts) >= 4 and parts[2] in ("inet", "inet6"):
                ip = parts[3].split("/")[0]
                if ip in ("127.0.0.1", "::1") or ip.startswith("fe80") or ip in addrs:
                    continue
                addrs.append(ip)
        return addrs
    except Exception as e:
        logger.warning(f"autodetect_addresses: {e}")
        return []


def redact_secrets(cfg: dict) -> dict:
    """v5.10.2 — deep copy of a generated Kea config with every dict value
    whose key is "password" replaced by "********". For the browser
    preview: the server needs the real lease-database / control-socket
    passwords to run `kea-dhcpX -t`, the human reviewing the JSON does
    not. Generic so it covers hosts-database(s), control-sockets auth
    clients, and whatever comes next."""
    if isinstance(cfg, dict):
        return {k: ("********" if k == "password" else redact_secrets(v)) for k, v in cfg.items()}
    if isinstance(cfg, list):
        return [redact_secrets(v) for v in cfg]
    return cfg


def _pool_for_cidr(cidr: str) -> str:
    """Whole-CIDR default pool (network address through broadcast/last
    address) — a conservative starting point the operator can narrow
    later via Jen's existing subnet-edit flow. Not attempting to carve
    out gateway/reserved ranges automatically; that's an edit, not an
    authoring decision."""
    import ipaddress

    net = ipaddress.ip_network(cidr, strict=False)
    if net.version == 4:
        hosts = list(net.hosts())
        if not hosts:
            return f"{net.network_address}-{net.broadcast_address}"
        return f"{hosts[0]}-{hosts[-1]}"
    # v6: whole /64 (or whatever prefix) as a range, first host through last.
    first = net.network_address + 1
    last = net.broadcast_address
    return f"{first}-{last}"


def socket_port_from_url(url: str):
    """Pull the explicit port out of a direct-mode api_url
    (``http://host:8004`` → 8004) for the authored control-socket entry.
    Returns None when the URL has no explicit port or doesn't parse —
    direct mode requires one, so the caller turns None into an error
    rather than guessing 8000/8006 (v5.10.2)."""
    from urllib.parse import urlparse

    try:
        return urlparse(url).port
    except ValueError:
        return None


def build_new_kea_config(
    service: str,
    interfaces: list,
    lease_db: dict,
    control_socket_path: str,
    subnets: dict,
    hooks_dir: str = "/usr/lib/x86_64-linux-gnu/kea/hooks",
    api_socket: dict = None,
) -> dict:
    """
    Build a complete Dhcp4/Dhcp6 config dict from scratch. `subnets` is
    Jen's own SUBNET_MAP/SUBNET6_MAP shape ({id: {"name","cidr",...}}) —
    subnet IDs in the generated file match Jen's own stored IDs, the
    same convention every other part of Jen already relies on.
    `lease_db` carries host/user/password/name — password comes from
    Jen's own extensions.KEA_DB_PASS/KEA6_DB_PASS (Jen already knows
    it), never re-asked or left as a placeholder.

    `api_socket` (v5.10.1, reworked v5.10.2) — when Jen is in
    `connection_mode = direct` (Kea 3.2 removed the Control Agent), the
    generated config must expose the daemon's own command socket or Jen
    can't reach it after it's running. Pass a dict with:
      scheme    "http" | "https" — the scheme Jen will actually dial
      address   IP literal to bind (never a hostname; Kea binds it)
      port      int, parsed from the API URL
      user / password   basic-auth credentials
      tls       (https only) {trust_anchor, cert_file, key_file, cert_required}
    and the config gets a `control-sockets` LIST: the unix socket (still
    needed for kea-shell / some hooks) plus the http/https entry. When
    None (the `ca` default) the config keeps the singular
    `control-socket` map exactly as every prior release emitted.
    """
    timers = DEFAULT_TIMERS[service]
    hooks_libraries = [{"library": os.path.join(hooks_dir, f"libdhcp_{h}.so")} for h in REQUIRED_HOOKS]

    subnet_blocks = []
    for sid, info in subnets.items():
        pool = _pool_for_cidr(info["cidr"])
        if service == "dhcp4":
            subnet_blocks.append(
                {
                    "id": sid,
                    "subnet": info["cidr"],
                    "pools": [{"pool": pool}],
                }
            )
        else:
            subnet_blocks.append(
                {
                    "id": sid,
                    "subnet": info["cidr"],
                    "pools": [{"pool": pool}],
                }
            )

    if api_socket:
        entry = {
            "socket-type": api_socket["scheme"],  # "http" | "https"
            # socket-address is an operator-chosen IP (the bind-address
            # picker in the authoring form, never a Jen-side default) —
            # written into the Kea daemon's OWN config, not a bind Jen
            # performs. See the authoring route + the form's warnings.
            "socket-address": api_socket["address"],
            "socket-port": int(api_socket["port"]),
            "authentication": {
                "type": "basic",
                "realm": "kea",
                "clients": [{"user": api_socket["user"], "password": api_socket["password"]}],
            },
        }
        if api_socket["scheme"] == "https":
            t = api_socket["tls"]
            entry.update(
                {
                    "trust-anchor": t["trust_anchor"],
                    "cert-file": t["cert_file"],
                    "key-file": t["key_file"],
                    "cert-required": bool(t["cert_required"]),
                }
            )
        control = {
            "control-sockets": [
                {"socket-type": "unix", "socket-name": control_socket_path},
                entry,
            ]
        }
    else:
        control = {"control-socket": {"socket-type": "unix", "socket-name": control_socket_path}}

    section = {
        "interfaces-config": {"interfaces": interfaces},
        **control,
        "lease-database": {
            "type": lease_db.get("type", "mysql"),
            "host": lease_db["host"],
            "user": lease_db["user"],
            "password": lease_db["password"],
            "name": lease_db["name"],
        },
        "hooks-libraries": hooks_libraries,
        **timers,
    }
    if service == "dhcp4":
        section["subnet4"] = subnet_blocks
        return {"Dhcp4": section}
    else:
        section["subnet6"] = subnet_blocks
        return {"Dhcp6": section}


def detect_installed_kea_services(ssh) -> dict:
    """
    Check whether the kea-dhcp4/kea-dhcp6 binaries actually exist on
    this server — for both protocols, not just whichever one triggered
    the check, since a user fixing one is likely to want to know about
    the other too. Returns {"dhcp4": bool, "dhcp6": bool}.

    v5.1.21 — this used to run `which kea-dhcp4 kea-dhcp6`, which
    searches $PATH. Paramiko's exec_command() runs a non-interactive,
    non-login shell by default, and depending on the target's sshd/PAM
    configuration that session's $PATH can easily exclude /usr/sbin —
    exactly where the official kea-dhcp4-server/kea-dhcp6-server .deb
    packages install these binaries (standard Debian policy for
    system-administration daemons). The practical result: a server
    where Kea is genuinely installed and running — Control Agent
    reachable, actually serving DHCP — got reported as "not installed"
    here, because `which` was searching a PATH that never included the
    directory the binary actually lives in. The existing test suite
    never caught this because it only exercised the function's output
    PARSING against a canned stdout string, never the real command's
    actual PATH-dependent behavior against a live, restricted SSH
    session — a genuine blind spot, not something the old tests were
    wrong about for what they checked.

    Now checks `command -v` (same PATH-based search as before, kept as
    the first, cheapest check — still catches non-standard install
    locations someone added to their own PATH) OR'd with explicit
    `test -x` checks against the two standard install directories
    (/usr/sbin, the actual real-world location; /usr/local/sbin, for a
    build-from-source install), so a restricted non-login PATH can no
    longer produce a false "not installed" for a binary that
    demonstrably exists and is genuinely running. `which` exiting
    non-zero (not found) is the expected, common case for a protocol
    not yet installed — never raises for that; only a genuine SSH/
    connection failure propagates to the caller.
    """
    result = {"dhcp4": False, "dhcp6": False}
    cmd = (
        "for f in kea-dhcp4 kea-dhcp6; do "
        'if command -v "$f" >/dev/null 2>&1 || '
        '[ -x "/usr/sbin/$f" ] || [ -x "/usr/local/sbin/$f" ]; then '
        'echo "${f}:FOUND"; else echo "${f}:MISSING"; fi; done'
    )
    _, stdout, _ = ssh.exec_command(cmd)
    out = stdout.read().decode()
    result["dhcp4"] = "kea-dhcp4:FOUND" in out
    result["dhcp6"] = "kea-dhcp6:FOUND" in out
    return result


def render_author_config_script(
    service: str,
    kea_conf_path: str,
    config_dict: dict,
    allow_overwrite: bool,
    dry_run: bool = False,
    tls_paths: list = (),
) -> str:
    """
    Build the remote Python script that writes a brand-new Kea config,
    tests it with `kea-dhcp4/6 -t`, and only keeps it if the test
    passes. Mirrors the exact safety contract of
    jen/routes/subnets.py's _build_subnet_patch_script() and
    jen/services/kea6.py's build_subnet6_patch_script():

    dry_run=True: test only, tmp file always removed, live path never
      touched under any outcome (pass or fail) — same guarantee the
      subnet-edit preview endpoints already have and are tested against.
    dry_run=False: on a passing test, only THEN does it check whether
      the target path already exists — if it does and allow_overwrite
      is False, it refuses and reports 'exists' rather than silently
      clobbering a real file. If it does exist and allow_overwrite is
      True, a backup is taken first, matching every other write path
      in this app.

    tls_paths (v5.10.2) — [(path, "file"|"dir"), ...] for an https
      control socket. `kea-dhcpX -t` validates syntax, NOT that the
      cert/key/trust-anchor files exist, so the script checks them
      itself — inside this one command, so the "one SSH command per
      server" property holds — and prints 'tlsmissing:<path>' if one
      is absent.
    """
    kea_binary = "kea-dhcp4" if service == "dhcp4" else "kea-dhcp6"
    config_json = json.dumps(config_dict, indent=2)
    tls_check = (
        f"""
for _p, _kind in {list(tls_paths)!r}:
    if not (os.path.exists(_p) if _kind == 'dir' else os.path.isfile(_p)):
        os.unlink(tmp)
        print('tlsmissing:' + _p)
        sys.exit(1)
"""
        if tls_paths
        else ""
    )

    if dry_run:
        on_pass = "os.unlink(tmp)\nprint('preview-ok')"
        exists_check = ""
    else:
        on_pass = (
            "if os.path.exists(path):\n    shutil.copy2(path, path + '.jen_backup')\nos.replace(tmp, path)\nprint('ok')"
        )
        exists_check = (
            f"if os.path.exists(path) and not {allow_overwrite!r}:\n"
            "    os.unlink(tmp)\n"
            "    print('exists')\n"
            "    sys.exit(1)\n"
        )

    return f"""
import json, sys, shutil, subprocess, os

path = {repr(kea_conf_path)}
cfg = {config_json}

tmp = path + '.jen_author_tmp'
with open(tmp, 'w') as f:
    json.dump(cfg, f, indent=2)

{exists_check}{tls_check}
try:
    result = subprocess.run(['{kea_binary}', '-t', tmp], capture_output=True, text=True)
except FileNotFoundError:
    os.unlink(tmp)
    print('missingbinary:{kea_binary}')
    sys.exit(1)
combined = result.stdout + result.stderr

if result.returncode != 0 or 'ERROR' in combined:
    os.unlink(tmp)
    error_lines = [l for l in combined.splitlines() if 'ERROR' in l or 'Error' in l]
    print('testerror:' + ' | '.join(error_lines[:3]))
    sys.exit(1)

{on_pass}
"""
