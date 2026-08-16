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

from jen import extensions

logger = logging.getLogger(__name__)

REQUIRED_HOOKS = ["host_cmds", "lease_cmds"]

# Kea's own documented defaults (see the ARM) — used only when nothing
# more specific (a sibling config, or the operator's own input) exists.
DEFAULT_TIMERS = {
    "dhcp4": {"valid-lifetime": 86400, "renew-timer": 43200, "rebind-timer": 75600},
    "dhcp6": {"preferred-lifetime": 3000, "valid-lifetime": 7200,
             "renew-timer": 1000, "rebind-timer": 2000},
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
        _, stdout, _ = ssh.exec_command(f"cat {path} 2>/dev/null")
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
    result = {"found": False, "interfaces": [], "lease_db_type": "",
             "lease_db_host": "", "lease_db_name": "", "hooks": []}
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


def build_new_kea_config(service: str, interfaces: list, lease_db: dict,
                         control_socket_path: str, subnets: dict,
                         hooks_dir: str = "/usr/lib/x86_64-linux-gnu/kea/hooks") -> dict:
    """
    Build a complete Dhcp4/Dhcp6 config dict from scratch. `subnets` is
    Jen's own SUBNET_MAP/SUBNET6_MAP shape ({id: {"name","cidr",...}}) —
    subnet IDs in the generated file match Jen's own stored IDs, the
    same convention every other part of Jen already relies on.
    `lease_db` carries host/user/password/name — password comes from
    Jen's own extensions.KEA_DB_PASS/KEA6_DB_PASS (Jen already knows
    it), never re-asked or left as a placeholder.
    """
    timers = DEFAULT_TIMERS[service]
    hooks_libraries = [
        {"library": os.path.join(hooks_dir, f"libdhcp_{h}.so")}
        for h in REQUIRED_HOOKS
    ]

    subnet_blocks = []
    for sid, info in subnets.items():
        pool = _pool_for_cidr(info["cidr"])
        if service == "dhcp4":
            subnet_blocks.append({
                "id": sid, "subnet": info["cidr"],
                "pools": [{"pool": pool}],
            })
        else:
            subnet_blocks.append({
                "id": sid, "subnet": info["cidr"],
                "pools": [{"pool": pool}],
            })

    section = {
        "interfaces-config": {"interfaces": interfaces},
        "control-socket": {"socket-type": "unix", "socket-name": control_socket_path},
        "lease-database": {
            "type": lease_db.get("type", "mysql"),
            "host": lease_db["host"], "user": lease_db["user"],
            "password": lease_db["password"], "name": lease_db["name"],
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
    the other too. Returns {"dhcp4": bool, "dhcp6": bool}. `which`
    exiting non-zero (not found) is the expected, common case for a
    protocol not yet installed — never raises for that; only a genuine
    SSH/connection failure propagates to the caller.
    """
    result = {"dhcp4": False, "dhcp6": False}
    _, stdout, _ = ssh.exec_command("which kea-dhcp4 kea-dhcp6 2>/dev/null")
    out = stdout.read().decode()
    result["dhcp4"] = "kea-dhcp4" in out
    result["dhcp6"] = "kea-dhcp6" in out
    return result


def install_kea_service(ssh, service: str) -> tuple:
    """
    Install the kea-dhcp4-server/kea-dhcp6-server package via apt —
    Jen's documented supported platform is Ubuntu 24.04 (see
    docs/ARCHITECTURE.md), so this targets apt specifically rather than
    trying to guess across package managers. Returns (ok, output) where
    output is the tail of apt's combined stdout/stderr, shown to the
    operator either way — on success as confirmation, on failure as the
    actual reason (missing repo, network issue, held package, etc.)
    rather than a bare "it didn't work."

    Runs `apt-get update` first — a freshly provisioned host's package
    index may not yet know about the kea-dhcp6-server package even when
    kea-dhcp4-server (installed earlier, index already current at the
    time) is present, and skipping it would turn a stale-cache failure
    into a confusing "package not found" message.
    """
    package = f"kea-{service}-server"
    cmd = (
        f"sudo apt-get update -qq 2>&1 && "
        f"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {package} 2>&1"
    )
    try:
        _, stdout, stderr = ssh.exec_command(cmd)
        out = stdout.read().decode()
        err = stderr.read().decode()
        exit_status = stdout.channel.recv_exit_status()
        combined = (out + err).strip()
        tail = "\n".join(combined.splitlines()[-15:])  # apt output can be long; keep it readable
        return exit_status == 0, tail
    except Exception as e:
        return False, str(e)


def render_author_config_script(service: str, kea_conf_path: str, config_dict: dict,
                                allow_overwrite: bool, dry_run: bool = False) -> str:
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
    """
    kea_binary = "kea-dhcp4" if service == "dhcp4" else "kea-dhcp6"
    config_json = json.dumps(config_dict, indent=2)

    if dry_run:
        on_pass = "os.unlink(tmp)\nprint('preview-ok')"
        exists_check = ""
    else:
        on_pass = (
            "if os.path.exists(path):\n"
            "    shutil.copy2(path, path + '.jen_backup')\n"
            "os.replace(tmp, path)\n"
            "print('ok')"
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

{exists_check}
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
