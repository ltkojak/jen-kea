"""
tests/system/stack.py
──────────────────────
Q84 — driving the real stack: `docker compose` to build and start it,
`docker exec` to run things inside it. Nothing here imports Jen; the
Jen-side scenarios run as small scripts INSIDE the `sys-jen` container
(`jen_py`), against the real MariaDB and the real Kea hosts.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = Path(__file__).resolve().parent / "compose"
COMPOSE_FILE = COMPOSE_DIR / "docker-compose.yml"
WORK = Path(os.environ.get("SYS_WORK") or (ROOT / "system-work")).resolve()

JEN = "sys-jen"
MARIADB = "sys-mariadb"
KEA_A = "sys-kea-a"
KEA_B = "sys-kea-b"
DNS = "sys-dns"
UPDATER = "sys-updater"

JEN_URL = "http://127.0.0.1:5050"
ADMIN_USER = "admin"
ADMIN_PASSWORD = os.environ.get("SYS_ADMIN_PASSWORD", "sys-Adm1n-Pass!")

KEA_CONF = "/etc/kea/kea-dhcp4.conf"
KEA_LOG = "/var/log/kea/kea-dhcp4.log"

# each Kea host's config as the harness first wrote it (filled by the `stack` fixture)
BASELINE: dict = {}


# ── processes ─────────────────────────────────────────────────────────────


def run(cmd, *, check=True, timeout=300, input=None, env=None) -> subprocess.CompletedProcess:
    p = subprocess.run(
        [str(c) for c in cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
        input=input,
        env={**os.environ, **(env or {})},
    )
    if check and p.returncode != 0:
        raise RuntimeError(
            f"{' '.join(map(str, cmd))[:300]}\nexit {p.returncode}\nstdout: {p.stdout[-2000:]}\nstderr: {p.stderr[-2000:]}"
        )
    return p


def compose(*args, check=True, timeout=900) -> subprocess.CompletedProcess:
    return run(
        ["docker", "compose", "-f", COMPOSE_FILE, *args],
        check=check,
        timeout=timeout,
        env={"SYS_WORK": str(WORK)},
    )


def dexec(container, *cmd, user=None, workdir=None, input=None, check=True, timeout=180) -> subprocess.CompletedProcess:
    args = ["docker", "exec"]
    if input is not None:
        args.append("-i")
    if user:
        args += ["-u", user]
    if workdir:
        args += ["-w", workdir]
    return run([*args, container, *cmd], check=check, timeout=timeout, input=input)


def dexec_bg(container, *cmd, user=None) -> subprocess.Popen:
    """A long-running `docker exec` the scenario watches and later reaps."""
    args = ["docker", "exec"]
    if user:
        args += ["-u", user]
    return subprocess.Popen([*args, container, *cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def sh(container, script, **kw) -> subprocess.CompletedProcess:
    return dexec(container, "sh", "-c", script, **kw)


def file_exists(container, path) -> bool:
    return dexec(container, "test", "-e", path, check=False).returncode == 0


def wait_for(predicate, *, timeout=60, interval=0.5, what="condition"):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        try:
            last = predicate()
            if last:
                return last
        except Exception as e:  # a probe that raises is "not yet"
            last = e
        time.sleep(interval)
    raise AssertionError(f"timed out after {timeout}s waiting for {what} (last: {last!r})")


# ── the Jen-side scripts ────────────────────────────────────────────────────

PRELUDE = """
import json, os, sys, time
sys.path.insert(0, "/opt/jen")
os.chdir("/opt/jen")
from jen import create_app, extensions
app = create_app()
def emit(obj):
    print("@@ " + json.dumps(obj, default=str), flush=True)
"""


def parse_emitted(stdout: str) -> list:
    return [json.loads(line[3:]) for line in stdout.splitlines() if line.startswith("@@ ")]


def jen_py(code, *, user="www-data", timeout=300, check=True):
    """Run `code` in a fresh Python process inside the Jen container (real
    config, real MariaDB, real SSH keys). Returns (emitted-objects, result)."""
    p = dexec(JEN, "python3", "-", user=user, input=PRELUDE + "\n" + code, check=check, timeout=timeout)
    return parse_emitted(p.stdout), p


def jen_py_bg(code, *, user="www-data") -> subprocess.Popen:
    args = ["docker", "exec", "-i", "-u", user, JEN, "python3", "-"]
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    p.stdin.write(PRELUDE + "\n" + code)
    p.stdin.close()
    return p


# ── the workdir the containers mount ──────────────────────────────────────


def kea_config(name: str, http_port=8004) -> dict:
    return {
        "Dhcp4": {
            "interfaces-config": {
                "interfaces": ["*"],
                "dhcp-socket-type": "udp",
                "service-sockets-require-all": False,
                "service-sockets-max-retries": 0,
            },
            "control-sockets": [
                {
                    "socket-type": "http",
                    "socket-address": "0.0.0.0",
                    "socket-port": http_port,
                    "authentication": {
                        "type": "basic",
                        "realm": "kea-system",
                        "directory": "/etc/kea",
                        "clients": [{"user-file": "jen-api.user", "password-file": "jen-api.pw"}],
                    },
                }
            ],
            "lease-database": {"type": "memfile", "persist": False},
            "hooks-libraries": [
                {"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"},
                {"library": "/usr/lib/kea/hooks/libdhcp_host_cmds.so"},
            ],
            "valid-lifetime": 3600,
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "10.99.0.0/24",
                    "pools": [{"pool": "10.99.0.100 - 10.99.0.200"}],
                    "relay": {"ip-addresses": ["10.99.0.1"]},
                    "option-data": [{"name": "routers", "data": "10.99.0.1"}],
                }
            ],
            "loggers": [
                {
                    "name": "kea-dhcp4",
                    "output-options": [{"output": KEA_LOG}],
                    "severity": "INFO",
                }
            ],
        }
    }


def jen_config(*, server2_url="http://kea-b:8004/") -> str:
    return f"""[kea]
name = kea-a
role = primary
ha_mode =
connection_mode = direct
api_url = http://kea-a:8004/
api_user = jen
api_pass = jen_api_pw
dhcp4_log_path = {KEA_LOG}

[kea_server_2]
name = kea-b
role = standby
api_url = {server2_url}
ssh_host = kea-b
ssh_user = keaadmin
kea_conf = {KEA_CONF}

[kea_ssh]
host = kea-a
user = keaadmin
key_path = /etc/jen/ssh/jen_rsa
kea_conf = {KEA_CONF}

[kea_db]
host = mariadb
user = kea
password = kea_pw
database = kea

[jen_db]
host = mariadb
user = jen
password = jen_pw
database = jen

[server]
http_port = 5050

[subnets]
1 = System, 10.99.0.0/24
"""


def _open(path: Path, mode: int):
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)


def prepare_workdir():
    """Everything the containers mount, written before `compose up`. Modes are
    deliberately loose: the containers run as different users (www-data in Jen,
    root in the Kea hosts) and this is a throwaway CI directory."""
    if WORK.exists():
        shutil.rmtree(WORK, ignore_errors=True)
    for sub in ("keys", "jen-etc", "jen-etc/ssh", "jen-etc/ssl", "jen-etc/backups", "kea-a", "kea-b", "results"):
        _open(WORK / sub, 0o777)

    key = WORK / "keys" / "jen_rsa"
    run(["ssh-keygen", "-q", "-t", "rsa", "-b", "2048", "-m", "PEM", "-N", "", "-f", key, "-C", "jen-system-tests"])
    os.chmod(key, 0o644)  # www-data in the Jen container must be able to read it
    os.chmod(WORK / "keys" / "jen_rsa.pub", 0o644)
    shutil.copy(key, WORK / "jen-etc" / "ssh" / "jen_rsa")
    os.chmod(WORK / "jen-etc" / "ssh" / "jen_rsa", 0o666)

    (WORK / "jen-etc" / "jen.config").write_text(jen_config(), encoding="utf-8")
    os.chmod(WORK / "jen-etc" / "jen.config", 0o666)

    for node in ("kea-a", "kea-b"):
        d = WORK / node
        (d / "kea-dhcp4.conf").write_text(json.dumps(kea_config(node), indent=2), encoding="utf-8")
        (d / "jen-api.user").write_text("jen", encoding="utf-8")
        (d / "jen-api.pw").write_text("jen_api_pw", encoding="utf-8")
        for f in d.iterdir():
            os.chmod(f, 0o644)


# ── the Jen web UI (real HTTP to gunicorn) ─────────────────────────────────


class Web:
    """A logged-in browser-ish session against the real Jen: cookie jar,
    CSRF token scraping, redirects followed."""

    def __init__(self, base=JEN_URL):
        import re

        import requests

        self._re = re
        self.base = base
        self.s = requests.Session()

    def _token(self, html):
        m = self._re.search(r'name="csrf_token"\s+value="([^"]+)"', html) or self._re.search(
            r'value="([^"]+)"\s+name="csrf_token"', html
        )
        return m.group(1) if m else ""

    def login(self, user=ADMIN_USER, password=ADMIN_PASSWORD):
        r = self.s.get(f"{self.base}/login", timeout=20)
        r = self.s.post(
            f"{self.base}/login",
            data={"username": user, "password": password, "csrf_token": self._token(r.text)},
            timeout=20,
        )
        if "/login" in r.url:
            raise AssertionError(f"login failed: {r.status_code} {r.url}")
        return self

    def get(self, path, **kw):
        kw.setdefault("timeout", 60)
        return self.s.get(f"{self.base}{path}", **kw)

    def post(self, path, data=None, page=None, **kw):
        """POST with a CSRF token scraped from `page` (a path to GET first)."""
        kw.setdefault("timeout", 120)
        r = self.s.get(f"{self.base}{page or path}", timeout=30)
        payload = dict(data or {})
        payload["csrf_token"] = self._token(r.text)
        return self.s.post(f"{self.base}{path}", data=payload, **kw)


def jen_healthy() -> bool:
    try:
        with urllib.request.urlopen(f"{JEN_URL}/api/v1/health", timeout=5) as r:
            return r.status == 200 and bool(json.loads(r.read()).get("jen_version"))
    except (urllib.error.URLError, OSError, ValueError):
        return False


def wait_jen_healthy(timeout=120):
    return wait_for(jen_healthy, timeout=timeout, interval=1.0, what="Jen answering /api/v1/health")


# ── the Kea hosts ─────────────────────────────────────────────────────────────


def kea_sha(container) -> str:
    return dexec(container, "sha256sum", KEA_CONF).stdout.split()[0]


def kea_conf_bytes(container) -> str:
    return dexec(container, "cat", KEA_CONF).stdout


def kea_running(container) -> bool:
    return dexec(container, "pgrep", "-x", "kea-dhcp4", check=False).returncode == 0


def sshd_running(container) -> bool:
    return dexec(container, "pgrep", "-x", "sshd", check=False).returncode == 0


def kea_answers(host, port=8004) -> bool:
    """Does the daemon itself answer, over its own http control socket?"""
    r = kea_command(host, "version-get", port)
    return bool(r) and r.get("result") == 0


# ── HA (scenario 8 only) ──────────────────────────────────────────────────────


def ha_kea_config(node: str) -> dict:
    """The baseline config plus the HA hook: kea-a primary, kea-b standby,
    hot-standby, each peer's dedicated HA listener on :8005."""
    cfg = kea_config(node)
    cfg["Dhcp4"]["hooks-libraries"].append(
        {
            "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
            "parameters": {
                "high-availability": [
                    {
                        "this-server-name": node,
                        "mode": "hot-standby",
                        "heartbeat-delay": 3000,
                        "max-response-delay": 6000,
                        "max-ack-delay": 2000,
                        "max-unacked-clients": 0,
                        "multi-threading": {
                            "enable-multi-threading": True,
                            "http-dedicated-listener": True,
                            "http-listener-threads": 2,
                            "http-client-threads": 2,
                        },
                        "peers": [
                            {"name": "kea-a", "url": "http://kea-a:8005/", "role": "primary"},
                            {"name": "kea-b", "url": "http://kea-b:8005/", "role": "standby"},
                        ],
                    }
                ]
            },
        }
    )
    return cfg


def kea_command(host, command, port=8004):
    """One command to a daemon's own http control socket, from inside the
    Jen container. Returns the parsed reply (or None when it does not answer)."""
    p = dexec(
        JEN,
        "curl",
        "-s",
        "-m",
        "6",
        "-u",
        "jen:jen_api_pw",
        "-H",
        "Content-Type: application/json",
        "-d",
        json.dumps({"command": command}),
        f"http://{host}:{port}/",
        check=False,
    )
    try:
        out = json.loads(p.stdout)
    except ValueError:
        return None
    return out[0] if isinstance(out, list) and out else out


def ha_state(host):
    r = kea_command(host, "status-get")
    try:
        return r["arguments"]["high-availability"][0]["ha-servers"]["local"]["state"]
    except (TypeError, KeyError, IndexError):
        return None


def container_ip(container) -> str:
    return run(
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container]
    ).stdout.strip()


def sentinel_wait(container, path, timeout=120):
    """Block until `path` exists inside `container` (a scenario's Jen-side
    script parks itself there so the harness can break something first)."""
    return wait_for(lambda: file_exists(container, path), timeout=timeout, interval=0.5, what=f"{path} in {container}")
