"""
Q84 fault injectors for the system-test stack. Stdlib only.

  python3 faults.py dns          a DNS server on UDP 53 that can be told to go
                                 silent after N queries
  python3 faults.py http [port]  a Control Agent stand-in that answers every
                                 request with HTTP 500

DNS control is by files in /ctl (the harness writes them with `docker exec`):
  /ctl/limit   an integer — answer that many queries, then say nothing at all
               (absent or -1 = never go silent)
  /ctl/reset   any content — zero the query counter, then the file is removed
Names it knows: host<N>.sys.test -> 10.77.0.<N>, and the reverse of that.
Anything else is NXDOMAIN. AAAA questions get an empty NOERROR answer.
"""

import contextlib
import os
import socket
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CTL = "/ctl"
SUFFIX = ".sys.test"


def _read_int(path, default):
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return default


def _parse_question(data):
    """(qname, qtype, question_bytes) from a query packet, or None."""
    if len(data) < 17:
        return None
    pos = 12
    labels = []
    while True:
        if pos >= len(data):
            return None
        n = data[pos]
        if n == 0:
            pos += 1
            break
        labels.append(data[pos + 1 : pos + 1 + n].decode("ascii", "replace").lower())
        pos += 1 + n
    if pos + 4 > len(data):
        return None
    qtype, _qclass = struct.unpack("!HH", data[pos : pos + 4])
    return ".".join(labels), qtype, data[12 : pos + 4]


def _name_wire(name):
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _answer(qname, qtype):
    """(rcode, [rdata-records]) — records are (type, rdata)."""
    if qname.endswith(SUFFIX) and qname.startswith("host"):
        num = qname[len("host") : -len(SUFFIX)]
        if num.isdigit():
            if qtype == 1:
                return 0, [(1, socket.inet_aton(f"10.77.0.{int(num)}"))]
            return 0, []  # AAAA and the rest: the name exists, no such record
    if qname.endswith(".0.77.10.in-addr.arpa") and qtype == 12:
        num = qname[: -len(".0.77.10.in-addr.arpa")]
        if num.isdigit():
            return 0, [(12, _name_wire(f"host{int(num)}{SUFFIX}"))]
    return 3, []


def serve_dns():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    count = 0
    print("dns: listening on udp/53", flush=True)
    while True:
        data, addr = sock.recvfrom(1500)
        if os.path.exists(f"{CTL}/reset"):
            count = 0
            with contextlib.suppress(OSError):
                os.remove(f"{CTL}/reset")
        limit = _read_int(f"{CTL}/limit", -1)
        count += 1
        if limit >= 0 and count > limit:
            continue  # silence — the client waits for its own timeout
        parsed = _parse_question(data)
        if not parsed:
            continue
        qname, qtype, question = parsed
        rcode, records = _answer(qname, qtype)
        flags = 0x8180 | rcode  # response, recursion desired + available
        header = data[:2] + struct.pack("!HHHHH", flags, 1, len(records), 0, 0)
        body = b""
        for rtype, rdata in records:
            body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
        sock.sendto(header + question + body, addr)


class _Always500(BaseHTTPRequestHandler):
    def _fail(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        body = b'{"result": 1, "text": "injected 500"}'
        self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = _fail

    def log_message(self, *a):
        pass


def serve_http(port):
    srv = ThreadingHTTPServer(("0.0.0.0", port), _Always500)
    print(f"http: answering 500 on tcp/{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "dns"
    if mode == "dns":
        serve_dns()
    elif mode == "http":
        threading.Thread(target=serve_http, args=(int(sys.argv[2]) if len(sys.argv) > 2 else 8500,)).start()
    else:
        raise SystemExit(f"unknown mode {mode!r}")
