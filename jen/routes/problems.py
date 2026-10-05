"""
jen/routes/problems.py
───────────────────────
v5.68.0-beta.5 (Q140) — the Problems inbox: recent DHCP failures by client, each row one click from its investigation.

`GET /problems` lists the open rows of `client_problems` (jen/services/client_problems.py), one entry per client, newest first. Every
row is filtered by `add_subnet_restriction` on the row's own `subnet_id`: a caller restricted to some subnets sees only rows in
them, and a row with no subnet - the client could not be placed - is for callers who may see every subnet (docs/ARCHITECTURE.md §2).
`GET /problems/answer?q=` is the lazy "why": the Investigation Overview's one-line answer (Q135) for one client, computed only when a
row is expanded and judged exactly as `/client` judges it - a client the caller cannot place in a subnet they may see gets nothing,
the same as one that does not exist.
"""

import logging

from flask import Blueprint, render_template, request
from flask_login import current_user, login_required

from jen import extensions
from jen.services import client_problems as __cp
from jen.services import client_subject as __subject
from jen.services.access import add_subnet_restriction, diagnostic_surface, get_accessible_subnet_map

logger = logging.getLogger(__name__)
bp = Blueprint("problems", __name__)


def _server_choices() -> list[dict]:
    return [
        {"id": s["id"], "name": s.get("name") or s.get("ssh_host") or f"Server {s['id']}"}
        for s in extensions.KEA_SERVERS or []
    ]


@bp.route("/problems")
@login_required
@diagnostic_surface(subject="client")
def problems_page():
    server = request.args.get("server", type=int)
    kind = (request.args.get("kind") or "").strip()
    if kind not in __cp.ALL_KINDS:
        kind = ""
    where: list[str] = []
    params: list = []
    where, params = add_subnet_restriction(where, params, "p", "subnet_id")
    if server is not None:
        where.append("p.server_id=%s")
        params.append(server)
    if kind:
        where.append("p.kind=%s")
        params.append(kind)
    try:
        rows = __cp.fetch_open(where, params)
        failed = False
    except Exception as e:
        logger.error(f"problems: could not read the inbox: {type(e).__name__}: {e}")
        rows, failed = [], True
    clients = __cp.group_by_client(rows)
    counts: dict[str, int] = {}
    for c in clients:
        for k in {x["kind"] for x in c["kinds"]}:
            counts[k] = counts.get(k, 0) + 1
    return render_template(
        "problems.html",
        clients=clients,
        failed=failed,
        counts=counts,
        kind=kind,
        server=server,
        servers=_server_choices(),
        kind_labels=__cp.KIND_LABELS,
        kind_help=__cp.KIND_HELP,
        kinds=__cp.ALL_KINDS,
        server_name=__cp.server_name,
        has_log_source=any(s.get("ssh_host") for s in extensions.KEA_SERVERS or []),
    )


@bp.route("/problems/answer")
@login_required
@diagnostic_surface(subject="client")
def problem_answer():
    q = (request.args.get("q") or "").strip()
    line = ""
    if q:
        from jen.routes.client import _overview_line

        accessible_ids = None if current_user.all_subnets else set(get_accessible_subnet_map())
        subject = __subject.resolve(q, accessible_ids=accessible_ids, all_subnets=current_user.all_subnets)
        if subject.kind in ("mac", "ipv4") and subject.found:
            view = __subject.authorize(subject, rule="per_object", accessible_ids=accessible_ids)
            placed = current_user.all_subnets or __subject.names_a_subnet(view)
            if placed and not view.candidates and view.mac:
                line = _overview_line(view)
    return render_template("_problem_answer.html", line=line, q=q)
