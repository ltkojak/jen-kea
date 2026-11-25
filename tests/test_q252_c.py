"""
tests/test_q252_c.py
────────────────────
Q252 (Jen 7.2.1) - six rows of the executing pass on v7.2.0-beta.9.

    TestASaveDoesNotJudgeWhatThePageDidNotShow   the SSH card posts the Kea log path only while it draws the field, and a save that did not post it
                                                 neither judges nor changes the stored one (BL4)
    TestLinkingARestrictedAccountSaysWhatFollows the link's confirmation, its flash and its audit row say what the first sign-in does to a restricted
                                                 account's subnets; the link itself changes none (BL6)
    TestEveryHealthHintIsASentence               every hint a health check carries is a sentence, over the whole tree under jen/ (BL12)
    TestTheDoctorsTimestampFinding               the finding links to the Kea logging card and says who can change it (BL13)

The browser's half (the confirmation as a person reads it, Health's hint lines at two widths, the Kea logging card's radios at 390 px) is
tests/e2e/test_q252_c.py.
"""

import ast
import configparser
import copy
import html as htmllib
import json
import pathlib
import re
from html.parser import HTMLParser

import pytest

from jen import extensions
from jen.config import app_config
from jen.services import config_doctor as doctor
from jen.services import kea_host
from tests._q249_a_world import FILE_LOGGER, KeaHost, dhcp4, kea_writes_defaults, packaged_logger
from tests.e2e._fake_kea_server import StatefulKeaServer

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def flashes(client):
    """What the last request flashed, taken out of the session so the next request starts with none."""
    with client.session_transaction() as sess:
        return list(sess.pop("_flashes", []))


def field_errors(client):
    """What the last request recorded against a field (`forms.flash_field`), as (field, message) pairs, taken out of the session."""
    with client.session_transaction() as sess:
        return [(item[0], item[1]) for item in sess.pop("field_errors", None) or []]


def last_audit(db, action, entity):
    db.commit()
    with db.cursor() as cur:
        cur.execute(
            "SELECT details FROM audit_log WHERE action=%s AND entity=%s ORDER BY id DESC LIMIT 1", (action, entity)
        )
        row = cur.fetchone()
    return row["details"] if row else None


# ── row 1 (BL4): the SSH card and a stored Kea log path the rule refuses ─────

SAVE_SSH = "/settings/infrastructure/save-ssh"
REFUSED_PATH = "/opt/not-var-log.log"  # a value saved before the rule existed, or by hand in jen.config: `valid_log_path` refuses it


class _FormFields(HTMLParser):
    """Every named input of the one form that posts to `action`, with its value: what a browser would send for the page as it was drawn."""

    def __init__(self, action):
        super().__init__()
        self.action, self.inside, self.fields = action, False, {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.inside = a.get("action") == self.action
        elif self.inside and tag == "input" and a.get("name"):
            self.fields[a["name"]] = a.get("value") or ""

    def handle_endtag(self, tag):
        if tag == "form":
            self.inside = False


def ssh_form(page):
    parser = _FormFields(SAVE_SSH)
    parser.feed(page)
    assert {"host", "user", "kea_conf"} <= set(parser.fields), "the SSH card's form was not found on the page"
    return parser.fields


def on_disk(path):
    p = configparser.ConfigParser()
    p.read(str(path))
    return p


def store_by_hand(path, value):
    """`[kea] dhcp4_log_path` written into jen.config the way an editor would, past every rule of the form."""
    p = on_disk(path)
    p.set("kea", "dhcp4_log_path", value)
    with open(path, "w") as f:
        p.write(f)
    app_config.reload()


def logger_on(daemon, options):
    entry = {"name": "kea-dhcp4", "output-options": copy.deepcopy(options), "severity": "INFO", "debuglevel": 0}
    daemon.file = dhcp4([entry])
    daemon.running = kea_writes_defaults(dhcp4([entry]))


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Jen's own configuration in a file of this test's (the route writes it for real), its one Kea server a stateful fake daemon over real HTTP with the
    Kea host behind it (`tests/_q249_a_world.py`). The daemon logs to the journal as the package ships it, so the page draws the Kea log path field;
    `logger_on(daemon, [FILE_LOGGER])` is the state in which the page does not. Nothing of the route or of the page's own reading is faked."""
    from jen.models.user import get_global_setting, set_global_setting
    from jen.services import log_tail

    daemon = StatefulKeaServer(dhcp4([packaged_logger()]))
    daemon.expand = kea_writes_defaults
    daemon.running = kea_writes_defaults(daemon.running)
    daemon.start()
    monkeypatch.setattr(kea_host, "helper_call", KeaHost(daemon).helper_call)
    original = extensions.CONFIG_FILE
    # every global `AppConfig.apply()` derives from the file (the log path among them): the route under test re-derives them from this test's file, and
    # the next test file must find the suite's own again, not `/opt/not-var-log.log`
    derived = {k: v for k, v in vars(extensions).items() if k.isupper() or k == "cfg"}
    restart_pending = get_global_setting("restart_pending", "false")
    cfg = configparser.ConfigParser()
    cfg["kea"] = {"api_url": daemon.url, "api_user": "", "api_pass": "", "config_transport": "file"}
    cfg["kea_ssh"] = {"host": "10.9.9.9", "user": "jen"}
    cfg["kea_db"] = {"host": "dbhost", "user": "du", "password": "dp", "database": "kea"}
    cfg["jen_db"] = {"host": "dbhost", "user": "ju", "password": "jp", "database": "jen"}
    cfg["server"] = {"http_port": "5050", "https_port": "8443"}
    cfg["subnets"] = {"1": "LAN, 192.168.1.0/24"}
    path = tmp_path / "jen.config"
    with open(path, "w") as f:
        cfg.write(f)
    extensions.CONFIG_FILE = str(path)
    app_config.reload()
    log_tail.clear()
    yield daemon, path
    extensions.CONFIG_FILE = original
    from tests.conftest import _patch_extensions

    _patch_extensions()
    for name, value in derived.items():
        if getattr(extensions, name, None) is not value:
            setattr(extensions, name, value)
    log_tail.clear()
    set_global_setting("restart_pending", restart_pending)
    daemon.stop()


class TestASaveDoesNotJudgeWhatThePageDidNotShow:
    def _page(self, client):
        r = client.get("/settings/kea")
        assert r.status_code == 200
        flashes(client)
        return r.get_data(as_text=True)

    def test_the_field_hidden_and_a_stored_path_the_rule_refuses(self, logged_in_client, db, world):
        daemon, path = world
        logger_on(daemon, [dict(FILE_LOGGER)])
        store_by_hand(path, REFUSED_PATH)
        page = self._page(logged_in_client)
        assert "data-log-path-from-kea" in page and 'id="f-dhcp4_log_path"' not in page, "the page state: no field"
        form = ssh_form(page)  # what the page as drawn would post
        form["user"] = "keaops"
        logged_in_client.post(SAVE_SSH, data=form)
        assert field_errors(logged_in_client) == [], (
            "no field is refused: the path was not posted, so it was not judged"
        )
        said = flashes(logged_in_client)
        assert ("success", "SSH settings saved. Restart Jen to apply.") in said, said
        saved = on_disk(path)
        assert (saved.get("kea_ssh", "host"), saved.get("kea_ssh", "user")) == ("10.9.9.9", "keaops")
        assert saved.get("kea", "dhcp4_log_path") == REFUSED_PATH, "byte for byte what was stored"
        assert last_audit(db, "SAVE_INFRA", "ssh") == "host=10.9.9.9 user=keaops log_path=kept"

    def test_the_page_with_the_field_hidden_holds_no_input_of_that_name(self, logged_in_client, world):
        daemon, path = world
        logger_on(daemon, [dict(FILE_LOGGER)])
        store_by_hand(path, "/var/log/kea/old.log")
        page = self._page(logged_in_client)
        assert "data-log-path-from-kea" in page
        assert (
            'name="dhcp4_log_path"' not in page
            and "/var/log/kea/old.log" not in page.split('id="kea-ssh"', 1)[1].split("</form>", 1)[0]
        )
        assert "dhcp4_log_path" not in ssh_form(page)
        assert 'Not needed: Kea names the file itself. See <a href="#kea-logging">Kea logging</a> on this page.' in page

    def test_the_field_shown_and_that_value_posted_is_refused_as_before(self, logged_in_client, db, world):
        _daemon, path = world
        store_by_hand(path, REFUSED_PATH)
        page = self._page(logged_in_client)
        assert 'id="f-dhcp4_log_path"' in page and "data-log-path-from-kea" not in page, "the page state: the field"
        form = ssh_form(page)
        assert form["dhcp4_log_path"] == REFUSED_PATH
        form["user"] = "keaops"
        logged_in_client.post(SAVE_SSH, data=form)
        refused = field_errors(logged_in_client)
        assert [f for f, m in refused if f == "dhcp4_log_path" and m.startswith("Invalid Kea log path")], refused
        assert flashes(logged_in_client) == []
        saved = on_disk(path)
        assert saved.get("kea_ssh", "user") == "jen", "a refused log path writes nothing of the form"
        assert saved.get("kea", "dhcp4_log_path") == REFUSED_PATH

    def test_the_field_shown_and_posted_blank_removes_the_option_as_before(self, logged_in_client, db, world):
        _daemon, path = world
        store_by_hand(path, "/var/log/kea/mine.log")
        form = ssh_form(self._page(logged_in_client))
        assert form["dhcp4_log_path"] == "/var/log/kea/mine.log"
        form["dhcp4_log_path"] = ""
        logged_in_client.post(SAVE_SSH, data=form)
        assert ("success", "SSH settings saved. Restart Jen to apply.") in flashes(logged_in_client)
        assert not on_disk(path).has_option("kea", "dhcp4_log_path")
        assert extensions.DHCP4_LOG == "/var/log/kea/kea-dhcp4.log"
        assert last_audit(db, "SAVE_INFRA", "ssh") == "host=10.9.9.9 user=jen log_path=default"

    def test_the_field_shown_and_a_good_value_posted_is_written_as_before(self, logged_in_client, db, world):
        _daemon, path = world
        form = ssh_form(self._page(logged_in_client))
        form["dhcp4_log_path"] = "/var/log/kea/dhcp4.log"
        logged_in_client.post(SAVE_SSH, data=form)
        assert on_disk(path).get("kea", "dhcp4_log_path") == "/var/log/kea/dhcp4.log"
        assert last_audit(db, "SAVE_INFRA", "ssh") == "host=10.9.9.9 user=jen log_path=/var/log/kea/dhcp4.log"

    def test_a_post_that_omits_the_field_while_the_page_shows_it_keeps_the_stored_path(
        self, logged_in_client, db, world
    ):
        _daemon, path = world
        store_by_hand(path, REFUSED_PATH)
        form = ssh_form(self._page(logged_in_client))
        del form["dhcp4_log_path"]  # a hand-made post
        form["user"] = "keaops"
        logged_in_client.post(SAVE_SSH, data=form)
        assert ("success", "SSH settings saved. Restart Jen to apply.") in flashes(logged_in_client)
        saved = on_disk(path)
        assert saved.get("kea_ssh", "user") == "keaops" and saved.get("kea", "dhcp4_log_path") == REFUSED_PATH
        assert last_audit(db, "SAVE_INFRA", "ssh") == "host=10.9.9.9 user=keaops log_path=kept"

    def test_no_line_of_the_route_reads_the_path_without_asking_whether_it_was_posted(self):
        """After the line that reads the field, every line of `save_infra_ssh` that names it asks `log_path_posted` on the same line or is the audit's."""
        body = (
            _src("jen/routes/settings/infrastructure.py")
            .split("def save_infra_ssh():", 1)[1]
            .split("\n@bp.route(", 1)[0]
        )
        after = body.split('dhcp4_log_path = request.form.get("dhcp4_log_path", "").strip()', 1)[1]
        lines = [ln.strip() for ln in after.splitlines() if re.search(r"\bdhcp4_log_path\b", ln)]
        loose = [
            ln
            for ln in lines
            if "log_path_posted" not in ln
            and ln
            not in (
                '"dhcp4_log_path",',  # the name of the field the refusal marks, inside the branch that asked
                'items.append(("kea", "dhcp4_log_path", dhcp4_log_path))',  # inside `if log_path_posted and dhcp4_log_path:`
                '"kea", "dhcp4_log_path"',  # the option removed, inside `if log_path_posted and not dhcp4_log_path ...:`
            )
        ]
        assert loose == [], loose
        assert len([ln for ln in lines if "log_path_posted" in ln]) == 4


# ── row 2 (BL6): linking a restricted local account to single sign-on ────────

QUESTION = "Link this account to SSO? Local username/password login will be disabled for it immediately."
NOW = "This account is restricted to some subnets now."
AFTER = (
    "After it signs in through the identity provider it gets the subnets its groups map to under "
    "Settings → Access & Security → Single Sign-On → Subnet Mapping, and every subnet when no mapping is set."
)


@pytest.fixture
def local_accounts(db):
    from jen.models.user import hash_password

    names = {"q252c_some": "[1, 2]", "q252c_none": "[]", "q252c_all": None}
    ids = {}
    with db.cursor() as cur:
        cur.execute("DELETE FROM users WHERE username LIKE %s", ("q252c\\_%",))
        for name, scope in names.items():
            cur.execute(
                "INSERT INTO users (username, password, role, subnet_access, must_change_password) VALUES (%s, %s, 'admin', %s, 0)",
                (name, hash_password("q252c-Not-used-1"), scope),
            )
            ids[name] = cur.lastrowid
    db.commit()
    yield ids
    with db.cursor() as cur:
        cur.execute("DELETE FROM users WHERE username LIKE %s", ("q252c\\_%",))
    db.commit()


def _row(db, user_id):
    db.commit()
    with db.cursor() as cur:
        cur.execute("SELECT auth_provider, external_id, subnet_access FROM users WHERE id=%s", (user_id,))
        return cur.fetchone()


class TestLinkingARestrictedAccountSaysWhatFollows:
    def _link(self, client, user_id, sub):
        flashes(client)
        client.post(f"/users/link-sso/{user_id}", data={"external_id": sub})
        return flashes(client)

    def test_a_restricted_account_the_flash_and_the_audit_row_say_it(self, logged_in_client, db, local_accounts):
        uid = local_accounts["q252c_some"]
        before = _row(db, uid)["subnet_access"]
        said = self._link(logged_in_client, uid, "q252c-sub-some")
        assert said == [
            ("success", "'q252c_some' is now linked to SSO — local login is disabled for this account. " + AFTER)
        ]
        row = _row(db, uid)
        assert (row["auth_provider"], row["external_id"]) == ("oidc", "q252c-sub-some")
        assert row["subnet_access"] == before and json.loads(row["subnet_access"]) == [1, 2], (
            "the link itself changes no subnet"
        )
        assert last_audit(db, "LINK_SSO", "q252c_some") == (
            "external_id=q252c-sub-some; was restricted to subnets 1, 2; the identity provider sets them from the next sign-in"
        )

    def test_an_account_restricted_to_no_subnet_is_a_restricted_account(self, logged_in_client, db, local_accounts):
        uid = local_accounts["q252c_none"]
        said = self._link(logged_in_client, uid, "q252c-sub-none")
        assert said[0][1].endswith(AFTER)
        assert json.loads(_row(db, uid)["subnet_access"]) == []
        assert last_audit(db, "LINK_SSO", "q252c_none") == (
            "external_id=q252c-sub-none; was restricted to subnets none; the identity provider sets them from the next sign-in"
        )

    def test_an_unrestricted_account_is_told_what_it_was_told_before(self, logged_in_client, db, local_accounts):
        uid = local_accounts["q252c_all"]
        said = self._link(logged_in_client, uid, "q252c-sub-all")
        assert said == [("success", "'q252c_all' is now linked to SSO — local login is disabled for this account.")]
        row = _row(db, uid)
        assert row["auth_provider"] == "oidc" and row["subnet_access"] is None
        assert last_audit(db, "LINK_SSO", "q252c_all") == "external_id=q252c-sub-all"

    def test_the_confirmation_carries_the_sentence_for_a_restricted_account_only(
        self, logged_in_client, db, local_accounts
    ):
        """The browser's half is tests/e2e/test_q252_c.py; this is what the page hands the dialog's script."""
        page = logged_in_client.get("/settings/users").get_data(as_text=True)
        form = re.search(r'<form id="link-sso-form"[^>]*>', page, re.S).group(0)
        attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', form))
        assert htmllib.unescape(attrs["data-confirm"]) == QUESTION, "what every account was asked before, word for word"
        assert htmllib.unescape(attrs["data-confirm-restricted"]) == NOW + " " + AFTER
        scopes = {}
        for raw in re.findall(r"data-user='([^']*)'", page):
            u = json.loads(htmllib.unescape(raw))
            scopes[u["username"]] = u["subnet_ids"]
        assert scopes["q252c_some"] == [1, 2] and scopes["q252c_none"] == [] and scopes["q252c_all"] is None
        script = page.split("function openEditModal(u, opener) {", 1)[1].split("\n}\n", 1)[0]
        assert (
            "linkSso.setAttribute('data-confirm', LINK_SSO_QUESTION + (Array.isArray(u.subnet_ids) ? ' ' + "
            "linkSso.getAttribute('data-confirm-restricted') : ''));"
        ) in script

    def test_the_words_are_one_sentence_in_two_places_and_the_settings_pages_own(self):
        from jen.routes import users

        assert (users.LINK_SSO_RESTRICTED_NOW, users.LINK_SSO_SUBNETS_AFTER) == (NOW, AFTER)
        security = _src("templates/settings_security.html")
        assert '<label for="oidc-subnet-map">Subnet Mapping ' in security
        assert "Access &amp; Security</h1>" in security and "Single Sign-On (OIDC)</span>" in security


# ── row 4 (BL12): every hint of a health check is a sentence ─────────────────


def _hint_sites():
    """Every place under jen/ that gives a health check its hint: a `fix_hint=` argument, and an assignment to `.fix_hint` (alone or as one of a
    pair). Yields (file, line, node) with the node of the value given."""
    for path in sorted((ROOT / "jen").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = path.relative_to(ROOT).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if kw.arg == "fix_hint":
                        yield rel, kw.value.lineno, kw.value
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "fix_hint":
                        yield rel, node.lineno, node.value
                    elif isinstance(target, ast.Tuple) and isinstance(node.value, ast.Tuple):
                        for t, v in zip(target.elts, node.value.elts, strict=True):
                            if isinstance(t, ast.Attribute) and t.attr == "fix_hint":
                                yield rel, node.lineno, v


def _module_strings(rel):
    tree = ast.parse(_src(rel))
    return {
        n.targets[0].id: n.value.value
        for n in tree.body
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and isinstance(n.value, ast.Constant)
        and isinstance(n.value.value, str)
    }


def is_sentence(text):
    return text.endswith(".") and " " in text


class TestEveryHealthHintIsASentence:
    #: the one hint that is put together while the check runs: `_problems_sweep` joins the `_SWEEP_*_HINT` sentences its servers call for (each is
    #: checked below, by name), or keeps the hint the check was built with (`... or c.fix_hint`)
    ASSEMBLED = [("jen/services/health.py", "BoolOp")]

    def test_every_string_given_as_a_hint_ends_with_a_period_and_holds_a_space(self):
        seen, assembled, bad = 0, [], []
        for rel, line, value in _hint_sites():
            seen += 1
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                text = value.value
            elif isinstance(value, ast.Name):
                text = _module_strings(rel).get(value.id)
                assert text is not None, f"{rel}:{line}: the hint `{value.id}` is not a string constant of its module"
            else:
                assembled.append((rel, type(value).__name__))
                continue
            if text and not is_sentence(
                text
            ):  # "" is no hint at all (a row whose page the account may not open is cleared)
                bad.append(f"{rel}:{line}: {text!r}")
        assert bad == [], bad
        assert assembled == self.ASSEMBLED, assembled
        assert seen >= 18, "the walk found the hints (eighteen sites when this was written)"

    def test_the_sentences_the_sweep_row_joins_are_sentences(self):
        hints = {k: v for k, v in _module_strings("jen/services/health.py").items() if k.endswith("_HINT")}
        assert len(hints) == 3 and all(is_sentence(v) for v in hints.values()), hints
        body = _src("jen/services/health.py").split("def _problems_sweep(ctx) -> Check:", 1)[1].split("\ndef ", 1)[0]
        appended = re.findall(r"hints\.append\(\s*([^)]*?)\s*\)", body, re.S)
        assert appended and all(set(re.findall(r"_SWEEP_\w+", a)) <= set(hints) and "_HINT" in a for a in appended), (
            appended
        )

    def test_no_check_is_built_with_a_hint_given_by_position(self):
        """`Check(id, title, group, status, detail, fix_hint, ...)`: a sixth positional argument would be a hint the walk above does not see."""
        for path in sorted((ROOT / "jen").rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "Check":
                    assert len(node.args) <= 5, f"{path.name}:{node.lineno}"

    def test_the_hints_that_were_a_links_label(self):
        text = _src("jen/services/health.py")
        for was in (
            '"Settings → Kea"',
            '"Settings → Kea → SSH"',
            '"Settings → Kea → D2"',
            '"Client Classes"',
            '"Servers"',
        ):
            assert f"fix_hint = {was}" not in text and f", {was}\n" not in text, was
        for now in (
            "Check the daemon, then acknowledge on Servers.",
            "Set up a direct socket for each server and daemon under Settings → Kea.",
            "Update the Kea host helper under Settings → Kea → SSH.",
            "Edit and save each class named above under Client Classes; Jen writes the spelling Kea uses now.",
            "Edit kea-dhcp4.conf by hand; Servers → Config history shows what Jen has pushed.",
            "Finish the upgrade so both peers run the same Kea version; planned maintenance is on Servers.",
            "Set kea-dhcp-ddns's own control socket under Settings → Kea → D2 Control Socket.",
        ):
            assert text.count(f'"{now}"') == 1, now

    def test_a_row_prints_the_sentence_under_its_detail(self, logged_in_client, mock_kea):
        page = logged_in_client.get("/health-center").get_data(as_text=True)
        hints = [htmllib.unescape(h) for h in re.findall(r'<div class="hc-hint">(.*?)</div>', page, re.S)]
        assert all(is_sentence(h) and len(h.split()) >= 4 for h in hints), hints


# ── row 5 (BL13): the Doctor's timestamp finding ─────────────────────────────

STDOUT = {"loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "stdout"}], "severity": "INFO"}]}
NO_TIME = {
    "loggers": [
        {
            "name": "kea-dhcp4",
            "output-options": [{"output": "/var/log/kea/kea-dhcp4.log", "pattern": "%-5p %m\n"}],
            "severity": "INFO",
        }
    ]
}
WHO = "A superadmin can choose a file under Settings → Kea → Kea logging"
NO_TIME_TITLE = "Kea&#39;s log lines carry no date and time"


def _doctor_card(page, title):
    """The Doctor's card for one finding: from its title to the next finding's (or the page's end)."""
    assert title in page
    return page.split(title, 1)[1].split("text-transform:uppercase", 1)[0]


class TestTheDoctorsTimestampFinding:
    def _finding(self, cfg, id_):
        return next(f for f in doctor.diagnose(cfg, hosts=[]) if f["id"] == id_)

    def test_it_links_to_the_kea_logging_card(self):
        assert self._finding(NO_TIME, "logger-pattern-no-timestamp")["fix_url"] == "/settings/kea#kea-logging"
        assert self._finding(STDOUT, "logger-no-file")["fix_url"] == "/settings/kea#kea-logging"

    def test_it_says_who_can_change_it_in_the_words_of_the_finding_beside_it(self):
        assert doctor._SUPERADMIN_CHOOSES_A_FILE == WHO
        note = self._finding(NO_TIME, "logger-pattern-no-timestamp")
        assert note["detail"] == (
            "The pattern '%-5p %m\\n' for /var/log/kea/kea-dhcp4.log has no %D, so its lines start with the level and no time. "
            'Remove the "pattern" key, or use Kea\'s default: "pattern": "' + doctor.LOGGER_PATTERN + '". ' + WHO + "."
        )
        assert (WHO + "; or paste this into that logger's entry") in self._finding(STDOUT, "logger-no-file")["detail"]

    def test_the_words_are_written_once(self):
        assert _src("jen/services/config_doctor.py").count(WHO) == 1

    def test_a_superadmins_page_links_to_the_card(self, logged_in_client, mock_kea, monkeypatch):
        self._kea_answers(monkeypatch, NO_TIME)
        card = _doctor_card(logged_in_client.get("/tools/doctor").get_data(as_text=True), NO_TIME_TITLE)
        assert WHO in card
        assert '<a class="btn btn-sm" href="/settings/kea#kea-logging">Fix →</a>' in card

    def test_an_admins_page_keeps_the_sentence_and_has_no_link(self, client, db, mock_kea, monkeypatch):
        from tests.conftest import restricted_client

        self._kea_answers(monkeypatch, NO_TIME)
        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username='q252c_admin'")
        db.commit()
        _client, uid = restricted_client(client, db, None, role="admin", username="q252c_admin")
        with db.cursor() as cur:
            cur.execute(
                "UPDATE users SET subnet_access=NULL WHERE id=%s", (uid,)
            )  # every subnet: the column is NULL, not the JSON null
        db.commit()
        try:
            r = client.get("/tools/doctor")
            assert r.status_code == 200
            page = r.get_data(as_text=True)
            card = _doctor_card(page, NO_TIME_TITLE)
            assert WHO in card
            assert "#kea-logging" not in page and "Fix →" not in card
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM users WHERE id=%s", (uid,))
            db.commit()

    @staticmethod
    def _kea_answers(monkeypatch, dhcp4_cfg):
        from jen.services import kea as kea_svc

        monkeypatch.setattr(
            kea_svc, "kea_command", lambda *a, **kw: {"result": 0, "text": "mocked", "arguments": {"Dhcp4": dhcp4_cfg}}
        )
