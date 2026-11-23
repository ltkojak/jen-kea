"""
tests/test_q248_a1.py
─────────────────────
Q248, stage a1 - keyboard access, dialogs and the Display menu: what a rendered page and the three user routes can hold. What only a browser can show (the keys,
focus, a row's height, a target's box) is tests/e2e/test_q248_a1.py.

* V1   the three kinds of menu: a toggle the keyboard reaches (never display:none), with a role, a state and a name; the dropdown is a menu of menu items.
* V2   the global search has a name and nothing in base.html switches the focus ring off.
* V3   Add User and Edit User are dialogs; a refused form comes back with what was typed (never a password) and the message against its field.
* V41  the subnet lists of Add User and Edit User are checkboxes, and the three routes read them: nothing ticked and All Subnets beside a subnet are refused.
* V9   a row checkbox and select-all say what they select.
* V45  a confirmation that deletes, removes, revokes, releases or resets names the action on its button.
* V50  Customize navigation: no Move up on the first row, no Move down on the last, and a phone bar nobody set is not "0 of 4".
* T1, T2, additions 12, 13, 17 - the Display menu: the default theme listed once as "(default)", Match My System, Display Times, Table Rows, a sample per theme.
* addition 8 - the Users list says the second factor in words.
"""

import json
import pathlib
import re

import pytest

from jen.routes.users import SUBNETS_ALL_AND_NAMED, SUBNETS_NONE_TICKED

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"
BASE = (TEMPLATES / "base.html").read_text(encoding="utf-8")


def _tag(html, needle):
    """The whole opening tag that holds `needle`."""
    i = html.index(needle)
    return html[html.rindex("<", 0, i) : html.index(">", i) + 1]


def _user(db, username, role="admin", access="[1]"):
    from jen.models.user import hash_password

    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password, role, subnet_access) VALUES (%s, %s, %s, %s)",
            (username, hash_password("x" * 12), role, access),
        )
        uid = cur.lastrowid
    db.commit()
    return uid


def _row(db, username):
    db.commit()  # a fresh read view: the route committed on another connection
    with db.cursor() as cur:
        cur.execute("SELECT id, role, subnet_access, session_timeout FROM users WHERE username=%s", (username,))
        return cur.fetchone()


# ───────────────────────────── V41: the three routes ─────────────────────────────


class TestAddUserReadsTheTickedSubnets:
    def _add(self, client, name, subnet_ids, role="viewer"):
        data = {"username": name, "password": "longenough1", "role": role}
        if subnet_ids is not None:
            data["subnet_ids"] = subnet_ids
        return client.post("/users/add", data=data, follow_redirects=True)

    def test_nothing_ticked_creates_nothing_and_says_why(self, logged_in_client, db):
        r = self._add(logged_in_client, "q248_none", None)
        assert SUBNETS_NONE_TICKED in r.get_data(as_text=True)
        assert _row(db, "q248_none") is None

    def test_all_beside_a_subnet_creates_nothing_and_says_why(self, logged_in_client, db):
        r = self._add(logged_in_client, "q248_both", ["all", "1"])
        assert SUBNETS_ALL_AND_NAMED in r.get_data(as_text=True)
        assert _row(db, "q248_both") is None

    def test_all_alone_stores_null(self, logged_in_client, db):
        self._add(logged_in_client, "q248_all", ["all"])
        row = _row(db, "q248_all")
        assert row is not None and row["subnet_access"] is None

    def test_one_subnet_stores_that_subnet(self, logged_in_client, db):
        self._add(logged_in_client, "q248_one", ["1"])
        row = _row(db, "q248_one")
        assert row is not None and json.loads(row["subnet_access"]) == [1]

    def test_a_superadmin_with_nothing_ticked_is_accepted_and_stores_null(self, logged_in_client, db):
        self._add(logged_in_client, "q248_super", None, role="superadmin")
        row = _row(db, "q248_super")
        assert row is not None and row["role"] == "superadmin" and row["subnet_access"] is None


class TestEditUserReadsTheTickedSubnets:
    def _edit(self, client, uid, subnet_ids, role="admin"):
        data = {"role": role, "timeout": ""}
        if subnet_ids is not None:
            data["subnet_ids"] = subnet_ids
        return client.post(f"/users/edit/{uid}", data=data, follow_redirects=True)

    def test_nothing_ticked_changes_nothing_and_says_why(self, logged_in_client, db):
        uid = _user(db, "q248_e_none")
        r = self._edit(logged_in_client, uid, None, role="viewer")
        assert SUBNETS_NONE_TICKED in r.get_data(as_text=True)
        row = _row(db, "q248_e_none")
        assert row["subnet_access"] == "[1]" and row["role"] == "admin", (
            "the role of the refused form was not stored either"
        )

    def test_all_beside_a_subnet_changes_nothing_and_says_why(self, logged_in_client, db):
        uid = _user(db, "q248_e_both")
        r = self._edit(logged_in_client, uid, ["all", "1"])
        assert SUBNETS_ALL_AND_NAMED in r.get_data(as_text=True)
        assert _row(db, "q248_e_both")["subnet_access"] == "[1]"

    def test_all_alone_stores_null(self, logged_in_client, db):
        uid = _user(db, "q248_e_all")
        self._edit(logged_in_client, uid, ["all"])
        assert _row(db, "q248_e_all")["subnet_access"] is None

    def test_one_subnet_stores_that_subnet(self, logged_in_client, db):
        uid = _user(db, "q248_e_one", access=None)
        self._edit(logged_in_client, uid, ["1"])
        assert json.loads(_row(db, "q248_e_one")["subnet_access"]) == [1]

    def test_a_superadmin_with_nothing_ticked_is_accepted_and_stores_null(self, logged_in_client, db):
        uid = _user(db, "q248_e_super")
        self._edit(logged_in_client, uid, None, role="superadmin")
        row = _row(db, "q248_e_super")
        assert row["role"] == "superadmin" and row["subnet_access"] is None


class TestSetUserSubnetsReadsTheTickedSubnets:
    def _set(self, client, uid, subnet_ids):
        data = {} if subnet_ids is None else {"subnet_ids": subnet_ids}
        return client.post(f"/users/set-subnets/{uid}", data=data, follow_redirects=True)

    def test_nothing_ticked_changes_nothing_and_says_why(self, logged_in_client, db):
        uid = _user(db, "q248_s_none")
        r = self._set(logged_in_client, uid, None)
        assert SUBNETS_NONE_TICKED in r.get_data(as_text=True)
        assert _row(db, "q248_s_none")["subnet_access"] == "[1]"

    def test_all_beside_a_subnet_changes_nothing_and_says_why(self, logged_in_client, db):
        uid = _user(db, "q248_s_both")
        r = self._set(logged_in_client, uid, ["1", "all"])
        assert SUBNETS_ALL_AND_NAMED in r.get_data(as_text=True)
        assert _row(db, "q248_s_both")["subnet_access"] == "[1]"

    def test_all_alone_stores_null(self, logged_in_client, db):
        uid = _user(db, "q248_s_all")
        self._set(logged_in_client, uid, ["all"])
        assert _row(db, "q248_s_all")["subnet_access"] is None

    def test_one_subnet_stores_that_subnet(self, logged_in_client, db):
        uid = _user(db, "q248_s_one", access=None)
        self._set(logged_in_client, uid, ["1"])
        assert json.loads(_row(db, "q248_s_one")["subnet_access"]) == [1]

    def test_a_superadmin_row_with_nothing_ticked_is_refused_here(self, logged_in_client, db):
        """This form carries no role, so no role is exempt on it: the superadmin exemption is Add User's and Edit User's, where the role is on the form."""
        uid = _user(db, "q248_s_super", role="superadmin", access="[1]")
        r = self._set(logged_in_client, uid, None)
        assert SUBNETS_NONE_TICKED in r.get_data(as_text=True)
        assert _row(db, "q248_s_super")["subnet_access"] == "[1]"


# ───────────────────────────── V3 and V41: the Users page ─────────────────────────────


class TestTheUserDialogs:
    def _page(self, client):
        return client.get("/settings/users").get_data(as_text=True)

    @pytest.mark.parametrize(
        ("dialog", "title"), [("add-modal", "add-modal-title"), ("edit-modal", "edit-modal-title")]
    )
    def test_each_is_a_dialog_named_by_its_title(self, logged_in_client, dialog, title):
        html = self._page(logged_in_client)
        tag = _tag(html, f'id="{dialog}"')
        assert 'role="dialog"' in tag and 'aria-modal="true"' in tag and f'aria-labelledby="{title}"' in tag
        assert " hidden" in tag and "style=" not in tag, "closed by the hidden attribute, which the dialog helper lifts"
        assert f'id="{title}"' in html

    def test_the_page_opens_them_through_the_one_helper(self, logged_in_client):
        html = self._page(logged_in_client)
        assert html.count("jenDialog.open(document.getElementById(") == 2
        assert "window.jenDialog = (function() {" in BASE
        assert BASE.index("window.jenDialog = (function() {") < BASE.index("<style>"), (
            "defined before the page's own script runs"
        )

    def test_a_password_that_is_required_is_required_and_eight_long_in_the_browser(self, logged_in_client):
        html = self._page(logged_in_client)
        add = _tag(html, 'id="f-password"')
        assert " required" in add and 'minlength="8"' in add
        for field in ("f-edit-new_password", "f-edit-confirm_password"):
            tag = _tag(html, f'id="{field}"')
            assert 'minlength="8"' in tag and " required" not in tag, "blank keeps the current password"

    @pytest.mark.parametrize("list_id", ["f-subnet_ids", "f-edit-subnet_ids"])
    def test_the_subnets_are_checkboxes_with_the_api_key_forms_hint(self, logged_in_client, list_id):
        html = self._page(logged_in_client)
        tag = _tag(html, f'id="{list_id}"')
        assert 'class="check-list"' in tag and 'role="group"' in tag
        box = html.split(f'id="{list_id}"', 1)[1].split("</div>", 1)[0]
        assert re.search(r'<input type="checkbox" name="subnet_ids" value="all"', box)
        assert re.search(r'<input type="checkbox" name="subnet_ids" value="1">', box)
        assert "<select" not in box
        assert f'id="{list_id}-hint">Tick All Subnets, or the subnets this account may use - not both.</div>' in html

    def test_add_user_starts_on_all_subnets_and_nothing_says_ctrl_click(self, logged_in_client):
        html = self._page(logged_in_client)
        assert '<input type="checkbox" name="subnet_ids" value="all" checked> All Subnets' in html
        assert "Ctrl/Cmd" not in html and "multiple" not in _tag(html, 'id="f-subnet_ids"')

    def test_one_handler_in_base_serves_every_check_list(self):
        assert "t.closest('.check-list')" in BASE
        api_keys = (TEMPLATES / "api_keys.html").read_text(encoding="utf-8")
        assert "{% block scripts %}" not in api_keys, "the API key page's own copy is gone"


class TestARefusedUserFormComesBack:
    def _back(self, html):
        return json.loads(re.search(r"var FORM_BACK = (.*?);\r?\n", html).group(1))

    def test_the_page_carries_no_form_when_nothing_was_refused(self, logged_in_client):
        assert self._back(logged_in_client.get("/settings/users").get_data(as_text=True)) is None

    def test_a_refused_add_keeps_the_username_the_role_the_subnets_and_the_timeout_never_the_password(
        self, logged_in_client, db
    ):
        r = logged_in_client.post(
            "/users/add",
            data={
                "username": "bad name!",
                "password": "S3cret-never-shown",
                "role": "admin",
                "subnet_ids": ["1"],
                "timeout": "45",
            },
        )
        assert r.status_code == 302 and r.headers["Location"].endswith("/settings/users")
        html = logged_in_client.get("/settings/users").get_data(as_text=True)
        assert self._back(html) == {
            "form": "add",
            "id": None,
            "username": "bad name!",
            "role": "admin",
            "subnet_ids": ["1"],
            "timeout": "45",
        }
        assert "S3cret-never-shown" not in html
        alert = _tag(html, 'data-field="username"')
        assert 'role="alert"' in alert
        assert "Username may only contain letters" in html
        # one render only: the next page is clean
        assert self._back(logged_in_client.get("/settings/users").get_data(as_text=True)) is None
        assert _row(db, "bad name!") is None

    @pytest.mark.parametrize(
        ("form", "field", "message"),
        [
            ({"username": "q248_r1", "password": "short", "subnet_ids": ["all"]}, "password", "at least 8 characters"),
            ({"username": "q248_r2", "password": "longenough1"}, "subnet_ids", SUBNETS_NONE_TICKED),
            (
                {"username": "q248_r3", "password": "longenough1", "subnet_ids": ["all"], "timeout": "9999"},
                "timeout",
                "Timeout must be 1",
            ),
        ],
    )
    def test_each_add_refusal_names_its_field(self, logged_in_client, db, form, field, message):
        html = logged_in_client.post("/users/add", data={"role": "viewer", **form}, follow_redirects=True).get_data(
            as_text=True
        )
        assert f'data-field="{field}"' in html and message in html
        assert self._back(html)["form"] == "add" and self._back(html)["username"] == form["username"]
        assert _row(db, form["username"]) is None

    def test_a_duplicate_username_comes_back_against_the_username(self, logged_in_client, db):
        _user(db, "q248_dup")
        html = logged_in_client.post(
            "/users/add",
            data={"username": "q248_dup", "password": "longenough1", "role": "viewer", "subnet_ids": ["all"]},
            follow_redirects=True,
        ).get_data(as_text=True)
        assert 'data-field="username"' in html and "already exists" in html
        assert self._back(html)["username"] == "q248_dup"

    @pytest.mark.parametrize(
        ("form", "field", "message"),
        [
            ({"subnet_ids": ["all"], "timeout": "0"}, "edit-timeout", "Timeout must be 1"),
            (
                {"subnet_ids": ["all"], "new_password": "short", "confirm_password": "short"},
                "edit-new_password",
                "at least 8 characters",
            ),
            (
                {"subnet_ids": ["all"], "new_password": "longenough1", "confirm_password": "longenough2"},
                "edit-confirm_password",
                "do not match",
            ),
            ({}, "edit-subnet_ids", SUBNETS_NONE_TICKED),
        ],
    )
    def test_each_edit_refusal_names_its_own_field_and_its_account(self, logged_in_client, db, form, field, message):
        uid = _user(db, "q248_edit_back")
        html = logged_in_client.post(
            f"/users/edit/{uid}", data={"role": "viewer", "timeout": "", **form}, follow_redirects=True
        ).get_data(as_text=True)
        assert f'data-field="{field}"' in html and message in html
        back = self._back(html)
        assert back["form"] == "edit" and back["id"] == uid and back["role"] == "viewer"
        assert "longenough" not in html and '"short"' not in html, "no password travels back"
        assert f'id="f-{field}"' in html, "the dialog has the field the message is for"
        assert f'data-user-id="{uid}"' in html, "and the row's button the page opens the dialog from"
        assert _row(db, "q248_edit_back")["role"] == "admin"


# ───────────────────────────── addition 8: the second factor in words ─────────────────────────────


class TestTheUsersListSaysTheMfaMethod:
    @pytest.fixture
    def factors(self, db):
        ids = {name: _user(db, name) for name in ("q248_mfa_none", "q248_mfa_totp", "q248_mfa_key", "q248_mfa_both")}
        with db.cursor() as cur:
            for name in ("q248_mfa_totp", "q248_mfa_both"):
                cur.execute(
                    "INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled) VALUES (%s, 'totp', 'x', 'Authenticator', 1)",
                    (ids[name],),
                )
            for name in ("q248_mfa_key", "q248_mfa_both"):
                cur.execute(
                    "INSERT INTO webauthn_credentials (user_id, credential_id, public_key) VALUES (%s, %s, 'q248')",
                    (ids[name], name),
                )
        db.commit()
        yield ids
        with db.cursor() as cur:
            cur.execute("DELETE FROM webauthn_credentials WHERE public_key='q248'")
        db.commit()

    def _cell(self, html, username):
        row = html.split(f"<strong>{username}</strong>", 1)[1].split("</tr>", 1)[0]
        return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", row.split("</td>")[3])).strip()

    def test_each_account_says_its_methods(self, logged_in_client, factors):
        html = logged_in_client.get("/settings/users").get_data(as_text=True)
        assert self._cell(html, "q248_mfa_none") == "MFA: None"
        assert self._cell(html, "q248_mfa_totp") == "MFA: Authenticator app"
        assert self._cell(html, "q248_mfa_key") == "MFA: Passkey"
        assert self._cell(html, "q248_mfa_both") == "MFA: Authenticator app, Passkey"
        assert "✓ Enrolled" not in html


# ───────────────────────────── V1, V2, the Display menu ─────────────────────────────


class TestTheMenusAreReachable:
    def test_no_menu_toggle_is_display_none(self):
        assert ".action-menu-toggle { display: none; }" not in BASE
        assert ".nav-dropdown input[type=checkbox] { display: none; }" not in BASE
        rule = re.search(r"input\.nav-dd-toggle, input\.action-menu-toggle \{([^}]*)\}", BASE).group(1)
        assert "opacity: 0" in rule and "display" not in rule and "visibility" not in rule
        assert ".nav-dd-toggle:focus-visible + label, .action-menu-toggle:focus-visible + label {" in BASE

    @pytest.mark.parametrize(
        ("toggle", "name", "menu"),
        [("dd-theme", "Display", "dd-theme-menu"), ("dd-avatar", "Account", "dd-avatar-menu")],
    )
    def test_a_top_row_menu_button_has_a_role_a_state_and_a_name(self, logged_in_client, toggle, name, menu):
        html = logged_in_client.get("/about").get_data(as_text=True)
        tag = _tag(html, f'id="{toggle}"')
        assert 'type="checkbox"' in tag, "it stays a checkbox, so the menu opens with no script"
        for attr in (
            'role="button"',
            'aria-haspopup="menu"',
            'aria-expanded="false"',
            f'aria-label="{name}"',
            f'aria-controls="{menu}"',
        ):
            assert attr in tag, attr
        panel = _tag(html, f'id="{menu}"')
        assert 'role="menu"' in panel and f'aria-label="{name}"' in panel

    def test_the_account_menus_items_are_menu_items_and_sign_out_is_one(self, logged_in_client):
        html = logged_in_client.get("/about").get_data(as_text=True)
        menu = html.split('id="dd-avatar-menu"', 1)[1].split("</nav>", 1)[0]
        assert menu.count('role="menuitem"') == 7  # Q248 a2 (V10): About is always in this menu
        assert re.search(
            r'<form method="POST" action="/logout">.*?<button type="submit" class="nav-dd-item danger" role="menuitem">',
            menu,
            re.S,
        )

    def test_a_lease_rows_menu_names_its_row(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
                "VALUES (INET_ATON('10.99.0.77'), UNHEX('AABBCC248001'), 3600, DATE_ADD(NOW(), INTERVAL 1 DAY), 1, 0, 'q248-host'), "
                "(INET_ATON('10.99.0.78'), UNHEX('AABBCC248002'), 3600, DATE_ADD(NOW(), INTERVAL 1 DAY), 1, 0, NULL)"
            )
        db.commit()
        try:
            html = logged_in_client.get("/leases").get_data(as_text=True)
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
            db.commit()
        tags = re.findall(r'<input type="checkbox" id="am-lease-[^"]*" class="action-menu-toggle"[^>]*>', html)
        assert len(tags) >= 2
        for tag in tags:
            assert 'role="button"' in tag and 'aria-haspopup="menu"' in tag and 'aria-expanded="false"' in tag
        assert any('aria-label="Actions for q248-host"' in t for t in tags)
        assert any('aria-label="Actions for 10.99.0.78"' in t for t in tags), (
            "a row with no hostname is named by its address"
        )
        assert html.count('<div class="action-menu-dropdown" role="menu">') == len(tags)
        assert 'class="action-menu-item danger" role="menuitem">' in html

    def test_every_row_menu_in_the_templates_is_dressed(self):
        for path in sorted(TEMPLATES.glob("*.html")):
            text = path.read_text(encoding="utf-8")
            for tag in re.findall(r'<input type="checkbox"[^>]*class="action-menu-toggle"[^>]*>', text):
                assert 'role="button"' in tag and 'aria-haspopup="menu"' in tag and 'aria-label="Actions for ' in tag, (
                    path.name,
                    tag,
                )
            assert '<div class="action-menu-dropdown">' not in text, path.name
            for tag in re.findall(r'<(?:a|button)\b[^>]*class="action-menu-item[^"]*"[^>]*>', text, re.S):
                assert 'role="menuitem"' in tag, (path.name, tag[:120])


class TestOneFocusRing:
    def test_the_search_box_has_a_name_and_does_not_switch_the_ring_off(self, logged_in_client):
        html = logged_in_client.get("/about").get_data(as_text=True)
        tag = _tag(html, 'placeholder="Search..."')
        assert 'aria-label="Search"' in tag and "outline" not in tag

    def test_nothing_in_base_switches_the_outline_off(self):
        assert not re.search(r"outline:\s*(none|0)\b", BASE)


class TestTheDisplayMenu:
    def _menu(self, html):
        return html.split('id="dd-theme-menu"', 1)[1].split('id="dd-avatar"', 1)[0]

    def _sheet(self, html):
        return html.split('id="theme-sheet"', 1)[1].split("<script", 1)[0]

    def test_the_default_theme_is_listed_once_and_reads_default(self, logged_in_client):
        html = logged_in_client.get("/about").get_data(as_text=True)
        for part in (self._menu(html), self._sheet(html)):
            text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", part))
            assert text.count("Dark (default)") == 1 and "Install default" not in text
            assert len(re.findall(r"\bDark\b", text)) == 1, "the preset that IS the default is not listed a second time"
            assert 'data-theme-id=""' in part and 'data-theme-id="dark"' not in part
            first = re.search(r'data-theme-id="([^"]*)"', part).group(1)
            assert first == "", "the default is the first row"
            assert re.findall(r'data-theme-id="([^"]*)"', part)[1] == "system"
            for other in ("light", "contrast", "phosphor", "slate", "ember", "retro"):
                assert part.count(f'data-theme-id="{other}"') == 1

    def test_another_default_moves_the_row_and_lists_dark_as_a_theme(self, logged_in_client):
        logged_in_client.post("/settings/theme/default", data={"theme_default": "phosphor"})
        html = logged_in_client.get("/about").get_data(as_text=True)
        menu = self._menu(html)
        assert (
            "Phosphor (default)" in menu and 'data-theme-id="phosphor"' not in menu and 'data-theme-id="dark"' in menu
        )
        assert "theme-sample-phosphor" in menu.split('data-theme-id=""', 1)[1].split("</button>", 1)[0]

    def test_its_name_its_sections_and_its_words(self, logged_in_client):
        html = logged_in_client.get("/about").get_data(as_text=True)
        assert 'title="Display"' in _tag(html, 'for="dd-theme"')
        menu, sheet = self._menu(html), self._sheet(html)
        assert "<strong>Display</strong>" in menu and '<div class="sheet-title">Display</div>' in sheet
        assert 'aria-label="Display"' in _tag(html, 'id="theme-sheet"')
        for part in (menu, sheet):
            text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", part))
            order = [
                text.index(w)
                for w in (
                    "Theme",
                    "Match My System",
                    "Display Times",
                    "Local Browser Time",
                    "UTC Time",
                    "Table Rows",
                    "Comfortable",
                    "Compact",
                )
            ]
            assert order == sorted(order), order
            for gone in ("In my browser's time zone", "In UTC", ">Times<"):
                assert gone not in part
            assert 'data-time-mode="local"' in part and 'data-time-mode="utc"' in part
            assert 'data-density="comfortable"' in part and 'data-density="compact"' in part
        assert "linkish" not in menu, "plain items, the Account menu's style"
        assert menu.count('role="menuitemradio"') == menu.count("nav-dd-item")

    def test_every_theme_row_carries_a_sample_drawn_by_a_rule(self, logged_in_client):
        from jen.services import theme

        html = logged_in_client.get("/about").get_data(as_text=True)
        style = html.split("<style>", 1)[1].split("</style>", 1)[0]
        for tid, preset in theme.PRESETS.items():
            t = preset["tokens"]
            assert f".theme-sample-{tid} .ts-bg{{background:{t['bg']};}}" in style
            assert f".theme-sample-{tid} .ts-surface{{background:{t['surface']};}}" in style
            assert f".theme-sample-{tid} .ts-accent{{background:{t['primary']};}}" in style
        assert ".theme-sample-system .ts-bg{background:" + theme.PRESETS["dark"]["tokens"]["bg"] in style
        menu = self._menu(html)
        rows = re.findall(r"<button[^>]*theme-pick[^>]*>.*?</button>", menu, re.S)
        assert len(rows) == 8 and all("theme-sample theme-sample-" in r and "style=" not in r for r in rows)

    def test_the_early_script_knows_system_and_the_density(self):
        head = BASE[: BASE.index("<style>")]
        assert "function jenThemeResolve(pick) {" in head and "if (pick === 'system')" in head
        assert "(prefers-color-scheme: dark)" in head
        assert "localStorage.getItem('jen-density-pick')" in head
        assert "document.documentElement.dataset.density = 'compact';" in head
        assert 'html[data-density="compact"] table.rowlist tbody td {' in BASE


class TestAppearanceShowsWhatIsInUse:
    def test_no_upload_says_default_beside_each_control(self, logged_in_client):
        html = logged_in_client.get("/settings/appearance").get_data(as_text=True)
        logo = html.split('id="app-logo-preview"', 1)[1].split("</div>", 1)[0]
        assert 'src="/static/icons/jen-logo-navbar.png" alt="Current navigation logo"' in logo and ">Default<" in logo
        icon = html.split('id="app-favicon-preview"', 1)[1].split("</div>", 1)[0]
        assert 'src="/favicon.ico" alt="Current favicon"' in icon and ">Default<" in icon

    def test_an_uploaded_logo_and_favicon_are_shown_with_their_remove_buttons_and_no_default(
        self, logged_in_client, tmp_path, monkeypatch
    ):
        from jen import extensions

        (tmp_path / "nav_logo.png").write_bytes(b"not a real image: the page only asks whether the file exists")
        (tmp_path / "favicon.ico").write_bytes(b"x")
        monkeypatch.setattr(extensions, "NAV_LOGO_PATH", str(tmp_path / "nav_logo"))
        monkeypatch.setattr(extensions, "FAVICON_PATH", str(tmp_path / "favicon.ico"))
        html = logged_in_client.get("/settings/appearance").get_data(as_text=True)
        logo = html.split('id="app-logo-preview"', 1)[1].split("</div>", 1)[0]
        assert 'src="/content/branding/nav_logo.png?v=' in logo and ">Default<" not in logo
        assert 'action="/settings/remove-nav-logo"' in logo
        icon = html.split('id="app-favicon-preview"', 1)[1].split("</div>", 1)[0]
        assert 'src="/favicon.ico"' in icon and ">Default<" not in icon and 'action="/settings/remove-favicon"' in icon


# ───────────────────────────── V9, V45, V50 ─────────────────────────────


class TestControlsSayWhatTheyAre:
    def test_select_all_and_the_row_boxes(self):
        for name in ("_devices_results.html", "_leases_results.html", "_reservations_results.html"):
            assert '<input type="checkbox" id="selectAll" aria-label="Select all rows">' in (
                TEMPLATES / name
            ).read_text(encoding="utf-8")
        for name in ("_device_rows.html", "_reservation_row.html", "_lease_rows.html"):
            text = (TEMPLATES / name).read_text(encoding="utf-8")
            boxes = re.findall(r'<input type="checkbox" class="row-checkbox"[^>]*>', text)
            assert boxes and all("aria-label=" in b for b in boxes), name

    def test_a_device_rows_box_is_named_for_the_device(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO devices (mac, device_name, last_ip, last_subnet_id, first_seen, last_seen) "
                "VALUES ('aa:bb:cc:24:80:01', 'Q248 Printer', '10.99.0.90', 1, NOW(), NOW())"
            )
        db.commit()
        html = logged_in_client.get("/devices").get_data(as_text=True)
        assert 'aria-label="Select Q248 Printer"' in html and 'aria-label="Actions for Q248 Printer"' in html


class TestARowsOwnFormIsARealForm:
    """A row's own form (Release lease, Remove from inventory, a plugin's POST action) used to sit INSIDE the list's bulk form. A form inside a form is not HTML: the
    browser drops the inner tag, so the row's button was the bulk form's and posted the BULK action, with no confirmation. The bulk form ends after its bar now."""

    @pytest.mark.parametrize(
        ("results", "row", "box"),
        [
            ("_leases_results.html", "_lease_rows.html", 'name="ips[]" value="{{ l.ip }}" form="bulk-form"'),
            ("_devices_results.html", "_device_rows.html", 'name="device_ids[]" value="{{ d.id }}" form="bulk-form"'),
            (
                "_reservations_results.html",
                "_reservation_row.html",
                'name="host_ids[]" value="{{ h.host_id }}" form="bulk-form"',
            ),
        ],
    )
    def test_the_bulk_form_ends_before_the_table_and_the_row_boxes_name_it(self, results, row, box):
        text = (TEMPLATES / results).read_text(encoding="utf-8")
        start = text.index('<form id="bulk-form"')
        assert start < text.index("</form>", start) < text.index("<table"), results
        assert box in (TEMPLATES / row).read_text(encoding="utf-8"), row

    def test_no_template_writes_a_form_inside_a_bulk_form(self):
        """Between the bulk form's two tags there is no other form, and no row partial (a Jinja comment may talk about one)."""
        for name in ("_leases_results.html", "_devices_results.html", "_reservations_results.html"):
            text = re.sub(r"\{#.*?#\}", "", (TEMPLATES / name).read_text(encoding="utf-8"), flags=re.S)
            start = text.index('<form id="bulk-form"')
            inside = text[start + 5 : text.index("</form>", start)]
            assert "<form" not in inside and "{% include" not in inside, name

    def test_a_rendered_lease_rows_release_form_is_outside_the_bulk_form(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) "
                "VALUES (INET_ATON('10.99.0.79'), UNHEX('AABBCC248003'), 3600, DATE_ADD(NOW(), INTERVAL 1 DAY), 1, 0, 'q248-form')"
            )
        db.commit()
        try:
            html = logged_in_client.get("/leases").get_data(as_text=True)
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE subnet_id=1")
            db.commit()
        start = html.index('<form id="bulk-form"')
        end = html.index("</form>", start)
        release = html.index('<form method="POST" action="/leases/release"')
        assert end < release
        assert 'name="ips[]" value="10.99.0.79" form="bulk-form"' in html

    def test_a_confirmed_button_with_its_own_action_posts_to_it(self):
        assert (
            "if (f && el.hasAttribute('formaction')) f.setAttribute('action', el.getAttribute('formaction'));" in BASE
        )


class TestAConfirmationNamesItsAction:
    VERBS = ("Delete", "Remove", "Revoke", "Release", "Reset")
    ATTR = re.compile(
        r'(?:data-confirm|hx-confirm)="((?:\{\{.*?\}\}|\{%.*?%\}|[^"])*)"((?:\s+data-confirm-label="[^"]*")?)', re.S
    )

    def test_every_such_sentence_in_the_templates_carries_its_verb_as_the_label(self):
        seen = 0
        for path in sorted(TEMPLATES.glob("*.html")):
            for sentence, label in self.ATTR.findall(path.read_text(encoding="utf-8")):
                verb = sentence.split(" ", 1)[0]
                if verb not in self.VERBS:
                    continue
                seen += 1
                assert label.strip() == f'data-confirm-label="{verb}"', (path.name, sentence[:60], label)
        assert seen >= 28, seen

    def test_the_dispatcher_hands_the_label_to_the_dialog_and_confirm_stays_the_default(self):
        assert BASE.count("el.getAttribute('data-confirm-label')") == 2
        assert "okBtn.textContent = confirmLabel || 'Confirm';" in BASE
        assert "document.addEventListener('htmx:confirm', function(e) {" in BASE

    def test_the_bulk_bars_say_the_count_and_the_action(self):
        text = (TEMPLATES / "devices.html").read_text(encoding="utf-8")
        assert (
            "jenConfirm(`Remove ${n} ${n === 1 ? 'device' : 'devices'} from inventory? This cannot be undone.`" in text
        )
        assert "}, 'Remove');" in text
        assert "jenConfirm(`Release ${n} ${n === 1 ? 'lease' : 'leases'}?" in (TEMPLATES / "leases.html").read_text(
            encoding="utf-8"
        )
        assert "}, 'Release');" in (TEMPLATES / "leases.html").read_text(encoding="utf-8")
        text = (TEMPLATES / "reservations.html").read_text(encoding="utf-8")
        assert "jenConfirm(`Delete ${n} ${n === 1 ? 'reservation' : 'reservations'}? This cannot be undone.`" in text
        assert "}, 'Delete');" in text

    def test_a_release_is_not_called_final_and_a_delete_is(self):
        lease = (TEMPLATES / "_lease_rows.html").read_text(encoding="utf-8")
        assert 'data-confirm="Release lease for {{ l.ip }}?" data-confirm-label="Release"' in lease
        row = (TEMPLATES / "_reservation_row.html").read_text(encoding="utf-8")
        assert (
            'hx-confirm="Delete the reservation for {{ h.ip }}? This cannot be undone." data-confirm-label="Delete"'
            in row
        )


class TestCustomizeNavigation:
    @pytest.fixture
    def three_favorites(self, logged_in_client, db):
        def wipe():
            with db.cursor() as cur:
                cur.execute("DELETE FROM user_nav")
            db.commit()

        wipe()
        for dest in ("/reports", "/problems", "/settings/kea"):
            logged_in_client.post("/navigation/edit", data={"place": "top", "action": "add", "dest": dest})
        yield
        wipe()

    def test_the_first_row_cannot_move_up_and_the_last_cannot_move_down(self, logged_in_client, three_favorites):
        html = logged_in_client.get("/navigation").get_data(as_text=True)
        card = html.split('id="navc-top"', 1)[1].split('id="navc-tabbar"', 1)[0]
        buttons = re.findall(
            r'<button type="submit" class="btn btn-sm btn-secondary" title="(Move up|Move down|Remove)"[^>]*>', card
        )
        assert buttons == ["Move up", "Move down", "Remove"] * 3
        tags = re.findall(
            r'<button type="submit" class="btn btn-sm btn-secondary" title="(?:Move up|Move down|Remove)"[^>]*>', card
        )
        disabled = [i for i, t in enumerate(tags) if " disabled" in t]
        assert disabled == [0, 7], "only Move up on the first row and Move down on the last"

    def test_a_phone_bar_nobody_set_says_so_in_words(self, logged_in_client, three_favorites):
        html = logged_in_client.get("/navigation").get_data(as_text=True)
        assert "Phone bar (the default pages)" in html and "(0 of 4)" not in html
        assert "Top row favorites (3 of 5)" in html
        logged_in_client.post("/navigation/edit", data={"place": "tabbar", "action": "add", "dest": "/leases"})
        assert "Phone bar (1 of 4)" in logged_in_client.get("/navigation").get_data(as_text=True)
