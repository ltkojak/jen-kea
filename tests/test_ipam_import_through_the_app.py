"""v7.2.0-beta.4 (Q246, the plugin audit's IPAM-3): an IPAM Lite import of the size the plugin documents is confirmed.

The audit reported that 2,000 rows, inside the documented limit, answered Confirm Import with 413: the previewed rows go to
the browser and come back as ONE hidden form field, and Werkzeug refused a form above `MAX_FORM_MEMORY_SIZE` (500,000
bytes). That was Werkzeug 3.1.8. From 3.1.9, Jen's own floor in `requirements.txt`, the limit applies to a multipart text
part and no longer to a urlencoded form, so the import works and the plugin was left as it was. This test is what holds
that: if the framework brings the limit back, or the floor moves down, it fails on the 413 itself.

Nothing is stood in for. The file goes through Jen's own application object with every bundled plugin enabled
(`plugin_app`), Werkzeug's real form parser, the plugin's real preview and commit routes and the real database, and the
commit posts back whatever hidden fields the preview page carries, as a browser does.
"""

# ruff: noqa: F811 - the fixtures are imported by name (the same way tests/test_stored_objects_wol.py imports them)
import html
import io
import re
from urllib.parse import urlencode

import pytest

from jen import extensions
from tests.test_authz_matrix import B_NAME, _caller, seeded  # noqa: F401 - fixtures are used by name
from tests.test_authz_matrix_plugins import pclient, plugin_app  # noqa: F401 - fixtures are used by name

pytestmark = pytest.mark.usefixtures("seeded")

LABEL = "q246-import-through-the-app"
ROWS = 2000
PREVIEW = "/network/ipam/subnet/kea/1/import/preview"
COMMIT = "/network/ipam/subnet/kea/1/import/commit"


def _csv(rows):
    lines = ["ip,status,label,owner,notes,hostname"]
    for i in range(rows):
        lines.append(
            f"10.98.{4 + i // 250}.{i % 250 + 1},static,{LABEL}-{i:04d},operations team,second rack from the door,host-{i:04d}.lab.example"
        )
    return ("\n".join(lines) + "\n").encode()


def _hidden_fields(page):
    """Every hidden field of the Confirm Import form, as a browser would post it back."""
    form = page[page.index("/import/commit") :]
    form = form[: form.index("</form>")]
    fields = {}
    for tag in re.findall(r"<input[^>]*type=\"hidden\"[^>]*>", form):
        name = re.search(r"name=\"([^\"]+)\"", tag).group(1)
        value = re.search(r"value=(\"[^\"]*\"|'[^']*')", tag).group(1)[1:-1]
        fields[name] = html.unescape(value)
    return fields


@pytest.fixture
def a_subnet_that_holds_the_file(monkeypatch, db):
    """Subnet 1 as a /20 (4,094 hosts) for this test, and nothing of the import left behind."""
    monkeypatch.setattr(
        extensions,
        "SUBNET_MAP",
        {1: {"name": "Alpha-A", "cidr": "10.98.0.0/20"}, 2: {"name": B_NAME, "cidr": "10.77.0.0/24"}},
    )

    def clean():
        with db.cursor() as cur:
            cur.execute("DELETE FROM ipam_static_entries WHERE label LIKE %s", (LABEL + "%",))
            cur.execute("DELETE FROM ipam_assignment_history WHERE label LIKE %s", (LABEL + "%",))
        db.commit()

    clean()
    yield
    clean()


class TestAnImportOfTheDocumentedSizeIsConfirmed:
    def test_two_thousand_rows_are_previewed_and_then_committed(self, pclient, db, a_subnet_that_holds_the_file):
        _caller(pclient, db, "superadmin")
        shown = pclient.post(
            PREVIEW,
            data={"import_format": "jen", "import_file": (io.BytesIO(_csv(ROWS)), "two-thousand.csv")},
            content_type="multipart/form-data",
        )
        assert shown.status_code == 200, shown.status_code
        page = shown.data.decode()
        assert f"Confirm Import ({ROWS})" in page, page[-600:]
        fields = _hidden_fields(page)
        # the case the audit named: the form that goes back is larger than the framework's form-memory limit
        assert len(urlencode(fields)) > 500_000, len(urlencode(fields))
        done = pclient.post(COMMIT, data=fields)
        assert done.status_code == 302, (done.status_code, len(urlencode(fields)))
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM ipam_static_entries WHERE label LIKE %s", (LABEL + "%",))
            assert cur.fetchone()["n"] == ROWS
        db.commit()
