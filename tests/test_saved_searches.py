"""
tests/test_saved_searches.py
─────────────────────────────
v5.39.0 (Q39) — the saved_searches table has no dedicated page test yet;
clean_tables already empties it every test, so the empty state is the
default case here.
"""


class TestSavedSearchesEmptyState:
    def test_teaches_instead_of_a_blank_table(self, logged_in_client, db):
        r = logged_in_client.get("/saved-searches")
        assert r.status_code == 200
        assert "No saved searches yet" in r.data.decode()

    def test_page_renders_with_a_saved_search(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO saved_searches (user_id, name, page, params) VALUES (%s, %s, %s, %s)",
                (1, "My filter", "leases", "search=10.0.0.1"),
            )
        db.commit()

        r = logged_in_client.get("/saved-searches")
        assert r.status_code == 200
        body = r.data.decode()
        assert "My filter" in body
        assert "No saved searches yet" not in body
