"""
tests/test_author_config_changeset.py - v5.68.0-beta.15 (Q150): Author Kea Config is a change set.

It used to loop `for server in KEA_SERVERS` in its route, calling `apply_config` per server with no expected sha, no preflight of the
other targets, no rollback, and Jen's own `[subnets]`/`[subnets6]` written when ANY server succeeded; with "overwrite" ticked it
replaced whatever was on each host at commit time, whatever the preview had shown. It now goes through
`jen.services.kea_changeset.apply_change`: every candidate built first, every target preflighted before the first write, each commit
guarded with the sha the PREVIEW showed ("" = no file), earlier targets put back (a file Jen created is removed again) when a later one
fails, a rollback that fails an incident on the Servers page, and Jen's own subnet record written only when the whole change stood.

Driven against tests/_kea_host_fakes.py::FakeHelper made STATEFUL (apply/remove really change what read-config answers), so a "restore"
is observed as the state of the fake hosts, not as a call count.
"""

import ast
import pathlib

import pytest

from jen.services import kea_changeset as cs
from jen.services import kea_host
from tests._author_world import FORM, URL, A, B, World

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def world(monkeypatch):
    return World(monkeypatch)


def _flashed(client):
    with client.session_transaction() as sess:
        return [msg for _cat, msg in sess.get("_flashes", [])]


def _post(client, world, **extra):
    data = dict(FORM)
    data.update(extra)
    client.post(URL, data=data, follow_redirects=False)
    return _flashed(client)


class TestAnAuthoredChangeIsAllOrNothing:
    def test_success_creates_every_file_guarded_as_absent_and_records_subnets_once(self, logged_in_client, world):
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        assert world.has(1) and world.has(2)
        applies = world.calls("apply-config")
        assert [(p["expect_sha256"], p["allow_overwrite"]) for _s, p in applies] == [("", False), ("", False)], (
            "an absent target may only CREATE the file: the helper refuses if one appeared in the meantime"
        )
        assert len(world.subnet_writes) == 1 and world.subnet_writes[0][1]["name"] == "V6LAN"
        assert sum("written" in f for f in flashes) == 2

    def test_a_later_servers_failed_validation_writes_nothing_anywhere(self, logged_in_client, world):
        world.fail_test.add(2)
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        assert world.calls("apply-config") == [], "the preflight of EVERY target comes before the first write"
        assert not world.has(1) and not world.has(2) and world.subnet_writes == []
        assert any("bad interface on kea-b" in f for f in flashes) and any("nothing was changed" in f for f in flashes)

    def test_a_later_servers_failed_commit_restores_the_first_and_leaves_jens_subnets_alone(
        self, logged_in_client, world
    ):
        world.fail_apply.add(2)
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        assert not world.has(1), "kea-a had no file before: the one Jen wrote is removed again"
        assert [p["expect_sha256"] for _s, p in world.calls("remove-config")] == ["written-1-1"], (
            "removed only if it still is exactly the file Jen wrote"
        )
        assert world.subnet_writes == [], "Jen's [subnets6] is written only when the whole change stood"
        assert any("could not write on kea-b" in f for f in flashes) and any("reverted 1 server" in f for f in flashes)

    def test_a_server_changed_after_the_preview_is_a_conflict_the_first_is_restored_the_second_untouched(
        self, logged_in_client, world
    ):
        world.put(2, {"Dhcp6": {"mine": "hand-edited since the preview"}}, "sha-now")
        flashes = _post(logged_in_client, world, allow_overwrite="true", base_sha_1="", base_sha_2="sha-at-preview")
        assert not world.has(1), "A was created, then restored (removed) when B refused"
        assert world.fake.configs[(2, "dhcp6")] == {"Dhcp6": {"mine": "hand-edited since the preview"}}
        assert world.sha(2) == "sha-now", "B is exactly as the other editor left it"
        assert world.subnet_writes == []
        assert any("changed since you previewed it" in f for f in flashes)

    def test_a_rollback_that_fails_is_an_incident_on_the_servers_page_not_just_a_flash(
        self, logged_in_client, world, monkeypatch
    ):
        recorded = []
        monkeypatch.setattr(
            cs, "record_outcome", lambda result, service, summary: recorded.append((result, service, summary))
        )
        world.fail_apply.add(2)
        world.fail_remove.add(1)
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        ((result, service, _summary),) = recorded
        assert result.status == "rollback_failed" and result.needs_hands == ["kea-a"] and service == "dhcp6"
        assert world.has(1), "the file Jen wrote is still there, and the banner says so"
        assert world.subnet_writes == []
        assert any("ROLLBACK FAILED" in f for f in flashes)

    def test_the_incident_is_really_stored_for_the_servers_banner(self, logged_in_client, world):
        world.fail_apply.add(2)
        world.fail_remove.add(1)
        _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        attention = cs.attention()
        assert attention and attention["incidents"][-1]["status"] == "rollback_failed"
        assert attention["incidents"][-1]["needs_hands"] == ["kea-a"]
        cs.clear_attention()


class TestOverwriteMeansTheFileThatWasPreviewed:
    def test_an_existing_file_is_not_replaced_without_the_overwrite_flag(self, logged_in_client, world):
        world.put(1, {"Dhcp6": {"old": True}}, "sha-1")
        flashes = _post(logged_in_client, world, base_sha_1="sha-1", base_sha_2="")
        assert world.calls("apply-config") == [] and world.sha(1) == "sha-1" and not world.has(2)
        assert any("already exists" in f and "overwrite" in f for f in flashes)

    def test_overwrite_without_a_preview_of_that_file_is_refused(self, logged_in_client, world):
        world.put(1, {"Dhcp6": {"old": True}}, "sha-1")
        flashes = _post(logged_in_client, world, allow_overwrite="true")  # no base_sha_<id> in the form at all
        assert world.calls("apply-config") == [] and world.sha(1) == "sha-1"
        assert any("Preview & Validate first" in f for f in flashes)

    def test_overwrite_replaces_exactly_the_previewed_file(self, logged_in_client, world):
        world.put(1, {"Dhcp6": {"old": True}}, "sha-1")
        _post(logged_in_client, world, allow_overwrite="true", base_sha_1="sha-1", base_sha_2="")
        ((_s, first), (_s2, second)) = world.calls("apply-config")
        assert (first["expect_sha256"], first["allow_overwrite"]) == ("sha-1", True)
        assert (second["expect_sha256"], second["allow_overwrite"]) == ("", False)
        assert world.fake.configs[(1, "dhcp6")] != {"Dhcp6": {"old": True}} and world.has(2)

    def test_a_previewed_absence_that_is_no_longer_true_is_a_conflict_not_an_overwrite(self, logged_in_client, world):
        """The preview saw no file on B; one has appeared. Without overwrite that is the plain 'exists' refusal; with it, the preview's
        absent state no longer matches and the helper's own guard refuses at commit."""
        world.put(2, {"Dhcp6": {"appeared": True}}, "sha-appeared")
        flashes = _post(logged_in_client, world, allow_overwrite="true", base_sha_1="", base_sha_2="")
        assert world.fake.configs[(2, "dhcp6")] == {"Dhcp6": {"appeared": True}} and not world.has(1)
        assert any("Preview & Validate first" in f or "changed since you previewed" in f for f in flashes)

    def test_a_host_that_cannot_be_read_is_not_an_absent_host(self, logged_in_client, world, monkeypatch):
        def unreachable(server, op, payload=None, timeout=60):
            if server["id"] == 2 and op == "read-config":  # the build check before it (op "version") still answers
                raise kea_host.HelperUnreachable("SSH to kea@10.0.0.2 failed - timed out")
            return world.fake.helper_call(server, op, payload, timeout)

        monkeypatch.setattr(kea_host, "helper_call", unreachable)
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        assert world.calls("apply-config") == [] and not world.has(1)
        assert any("could not read its config" in f and "timed out" in f for f in flashes)


class TestThePreviewCarriesTheFileItShowed:
    def _preview(self, client):
        return client.post(URL + "/preview", data=FORM).get_json()

    def test_absent_is_an_empty_sha_and_present_is_its_sha(self, logged_in_client, world):
        world.put(2, {"Dhcp6": {"old": True}}, "sha-b")
        data = self._preview(logged_in_client)
        rows = {r["id"]: r for r in data["servers"]}
        assert (rows[1]["exists"], rows[1]["base_sha"]) == (False, "")
        assert (rows[2]["exists"], rows[2]["base_sha"]) == (True, "sha-b")
        assert "already exists" in rows[2]["message"] and "no config file here yet" in rows[1]["message"]

    def test_a_host_whose_state_cannot_be_read_carries_no_base_sha(self, logged_in_client, world, monkeypatch):
        def broken(server, op, payload=None, timeout=60):
            if op == "read-config" and server["id"] == 1:
                raise kea_host.HelperError("garbage")
            return world.fake.helper_call(server, op, payload, timeout)

        monkeypatch.setattr(kea_host, "helper_call", broken)
        row = {r["id"]: r for r in self._preview(logged_in_client)["servers"]}[1]
        assert row["base_sha"] is None and row["exists"] is None and row["ok"] is True


class TestAbsentIsAnExpectedStateOfTheChangeSet:
    """The primitive itself, below the route."""

    def test_without_the_flag_a_missing_config_is_still_a_failure(self, world):
        result = cs.apply_change("dhcp6", lambda cfg: (cfg, "ok"), "x", servers=[A])
        assert result.status == "aborted" and result.last_code == "notfound-conf"

    def test_with_the_flag_it_is_a_target_expected_sha_empty_overwrite_off(self, world):
        result = cs.apply_change(
            "dhcp6",
            None,
            "x",
            servers=[A],
            restart=False,
            candidate_for=lambda server, cfg: ({"Dhcp6": {"new": 1}}, "ok"),
            absent_is_expected=True,
        )
        assert result.status == "ok" and world.has(1)
        (payload,) = [p for _s, p in world.calls("apply-config")]
        assert payload["expect_sha256"] == "" and payload["allow_overwrite"] is False

    def test_each_target_gets_its_own_candidate_and_its_own_tls_paths(self, world):
        by_id = {1: {"Dhcp6": {"for": "a"}}, 2: {"Dhcp6": {"for": "b"}}}
        tls = {1: [("/etc/kea/a.pem", "file")], 2: [("/etc/kea/b.pem", "file")]}
        cs.apply_change(
            "dhcp6",
            None,
            "x",
            servers=[A, B],
            restart=False,
            candidate_for=lambda server, cfg: (by_id[server["id"]], "ok"),
            absent_is_expected=True,
            tls_paths_for=lambda server: tls[server["id"]],
        )
        assert world.fake.configs[(1, "dhcp6")] == by_id[1] and world.fake.configs[(2, "dhcp6")] == by_id[2]
        for sid, payload in world.calls("test-config") + world.calls("apply-config"):
            assert payload["tls_paths"] == [[tls[sid][0][0], "file"]] or payload["tls_paths"] == [list(tls[sid][0])]

    def test_a_target_that_existed_is_rolled_back_by_re_applying_what_it_had_not_by_removing_it(self, world):
        world.put(1, {"Dhcp6": {"original": True}}, "orig-sha")
        world.fail_apply.add(2)
        result = cs.apply_change(
            "dhcp6",
            None,
            "x",
            servers=[A, B],
            restart=False,
            candidate_for=lambda server, cfg: ({"Dhcp6": {"new": server["id"]}}, "ok"),
            absent_is_expected=True,
            expected_sha_for=lambda server: "orig-sha" if server["id"] == 1 else "",
        )
        assert result.status == "aborted"
        assert world.fake.configs[(1, "dhcp6")] == {"Dhcp6": {"original": True}}
        assert world.calls("remove-config") == [], "the file was there before: it is put back, never deleted"


class TestNoRouteLoopsApplyConfig:
    """The source guard for the per-route read/mutate/apply loop (Q150): no route may call `apply_config` inside a `for`/`while`, and
    the authoring route no longer has its own `_run_author_script`."""

    def test_no_apply_config_call_in_a_loop_in_any_route(self):
        offenders = []
        for path in sorted((ROOT / "jen" / "routes").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            parents = {}
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    parents[child] = node
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "apply_config"
                ):
                    ancestor = node
                    while ancestor in parents:
                        ancestor = parents[ancestor]
                        if isinstance(ancestor, (ast.For, ast.While, ast.ListComp, ast.GeneratorExp)):
                            offenders.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
                            break
        assert not offenders, f"a route applies a config server by server instead of through kea_changeset: {offenders}"

    def test_the_authoring_route_goes_through_the_change_set(self):
        text = (ROOT / "jen" / "routes" / "settings" / "authoring.py").read_text(encoding="utf-8")
        assert "_run_author_script" not in text and "__changeset.apply_change(" in text
        assert "__host.apply_config(" not in text


class TestRemoveConfig:
    """`kea_host.remove_config`: the rollback of an authored target that had no file. Never raises; says WHY it could not."""

    def _call(self, world, sha="written-1-1", server=A):
        return kea_host.remove_config(server, "dhcp6", sha)

    def test_removes_the_file_only_if_it_still_is_the_one_jen_wrote(self, world):
        world.put(1, {"Dhcp6": {}}, "written-1-1")
        assert self._call(world)["ok"] is True and not world.has(1)
        world.put(1, {"Dhcp6": {"someone": "else"}}, "someone-elses-sha")
        res = self._call(world)
        assert res["ok"] is False and res["code"] == "conflict" and world.has(1), (
            "a file somebody replaced is left alone"
        )

    def test_a_sha_that_cannot_be_checked_is_not_a_license_to_delete(self, world):
        world.put(1, {"Dhcp6": {}}, "written-1-1")
        for sha in ("", None, "canonical:abc"):
            res = self._call(world, sha=sha)
            assert res["ok"] is False and "cannot be checked" in res["detail"]
        assert world.calls("remove-config") == [] and world.has(1)

    def test_a_host_without_the_helper_or_with_an_older_one_says_what_to_do_by_hand(self, world, monkeypatch):
        world.fake.missing_for.add(1)
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda server: None)
        assert "delete that file by hand" in self._call(world)["detail"]
        world.fake.missing_for.clear()
        world.fake.responses["remove-config"] = {"ok": False, "error": "unknown-op"}
        res = self._call(world)
        assert res["ok"] is False and "too old" in res["detail"] and "Update helper" in res["detail"]


class TestEveryTargetNeedsACurrentHelperBeforeAnythingHappens:
    """v5.68.0-beta.16 (Q151, item 4). A helper-less target used to be written through the legacy script (which cannot roll back) and then could not
    be undone when a later server failed: A written, B failing, `rollback_failed`, A keeps the file. Author Kea Config now refuses before the first
    preflight unless EVERY target has a helper at build 13 or later (the one with `remove-config`), and runs `helper_only` (never the legacy script)."""

    def test_a_helper_less_target_and_a_current_one_refuses_before_any_call_that_changes_anything(
        self, logged_in_client, world
    ):
        world.fake.missing_for.add(1)
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        assert [op for (_sid, op, _p) in world.fake.calls if op in ("test-config", "apply-config", "read-config")] == []
        assert not world.has(1) and not world.has(2) and world.subnet_writes == []
        assert any("Update helper on kea-a" in f and "build 13" in f for f in flashes)

    def test_a_helper_too_old_for_remove_config_is_refused(self, logged_in_client, world):
        world.fake.builds[2] = 12
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        assert world.calls("apply-config") == [] and not world.has(1) and not world.has(2)
        assert any("Update helper on kea-b" in f for f in flashes)

    def test_a_helper_that_reports_no_build_at_all_is_refused(self, logged_in_client, world):
        world.fake.builds.clear()
        world.fake.helper_build = None  # a pre-v7 helper answers `version` with no build
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        assert world.calls("apply-config") == [] and any("Update helper on kea-a, kea-b" in f for f in flashes)

    def test_mixed_builds_name_only_the_hosts_that_need_it(self, logged_in_client, world):
        world.fake.builds[1] = 13
        world.fake.builds[2] = 11
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        assert any("Update helper on kea-b" in f for f in flashes)
        assert not any("kea-a" in f and "Update helper" in f for f in flashes)

    def test_an_unreachable_host_is_not_a_helper_less_one(self, logged_in_client, world, monkeypatch):
        def unreachable(server, op, payload=None, timeout=60):
            if server["id"] == 2:
                raise kea_host.HelperUnreachable("SSH to kea@10.0.0.2 failed - timed out")
            return world.fake.helper_call(server, op, payload, timeout)

        monkeypatch.setattr(kea_host, "helper_call", unreachable)
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        assert world.calls("apply-config") == [] and any("Could not reach kea-b" in f for f in flashes)
        assert not any("Update helper on kea-b" in f for f in flashes)

    def test_helper_only_never_reaches_the_legacy_engine(self, world, monkeypatch):
        world.fake.missing_for.add(1)
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda server: None)

        def boom(*a, **k):
            raise AssertionError("the legacy sudo-python3 engine was used")

        monkeypatch.setattr(kea_host, "_legacy_python3", boom)
        for call in (
            lambda: kea_host.test_config(A, "dhcp6", {"Dhcp6": {}}, helper_only=True),
            lambda: kea_host.apply_config(A, "dhcp6", {"Dhcp6": {}}, helper_only=True),
        ):
            res = call()
            assert res["ok"] is False and res["detail"] == kea_host.HELPER_REQUIRED


class TestJensOwnRecordIsPartOfTheTransaction:
    """Item 3. Everything Jen does locally because of the change runs in `finalize`, after every target committed; if it raises, every server goes
    back and the operation is `rolled_back`, never ok. Names are validated before any of it starts."""

    def test_a_kea_valid_jen_invalid_name_is_refused_before_any_server_is_touched(self, logged_in_client, world):
        flashes = _post(logged_in_client, world, subnets="1 = V6[LAN], 2001:db8::/64", base_sha_1="", base_sha_2="")
        assert world.calls("apply-config") == [] and world.calls("test-config") == []
        assert not world.has(1) and not world.has(2) and world.subnet_writes == []
        assert any("Name must not contain" in f for f in flashes)

    def test_the_preview_refuses_it_too(self, logged_in_client, world):
        r = logged_in_client.post(URL + "/preview", data=dict(FORM, subnets="1 = V6[LAN], 2001:db8::/64"))
        assert r.status_code == 400 and "Name must not contain" in r.get_json()["error"]

    def test_an_oserror_while_recording_the_subnets_rolls_every_server_back_and_leaves_jens_map_alone(
        self, logged_in_client, world, monkeypatch
    ):
        def disk_full(subnets):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr("jen.config.write_subnets6_config", disk_full)
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        assert not world.has(1) and not world.has(2), "both servers are back to having no file"
        assert world.subnet_writes == []
        assert any("could not record this change" in f for f in flashes) and not any(
            "written. Enable" in f for f in flashes
        )
        cs.clear_attention()

    def test_a_server_that_cannot_be_restored_after_a_failed_finalize_is_an_incident(
        self, logged_in_client, world, monkeypatch
    ):
        def disk_full(subnets):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr("jen.config.write_subnets6_config", disk_full)
        world.fail_remove.add(1)
        flashes = _post(logged_in_client, world, base_sha_1="", base_sha_2="")
        attention = cs.attention()
        assert attention and attention["incidents"][-1]["status"] == "rollback_failed"
        assert attention["incidents"][-1]["needs_hands"] == ["kea-a"]
        assert world.has(1) and not world.has(2) and any("ROLLBACK FAILED" in f for f in flashes)
        cs.clear_attention()


class TestFinalizeInTheChangeSetItself:
    def _author(self, finalize, **kw):
        return cs.apply_change(
            "dhcp6",
            None,
            "x",
            servers=[A, B],
            restart=False,
            candidate_for=lambda server, cfg: ({"Dhcp6": {"for": server["id"]}}, "ok"),
            absent_is_expected=True,
            finalize=finalize,
            **kw,
        )

    def test_finalize_runs_once_after_every_target_committed(self, world):
        seen = []
        result = self._author(lambda r: seen.append((world.has(1), world.has(2), r.status, sorted(r.covered))))
        assert result.status == "ok" and seen == [(True, True, "ok", ["kea-a", "kea-b"])]

    def test_it_does_not_run_when_a_target_failed(self, world):
        world.fail_apply.add(2)
        seen = []
        result = self._author(lambda r: seen.append(1))
        assert result.status == "aborted" and seen == []

    def test_a_raising_finalize_restores_every_target_and_reports_rolled_back(self, world):
        def boom(result):
            raise ValueError("a subnet name the validator refuses")

        result = self._author(boom)
        assert result.status == "rolled_back" and result.last_code == "finalize-failed"
        assert not world.has(1) and not world.has(2)
        assert not any("subnet name the validator" in text for _kind, text in result.lines), (
            "the exception's own text is logged, never shown"
        )

    def test_a_restore_that_fails_after_a_raising_finalize_is_rollback_failed(self, world):
        world.fail_remove.add(2)

        def boom(result):
            raise OSError("disk")

        result = self._author(boom)
        assert (
            result.status == "rollback_failed" and result.needs_hands == ["kea-b"] and world.has(2) and not world.has(1)
        )

    def test_a_target_that_existed_is_restored_by_re_applying_what_it_had(self, world):
        world.put(1, {"Dhcp6": {"original": True}}, "orig")

        def boom(result):
            raise RuntimeError("x")

        result = cs.apply_change(
            "dhcp6",
            None,
            "x",
            servers=[A],
            restart=False,
            candidate_for=lambda server, cfg: ({"Dhcp6": {"new": True}}, "ok"),
            absent_is_expected=True,
            expected_sha_for=lambda server: "orig",
            finalize=boom,
        )
        assert result.status == "rolled_back" and world.fake.configs[(1, "dhcp6")] == {"Dhcp6": {"original": True}}
