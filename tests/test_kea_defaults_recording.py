"""
tests/test_kea_defaults_recording.py
────────────────────────────────────
Q218 D1 and D4 - the pure part of compat row 12 (`tests/kea_compat/test_config_write.py`): what is recorded from the daemon's answers. A scalar the daemon writes out is recorded WITH its value and kept only
when every recording agreed; a populated list two recordings disagree on is dropped, never last-writer-wins. The row itself needs a real daemon; this runs under `--noconftest`.
"""

import tests.kea_compat.test_config_write as row


class TestWhatIsRecorded:
    def test_a_scalar_the_daemon_added_is_recorded_with_its_value(self):
        observed = {}
        row._added_by_the_daemon({"a": 1}, {"a": 1, "t1-percent": 0.5, "sub": {"x": True}}, "", {}, observed)
        assert observed == {"t1-percent": [0.5], "sub.x": [True]}

    def test_a_scalar_inside_a_list_is_not_recorded(self):
        observed = {}
        row._all_paths({"ids": ["hw-address", "duid"], "k": 3}, "top", {}, observed)
        assert observed == {"top.k": [3]}

    def test_the_value_kept_is_the_one_every_recording_saw(self):
        scalars, contextual = row._agreed_scalars(
            {"t1-percent": [0.5, 0.5, 0.5], "subnet4[].valid-lifetime": [7200, 3600], "echo-client-id": [True]}
        )
        assert scalars == {"echo-client-id": True, "t1-percent": 0.5}
        assert contextual == ["subnet4[].valid-lifetime"]
        assert row._agreed_scalars({"a": [1, True]})[0] == {}  # a boolean and a number are different values

    def test_a_populated_path_that_two_recordings_disagree_on_is_dropped(self):
        populated = {}
        row._all_paths({"loggers": [{"name": "kea-dhcp4"}]}, "", populated)
        row._all_paths({"loggers": [{"name": "kea-dhcp4"}]}, "", populated)  # the same list again: kept
        assert row._agreed_populated(populated) == {".loggers": [{"name": "kea-dhcp4"}]}
        row._all_paths({"loggers": [{"name": "other"}]}, "", populated)
        assert row._agreed_populated(populated) == {}
