"""
tests/test_ci_updater_hop.py
─────────────────────────────
v5.67.0-beta.10 (Q122, Part 1) — tools/ci_updater_hop.py, the harness the
upgrade-from-stable job uses to drive a release's own root updater through a
real hop. The hop itself runs in CI (it needs root, a systemd and a real Jen);
this proves the harness's own pieces, and — more usefully — that every seam it
stands in for exists on THIS tree's updater, so the stand-ins cannot quietly
stop standing in for anything.
"""

import gzip
import hashlib
import importlib.util
import io
import pathlib
import tarfile

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def hop():
    return _load(REPO / "tools" / "ci_updater_hop.py", "ci_updater_hop")


@pytest.fixture()
def updater():
    return _load(REPO / "jen-update-root.py", "jen_updater_head")


def _tarball(files: dict[str, str]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return out.getvalue()


class TestTheSeamsExistOnTheRealUpdater:
    def test_every_stand_in_and_required_name_is_on_this_trees_updater(self, hop, updater):
        missing = [n for n in hop.REQUIRED if not hasattr(updater, n)]
        assert missing == []

    def test_the_stand_ins_are_exactly_the_four_network_facing_seams(self, hop):
        assert set(hop.STAND_INS) == {"fetch_json", "fetch_text", "verify_release_signature", "fetch_bytes_with_sha256"}

    def test_a_module_without_a_seam_is_refused_loudly(self, hop, tmp_path):
        fake = tmp_path / "not-an-updater.py"
        fake.write_text("def main():\n    return 0\n", encoding="utf-8")
        with pytest.raises(SystemExit) as e:
            hop.load_updater(str(fake))
        assert "fetch_json" in str(e.value)


class TestTheStandInsFeedTheRealMain:
    def test_the_release_list_is_what_main_reads(self, hop, updater):
        """pick_release, the asset checks and the checksum verification are the updater's OWN functions."""
        tarball = _tarball({"jen/jen/__init__.py": 'JEN_VERSION = "9.9.9"\n'})
        sha = hop.install_stand_ins(updater, tarball, "9.9.9", prerelease=False)
        assert sha == hashlib.sha256(tarball).hexdigest()

        releases = updater.fetch_json("https://api.github.com/repos/x/y/releases")
        picked = updater.pick_release(releases, "stable")
        assert picked["tag_name"] == "v9.9.9"
        urls = {a["name"]: a["browser_download_url"] for a in picked["assets"]}
        assert all(u.startswith(updater.GITHUB_ASSET_PREFIX) for u in urls.values())

        name = "jen-v9.9.9.tar.gz"
        checksum_text = updater.fetch_text(urls["SHA256SUMS"])
        assert updater.verify_release_checksum(name, sha, checksum_text) is True
        assert updater.verify_release_checksum(name, "0" * 64, checksum_text) is False, "a wrong hash must still fail"
        assert updater.verify_release_signature("x", b"y", "z") is True, "the signature step is the named stand-in"
        body, got = updater.fetch_bytes_with_sha256(urls[name])
        assert body == tarball and got == sha

    def test_a_prerelease_is_only_offered_on_the_beta_channel(self, hop, updater):
        tarball = _tarball({"jen/jen/__init__.py": 'JEN_VERSION = "9.9.9-beta.1"\n'})
        hop.install_stand_ins(updater, tarball, "9.9.9-beta.1", prerelease=True)
        releases = updater.fetch_json("")
        assert updater.pick_release(releases, "stable") is None
        assert updater.pick_release(releases, "beta")["tag_name"] == "v9.9.9-beta.1"


class TestBump:
    def test_only_the_version_line_changes(self, hop):
        src = _tarball(
            {
                "jen/jen/__init__.py": '"""doc"""\nJEN_VERSION = "5.67.0-beta.10"\nOTHER = "5.67.0-beta.10"\n',
                "jen/install.sh": 'JEN_VERSION="5.67.0-beta.10"\n',
            }
        )
        out = hop.bump_tarball(src, "5.67.1")
        with tarfile.open(fileobj=io.BytesIO(out), mode="r:gz") as tf:
            init = tf.extractfile("jen/jen/__init__.py").read().decode()
            sh = tf.extractfile("jen/install.sh").read().decode()
            size = tf.getmember("jen/jen/__init__.py").size
        assert 'JEN_VERSION = "5.67.1"' in init
        assert 'OTHER = "5.67.0-beta.10"' in init, "only the version line moves"
        assert sh == 'JEN_VERSION="5.67.0-beta.10"\n', "the installer's own copy is left alone"
        assert size == len(init.encode()), "the member's recorded size follows its new content"

    def test_a_tarball_with_no_version_line_is_refused(self, hop):
        with pytest.raises(SystemExit):
            hop.bump_tarball(_tarball({"jen/jen/__init__.py": "x = 1\n"}), "5.67.1")

    def test_the_output_is_a_valid_gzip_tarball(self, hop):
        out = hop.bump_tarball(_tarball({"jen/jen/__init__.py": 'JEN_VERSION = "1.0.0"\n'}), "1.0.1")
        assert gzip.decompress(out)[:1] is not None
        with tarfile.open(fileobj=io.BytesIO(out), mode="r:gz") as tf:
            assert tf.getnames() == ["jen/jen/__init__.py"]

    def test_this_trees_real_init_has_a_line_the_bump_can_change(self, hop):
        text = (REPO / "jen" / "__init__.py").read_text(encoding="utf-8")
        out = hop.bump_tarball(_tarball({"jen/jen/__init__.py": text}), "9.9.9")
        with tarfile.open(fileobj=io.BytesIO(out), mode="r:gz") as tf:
            assert 'JEN_VERSION = "9.9.9"' in tf.extractfile("jen/jen/__init__.py").read().decode()
