"""
tests/test_readme_images.py
─────────────────────────────
v5.54.0-era (Q62) — every image the README references is real, small, and a
PNG; every file under docs/images (except the logo) is referenced by the
README, so nothing lingers there unused. Since Q62, the README's screenshots
come only from tests/e2e/test_docs_screenshots.py's docs-screenshots artifact
(gh run download -n docs-screenshots -D docs/images), never from a real
install — a stray .jpg here would mean someone reached for a manual capture
again, so that's a hard failure too.

Pure, runs on Windows: `py -m pytest --noconftest tests/test_readme_images.py`.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMAGES_DIR = ROOT / "docs" / "images"
README = ROOT / "README.md"
MAX_BYTES = 500 * 1024
LOGO = "jen-logo.png"


def _referenced_images() -> set[str]:
    text = README.read_text(encoding="utf-8")
    md = re.findall(r"!\[[^\]]*\]\(docs/images/([^)\s]+)\)", text)
    html = re.findall(r'<img\s[^>]*src="docs/images/([^"]+)"', text)
    return set(md) | set(html)


class TestReadmeImagesExistAndAreSmall:
    def test_every_referenced_image_exists(self):
        missing = [name for name in _referenced_images() if not (IMAGES_DIR / name).is_file()]
        assert not missing, missing

    def test_every_referenced_image_is_under_the_size_limit(self):
        over = []
        for name in _referenced_images():
            p = IMAGES_DIR / name
            if p.is_file() and p.stat().st_size > MAX_BYTES:
                over.append((name, p.stat().st_size))
        assert not over, over

    def test_the_readme_references_at_least_the_eight_docs_screenshots(self):
        expected = {
            "dashboard.png",
            "leases.png",
            "reservations.png",
            "subnets.png",
            "reports.png",
            "phone-dashboard.png",
            "phone-leases.png",
            "phone-more.png",
        }
        assert expected <= _referenced_images()


class TestNoJpgsAndNoOrphans:
    def test_no_jpg_under_docs_images(self):
        jpgs = [p.name for p in IMAGES_DIR.glob("*") if p.suffix.lower() in (".jpg", ".jpeg")]
        assert not jpgs, f"a screenshot here should come only from the docs-screenshots CI artifact: {jpgs}"

    def test_every_file_except_the_logo_is_referenced(self):
        referenced = _referenced_images()
        on_disk = {p.name for p in IMAGES_DIR.iterdir() if p.is_file()}
        orphans = on_disk - referenced - {LOGO}
        assert not orphans, f"unreferenced file(s) under docs/images: {orphans}"

    def test_the_logo_itself_still_exists(self):
        assert (IMAGES_DIR / LOGO).is_file()
