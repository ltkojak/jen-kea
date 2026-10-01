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
# v5.67.0-beta.4 (Q116) — GitHub's own repo social-preview setting, not
# embedded in the README: uploading it is a GitHub settings click only
# the maintainer can make (gh repo edit has no flag for it), so this
# file is intentionally referenced nowhere in markdown, same reasoning
# as the logo being exempt.
SOCIAL_PREVIEW = "social-preview.png"


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
        orphans = on_disk - referenced - {LOGO, SOCIAL_PREVIEW}
        assert not orphans, f"unreferenced file(s) under docs/images: {orphans}"

    def test_the_logo_itself_still_exists(self):
        assert (IMAGES_DIR / LOGO).is_file()

    def test_the_social_preview_image_exists_and_is_the_right_size(self):
        from PIL import Image

        p = IMAGES_DIR / SOCIAL_PREVIEW
        assert p.is_file(), f"{SOCIAL_PREVIEW} is missing — GitHub's social-preview upload needs it"
        assert p.stat().st_size <= MAX_BYTES
        with Image.open(p) as img:
            assert img.size == (1280, 640), f"GitHub's social preview must be 1280x640, got {img.size}"
