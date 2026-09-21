#!/usr/bin/env python3
"""
tools/replace_emoji_icons.py — the one-shot emoji -> icon swap for v5.50.0 (Q57),
kept in the repo for the record. Stdlib only.

    py tools/replace_emoji_icons.py --dry-run     # report what it would do
    py tools/replace_emoji_icons.py               # rewrite templates/*.html in place

Reads tools/icon_map.json. For every emoji in a template it decides by CONTEXT:

* plain text            -> {{ icon("name") }}   (h1 lead icons get class ico-lg;
                           an icon that is the only content of a button/link also
                           gets title + aria-label)
* attribute values, <option>, <title>, <textarea>, {# comments #}
                        -> the glyph is removed (they cannot hold an SVG)
* a Jinja string literal-> icon("name") [~ " rest"]   (the macro returns Markup)
* <script> blocks       -> removed from textContent-style lines, or replaced by an
                           inline <svg><use> string on HTML-building lines

Anything it cannot place safely is reported (and left in place) for hand-fixing.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
MAP = json.loads((ROOT / "tools" / "icon_map.json").read_text(encoding="utf-8"))

# Unicode Extended_Pictographic (the ranges the scanner in tests/test_icons.py uses).
PICT = [
    (0x00A9, 0x00A9), (0x00AE, 0x00AE), (0x203C, 0x203C), (0x2049, 0x2049), (0x2122, 0x2122), (0x2139, 0x2139),
    (0x2194, 0x2199), (0x21A9, 0x21AA), (0x231A, 0x231B), (0x2328, 0x2328), (0x2388, 0x2388), (0x23CF, 0x23CF),
    (0x23E9, 0x23F3), (0x23F8, 0x23FA), (0x24C2, 0x24C2), (0x25AA, 0x25AB), (0x25B6, 0x25B6), (0x25C0, 0x25C0),
    (0x25FB, 0x25FE), (0x2600, 0x2605), (0x2607, 0x2612), (0x2614, 0x2685), (0x2690, 0x2705), (0x2708, 0x2712),
    (0x2714, 0x2714), (0x2716, 0x2716), (0x271D, 0x271D), (0x2721, 0x2721), (0x2728, 0x2728), (0x2733, 0x2734),
    (0x2744, 0x2744), (0x2747, 0x2747), (0x274C, 0x274C), (0x274E, 0x274E), (0x2753, 0x2755), (0x2757, 0x2757),
    (0x2763, 0x2767), (0x2795, 0x2797), (0x27A1, 0x27A1), (0x27B0, 0x27B0), (0x27BF, 0x27BF), (0x2934, 0x2935),
    (0x2B05, 0x2B07), (0x2B1B, 0x2B1C), (0x2B50, 0x2B50), (0x2B55, 0x2B55), (0x3030, 0x3030), (0x303D, 0x303D),
    (0x3297, 0x3297), (0x3299, 0x3299), (0x1F000, 0x1F0FF), (0x1F10D, 0x1F10F), (0x1F12F, 0x1F12F),
    (0x1F16C, 0x1F171), (0x1F17E, 0x1F17F), (0x1F18E, 0x1F18E), (0x1F191, 0x1F19A), (0x1F1AD, 0x1F1E5),
    (0x1F201, 0x1F20F), (0x1F21A, 0x1F21A), (0x1F22F, 0x1F22F), (0x1F232, 0x1F23A), (0x1F23C, 0x1F23F),
    (0x1F249, 0x1F3FA), (0x1F400, 0x1F53D), (0x1F546, 0x1F64F), (0x1F680, 0x1F6FF), (0x1F774, 0x1F77F),
    (0x1F7D5, 0x1F7FF), (0x1F80C, 0x1F80F), (0x1F848, 0x1F84F), (0x1F85A, 0x1F85F), (0x1F888, 0x1F88F),
    (0x1F8AE, 0x1F8FF), (0x1F90C, 0x1F93A), (0x1F93C, 0x1F945), (0x1F947, 0x1FAFF), (0x1FC00, 0x1FFFD),
]  # fmt: skip
VS16, ZWJ = "️", "‍"


def is_pict(ch: str) -> bool:
    cp = ord(ch)
    return any(a <= cp <= b for a, b in PICT)


def cluster_at(text: str, i: int):
    """(end, key) for the emoji cluster starting at i, or None. key = the base glyph without VS16."""
    if i >= len(text) or not is_pict(text[i]):
        return None
    j = i + 1
    while j < len(text) and (text[j] in (VS16, ZWJ) or is_pict(text[j]) and text[j - 1] == ZWJ):
        j += 1
    return j, text[i]


def pick_name(key: str, before: str, after: str, path: str) -> str | None:
    for rule in MAP["rules"]:
        if rule["emoji"] != key:
            continue
        if "file" in rule and not re.search(rule["file"], path):
            continue
        if "after" in rule and not re.search(rule["after"], after):
            continue
        if "before" in rule and not re.search(rule["before"], before):
            continue
        return rule["name"]
    return MAP["default"].get(key)


def _strip_glyph(s: str) -> str:
    """Remove every emoji cluster from `s` plus ONE adjacent space."""
    out, i = [], 0
    while i < len(s):
        c = cluster_at(s, i)
        if c:
            end, _key = c
            if end < len(s) and s[end] == " ":
                end += 1
            elif out and out[-1] == " " and (end >= len(s) or s[end] in "\"'<"):
                out.pop()
            i = end
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def icon_call(name: str, key: str, quote: str = '"', cls: str = "", label: str | None = None) -> str:
    extra = MAP["classes"].get(key, "")
    klass = f"{cls} {extra}".strip()
    args = f"{quote}{name}{quote}"
    if klass or label:
        args += f", {quote}{klass}{quote}"
    if label:
        args += f", {quote}{label}{quote}"
    return f"icon({args})"


def svg_string(name: str, key: str) -> str:
    extra = MAP["classes"].get(key, "")
    klass = f"ico {extra}".strip()
    return f'<svg class="{klass}" aria-hidden="true"><use href="#i-{name}"></use></svg>'


# ── Jinja blocks ────────────────────────────────────────────────────────────
_LIT = re.compile(r"""'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)\"""")


def process_jinja(block: str, attr: bool, path: str, report: list) -> str:
    if not any(is_pict(c) for c in block):
        return block

    def sub(m):
        body = m.group(1) if m.group(1) is not None else m.group(2)
        q = "'" if m.group(1) is not None else '"'
        if not any(is_pict(c) for c in body):
            return m.group(0)
        if attr:
            return f"{q}{_strip_glyph(body)}{q}"
        c = cluster_at(body, 0)
        if not c:
            report.append(f"{path}: emoji not at the start of a Jinja literal: {body[:50]!r}")
            return m.group(0)
        end, key = c
        name = pick_name(key, "", body[end:], path)
        if not name:
            report.append(f"{path}: UNMAPPED {key!r} (U+{ord(key):04X}) in a Jinja literal")
            return m.group(0)
        call = icon_call(name, key, quote=q)
        rest = body[end:]
        if any(is_pict(ch) for ch in rest):
            report.append(f"{path}: second emoji in a Jinja literal: {body[:50]!r}")
        return call if not rest else f"({call} ~ {q}{rest}{q})"

    return _LIT.sub(sub, block)


# ── <script> blocks ─────────────────────────────────────────────────────────
_TEXT_ONLY = re.compile(r"textContent|innerText|\.value\s*=|placeholder|alert\(|confirm\(|\.title\s*=|console\.")


def process_js(js: str, path: str, report: list) -> str:
    out = []
    for line in js.split("\n"):
        if not any(is_pict(c) for c in line):
            out.append(line)
            continue
        if _TEXT_ONLY.search(line):
            out.append(_strip_glyph(line))
            continue
        # HTML-building line: swap each glyph for an inline <svg><use>
        res, i = [], 0
        while i < len(line):
            c = cluster_at(line, i)
            if c:
                end, key = c
                name = pick_name(key, line[:i], line[end:], path)
                if not name:
                    report.append(f"{path}: UNMAPPED {key!r} in script: {line.strip()[:60]!r}")
                    res.append(line[i:end])
                else:
                    res.append(svg_string(name, key))
                i = end
            else:
                res.append(line[i])
                i += 1
        report.append(f"{path}: script line rewritten to inline SVG — check it builds HTML: {line.strip()[:70]!r}")
        out.append("".join(res))
    return "\n".join(out)


# ── tags & text ─────────────────────────────────────────────────────────────
VOID = {"br", "hr", "img", "input", "meta", "link", "source", "area", "base", "col", "embed", "wbr"}


def find_tag_end(text: str, i: int) -> int:
    q = None
    j = i + 1
    n = len(text)
    while j < n:
        if text.startswith("{{", j) or text.startswith("{%", j):
            close = "}}" if text.startswith("{{", j) else "%}"
            k = text.find(close, j + 2)
            j = (k + 2) if k != -1 else n
            continue
        c = text[j]
        if q:
            if c == q:
                q = None
        elif c in "\"'":
            q = c
        elif c == ">":
            return j
        j += 1
    return n - 1


def process_tag(tag: str, path: str, report: list) -> str:
    """Attribute context: strip glyphs; Jinja blocks inside are processed as attr."""
    out, i = [], 0
    while i < len(tag):
        if tag.startswith("{{", i) or tag.startswith("{%", i):
            close = "}}" if tag.startswith("{{", i) else "%}"
            k = tag.find(close, i + 2)
            k = len(tag) if k == -1 else k + 2
            out.append(process_jinja(tag[i:k], True, path, report))
            i = k
        else:
            j = i
            while j < len(tag) and not (tag.startswith("{{", j) or tag.startswith("{%", j)):
                j += 1
            out.append(_strip_glyph(tag[i:j]))
            i = j
    return "".join(out)


def transform(text: str, path: str, report: list) -> str:
    out: list[str] = []
    stack: list[str] = []
    last_open = None  # index in `out` of the most recent open tag
    i, n = 0, len(text)
    while i < n:
        if text.startswith("{#", i):
            j = text.find("#}", i)
            j = n if j == -1 else j + 2
            out.append(_strip_glyph(text[i:j]))
            i = j
        elif text.startswith("{{", i) or text.startswith("{%", i):
            close = "}}" if text.startswith("{{", i) else "%}"
            j = text.find(close, i + 2)
            j = n if j == -1 else j + 2
            out.append(process_jinja(text[i:j], False, path, report))
            i = j
        elif text.startswith("<script", i):
            j = text.find("</script>", i)
            j = n if j == -1 else j
            head_end = text.find(">", i) + 1
            out.append(text[i:head_end])
            out.append(process_js(text[head_end:j], path, report))
            i = j
        elif text.startswith("<style", i):
            j = text.find("</style>", i)
            j = n if j == -1 else j
            out.append(text[i:j])
            i = j
        elif text[i] == "<" and i + 1 < n and (text[i + 1].isalpha() or text[i + 1] in "/!"):
            j = find_tag_end(text, i)
            raw = text[i : j + 1]
            new = process_tag(raw, path, report)
            m = re.match(r"</?\s*([a-zA-Z0-9-]+)", raw)
            name = m.group(1).lower() if m else ""
            if raw.startswith("</"):
                if name in stack:
                    while stack and stack.pop() != name:
                        pass
            elif not raw.startswith("<!") and name not in VOID and not raw.endswith("/>"):
                stack.append(name)
                last_open = len(out)
            out.append(new)
            i = j + 1
        else:
            k = i
            while k < n and not (
                text[k] == "<" or text.startswith("{{", k) or text.startswith("{%", k) or text.startswith("{#", k)
            ):
                k += 1
            if k == i:
                k = i + 1
            run = text[i:k]
            parent = stack[-1] if stack else ""
            if any(is_pict(c) for c in run):
                run = process_text(run, parent, path, report, out, last_open, text[k : k + 40])
            out.append(run)
            i = k
    return "".join(out)


def process_text(run: str, parent: str, path: str, report: list, out: list, last_open, following: str) -> str:
    if parent in ("option", "title", "textarea"):
        return _strip_glyph(run)
    stripped = run.strip()
    first = cluster_at(stripped, 0) if stripped else None
    only_glyph = bool(first) and first[0] == len(stripped)
    res, i = [], 0
    while i < len(run):
        c = cluster_at(run, i)
        if not c:
            res.append(run[i])
            i += 1
            continue
        end, key = c
        after = run[end:] + (following if end >= len(run) else "")
        before = "".join(res)[-60:]
        name = pick_name(key, before, after, path)
        if not name:
            report.append(f"{path}: UNMAPPED {key!r} (U+{ord(key):04X}) near {run.strip()[:50]!r}")
            res.append(run[i:end])
            i = end
            continue
        cls = "ico-lg" if parent in ("h1",) and not "".join(res).strip() else ""
        res.append("{{ " + icon_call(name, key, cls=cls) + " }}")
        if only_glyph and last_open is not None and parent in ("button", "a", "summary", "span", "div"):
            label = MAP["labels"].get(name)
            if label:
                tag = out[last_open]
                if parent in ("button", "a", "summary") and "aria-label" not in tag and "title=" not in tag:
                    out[last_open] = tag[:-1] + f' title="{label}" aria-label="{label}">'
            else:
                report.append(f"{path}: icon-only {parent} without a label ({name}) near {run.strip()[:20]!r}")
        i = end
        # keep the source's single space after the glyph
    return "".join(res)


def main(argv: list[str]) -> int:
    dry = "--dry-run" in argv
    report: list[str] = []
    changed = 0
    for p in sorted((ROOT / "templates").glob("*.html")):
        rel = f"templates/{p.name}"
        text = p.read_text(encoding="utf-8")
        crlf = "\r\n" in text
        new = transform(text.replace("\r\n", "\n"), rel, report)
        if new != text.replace("\r\n", "\n"):
            changed += 1
            if not dry:
                p.write_text(new.replace("\n", "\r\n") if crlf else new, encoding="utf-8", newline="")
    print(f"{'would change' if dry else 'changed'} {changed} template(s)")
    for line in report:
        print("  -", line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
