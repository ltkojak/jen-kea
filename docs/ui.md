# Jen's UI: tokens, phone patterns and how to make a page phone-ready

This is the developer's guide to the shared UI in `templates/base.html`. Pages
are Jinja templates; the styles and the small amount of script every page needs
live in `base.html` so a page rarely needs either of its own.

## Tokens

Layout tokens (spacing, type scale, radius, tap target) are hand-written once
in `base.html`. Use them instead of literal values in new CSS.

| Token | Value | Use |
|---|---|---|
| `--sp-1` … `--sp-6` | 4, 8, 12, 16, 24, 32 px | gaps, padding, margins |
| `--fs-xs` … `--fs-2xl` | 11, 12, 13, 15, 20, 26 px | font sizes (`--fs-md` is body text) |
| `--tap` | 44 px | minimum height of anything a thumb must hit |
| `--tabbar-h` | 56 px | the phone tab bar |
| `--font-ui`, `--font-mono` | system sans, mono stack | a preset can point `--font-ui` at `--font-mono` on desktop (Phosphor) |

**Color and radius tokens are generated, not hand-written** (v5.55.0, Q63) —
`jen/services/theme.py` is the single source. `--bg`, `--surface`, `--surface2`,
`--surface3`, `--border`, `--text`, `--text-muted`, `--primary`, `--success`,
`--warning`, `--danger` and `--radius`/`--radius-sm` exist for every theme
(the four built-in presets plus an install's own custom palette, if it has
one); never hard-code a color or radius that has to work across all of them.
A new built-in preset is one entry in `theme.py`'s `PRESETS` dict — nothing
in `base.html` changes.

A **tint** (a color at partial opacity over the page background — a badge, an
alert, a hover state) is `color-mix(in srgb, var(--token) N%, transparent)`,
not a separate hard-coded hex per theme. `tests/test_theme.py`'s "hex wall"
fails the build on a literal `#rrggbb`/`#rgb` in any template that extends
`base.html` (a short, reasoned allow-list covers the handful of legitimate
exceptions — the standalone auth pages, the categorical per-device-type
badge palette, and hex-format example text). Chart.js/Canvas code can't use
`var(--x)` directly; resolve it through `window.jenColor('var(--x)')`
(`base.html`) instead, and rebuild on the `jen:theme` event a switch fires.

**Which theme actually applies** (v5.55.3, Q66): a personal pick, stored in
`localStorage['jen-theme-pick']` and written only by an actual click in the
picker; else the install default (`theme_default`, Settings → Appearance →
Theme); else Dark. `applyTheme(id, persist)`'s `persist` argument is the
whole precedence guarantee — every call site outside the picker's own click
handler passes `false`, so loading a page (including the very first one) can
never itself write a pick. The pre-v5.55.3 key, `jen-theme`, was written on
every load with no such guard and is actively removed on the next load
rather than read.

### Utility classes

`.muted` `.small` `.xs` `.mono` `.flex` `.wrap` `.stack` `.grow` `.right`
`.center` `.nowrap` `.contents` `.items-center` `.between` `.ok` `.warn` `.bad`
`.gap-1` … `.gap-4` `.mt-2` `.mt-3` `.mt-4` `.mb-2` `.mb-3` `.mb-4`.

These replace the inline styles the templates repeated most. Before writing a
new `style="…"`, check whether a token or utility covers it; `tests/test_ui_ratchet.py`
fails the build if the count of inline styles in `templates/` goes up.

### Icons

`{{ icon("name") }}` (see the admin guide's Icons section). Never an emoji: a
scanner test refuses them.

## The phone (≤ 768 px)

Everything below is invisible above 768 px; the desktop layout is unchanged.

### Bottom tab bar and the More sheet

`<nav class="tabbar">` shows Dashboard, Leases, Reservations, Settings and
**More** (a viewer, who has no Settings, gets Devices in that slot). The active
item comes from the current endpoint; when the page is none of the four, More is
lit. **More** opens a bottom sheet listing every destination grouped like the
desktop nav (Management, Network, Settings, plugins), plus search, the theme
toggle, the account links and Logout.

Both are computed by `nav_context()` in `jen/routes/settings/nav.py`
(`tabbar`, `tabbar_more_active`, `sheet`) with the same role and subnet-scope
filtering as everything else there. To add a destination, add it to the tables in
that file; the strip, the sheet and the settings landing page all read them. The
top bar on a phone keeps the logo, the status dot and the avatar. The body gets
bottom padding so content never hides behind the bar; the bar honours
`env(safe-area-inset-bottom)`, and sheets use `85dvh` with a `vh` fallback.

### Sheets

One mechanism: `data-sheet-open="<id>"` opens the `.sheet` with that id,
`data-sheet-close`, the backdrop or Esc closes it. `window.jenSheet.open(id)` /
`.close()` do the same from script. No inline handlers — the CSP has none.

### Dense rows: `table.rowlist` and `data-m`

Keep the `<table>`; add `class="rowlist"` and tag the cells:

| `data-m` | On a phone |
|---|---|
| `primary` | line one, bold: the name |
| `badge` | line one, after the name: a vendor or status badge |
| `secondary` | line two, joined with " · " (IP · subnet · expiry) |
| `trailing` | right edge of line one: the kebab / action menu |
| `hide` | not shown on a phone |
| `full` | a single cell that spans the line (an empty-state row) |
| *(none)* | treated as `secondary` |

Tapping a row (anywhere that is not itself a control) opens the row's action menu — the same target as the kebab — or, when the row has no menu, its primary link; in Select mode it ticks the row. Pairs of `class="desk-only"` / `class="phone-only"` spans give a cell a full desktop value and a short phone value (Leases' expiry is a timestamp on a desktop and "in 3 d" on a phone, via the `relfmt` filter). `_sort_controls.html` renders the phone's Sort and Order selects for a list page's filter form.

A cell whose text is empty or exactly "—" is dropped, so a row never shows
"NOTES —". Rows are at least 56 px. The cell holding a `.row-checkbox` is
recognised automatically. The older `table.mobile-cards` / `data-label` pattern
is no longer used by any page (Q59 and Q60 converted them); the CSS remains for a plugin that still has it.
`window.jenUi.enhance(root)` re-runs the cell classification; it already runs at
load and after every htmx swap.

### Select mode

`.row-checkbox` and `#selectAll` are hidden on a phone. Any page that has a
`.row-checkbox` gets a **Select** button (in its filter bar, else its action bar);
tapping it sets `body.select-mode`, which shows the checkboxes and pins any
`*-bulk-bar` above the tab bar. Leaving Select mode clears the selection.

### Filter sheet: `.filter-bar`

A `.filter-bar` that contains a text search input (tag it `data-m="primary"`, or
name it `search`/`q`) collapses to that input plus a **Filters (n)** button, where
n counts the non-default values. Everything else opens in a bottom sheet with a
Done button; the form's own submit and Clear controls are the Apply and Clear.
Give every `<select>` an `aria-label` (or a `title`): the sheet shows it as the
control's label, which is what tells two dropdowns apart. A bar with no text input
is left alone.

### Action overflow: `.action-bar`

On a phone the first `.btn-primary` stays full width and the remaining buttons
fold into a **More actions** sheet, provided at least two would fold. Mark a
button `data-m="keep"` to keep it visible. A bar with no `.btn-primary`, and any
`*-bulk-bar`, is left alone.

### Chip rows

`.chip-row` (and the Settings `.card-toc`) is one horizontally scrolling line with
a fade at the right edge instead of a wrapping block.

### Accordion rows

A long list of small editors (the Settings → Alerts message templates) is a list of
`<details class="al-tpl">`: the summary is the name plus the first line, closed by default,
open shows the editor. Expand all and Collapse all sit above it. Keep the two forms
(Save, Reset) as siblings — a form inside a form is dropped by the browser.


## Making a new page phone-ready

1. Build it from the shared classes — `.card`, `.filter-bar`, `.action-bar`,
   `.btn`, `.table-wrap` — and the tokens and utilities. No new inline `style=`.
2. A list? `class="rowlist"` and a `data-m` on every cell (`primary` first).
3. A filter bar? A search input, a label on every select.
4. Give every icon-only control a `title` and `aria-label`.
5. Check it at 390 px wide in the screenshot job's output (below).

## The phone screenshot job

`tests/e2e/test_mobile.py` runs in the `e2e (Playwright)` CI job. It logs in once,
opens every page in its `PAGES` list at 390 × 844 (device scale 2, Chromium with
`bypass_csp` because it must call `page.evaluate`; the journey tests keep the CSP on),
and fails on a server error, on horizontal overflow
(the page wider than the 390px device; a phone browser widens `innerWidth` to fit overflow, so it is measured against the constant), or on a tab-bar item or `.btn` outside a table
shorter than 44 px. It also drives each pattern above against a small synthetic
page, and repeats the page list at 1440 × 900 to prove the desktop is unchanged.

The screenshots are the point: the `mobile-screenshots` and `desktop-screenshots`
artifacts are uploaded on **every** run, pass or fail. Open the run in GitHub →
Artifacts, download, and look at them on a phone. To add a page, add it to
`PAGES`. `KNOWN_OVERFLOW` lists pages that still overflow with the release that
fixes them; it only shrinks.

## The ratchet

`tests/test_ui_ratchet.py` holds two numbers that only go down: the count of
inline `style="` attributes across `templates/` and the size of the emoji
scanner's allowlist. A change that lowers the first lowers `MAX_INLINE_STYLES` in
the same commit (a second test fails until it does) and says so in the CHANGELOG.

## The extracted inline styles

`static/css/ui-classes.css` (linked from `base.html`) is generated: `tools/extract_inline_styles.py`
moves a static `style="…"` that appears at least twice into a class `u-<hash of the declarations>`
and records it in `tools/inline_style_map.json`. Each rule doubles its selector (`.u-x.u-x`) so it
keeps the precedence the inline style had; a script-set inline style still wins. Left as inline on
purpose: any style containing Jinja, `display:none` and `position:fixed` (scripts toggle those), and
one-offs. A fixed multi-column grid collapses to one column on a phone. Run
`py tools/extract_inline_styles.py templates/your_page.html` after building a page and
`py tools/extract_inline_styles.py --check` to regenerate the CSS; `tests/test_ui_classes.py` fails on
drift, on an unused or missing class, and when a template still has extractable styles.
For new markup prefer the tokens and utilities above.

## Refreshing the README screenshots

**Screenshots in the README come only from this job, never from a real install.**
Every one of them is generated in CI, on every `e2e` run, from
`tests/e2e/demo_data.py`'s fictional homelab dataset
(`tests/e2e/test_docs_screenshots.py`, `JEN_E2E_DATASET=demo`) — a real
capture would carry real hostnames, real people's names in reservation
notes, and the maintainer's own addresses, none of which belong on the
project's front door.

To pick up a new set after a UI change, download the latest run's artifact
and commit it:

```bash
gh run list --limit 1 --json databaseId
gh run download <id> -n docs-screenshots -D docs/images
git add docs/images && git commit
```

`tests/test_readme_images.py` fails the build if a downloaded image is
missing, over 500 KB, a `.jpg` (the old, hand-captured format — never bring
one back), or left uncommitted while the README stops referencing it.
