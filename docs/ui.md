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
(the seven built-in presets plus an install's own custom palette, if it has
one); never hard-code a color or radius that has to work across all of them.
A new built-in preset is one entry in `theme.py`'s `PRESETS` dict — nothing
in `base.html` changes. A preset may also carry a fixed `extra_css` string
(v5.56.0, Q67) — CSS scoped to its own `data-theme` selector, appended
verbatim by `render_css()`. Retro's bevel borders and title-bar nav are the
one example; the custom-palette form has no such field and can never
produce one — `extra_css` only ever comes from a literal in `theme.py`.

**Every theme also carries the colors it derives from its tokens** (Q248;
`theme.py` `derived_vars`, emitted after the tokens by `render_css()`), and
new CSS uses them wherever text sits on a theme color:

| Name | What it is | Use |
|---|---|---|
| `--on-accent`, `--on-success`, `--on-warning`, `--on-danger` | black or white, whichever reads better on that token | the text and icons on a SOLID background of that token (a button, the current page of a pagination, the avatar); never `white` or `black` |
| `--primary-ink`, `--success-ink`, `--warning-ink`, `--danger-ink`, `--muted-ink` | the token as text: the token itself where it reads at 4.5:1 on its own chip, else moved toward black or white until it does. The three status inks also read at 4.5:1 with no chip, on `--bg`, `--surface` and `--surface2` | the text of a banner or a badge; a status word printed as plain text (`.ok`, `.warn`, `.bad`, a field's error) - never the bare `var(--success)`, `var(--warning)` or `var(--danger)` as a text color |
| `--tint-base` | the theme's surface | what a chip's color is mixed into (below) |
| `--hue-keep`, `--hue-pole`, `--tone-keep`, `--tone-pole` | how much of a categorical hue a badge's text keeps, and the black or white it takes the rest from | `.mfr-badge` (a device-type color, handed over as `--tc`) and the yellow and purple subnet tones |
| `--vendor-invert` | 1 on a dark surface, 0 on a light one | a manufacturer logo drawn as a one-color silhouette |

Muted text (`--text-muted`) is at least 4.5:1 on `--bg`, `--surface` and
`--surface2` in every preset. `tests/test_q248_c1.py` holds all of this for
every preset with `theme.contrast_ratio`, and `tests/e2e/test_q248_c1.py`
measures the composited result in a browser. A custom palette gets its
`--on-accent` computed; its other derived names carry what a page drew
before they existed, so an operator's palette is not redrawn.

A **chip** (the background of a badge or a banner) is
`color-mix(in srgb, var(--token) 18%, var(--tint-base))` with the token's ink
as its text: one known color wherever it sits, so its text can be held to a
ratio. A **tint** that carries no text (a hover state, a border, a legend
swatch) is `color-mix(in srgb, var(--token) N%, transparent)`. Neither is a
separate hard-coded hex per theme. `tests/test_theme.py`'s "hex wall"
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

**The Display menu** (Q248) holds three per-browser picks, written once by the
`display_picks` macro in `base.html` for the top row's menu and the phone's
sheet. Theme: the install's default is the first row, "<name> (default)", with
an empty `data-theme-id` (picking it removes the stored pick); `system`
("Match My System") is a pick that is not a preset and resolves to `dark` or
`light` through `jenThemeResolve()`, before paint and when the operating
system changes. Display Times: `jen-time-pick` (`utc`, else local). Table
Rows: `jen-density-pick` = `compact` puts `data-density="compact"` on `<html>`,
which only `table.rowlist` body cells read, at desktop widths.

**Menus, dialogs and confirmations** (Q248). A menu's toggle (`.nav-dd-toggle`,
`.action-menu-toggle`) is a checkbox the keyboard reaches, never
`display: none`; it carries `role="button"`, `aria-haspopup="menu"`,
`aria-expanded` and a name ("Actions for <the row>"), its dropdown
`role="menu"` and its items `role="menuitem"`. One delegated script in
`base.html` supplies the keys. A page's own dialog is an overlay with
`class="jen-dialog-overlay" role="dialog" aria-modal="true" hidden` opened
with `jenDialog.open(overlay, opener)`; `[data-dialog-close]` closes it. A
`data-confirm` that deletes, removes, revokes, releases or resets carries
`data-confirm-label` with that verb, which is the dialog's button. A row's
own form is never written inside a list's bulk form: the bulk form ends after
its bar and each row checkbox names it with `form="bulk-form"`.

**Lists and the page's column** (Q248). A value a client or an operator chose (a hostname, a device name, an owner, an audit event's details) is written in
`<span class="clip" title="the whole value">`: one line, cut with an ellipsis at its column's width, so one long value never makes a table wider than its card.
The `hostname_clip` macro (`_hostname.html`) writes a hostname this way; a cell that holds a clip and something after it (a vendor badge, the Investigate button)
wraps them in `<div class="clip-row">`. A date, a time and a `.badge` in a `table.rowlist` never wrap. A list that has more columns than a window holds drops
some with `.hide-tablet` (1024 px and under), `.hide-below-1280` or `.hide-below-1440` on the header AND on its cells, never on the column it is sorted by by
default nor on the row menu's. A table page fills `{% block content_class %}content--wide{% endblock %}`: its content column, the top row's inner wrapper
(`.nav-inner`) and the section strip are then 1,800 px wide at most instead of 1,400, and the bars' backgrounds still run edge to edge. A detail page (one
reached from a row or a card of another page) is listed on its parent's tab in `jen/routes/settings/nav.py`, so it keeps the parent's strip, and starts its
content with `<a class="back-link" href="...">&larr; Parent's title</a>`, its only way back; every page of a plugin's blueprint is shown under the plugin's tab.

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
toggle, the account links and Logout. Its first control is a **Close** button,
so opening it never puts the caret in the search field. The phone's top bar has
its own search button (`#nav-search-btn`), which shows the desktop's search
field as a row under the bar (`.nav.search-open`).

**The top row fits** (Q248). `.nav-links` may shrink and clips; the right-hand
group never shrinks. `jenNavFit()` in `base.html` measures the row on load, on a
resize and when fonts load, and steps through `nav-fit-1` (favorites show their
icon only), `nav-fit-2` (About leaves the row; it is always in the Account
menu) and `nav-fit-3` (Getting started shows its icon only) until the row holds
no more than it shows. Never add a width `@media` that hides part of the row.

**Copy buttons** (Q248). `{% from "_copy.html" import copy_button %}` and
`{{ copy_button("element-id", what="the install command") }}` beside a block of
text (`class="copy-box"` for one line that scrolls sideways inside its card,
`copy-box--wrap` for text that wraps). The one delegated copy listener in
`base.html` copies the element's text and says "Copied" on the button for two
seconds, or "Copy failed - select the text". `copy_cell()` is still the control
for a MAC or an IP printed in a list.

**A row of buttons** that may wrap is `class="btn-row"` (8 px between them on
every line). Buttons written one after another as inline boxes touch when a
phone stacks them.

**Fields.** A placeholder is a short example that fits its field at 390 px;
what the field means goes in its `.form-hint` (with `aria-describedby`). A
field that takes an IPv4 address asks for no keypad (`inputmode="decimal"` shows
a comma and no dot on an iPhone whose region writes decimals with a comma) and
carries `autocapitalize="off" spellcheck="false"`; a MAC or another hex identifier
`autocapitalize="off" autocomplete="off" spellcheck="false"`; a host name
`autocapitalize="off" spellcheck="false"`. `tests/test_q248_a2.py` walks the
whole template tree for the last two.

Both are computed by `nav_context()` in `jen/routes/settings/nav.py`
(`tabbar`, `tabbar_more_active`, `sheet`) with the same role and subnet-scope
filtering as everything else there. To add a destination, add it to the tables in
that file; the strip, the sheet and the settings landing page all read them. The
top bar on a phone keeps the logo, the status dot and the avatar. The body gets
bottom padding so content never hides behind the bar; the bar honors
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
| `third` | line three, small, joined with " · ": the MAC in the code font (and on Devices the subnet and the status) |
| `trailing` | right edge of line one: the kebab / action menu |
| `hide` | not shown on a phone |
| `full` | a single cell that spans the line (an empty-state row) |
| *(none)* | treated as `secondary` |

Tapping a row (anywhere that is not itself a control) opens the row's action menu — the same target as the kebab — or, when the row has no menu, its primary link; in Select mode it ticks the row. Pairs of `class="desk-only"` / `class="phone-only"` spans give a cell a full desktop value and a short phone value (Devices' Last seen is a timestamp on a desktop and "2 h ago" on a phone, via the `relfmt` filter). A `relfmt` time carries its exact moment as its `title`, in the reader's zone or in UTC as they picked: Leases' expiry is the relative phrase at every width. `_sort_controls.html` renders the phone's Sort and Order selects for a list page's filter form.

A cell whose text is empty or exactly "—" is dropped, so a row never shows
"NOTES —". Rows are at least 56 px. The cell holding a `.row-checkbox` is
recognized automatically. The older `table.mobile-cards` / `data-label` pattern
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

`.chip-row` is one horizontally scrolling line with
a fade at the right edge instead of a wrapping block.

### In-page tabs and the jump line

The pages of one group (the pages of a Settings group, the DDNS page's views,
the Investigate page's views) are **tabs**: `{{ subtabs(items, active_id) }}`
from `_settings_subtabs.html` draws a `nav.page-tabs` of `a.page-tab` links,
the current one with `aria-current="page"`. It is the only in-page tab style;
do not build a row of pills or badges for the same job. Every page of a group
draws its group's row (so there is always a way back), a tab is listed only
for the roles its page lets in (`SUBTABS` in `jen/routes/settings/nav.py`),
and a row of one tab is not drawn. A phone gets one scrolling row, 40 px tall.

A Settings page with several cards lists them on one plain line under its
tabs: set `toc` to `(card id, the card's own title)` for EVERY card in the
order the cards come, then `{% include '_card_toc.html' %}`. A desktop shows
"On this page:" and a text link per card; a phone does not show the line (the
same list makes its cards fold). `tests/test_q248_c2.py` renders each page
and compares the line with the cards.

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

The capture job also checks every screenshot's text against a list of markers that must never appear
(`demo_data.FORBIDDEN`). The committed part of that list is only the generic address range; the personal
names (family first names, surname, domain) live in the repository secret `JEN_DOCS_FORBIDDEN`, a
comma-separated list, so they are not published in the repository the guard protects. Create it once
with `gh secret set JEN_DOCS_FORBIDDEN --body "name1,name2,..."`; the reusable workflow receives it from
`ci.yml` and `release.yml` by name, and the docs job fails if it arrives empty (a Dependabot run or a
pull request from a fork gets no secrets, so the check is skipped there). The old list is still in `git log`.

`tests/test_readme_images.py` fails the build if a downloaded image is
missing, over 500 KB, a `.jpg` (the old, hand-captured format — never bring
one back), or left uncommitted while the README stops referencing it.
