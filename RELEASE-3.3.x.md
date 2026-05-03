# Jen v3.3.12 — Release Notes
**Released:** 2026-04-30
**Series:** 3.3.x — Mobile Polish

---

## Overview

The 3.3.x series focused entirely on mobile (iOS) experience. All changes are in `templates/base.html` — no database migrations, no API changes, no configuration changes. Upgrading from any 3.2.x or earlier release is a drop-in install.

---

## What Changed

### 🐛 Mobile Nav Drawer — Always Visible on iOS (Fixed in 3.3.10)

**Symptom:** On iPhones using Brave, Edge, or other iOS browsers, the hamburger menu drawer appeared permanently open at the top of every page. The "Jen" logo appeared clipped, and a stray "ℹ️ About" link floated above the navigation bar.

**Root Cause:** The drawer used `transform: translateY(-110%)` to hide itself off-screen. On iOS WebKit with `position: fixed` and `height: auto`, this transform was being computed as `translateY(0)` — keeping the drawer fully visible at all times. A mobile media query override (`display: block`) compounded the issue by ensuring the drawer could never collapse.

**Fix:** Replaced the CSS transform show/hide pattern with `display: none` (hidden) / `display: block` (open). The hamburger tap toggle adds/removes the `.open` class. The drawer is now reliably hidden by default on all iOS browsers. Trade-off: the slide-down open animation is gone — the drawer snaps open/closed. A CSS `max-height` transition replacement is planned for a future release.

---

### 🐛 Mobile Section Tabs — Horizontal Scroll Blocked on iOS (Fixed in 3.3.12)

**Symptom:** On the Settings page (and any page with many section sub-tabs), the tab row extended off the right edge of the screen but could not be scrolled horizontally. Attempting to swipe left on a tab would navigate to that tab instead of scrolling the row.

**Root Cause:** A global `touchstart` handler on all `<a href>` elements called `e.preventDefault()` immediately on every touch event — including horizontal swipe gestures. This prevented the browser's native scroll handling from ever receiving the event. The container had `overflow-x: auto` and `touch-action: pan-x` but neither could override the JS `preventDefault()`.

**Fix:** Replaced the `touchstart`-only navigation handler with a three-event pattern:
- `touchstart` — records the initial touch position (passive listener, no `preventDefault`)
- `touchmove` — detects if horizontal movement has exceeded vertical by more than 6px, sets a `didScroll` flag (passive)
- `touchend` — navigates only if `didScroll` is false (tap), otherwise lets the scroll pass through

Tap-to-navigate still works with no perceptible delay. Horizontal swipes on tab rows now correctly scroll the container.

---

### 🔧 iOS Safe-Area Inset — Nav Padding (3.3.3 → 3.3.8)

Added `env(safe-area-inset-top/left/right)` to the nav's own padding (rather than on `<body>`), ensuring the nav content always sits below the iOS Dynamic Island / notch region regardless of sticky positioning or scroll state. This is standard iOS web app hygiene for pages using `viewport-fit=cover`.

---

### 🔧 Nav Logo — Horizontal Layout & Fixed Dimensions (3.3.5)

The branding logo and version label were previously stacked vertically (logo above, version below). Restructured to a horizontal inline layout with fixed `height: 28px` on the image and `object-fit: contain`. This prevents any logo aspect ratio from causing vertical overflow in the nav bar.

---

## Version History (3.3.x)

| Version | Date | Description |
|---------|------|-------------|
| 3.3.3 | 2026-04-30 | iOS safe-area inset, nav drawer z-index fix |
| 3.3.4 | — | Skipped |
| 3.3.5 | 2026-04-30 | Nav logo horizontal layout, min-height bump |
| 3.3.6 | — | Skipped |
| 3.3.7 | 2026-04-30 | Diagnostic build (red banner + purple nav) — confirmed deploy chain working |
| 3.3.8 | 2026-04-30 | Safe-area inset moved to nav padding |
| 3.3.9 | 2026-04-30 | Hardcoded 50px padding-top floor (superseded by 3.3.10) |
| 3.3.10 | 2026-04-30 | **Nav drawer always-visible bug fixed** — display none/block replaces transform |
| 3.3.11 | 2026-04-30 | Section tabs touch-action: pan-x (CSS-only, insufficient) |
| 3.3.12 | 2026-04-30 | **Section tab horizontal scroll fixed** — touchstart preventDefault removed |

---

## Upgrading

No database migrations. No config file changes.

```bash
cd ~
tar xzf jen-v3.3.12.tar.gz
cd jen
sudo ./install.sh
```

Upgrade from any version in the 3.x series is supported. Upgrading from 2.x is also supported — run the installer and it will handle the transition.

---

## Known Issues / Coming Next

- **Drawer open animation:** The slide-down animation was removed in 3.3.10 as part of the iOS fix. A replacement using `max-height` CSS transitions (which are reliable on iOS) is planned.
- **Section tab overflow indicator:** On pages with many tabs, there's no visual cue that the row is scrollable. A right-edge gradient fade is planned.

---

*Jen is a self-hosted DHCP infrastructure management UI for ISC Kea.*
*GPL v3 — Copyright 2026 Matthew Thibodeau*
