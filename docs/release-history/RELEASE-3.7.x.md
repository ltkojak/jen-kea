# Jen v3.7.1 — Release Notes
**Released:** 2026-06-09
**Series:** 3.7.x — Plugin Architecture

---

## Overview

The 3.7.x series is a structural release. No user-visible features change from 3.6.x. The plugin implementations move out of the main Jen repository into their own dedicated GitHub repositories, giving each plugin independent versioning, issue tracking, and release history. A follow-up audit patch (3.7.1) fixes two installer and template issues found immediately after the initial release.

---

## What's New — 3.7.0

### 🗂️ Plugin Repositories Split Into Separate Repos

Plugins previously lived in `plugins/network-discovery/` and `plugins/ipam/` inside the main `jen-kea` repo. They now live at:

| Plugin | Repository |
|--------|-----------|
| Network Discovery | [github.com/ltkojak/jen-plugin-network-discovery](https://github.com/ltkojak/jen-plugin-network-discovery) |
| IPAM Lite | [github.com/ltkojak/jen-plugin-ipam](https://github.com/ltkojak/jen-plugin-ipam) |

`plugins/registry.json` remains in the main repo — the registry catalogue is part of Jen core. The `download_url` values in the registry now point to the new repos.

**Why this matters:**

Before, a bug fix to IPAM required a Jen core version bump, implying something changed in Jen itself. The main repo's commit history and issue tracker collected plugin concerns alongside core changes.

After, IPAM v1.2.0 is a tag on `jen-plugin-ipam`. Network Discovery v1.1.0 is a tag on `jen-plugin-network-discovery`. Jen core versions only change when Jen core changes. Each plugin has its own issues list, its own README, its own release history.

For community contributors: adding a plugin to the registry is a one-line PR to `registry.json` pointing at their own repo. They own their code, Jen core just curates the catalogue.

**No changes to the install flow.** Install, enable, disable, and update in Settings → Plugins work identically. The only difference is where the plugin zip is downloaded from — transparent to the user.

---

## Patch — 3.7.1

### Full Audit Fixes

A full end-to-end audit of 3.7.0 found two issues:

**🔴 `/opt/jen/plugins/` not created by installer**

The `mkdir -p` block in `install.sh` that creates the Jen directory structure was missing `/opt/jen/plugins/`. On a fresh install, if a user opened Settings → Plugins and clicked Install before the directory existed, the install would fail silently. Fixed by adding the plugins directory to the installer's directory creation block.

**🟡 Duplicate condition on Network section-tabs**

The `{% if %}` block controlling when the Network section-tabs bar renders (Subnets / Servers / DDNS / plugin tabs) had the plugin endpoint check written twice:
```
or (plugin_nav_items and ...) or (plugin_nav_items and ...)
```
Harmless — the condition evaluated correctly — but redundant. Cleaned up to a single check.

---

## Version History (3.7.x)

| Version | Date | Description |
|---------|------|-------------|
| 3.7.0 | 2026-06-09 | Move plugins to separate repos, update registry URLs |
| 3.7.1 | 2026-06-09 | Audit fixes: plugin dir in installer, duplicate nav condition |

---

## Versioning Going Forward

| Track | Next | Trigger |
|-------|------|---------|
| Jen core | 3.7.x | Any further core bug fixes |
| Jen core | 4.0 | Plugin framework v2 (settings API, scheduled job registration) |
| Network Discovery | Independent | In `jen-plugin-network-discovery` repo |
| IPAM Lite | Independent | In `jen-plugin-ipam` repo |

---

## Upgrading

No DB changes. No config changes. Any already-installed plugins continue to work without reinstalling.

```bash
cd ~
tar xzf jen-v3.7.1.tar.gz
cd jen
sudo ./install.sh
```

---

*Jen is a self-hosted DHCP infrastructure management UI for ISC Kea.*
*GPL v3 — Copyright 2026 Matthew Thibodeau*
