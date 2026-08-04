# Jen v3.7.0 — Release Notes
**Released:** 2026-06-09
**Series:** 3.7.x — Plugin Architecture

---

## Overview

3.7.0 is a structural release. No user-visible features change. The plugin implementations move out of the main Jen repository into their own dedicated GitHub repositories, giving each plugin independent versioning, issue tracking, and release history.

---

## What Changed

### Plugin Repositories Split Out

Plugins previously lived in `plugins/network-discovery/` and `plugins/ipam/` inside the main `jen-kea` repo. They now live at:

| Plugin | Repository |
|--------|-----------|
| Network Discovery | [github.com/ltkojak/jen-plugin-network-discovery](https://github.com/ltkojak/jen-plugin-network-discovery) |
| IPAM Lite | [github.com/ltkojak/jen-plugin-ipam](https://github.com/ltkojak/jen-plugin-ipam) |

The `plugins/registry.json` file remains in the main repo — that's correct, the registry catalogue is part of Jen core. The `download_url` values in the registry now point to the new repos.

### Why This Matters

**Before:** A bug fix to IPAM required a Jen core version bump (`v3.6.x`), which implied something changed in Jen itself. The commit history and issue tracker of the main repo collected plugin concerns.

**After:** IPAM v1.2.0 is a tag on `jen-plugin-ipam`. Network Discovery v1.1.0 is a tag on `jen-plugin-network-discovery`. Jen core versions only change when Jen core changes. Each plugin has its own issues list, its own README, its own release history.

**For community contributors:** Adding a plugin to the registry is a one-line PR to `registry.json` pointing at their own repo. They own their code, Jen core just curates the catalogue.

### No Changes to Install Flow

The install, enable, disable, and update flows in Settings → Plugins are identical. The only difference is where the plugin zip is downloaded from — transparent to the user.

---

## Versioning Going Forward

| Track | Scope |
|-------|-------|
| Jen 3.7.x | Patches to the plugin architecture or registry |
| Jen 4.0 | Plugin framework v2 — settings API, scheduled job registration |
| Network Discovery x.y.z | Independent releases in `jen-plugin-network-discovery` |
| IPAM Lite x.y.z | Independent releases in `jen-plugin-ipam` |

---

## Upgrading

```bash
cd ~
tar xzf jen-v3.7.0.tar.gz
cd jen
sudo ./install.sh
```

No DB changes. No config changes. Any already-installed plugins continue to work without reinstalling.

---

*Jen is a self-hosted DHCP infrastructure management UI for ISC Kea.*
*GPL v3 — Copyright 2026 Matthew Thibodeau*
