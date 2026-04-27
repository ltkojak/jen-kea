# Jen Wiki

Welcome to the Jen documentation wiki.

Jen is a web-based management interface for [ISC Kea DHCP Server](https://www.isc.org/kea/), built by Matthew Thibodeau. It provides a full-featured browser UI for managing leases, reservations, subnets, and DHCP settings.

---

## Quick Links

| | |
|---|---|
| 📦 [Installation Guide](installation.md) | Get Jen up and running |
| ⚙️ [Configuration Reference](configuration.md) | Every config option explained |
| 👤 [User Guide](user-guide.md) | Using Jen day to day |
| 🔧 [Admin Guide](admin-guide.md) | Setup, users, settings, upgrades |
| 🐳 [Docker Guide](docker.md) | Running Jen in Docker |
| ❓ [FAQ](faq.md) | Common questions answered |
| 🔍 [Troubleshooting](troubleshooting.md) | Fix common problems |
| 📋 [Release Notes](release-notes.md) | What changed in each version |

---

## Current Version

**Jen v2.5.1**

---

## Getting Started

New to Jen? Start here:

1. Review the [requirements](installation.md#requirements)
2. Follow the [Installation Guide](installation.md)
3. Complete the [First-Time Setup Checklist](admin-guide.md#first-time-setup-checklist)
4. Read the [User Guide](user-guide.md) to learn the UI

---

## Architecture Overview

```
┌─────────────────┐         ┌─────────────────────┐
│   Your Browser  │────────▶│   Jen (your-jen-server)       │
│  (any device)   │  HTTPS  │   Flask + Python     │
└─────────────────┘  8443   │   /opt/jen/jen.py    │
                            └──────────┬──────────┘
                                       │
                    ┌──────────────────┼──────────────────┐
                    │                  │                   │
                    ▼                  ▼                   ▼
          ┌─────────────┐   ┌─────────────────┐  ┌──────────────┐
          │  Kea API    │   │  Kea MySQL DB   │  │  Jen MySQL   │
          │  Port 8000  │   │  (kea database) │  │  (jen database)│
          │  your-kea-server  │   │  your-kea-server      │  │  your-kea-server   │
          └─────────────┘   └─────────────────┘  └──────────────┘
                    │
                    ▼
          ┌─────────────────┐
          │  Kea DHCP       │
          │  isc-kea-dhcp4  │
          │  your-kea-server      │
          └─────────────────┘
```

Jen connects to three things on your Kea server: the Control Agent REST API (for reservation management and config reads), the Kea MySQL database (for lease and host data), and via SSH for subnet config editing.
