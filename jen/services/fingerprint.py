"""
jen/services/fingerprint.py
───────────────────────────
Device fingerprinting: OUI database, manufacturer icon mapping,
device type display config, and classification helpers.
"""

import json
import logging
import os

from jen import extensions

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────

# OUI -> (manufacturer, device_type, icon). ~1,350 entries; moved out of
# this module into a JSON data file in v5.11.1 (the dict dominated the
# file). Regenerate/normalise with scripts/oui_to_json.py.
# device_type values: apple, android, windows, linux, amazon, iot, tv,
#                     printer, nas, network, voip, gaming, raspberry_pi, unknown
_OUI_DB_PATH = os.path.join(os.path.dirname(__file__), "oui_db.json")
with open(_OUI_DB_PATH, encoding="utf-8") as _f:
    OUI_DB = {k: tuple(v) for k, v in json.load(_f).items()}

# Device type display config: (label, CSS color)
DEVICE_TYPE_DISPLAY = {
    "apple": ("Apple", "#a8a8a8"),
    "android": ("Android", "#a4c639"),
    "windows": ("Windows", "#00a4ef"),
    "linux": ("Linux", "#e95420"),
    "amazon": ("Amazon", "#ff9900"),
    "iot": ("IoT", "#00b4d8"),
    "tv": ("Smart TV", "#9b59b6"),
    "printer": ("Printer", "#7f8c8d"),
    "nas": ("NAS", "#16a085"),
    "network": ("Network", "#27ae60"),
    "voip": ("VoIP", "#2980b9"),
    "gaming": ("Gaming", "#e74c3c"),
    "raspberry_pi": ("Raspberry Pi", "#c7053d"),
    "google": ("Google", "#4285f4"),
    "pc": ("PC", "#3498db"),
    "unknown": ("Unknown", "#555555"),
}


def lookup_oui(mac: str) -> tuple:
    """
    Look up OUI from MAC address.
    Returns (manufacturer, device_type, icon) or ("Unknown", "unknown", "❓")
    Also applies hostname-based sub-classification for Apple devices.
    """
    if not mac or len(mac) < 8:
        return ("Unknown", "unknown", "❓")
    oui = mac[:8].lower()
    result = OUI_DB.get(oui)
    if result:
        return result
    return ("Unknown", "unknown", "❓")


# Map manufacturer names to SVG icon filenames (without .svg)
# Custom user uploads take priority over bundled icons
MANUFACTURER_ICON_MAP = {
    "Apple": "apple",
    "Apple TV": "appletv",
    "Android": "android",  # hostname detected
    "Samsung": "samsung",
    "Amazon": "amazon",
    "Amazon/Ecobee": "amazon",
    "Eero": "amazon",
    "Google": "google",
    "Raspberry Pi": "raspberrypi",
    "Roku": "roku",
    "Ring": "ring",
    "Sonos": "sonos",
    "Ubiquiti": "ubiquiti",
    "Cisco": "cisco",
    "Netgear": "netgear",
    "Synology": "synology",
    "QNAP": "qnap",
    "Philips Hue": "philipshue",
    "TP-Link": "tplink",
    "Nintendo": "nintendo",
    "Sony PlayStation": "playstation",
    "Microsoft": "microsoft",
    "Microsoft/Xbox": "xbox",
    "Hyper-V": "microsoft",
    "Dell": "dell",
    "Dell/VirtualBox": "dell",
    "HP": "hp",
    "HP Printer": "hp",
    "Lenovo": "lenovo",
    "Intel": "intel",
    "LG": "lg",
    "Epson Printer": "epson",
    "Brother Printer": "brother",
    "Canon Printer": "canon",
    "Lutron": "lutron",
    "Nest": "googlenest",
    "Espressif": "espressif",
    "VMware": "vmware",
    "Realtek/QEMU": "qemu",
    "QEMU/KVM": "qemu",
    "Netgate": "netgate",
    "Meross": "meross",
    "Ecobee": "ecobee",
    "Belkin/Wemo": "belkin",
    "Tuya IoT": "tuya",
}


def get_manufacturer_icon_url(manufacturer: str) -> str:
    """
    Returns the URL path to the best available icon for a manufacturer.
    Priority: custom user upload > bundled Simple Icons > None
    """
    icon_name = MANUFACTURER_ICON_MAP.get(manufacturer)
    if not icon_name:
        return None
    # Check custom first
    custom_path = f"{extensions.ICONS_CUSTOM_DIR}/{icon_name}.svg"
    if os.path.exists(custom_path):
        return f"/static/icons/custom/{icon_name}.svg"
    # Check bundled
    bundled_path = f"{extensions.ICONS_BUNDLED_DIR}/{icon_name}.svg"
    if os.path.exists(bundled_path):
        return f"/static/icons/brands/{icon_name}.svg"
    return None


def classify_device(mac: str, hostname: str = "") -> tuple:
    """
    Returns (manufacturer, device_type, icon) with hostname-based refinement.
    For Apple devices, uses hostname to distinguish iPhone/iPad from Mac.
    Also uses hostname patterns when OUI is unknown (e.g. randomized/private MACs).
    """
    manufacturer, device_type, icon = lookup_oui(mac)

    # Hostname-based refinement for known Apple OUI
    if manufacturer == "Apple" and hostname:
        h = hostname.lower()
        if any(x in h for x in ("iphone", "ipad", "ipod")):
            return (manufacturer, "apple", "📱")
        elif any(x in h for x in ("macbook", "imac", "mac-mini", "mac-pro", "macpro", "macmini")):
            return (manufacturer, "apple", "💻")
        elif "appletv" in h or "apple-tv" in h:
            return ("Apple TV", "apple", "📺")

    # Hostname-based detection for unknown OUIs (randomized MACs, missing OUI entries)
    if manufacturer == "Unknown" and hostname:
        h = hostname.lower()
        if any(x in h for x in ("iphone", "ipad", "ipod")):
            return ("Apple", "apple", "📱")
        elif any(x in h for x in ("macbook", "imac", "mac-mini", "macpro", "macmini")):
            return ("Apple", "apple", "💻")
        elif "appletv" in h or "apple-tv" in h:
            return ("Apple", "apple", "📺")
        elif any(x in h for x in ("android", "pixel", "galaxy", "samsung")):
            return ("Android", "android", "📱")
        elif any(x in h for x in ("echo", "alexa", "kindle", "firetv", "fire-tv")):
            return ("Amazon", "amazon", "📦")
        elif any(x in h for x in ("chromecast", "googletv", "google-tv")):
            return ("Google", "google", "🔍")
        elif "roku" in h:
            return ("Roku", "tv", "📺")
        elif any(x in h for x in ("ring-", "ring_")):
            return ("Ring", "iot", "🔔")
        elif "nest" in h:
            return ("Nest", "iot", "🌡️")
        elif "sonos" in h:
            return ("Sonos", "iot", "🔊")
        elif any(x in h for x in ("meross", "kasa", "wemo", "tuya", "shelly", "tasmota", "espressif", "esphome")):
            return ("IoT Device", "iot", "🔌")
        elif any(x in h for x in ("xbox", "playstation", "nintendo", "switch")):
            return ("Gaming", "gaming", "🎮")
        elif any(x in h for x in ("printer", "print", "hp-", "canon-", "epson-", "brother-")):
            return ("Printer", "printer", "🖨️")

    return (manufacturer, device_type, icon)


def get_device_info_map(mac_list: list) -> dict:
    """
    Given a list of MAC address strings, returns a dict mapping mac -> device info dict.
    Uses override values when set, falls back to auto-detected values.
    Normalizes all MACs to lowercase for consistent lookup.
    Result: {mac: {"manufacturer": str, "device_type": str, "device_icon": str, "icon_url": str, "is_manual": bool}}
    """
    if not mac_list:
        return {}
    # Normalize all input MACs to lowercase
    normalized = [m.lower() for m in mac_list if m]
    if not normalized:
        return {}
    result = {}
    try:
        from jen.models.db import jen_db

        with jen_db() as db, db.cursor() as cur:
            placeholders = ",".join(["%s"] * len(normalized))
            cur.execute(
                f"""
                    SELECT LOWER(mac) AS mac,
                           COALESCE(manufacturer_override, manufacturer) AS manufacturer,
                           COALESCE(device_type_override, device_type) AS device_type,
                           COALESCE(device_icon_override, device_icon) AS device_icon,
                           manufacturer_override IS NOT NULL AS is_manual
                    FROM devices WHERE LOWER(mac) IN ({placeholders})
                """,
                normalized,
            )
            for row in cur.fetchall():
                mfr = row["manufacturer"] or ""
                dtype = row["device_type"] or "unknown"
                dicon = row["device_icon"] or "❓"
                # If there's an icon override that's a valid icon name, use it directly
                icon_url = None
                if row["is_manual"] and dicon and len(dicon) > 2:
                    # dicon might be an icon name (e.g. "appletv") not an emoji
                    test_custom = f"{extensions.ICONS_CUSTOM_DIR}/{dicon}.svg"
                    test_bundled = f"{extensions.ICONS_BUNDLED_DIR}/{dicon}.svg"
                    if os.path.exists(test_custom):
                        icon_url = f"/static/icons/custom/{dicon}.svg"
                    elif os.path.exists(test_bundled):
                        icon_url = f"/static/icons/brands/{dicon}.svg"
                    else:
                        icon_url = get_manufacturer_icon_url(mfr)
                else:
                    icon_url = get_manufacturer_icon_url(mfr)
                result[row["mac"]] = {
                    "manufacturer": mfr,
                    "device_type": dtype,
                    "device_icon": dicon,
                    "icon_url": icon_url,
                    "is_manual": bool(row["is_manual"]),
                }
    except Exception as e:
        logger.error(f"get_device_info_map error: {e}")
    return result


# ─────────────────────────────────────────


# ── Client device identification (v4.3.0) ─────────────────────────────────────


def friendly_user_agent(ua: str) -> str:
    """
    Parse a raw User-Agent string into a short human-readable description
    like "iPhone (iOS 18.7) · Safari" or "Windows · Chrome 147".
    Returns "Unknown device" if the string is empty or unrecognisable.
    """
    import re

    if not ua or not ua.strip():
        return "Unknown device"

    # ── Platform ──
    platform = ""
    m = re.search(r"iPhone OS (\d+)[._](\d+)", ua)
    if m:
        platform = f"iPhone (iOS {m.group(1)}.{m.group(2)})"
    elif "iPhone" in ua:
        platform = "iPhone"
    elif re.search(r"iPad", ua):
        m = re.search(r"CPU OS (\d+)[._](\d+)", ua)
        platform = f"iPad (iPadOS {m.group(1)}.{m.group(2)})" if m else "iPad"
    elif "Android" in ua:
        m = re.search(r"Android (\d+)", ua)
        platform = f"Android {m.group(1)}" if m else "Android"
    elif "Windows NT 10.0" in ua or "Windows" in ua:
        platform = "Windows"
    elif "Mac OS X" in ua:
        platform = "Mac"
    elif "CrOS" in ua:
        platform = "ChromeOS"
    elif "Linux" in ua:
        platform = "Linux"

    # ── Browser (order matters: Edge/Opera embed "Chrome", Chrome embeds "Safari") ──
    browser = ""
    m = re.search(r"Edg(?:e|A|iOS)?/(\d+)", ua)
    if m:
        browser = f"Edge {m.group(1)}"
    else:
        m = re.search(r"OPR/(\d+)", ua)
        if m:
            browser = f"Opera {m.group(1)}"
        else:
            m = re.search(r"Firefox/(\d+)", ua)
            if m:
                browser = f"Firefox {m.group(1)}"
            else:
                m = re.search(r"(?:Chrome|CriOS)/(\d+)", ua)
                if m:
                    browser = f"Chrome {m.group(1)}"
                elif "Safari" in ua:
                    browser = "Safari"

    if platform and browser:
        return f"{platform} · {browser}"
    return platform or browser or "Unknown device"


def client_hostname(ip: str) -> str:
    """
    Best-effort hostname for a client IP using Jen's own knowledge of the
    network: the active Kea lease first, then the devices table. Returns ""
    if nothing is known. Never raises — this runs during login.
    """
    if not ip:
        return ""
    try:
        from jen.models.db import kea_db

        with kea_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT hostname FROM lease4 WHERE inet_ntoa(address)=%s AND state=0 ORDER BY expire DESC LIMIT 1",
                (ip,),
            )
            row = cur.fetchone()
        if row and row.get("hostname"):
            return str(row["hostname"]).rstrip(".").strip()
    except Exception:
        pass
    try:
        from jen.models.db import jen_db

        with jen_db() as db, db.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(NULLIF(device_name,''), NULLIF(last_hostname,'')) AS name "
                "FROM devices WHERE last_ip=%s "
                "ORDER BY last_seen DESC LIMIT 1",
                (ip,),
            )
            row = cur.fetchone()
        if row and row.get("name"):
            return str(row["name"]).rstrip(".").strip()
    except Exception:
        pass
    return ""


def describe_client_device(ip: str, ua: str) -> str:
    """
    Full friendly description of a connecting client:
    "kojak-pc — Windows · Chrome 147" when the hostname is known,
    otherwise just the parsed user agent.
    """
    friendly = friendly_user_agent(ua)
    hostname = client_hostname(ip)
    if hostname:
        return f"{hostname} — {friendly}"[:200]
    return friendly[:200]
