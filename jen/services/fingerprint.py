"""
jen/services/fingerprint.py
───────────────────────────
Device fingerprinting: OUI database, manufacturer icon mapping,
device type display config, and classification helpers.
"""

import logging
import os

from jen import extensions

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────

# (manufacturer, device_type, icon)
# device_type values: apple, android, windows, linux, amazon, iot, tv, printer,
#                     nas, network, voip, gaming, raspberry_pi, unknown
OUI_DB = {
    # Apple
    "00:03:93": ("Apple", "apple", "🍎"), "00:05:02": ("Apple", "apple", "🍎"),
    "00:0a:27": ("Apple", "apple", "🍎"), "00:0a:95": ("Apple", "apple", "🍎"),
    "00:0d:93": ("Apple", "apple", "🍎"), "00:11:24": ("Apple", "apple", "🍎"),
    "00:14:51": ("Apple", "apple", "🍎"), "00:16:cb": ("Apple", "apple", "🍎"),
    "00:17:f2": ("Apple", "apple", "🍎"), "00:19:e3": ("Apple", "apple", "🍎"),
    "00:1b:63": ("Apple", "apple", "🍎"), "00:1c:b3": ("Apple", "apple", "🍎"),
    "00:1d:4f": ("Apple", "apple", "🍎"), "00:1e:52": ("Apple", "apple", "🍎"),
    "00:1e:c2": ("Apple", "apple", "🍎"), "00:1f:5b": ("Apple", "apple", "🍎"),
    "00:1f:f3": ("Apple", "apple", "🍎"), "00:21:e9": ("Apple", "apple", "🍎"),
    "00:22:41": ("Apple", "apple", "🍎"), "00:23:12": ("Apple", "apple", "🍎"),
    "00:23:32": ("Apple", "apple", "🍎"), "00:23:6c": ("Apple", "apple", "🍎"),
    "00:23:df": ("Apple", "apple", "🍎"), "00:24:36": ("Apple", "apple", "🍎"),
    "00:25:00": ("Apple", "apple", "🍎"), "00:25:4b": ("Apple", "apple", "🍎"),
    "00:25:bc": ("Apple", "apple", "🍎"), "00:26:08": ("Apple", "apple", "🍎"),
    "00:26:4a": ("Apple", "apple", "🍎"), "00:26:b0": ("Apple", "apple", "🍎"),
    "00:26:bb": ("Apple", "apple", "🍎"), "00:30:65": ("Apple", "apple", "🍎"),
    "00:3e:e1": ("Apple", "apple", "🍎"), "00:50:e4": ("Apple", "apple", "🍎"),
    "00:56:cd": ("Apple", "apple", "🍎"), "00:61:71": ("Apple", "apple", "🍎"),
    "00:6d:52": ("Apple", "apple", "🍎"), "00:88:65": ("Apple", "apple", "🍎"),
    "04:0c:ce": ("Apple", "apple", "🍎"), "04:15:52": ("Apple", "apple", "🍎"),
    "04:1e:64": ("Apple", "apple", "🍎"), "04:26:65": ("Apple", "apple", "🍎"),
    "04:48:9a": ("Apple", "apple", "🍎"), "04:4b:ed": ("Apple", "apple", "🍎"),
    "04:52:f3": ("Apple", "apple", "🍎"), "04:54:53": ("Apple", "apple", "🍎"),
    "04:69:f8": ("Apple", "apple", "🍎"), "04:d3:cf": ("Apple", "apple", "🍎"),
    "04:e5:36": ("Apple", "apple", "🍎"), "04:f1:3e": ("Apple", "apple", "🍎"),
    "08:00:07": ("Apple", "apple", "🍎"), "08:6d:41": ("Apple", "apple", "🍎"),
    "08:70:45": ("Apple", "apple", "🍎"), "08:74:02": ("Apple", "apple", "🍎"),
    "0c:3e:9f": ("Apple", "apple", "🍎"), "0c:4d:e9": ("Apple", "apple", "🍎"),
    "0c:74:c2": ("Apple", "apple", "🍎"), "0c:77:1a": ("Apple", "apple", "🍎"),
    "0c:bc:9f": ("Apple", "apple", "🍎"), "0c:d7:46": ("Apple", "apple", "🍎"),
    "10:1c:0c": ("Apple", "apple", "🍎"), "10:40:f3": ("Apple", "apple", "🍎"),
    "10:41:7f": ("Apple", "apple", "🍎"), "10:93:e9": ("Apple", "apple", "🍎"),
    "10:9a:dd": ("Apple", "apple", "🍎"), "14:10:9f": ("Apple", "apple", "🍎"),
    "14:20:5e": ("Apple", "apple", "🍎"), "14:5a:05": ("Apple", "apple", "🍎"),
    "14:8f:c6": ("Apple", "apple", "🍎"), "14:99:e2": ("Apple", "apple", "🍎"),
    "18:20:32": ("Apple", "apple", "🍎"), "18:34:51": ("Apple", "apple", "🍎"),
    "18:65:90": ("Apple", "apple", "🍎"), "18:81:0e": ("Apple", "apple", "🍎"),
    "18:9e:fc": ("Apple", "apple", "🍎"), "18:af:61": ("Apple", "apple", "🍎"),
    "18:e7:f4": ("Apple", "apple", "🍎"), "1c:1a:c0": ("Apple", "apple", "🍎"),
    "1c:36:bb": ("Apple", "apple", "🍎"), "1c:91:48": ("Apple", "apple", "🍎"),
    "1c:9e:46": ("Apple", "apple", "🍎"), "20:78:f0": ("Apple", "apple", "🍎"),
    "20:a2:e4": ("Apple", "apple", "🍎"), "20:ab:37": ("Apple", "apple", "🍎"),
    "20:c9:d0": ("Apple", "apple", "🍎"), "24:1e:eb": ("Apple", "apple", "🍎"),
    "24:24:0e": ("Apple", "apple", "🍎"), "24:5b:a7": ("Apple", "apple", "🍎"),
    "24:a0:74": ("Apple", "apple", "🍎"), "24:ab:81": ("Apple", "apple", "🍎"),
    "28:0b:5c": ("Apple", "apple", "🍎"), "28:37:37": ("Apple", "apple", "🍎"),
    "28:6a:b8": ("Apple", "apple", "🍎"), "28:6a:ba": ("Apple", "apple", "🍎"),
    "28:cf:da": ("Apple", "apple", "🍎"), "28:cf:e9": ("Apple", "apple", "🍎"),
    "28:e1:4c": ("Apple", "apple", "🍎"), "2c:1f:23": ("Apple", "apple", "🍎"),
    "2c:20:0b": ("Apple", "apple", "🍎"), "2c:be:08": ("Apple", "apple", "🍎"),
    "2c:f0:a2": ("Apple", "apple", "🍎"), "30:10:e4": ("Apple", "apple", "🍎"),
    "30:35:ad": ("Apple", "apple", "🍎"), "30:63:6b": ("Apple", "apple", "🍎"),
    "30:90:ab": ("Apple", "apple", "🍎"), "34:08:bc": ("Apple", "apple", "🍎"),
    "34:15:9e": ("Apple", "apple", "🍎"), "34:36:3b": ("Apple", "apple", "🍎"),
    "34:51:c9": ("Apple", "apple", "🍎"), "34:c0:59": ("Apple", "apple", "🍎"),
    "38:0f:4a": ("Apple", "apple", "🍎"), "38:48:4c": ("Apple", "apple", "🍎"),
    "38:b5:4d": ("Apple", "apple", "🍎"), "38:ca:da": ("Apple", "apple", "🍎"),
    "3c:07:54": ("Apple", "apple", "🍎"), "3c:15:c2": ("Apple", "apple", "🍎"),
    "3c:2e:f9": ("Apple", "apple", "🍎"), "3c:d0:f8": ("Apple", "apple", "🍎"),
    "40:31:3c": ("Apple", "apple", "🍎"), "40:33:1a": ("Apple", "apple", "🍎"),
    "40:3c:fc": ("Apple", "apple", "🍎"), "40:4d:7f": ("Apple", "apple", "🍎"),
    "40:6c:8f": ("Apple", "apple", "🍎"), "40:83:1d": ("Apple", "apple", "🍎"),
    "40:9c:28": ("Apple", "apple", "🍎"), "40:a6:d9": ("Apple", "apple", "🍎"),
    "40:b3:95": ("Apple", "apple", "🍎"), "40:cb:c0": ("Apple", "apple", "🍎"),
    "40:d3:2d": ("Apple", "apple", "🍎"), "44:00:10": ("Apple", "apple", "🍎"),
    "44:2a:60": ("Apple", "apple", "🍎"), "44:4c:0c": ("Apple", "apple", "🍎"),
    "44:d8:84": ("Apple", "apple", "🍎"), "44:fb:42": ("Apple", "apple", "🍎"),
    "48:43:7c": ("Apple", "apple", "🍎"), "48:60:bc": ("Apple", "apple", "🍎"),
    "48:74:6e": ("Apple", "apple", "🍎"), "48:bf:6b": ("Apple", "apple", "🍎"),
    "48:d7:05": ("Apple", "apple", "🍎"), "4c:32:75": ("Apple", "apple", "🍎"),
    "4c:57:ca": ("Apple", "apple", "🍎"), "4c:74:bf": ("Apple", "apple", "🍎"),
    "4c:7c:5f": ("Apple", "apple", "🍎"), "4c:8d:79": ("Apple", "apple", "🍎"),
    "50:2b:73": ("Apple", "apple", "🍎"), "50:32:75": ("Apple", "apple", "🍎"),
    "50:7a:55": ("Apple", "apple", "🍎"), "50:82:d5": ("Apple", "apple", "🍎"),
    "50:ea:d6": ("Apple", "apple", "🍎"), "54:26:96": ("Apple", "apple", "🍎"),
    "54:33:cb": ("Apple", "apple", "🍎"), "54:4e:90": ("Apple", "apple", "🍎"),
    "54:72:4f": ("Apple", "apple", "🍎"), "54:9f:13": ("Apple", "apple", "🍎"),
    "54:ae:27": ("Apple", "apple", "🍎"), "54:e4:3a": ("Apple", "apple", "🍎"),
    "58:1f:aa": ("Apple", "apple", "🍎"), "58:40:4e": ("Apple", "apple", "🍎"),
    "58:55:ca": ("Apple", "apple", "🍎"), "58:7f:57": ("Apple", "apple", "🍎"),
    "58:b0:35": ("Apple", "apple", "🍎"), "5c:59:48": ("Apple", "apple", "🍎"),
    "5c:95:ae": ("Apple", "apple", "🍎"), "5c:ad:cf": ("Apple", "apple", "🍎"),
    "5c:f9:38": ("Apple", "apple", "🍎"), "60:03:08": ("Apple", "apple", "🍎"),
    "60:33:4b": ("Apple", "apple", "🍎"), "60:69:44": ("Apple", "apple", "🍎"),
    "60:8c:4a": ("Apple", "apple", "🍎"), "60:92:17": ("Apple", "apple", "🍎"),
    "60:c5:47": ("Apple", "apple", "🍎"), "60:d9:c7": ("Apple", "apple", "🍎"),
    "60:f4:45": ("Apple", "apple", "🍎"), "60:f8:1d": ("Apple", "apple", "🍎"),
    "60:fb:42": ("Apple", "apple", "🍎"), "64:20:0c": ("Apple", "apple", "🍎"),
    "64:76:ba": ("Apple", "apple", "🍎"), "64:9a:be": ("Apple", "apple", "🍎"),
    "64:a3:cb": ("Apple", "apple", "🍎"), "64:b9:e8": ("Apple", "apple", "🍎"),
    "68:09:27": ("Apple", "apple", "🍎"), "68:5b:35": ("Apple", "apple", "🍎"),
    "68:64:4b": ("Apple", "apple", "🍎"), "68:96:7b": ("Apple", "apple", "🍎"),
    "68:9c:70": ("Apple", "apple", "🍎"), "68:a8:6d": ("Apple", "apple", "🍎"),
    "68:ab:1e": ("Apple", "apple", "🍎"), "6c:19:c0": ("Apple", "apple", "🍎"),
    "6c:40:08": ("Apple", "apple", "🍎"), "6c:72:20": ("Apple", "apple", "🍎"),
    "6c:94:f8": ("Apple", "apple", "🍎"), "6c:96:cf": ("Apple", "apple", "🍎"),
    "70:11:24": ("Apple", "apple", "🍎"), "70:14:a6": ("Apple", "apple", "🍎"),
    "70:3e:ac": ("Apple", "apple", "🍎"), "70:48:0f": ("Apple", "apple", "🍎"),
    "70:56:81": ("Apple", "apple", "🍎"), "70:73:cb": ("Apple", "apple", "🍎"),
    "70:cd:60": ("Apple", "apple", "🍎"), "70:de:e2": ("Apple", "apple", "🍎"),
    "70:ec:e4": ("Apple", "apple", "🍎"), "74:1b:b2": ("Apple", "apple", "🍎"),
    "74:2f:68": ("Apple", "apple", "🍎"), "74:8d:08": ("Apple", "apple", "🍎"),
    "74:e1:b6": ("Apple", "apple", "🍎"), "78:31:c1": ("Apple", "apple", "🍎"),
    "78:4f:43": ("Apple", "apple", "🍎"), "78:67:d7": ("Apple", "apple", "🍎"),
    "78:7e:61": ("Apple", "apple", "🍎"), "78:9f:70": ("Apple", "apple", "🍎"),
    "78:a3:e4": ("Apple", "apple", "🍎"), "78:ca:39": ("Apple", "apple", "🍎"),
    "78:d7:5f": ("Apple", "apple", "🍎"), "7c:01:91": ("Apple", "apple", "🍎"),
    "7c:04:d0": ("Apple", "apple", "🍎"), "7c:11:be": ("Apple", "apple", "🍎"),
    "7c:6d:62": ("Apple", "apple", "🍎"), "7c:c3:a1": ("Apple", "apple", "🍎"),
    "7c:d1:c3": ("Apple", "apple", "🍎"), "7c:f0:5f": ("Apple", "apple", "🍎"),
    "80:00:6e": ("Apple", "apple", "🍎"), "80:49:71": ("Apple", "apple", "🍎"),
    "80:82:23": ("Apple", "apple", "🍎"), "80:86:f2": ("Apple", "apple", "🍎"),
    "80:be:05": ("Apple", "apple", "🍎"), "80:e6:50": ("Apple", "apple", "🍎"),
    "84:29:99": ("Apple", "apple", "🍎"), "84:38:35": ("Apple", "apple", "🍎"),
    "84:78:8b": ("Apple", "apple", "🍎"), "84:85:06": ("Apple", "apple", "🍎"),
    "84:89:ad": ("Apple", "apple", "🍎"), "84:a1:34": ("Apple", "apple", "🍎"),
    "84:b1:53": ("Apple", "apple", "🍎"), "84:fc:ac": ("Apple", "apple", "🍎"),
    "88:1f:a1": ("Apple", "apple", "🍎"), "88:53:2e": ("Apple", "apple", "🍎"),
    "88:63:df": ("Apple", "apple", "🍎"), "88:66:a5": ("Apple", "apple", "🍎"),
    "88:ae:07": ("Apple", "apple", "🍎"), "88:c6:63": ("Apple", "apple", "🍎"),
    "88:e9:fe": ("Apple", "apple", "🍎"), "8c:00:6d": ("Apple", "apple", "🍎"),
    "8c:29:37": ("Apple", "apple", "🍎"), "8c:2d:aa": ("Apple", "apple", "🍎"),
    "8c:4b:14": ("Apple", "apple", "🍎"), "8c:7b:9d": ("Apple", "apple", "🍎"),
    "8c:85:90": ("Apple", "apple", "🍎"), "8c:8e:f2": ("Apple", "apple", "🍎"),
    "90:27:e4": ("Apple", "apple", "🍎"), "90:3c:92": ("Apple", "apple", "🍎"),
    "90:60:f1": ("Apple", "apple", "🍎"), "90:72:40": ("Apple", "apple", "🍎"),
    "90:84:0d": ("Apple", "apple", "🍎"), "90:8d:6c": ("Apple", "apple", "🍎"),
    "90:b0:ed": ("Apple", "apple", "🍎"), "90:b9:31": ("Apple", "apple", "🍎"),
    "90:c1:c6": ("Apple", "apple", "🍎"), "94:bf:2d": ("Apple", "apple", "🍎"),
    "94:e9:6a": ("Apple", "apple", "🍎"), "94:f6:a3": ("Apple", "apple", "🍎"),
    "98:01:a7": ("Apple", "apple", "🍎"), "98:03:d8": ("Apple", "apple", "🍎"),
    "98:10:e7": ("Apple", "apple", "🍎"), "98:46:0a": ("Apple", "apple", "🍎"),
    "98:9e:63": ("Apple", "apple", "🍎"), "98:d6:bb": ("Apple", "apple", "🍎"),
    "98:e0:d9": ("Apple", "apple", "🍎"), "98:f0:ab": ("Apple", "apple", "🍎"),
    "9c:04:eb": ("Apple", "apple", "🍎"), "9c:20:7b": ("Apple", "apple", "🍎"),
    "9c:29:3f": ("Apple", "apple", "🍎"), "9c:35:eb": ("Apple", "apple", "🍎"),
    "9c:4f:da": ("Apple", "apple", "🍎"), "9c:84:bf": ("Apple", "apple", "🍎"),
    "9c:f3:87": ("Apple", "apple", "🍎"), "a0:11:5e": ("Apple", "apple", "🍎"),
    "a0:3b:e3": ("Apple", "apple", "🍎"), "a0:4e:a7": ("Apple", "apple", "🍎"),
    "a0:99:9b": ("Apple", "apple", "🍎"), "a0:d7:95": ("Apple", "apple", "🍎"),
    "a4:5e:60": ("Apple", "apple", "🍎"), "a4:67:06": ("Apple", "apple", "🍎"),
    "a4:b1:97": ("Apple", "apple", "🍎"), "a4:b8:05": ("Apple", "apple", "🍎"),
    "a4:c3:61": ("Apple", "apple", "🍎"), "a4:d1:8c": ("Apple", "apple", "🍎"),
    "a4:d9:31": ("Apple", "apple", "🍎"), "a4:f1:e8": ("Apple", "apple", "🍎"),
    "a8:20:66": ("Apple", "apple", "🍎"), "a8:51:ab": ("Apple", "apple", "🍎"),
    "a8:5b:78": ("Apple", "apple", "🍎"), "a8:60:b6": ("Apple", "apple", "🍎"),
    "a8:86:dd": ("Apple", "apple", "🍎"), "a8:88:08": ("Apple", "apple", "🍎"),
    "a8:96:8a": ("Apple", "apple", "🍎"), "a8:be:27": ("Apple", "apple", "🍎"),
    "a8:fa:d8": ("Apple", "apple", "🍎"), "ac:1f:74": ("Apple", "apple", "🍎"),
    "ac:29:3a": ("Apple", "apple", "🍎"), "ac:3c:0b": ("Apple", "apple", "🍎"),
    "ac:61:ea": ("Apple", "apple", "🍎"), "ac:7f:3e": ("Apple", "apple", "🍎"),
    "ac:87:a3": ("Apple", "apple", "🍎"), "ac:bc:32": ("Apple", "apple", "🍎"),
    "ac:cf:5c": ("Apple", "apple", "🍎"), "ac:de:48": ("Apple", "apple", "🍎"),
    "ac:e4:b5": ("Apple", "apple", "🍎"), "ac:fd:ec": ("Apple", "apple", "🍎"),
    "b0:19:c6": ("Apple", "apple", "🍎"), "b0:34:95": ("Apple", "apple", "🍎"),
    "b0:65:bd": ("Apple", "apple", "🍎"), "b0:70:2d": ("Apple", "apple", "🍎"),
    "b0:9f:ba": ("Apple", "apple", "🍎"), "b4:18:d1": ("Apple", "apple", "🍎"),
    "b4:4b:d2": ("Apple", "apple", "🍎"), "b4:f0:ab": ("Apple", "apple", "🍎"),
    "b8:08:cf": ("Apple", "apple", "🍎"), "b8:17:c2": ("Apple", "apple", "🍎"),
    "b8:41:a4": ("Apple", "apple", "🍎"), "b8:53:ac": ("Apple", "apple", "🍎"),
    "b8:5d:0a": ("Apple", "apple", "🍎"), "b8:63:4d": ("Apple", "apple", "🍎"),
    "b8:78:2e": ("Apple", "apple", "🍎"), "b8:c7:5d": ("Apple", "apple", "🍎"),
    "b8:e8:56": ("Apple", "apple", "🍎"), "b8:f6:b1": ("Apple", "apple", "🍎"),
    "bc:3b:af": ("Apple", "apple", "🍎"), "bc:52:b7": ("Apple", "apple", "🍎"),
    "bc:54:51": ("Apple", "apple", "🍎"), "bc:67:78": ("Apple", "apple", "🍎"),
    "bc:92:6b": ("Apple", "apple", "🍎"), "bc:9f:ef": ("Apple", "apple", "🍎"),
    "bc:a9:20": ("Apple", "apple", "🍎"), "bc:d1:74": ("Apple", "apple", "🍎"),
    "bc:ec:6d": ("Apple", "apple", "🍎"), "c0:1a:da": ("Apple", "apple", "🍎"),
    "c0:84:7a": ("Apple", "apple", "🍎"), "c0:9f:42": ("Apple", "apple", "🍎"),
    "c0:a5:e8": ("Apple", "apple", "🍎"), "c0:cc:f8": ("Apple", "apple", "🍎"),
    "c0:ce:cd": ("Apple", "apple", "🍎"), "c0:d0:12": ("Apple", "apple", "🍎"),
    "c0:f2:fb": ("Apple", "apple", "🍎"), "c4:2c:03": ("Apple", "apple", "🍎"),
    "c4:61:8b": ("Apple", "apple", "🍎"), "c4:b3:01": ("Apple", "apple", "🍎"),
    "c8:1e:e7": ("Apple", "apple", "🍎"), "c8:2a:14": ("Apple", "apple", "🍎"),
    "c8:33:4b": ("Apple", "apple", "🍎"), "c8:3c:85": ("Apple", "apple", "🍎"),
    "c8:6f:1d": ("Apple", "apple", "🍎"), "c8:85:50": ("Apple", "apple", "🍎"),
    "c8:bc:c8": ("Apple", "apple", "🍎"), "c8:d0:83": ("Apple", "apple", "🍎"),
    "c8:e0:eb": ("Apple", "apple", "🍎"), "c8:f6:50": ("Apple", "apple", "🍎"),
    "cc:08:8d": ("Apple", "apple", "🍎"), "cc:20:e8": ("Apple", "apple", "🍎"),
    "cc:25:ef": ("Apple", "apple", "🍎"), "cc:29:f5": ("Apple", "apple", "🍎"),
    "cc:44:63": ("Apple", "apple", "🍎"), "cc:78:ab": ("Apple", "apple", "🍎"),
    "cc:c7:60": ("Apple", "apple", "🍎"), "d0:03:4b": ("Apple", "apple", "🍎"),
    "d0:23:db": ("Apple", "apple", "🍎"), "d0:25:98": ("Apple", "apple", "🍎"),
    "d0:4f:7e": ("Apple", "apple", "🍎"), "d0:81:7a": ("Apple", "apple", "🍎"),
    "d0:a6:37": ("Apple", "apple", "🍎"), "d0:c5:f3": ("Apple", "apple", "🍎"),
    "d0:e1:40": ("Apple", "apple", "🍎"), "d4:61:9d": ("Apple", "apple", "🍎"),
    "d4:90:9c": ("Apple", "apple", "🍎"), "d4:9a:20": ("Apple", "apple", "🍎"),
    "d4:dc:cd": ("Apple", "apple", "🍎"), "d4:f4:6f": ("Apple", "apple", "🍎"),
    "d8:1d:72": ("Apple", "apple", "🍎"), "d8:30:62": ("Apple", "apple", "🍎"),
    "d8:96:95": ("Apple", "apple", "🍎"), "d8:9e:3f": ("Apple", "apple", "🍎"),
    "d8:bb:2c": ("Apple", "apple", "🍎"), "d8:cf:9c": ("Apple", "apple", "🍎"),
    "dc:0c:5c": ("Apple", "apple", "🍎"), "dc:2b:2a": ("Apple", "apple", "🍎"),
    "dc:37:14": ("Apple", "apple", "🍎"), "dc:41:5f": ("Apple", "apple", "🍎"),
    "dc:56:e7": ("Apple", "apple", "🍎"), "dc:86:d8": ("Apple", "apple", "🍎"),
    "dc:9b:9c": ("Apple", "apple", "🍎"), "dc:a4:ca": ("Apple", "apple", "🍎"),
    "dc:a9:04": ("Apple", "apple", "🍎"), "e0:66:78": ("Apple", "apple", "🍎"),
    "e0:ac:cb": ("Apple", "apple", "🍎"), "e0:b5:2d": ("Apple", "apple", "🍎"),
    "e0:f5:c6": ("Apple", "apple", "🍎"), "e4:25:e7": ("Apple", "apple", "🍎"),
    "e4:40:e2": ("Apple", "apple", "🍎"), "e4:50:eb": ("Apple", "apple", "🍎"),
    "e4:8b:7f": ("Apple", "apple", "🍎"), "e4:9a:79": ("Apple", "apple", "🍎"),
    "e4:c6:3d": ("Apple", "apple", "🍎"), "e4:ce:8f": ("Apple", "apple", "🍎"),
    "e4:e0:a6": ("Apple", "apple", "🍎"), "e8:04:0b": ("Apple", "apple", "🍎"),
    "e8:06:88": ("Apple", "apple", "🍎"), "e8:80:2e": ("Apple", "apple", "🍎"),
    "e8:8d:28": ("Apple", "apple", "🍎"), "ec:35:86": ("Apple", "apple", "🍎"),
    "ec:85:2f": ("Apple", "apple", "🍎"), "f0:18:98": ("Apple", "apple", "🍎"),
    "f0:24:75": ("Apple", "apple", "🍎"), "f0:5c:19": ("Apple", "apple", "🍎"),
    "f0:6d:3b": ("Apple", "apple", "🍎"), "f0:79:60": ("Apple", "apple", "🍎"),
    "f0:99:bf": ("Apple", "apple", "🍎"), "f0:b4:79": ("Apple", "apple", "🍎"),
    "f0:c1:f1": ("Apple", "apple", "🍎"), "f0:cb:a1": ("Apple", "apple", "🍎"),
    "f0:d1:a9": ("Apple", "apple", "🍎"), "f0:db:e2": ("Apple", "apple", "🍎"),
    "f0:dc:e2": ("Apple", "apple", "🍎"), "f0:f6:1c": ("Apple", "apple", "🍎"),
    "f4:0f:24": ("Apple", "apple", "🍎"), "f4:1b:a1": ("Apple", "apple", "🍎"),
    "f4:37:b7": ("Apple", "apple", "🍎"), "f4:5c:89": ("Apple", "apple", "🍎"),
    "f4:f1:5a": ("Apple", "apple", "🍎"), "f8:1e:df": ("Apple", "apple", "🍎"),
    "f8:27:93": ("Apple", "apple", "🍎"), "f8:38:80": ("Apple", "apple", "🍎"),
    "f8:62:14": ("Apple", "apple", "🍎"), "f8:87:f1": ("Apple", "apple", "🍎"),
    "fc:25:3f": ("Apple", "apple", "🍎"), "fc:e9:98": ("Apple", "apple", "🍎"),

    # Samsung
    "00:00:f0": ("Samsung", "android", "📱"), "00:02:78": ("Samsung", "android", "📱"),
    "00:07:ab": ("Samsung", "android", "📱"), "00:12:47": ("Samsung", "android", "📱"),
    "00:12:fb": ("Samsung", "android", "📱"), "00:13:77": ("Samsung", "android", "📱"),
    "00:15:b9": ("Samsung", "android", "📱"), "00:16:32": ("Samsung", "android", "📱"),
    "00:16:db": ("Samsung", "android", "📱"), "00:17:c9": ("Samsung", "android", "📱"),
    "00:17:d5": ("Samsung", "android", "📱"), "00:18:af": ("Samsung", "android", "📱"),
    "00:1a:8a": ("Samsung", "android", "📱"), "00:1b:98": ("Samsung", "android", "📱"),
    "00:1c:43": ("Samsung", "android", "📱"), "00:1d:25": ("Samsung", "android", "📱"),
    "00:1e:7d": ("Samsung", "android", "📱"), "00:1f:cc": ("Samsung", "android", "📱"),
    "00:21:19": ("Samsung", "android", "📱"), "00:23:39": ("Samsung", "android", "📱"),
    "00:23:99": ("Samsung", "android", "📱"), "00:24:54": ("Samsung", "android", "📱"),
    "00:24:91": ("Samsung", "android", "📱"), "00:25:66": ("Samsung", "android", "📱"),
    "00:26:37": ("Samsung", "android", "📱"), "00:e3:b2": ("Samsung", "android", "📱"),
    "04:18:d6": ("Samsung", "android", "📱"), "04:b1:67": ("Samsung", "android", "📱"),
    "04:fe:31": ("Samsung", "android", "📱"), "08:08:c2": ("Samsung", "android", "📱"),
    "08:37:3d": ("Samsung", "android", "📱"), "08:d4:0c": ("Samsung", "android", "📱"),
    "08:fc:88": ("Samsung", "android", "📱"), "0c:14:20": ("Samsung", "android", "📱"),
    "0c:71:5d": ("Samsung", "android", "📱"), "0c:89:10": ("Samsung", "android", "📱"),
    "10:1d:c0": ("Samsung", "android", "📱"), "10:30:47": ("Samsung", "android", "📱"),
    "10:d5:42": ("Samsung", "android", "📱"), "14:49:e0": ("Samsung", "android", "📱"),
    "14:bb:6e": ("Samsung", "android", "📱"), "18:3a:2d": ("Samsung", "android", "📱"),
    "18:46:17": ("Samsung", "android", "📱"), "1c:62:b8": ("Samsung", "android", "📱"),
    "1c:66:aa": ("Samsung", "android", "📱"), "20:13:e0": ("Samsung", "android", "📱"),
    "20:6e:9c": ("Samsung", "android", "📱"), "24:4b:03": ("Samsung", "android", "📱"),
    "24:4e:7b": ("Samsung", "android", "📱"), "24:c6:96": ("Samsung", "android", "📱"),
    "28:27:bf": ("Samsung", "android", "📱"), "28:39:26": ("Samsung", "android", "📱"),
    "28:ba:b5": ("Samsung", "android", "📱"), "28:cc:01": ("Samsung", "android", "📱"),
    "2c:ae:2b": ("Samsung", "android", "📱"), "30:07:4d": ("Samsung", "android", "📱"),
    "30:19:66": ("Samsung", "android", "📱"), "30:cd:a7": ("Samsung", "android", "📱"),
    "34:14:5f": ("Samsung", "android", "📱"), "34:23:ba": ("Samsung", "android", "📱"),
    "34:31:11": ("Samsung", "android", "📱"), "34:aa:8b": ("Samsung", "android", "📱"),
    "34:be:00": ("Samsung", "android", "📱"), "34:c3:ac": ("Samsung", "android", "📱"),
    "38:01:97": ("Samsung", "android", "📱"), "38:0a:94": ("Samsung", "android", "📱"),
    "38:16:d1": ("Samsung", "android", "📱"), "3c:5a:37": ("Samsung", "android", "📱"),
    "3c:62:00": ("Samsung", "android", "📱"), "3c:8b:fe": ("Samsung", "android", "📱"),
    "40:0e:85": ("Samsung", "android", "📱"), "40:16:7e": ("Samsung", "android", "📱"),
    "44:4e:1a": ("Samsung", "android", "📱"), "44:78:3e": ("Samsung", "android", "📱"),
    "48:44:f7": ("Samsung", "android", "📱"), "48:5a:3f": ("Samsung", "android", "📱"),
    "4c:3c:16": ("Samsung", "android", "📱"), "4c:bc:98": ("Samsung", "android", "📱"),
    "50:01:bb": ("Samsung", "android", "📱"), "50:32:37": ("Samsung", "android", "📱"),
    "50:85:69": ("Samsung", "android", "📱"), "50:a4:c8": ("Samsung", "android", "📱"),
    "50:b7:c3": ("Samsung", "android", "📱"), "54:40:ad": ("Samsung", "android", "📱"),
    "54:88:0e": ("Samsung", "android", "📱"), "58:ef:68": ("Samsung", "android", "📱"),
    "5c:a3:9d": ("Samsung", "android", "📱"), "5c:e8:eb": ("Samsung", "android", "📱"),
    "5c:f6:dc": ("Samsung", "android", "📱"), "60:6b:bd": ("Samsung", "android", "📱"),
    "60:d0:a9": ("Samsung", "android", "📱"), "64:77:91": ("Samsung", "android", "📱"),
    "68:27:37": ("Samsung", "android", "📱"), "68:48:98": ("Samsung", "android", "📱"),
    "6c:2f:2c": ("Samsung", "android", "📱"), "6c:83:36": ("Samsung", "android", "📱"),
    "70:2c:1f": ("Samsung", "android", "📱"), "70:f9:27": ("Samsung", "android", "📱"),
    "78:1f:db": ("Samsung", "android", "📱"), "78:25:ad": ("Samsung", "android", "📱"),
    "78:40:e4": ("Samsung", "android", "📱"), "7c:1c:4e": ("Samsung", "android", "📱"),
    "7c:64:56": ("Samsung", "android", "📱"), "80:65:6d": ("Samsung", "android", "📱"),
    "84:11:9e": ("Samsung", "android", "📱"), "84:25:db": ("Samsung", "android", "📱"),
    "84:38:38": ("Samsung", "android", "📱"), "84:55:a5": ("Samsung", "android", "📱"),
    "88:32:9b": ("Samsung", "android", "📱"), "88:9b:39": ("Samsung", "android", "📱"),
    "8c:1a:bf": ("Samsung", "android", "📱"), "8c:71:f8": ("Samsung", "android", "📱"),
    "8c:77:12": ("Samsung", "android", "📱"), "90:18:7c": ("Samsung", "android", "📱"),
    "94:35:0a": ("Samsung", "android", "📱"), "94:51:03": ("Samsung", "android", "📱"),
    "94:76:b7": ("Samsung", "android", "📱"), "98:0c:82": ("Samsung", "android", "📱"),
    "9c:02:98": ("Samsung", "android", "📱"), "9c:3a:af": ("Samsung", "android", "📱"),
    "a0:07:98": ("Samsung", "android", "📱"), "a0:0b:ba": ("Samsung", "android", "📱"),
    "a0:21:95": ("Samsung", "android", "📱"), "a0:75:91": ("Samsung", "android", "📱"),
    "a4:eb:d3": ("Samsung", "android", "📱"), "a8:06:00": ("Samsung", "android", "📱"),
    "a8:7d:12": ("Samsung", "android", "📱"), "ac:36:13": ("Samsung", "android", "📱"),
    "ac:5f:3e": ("Samsung", "android", "📱"), "b0:ec:71": ("Samsung", "android", "📱"),
    "b4:3a:28": ("Samsung", "android", "📱"), "b4:62:93": ("Samsung", "android", "📱"),
    "b4:79:a7": ("Samsung", "android", "📱"), "b8:5e:7b": ("Samsung", "android", "📱"),
    "bc:14:85": ("Samsung", "android", "📱"), "bc:20:a4": ("Samsung", "android", "📱"),
    "bc:72:b1": ("Samsung", "android", "📱"), "bc:85:1f": ("Samsung", "android", "📱"),
    "bc:8c:cd": ("Samsung", "android", "📱"), "c0:bd:d1": ("Samsung", "android", "📱"),
    "c4:42:02": ("Samsung", "android", "📱"), "c4:57:6e": ("Samsung", "android", "📱"),
    "c4:62:ea": ("Samsung", "android", "📱"), "c4:73:1e": ("Samsung", "android", "📱"),
    "c8:19:f7": ("Samsung", "android", "📱"), "c8:ba:94": ("Samsung", "android", "📱"),
    "cc:07:ab": ("Samsung", "android", "📱"), "d0:17:6a": ("Samsung", "android", "📱"),
    "d0:22:be": ("Samsung", "android", "📱"), "d0:59:e4": ("Samsung", "android", "📱"),
    "d0:87:e2": ("Samsung", "android", "📱"), "d4:88:90": ("Samsung", "android", "📱"),
    "d4:e8:b2": ("Samsung", "android", "📱"), "d8:57:ef": ("Samsung", "android", "📱"),
    "d8:e0:e1": ("Samsung", "android", "📱"), "dc:71:96": ("Samsung", "android", "📱"),
    "e4:32:cb": ("Samsung", "android", "📱"), "e4:40:e2": ("Samsung", "android", "📱"),
    "e4:92:fb": ("Samsung", "android", "📱"), "e8:03:9a": ("Samsung", "android", "📱"),
    "e8:39:df": ("Samsung", "android", "📱"), "e8:50:8b": ("Samsung", "android", "📱"),
    "ec:1f:72": ("Samsung", "android", "📱"), "ec:9b:f3": ("Samsung", "android", "📱"),
    "f0:25:b7": ("Samsung", "android", "📱"), "f0:5a:09": ("Samsung", "android", "📱"),
    "f0:72:ea": ("Samsung", "android", "📱"), "f4:42:8f": ("Samsung", "android", "📱"),
    "f4:7b:5e": ("Samsung", "android", "📱"), "f4:9f:54": ("Samsung", "android", "📱"),
    "f8:04:2e": ("Samsung", "android", "📱"), "f8:77:b8": ("Samsung", "android", "📱"),
    "fc:00:12": ("Samsung", "android", "📱"), "fc:a1:3e": ("Samsung", "android", "📱"),

    # Amazon
    "00:bb:3a": ("Amazon", "amazon", "📦"), "0c:47:c9": ("Amazon", "amazon", "📦"),
    "0c:54:a5": ("Amazon", "amazon", "📦"), "10:ae:60": ("Amazon", "amazon", "📦"),
    "18:74:2e": ("Amazon", "amazon", "📦"), "1c:12:b0": ("Amazon", "amazon", "📦"),
    "34:d2:70": ("Amazon", "amazon", "📦"), "38:f7:3d": ("Amazon", "amazon", "📦"),
    "40:b4:cd": ("Amazon", "amazon", "📦"), "44:65:0d": ("Amazon", "amazon", "📦"),
    "44:61:32": ("Amazon", "amazon", "📦"), "48:23:35": ("Amazon", "amazon", "📦"),
    "4c:ef:c0": ("Amazon", "amazon", "📦"), "50:dc:e7": ("Amazon", "amazon", "📦"),
    "54:75:d0": ("Amazon", "amazon", "📦"), "68:37:e9": ("Amazon", "amazon", "📦"),
    "6c:56:97": ("Amazon", "amazon", "📦"), "74:c2:46": ("Amazon", "amazon", "📦"),
    "78:e1:03": ("Amazon", "amazon", "📦"), "84:d6:d0": ("Amazon", "amazon", "📦"),
    "88:71:e5": ("Amazon", "amazon", "📦"), "8c:49:62": ("Amazon", "amazon", "📦"),
    "a0:02:dc": ("Amazon", "amazon", "📦"), "ac:63:be": ("Amazon", "amazon", "📦"),
    "b4:7c:59": ("Amazon", "amazon", "📦"), "b8:27:eb": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "bc:ff:4d": ("Amazon", "amazon", "📦"), "c0:ee:fb": ("Amazon", "amazon", "📦"),
    "d4:f5:47": ("Amazon", "amazon", "📦"), "e8:9d:87": ("Amazon", "amazon", "📦"),
    "f0:27:2d": ("Amazon", "amazon", "📦"), "f0:81:73": ("Amazon", "amazon", "📦"),
    "f0:a2:25": ("Amazon", "amazon", "📦"), "fc:65:de": ("Amazon", "amazon", "📦"),
    "fc:a6:67": ("Amazon", "amazon", "📦"),

    # Raspberry Pi
    "b8:27:eb": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "dc:a6:32": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "e4:5f:01": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "28:cd:c1": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "2c:cf:67": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "d8:3a:dd": ("Raspberry Pi", "raspberry_pi", "🥧"),

    # Google
    "00:1a:11": ("Google", "google", "🔍"), "08:9e:08": ("Google", "google", "🔍"),
    "10:9a:dd": ("Google", "google", "🔍"), "1c:f2:9a": ("Google", "google", "🔍"),
    "20:df:b9": ("Google", "google", "🔍"), "48:d6:d5": ("Google", "google", "🔍"),
    "50:dc:e7": ("Google", "google", "🔍"), "54:60:09": ("Google", "google", "🔍"),
    "6c:ad:f8": ("Google", "google", "🔍"), "80:7d:3a": ("Google", "google", "🔍"),
    "94:eb:2c": ("Google", "google", "🔍"), "a4:77:33": ("Google", "google", "🔍"),
    "ac:37:43": ("Google", "google", "🔍"), "d4:f5:47": ("Google", "google", "🔍"),
    "f4:f5:d8": ("Google", "google", "🔍"), "f8:8f:ca": ("Google", "google", "🔍"),
    "00:1a:11": ("Google", "google", "🔍"),

    # Meross
    "48:e1:e9": ("Meross", "iot", "🔌"), "34:29:12": ("Meross", "iot", "🔌"),
    "0c:dc:7e": ("Meross", "iot", "🔌"),

    # TP-Link / Kasa
    "00:1d:0f": ("TP-Link", "iot", "🔌"), "10:fe:ed": ("TP-Link", "iot", "🔌"),
    "14:cc:20": ("TP-Link", "iot", "🔌"), "18:a6:f7": ("TP-Link", "iot", "🔌"),
    "1c:61:b4": ("TP-Link", "iot", "🔌"), "24:69:68": ("TP-Link", "iot", "🔌"),
    "2c:fd:a1": ("TP-Link", "iot", "🔌"), "30:b5:c2": ("TP-Link", "iot", "🔌"),
    "38:10:d5": ("TP-Link", "iot", "🔌"), "3c:84:6a": ("TP-Link", "iot", "🔌"),
    "44:94:fc": ("TP-Link", "iot", "🔌"), "50:3e:aa": ("TP-Link", "iot", "🔌"),
    "54:af:97": ("TP-Link", "iot", "🔌"), "60:32:b1": ("TP-Link", "iot", "🔌"),
    "64:70:02": ("TP-Link", "iot", "🔌"), "6c:5a:b0": ("TP-Link", "iot", "🔌"),
    "70:4f:57": ("TP-Link", "iot", "🔌"), "74:da:38": ("TP-Link", "iot", "🔌"),
    "78:8c:b5": ("TP-Link", "iot", "🔌"), "7c:8b:ca": ("TP-Link", "iot", "🔌"),
    "80:8f:1d": ("TP-Link", "iot", "🔌"), "84:16:f9": ("TP-Link", "iot", "🔌"),
    "90:9a:4a": ("TP-Link", "iot", "🔌"), "98:da:c4": ("TP-Link", "iot", "🔌"),
    "a0:f3:c1": ("TP-Link", "iot", "🔌"), "ac:84:c6": ("TP-Link", "iot", "🔌"),
    "b0:48:7a": ("TP-Link", "iot", "🔌"), "b4:b0:24": ("TP-Link", "iot", "🔌"),
    "b8:27:eb": ("Raspberry Pi", "raspberry_pi", "🥧"),
    "bc:46:99": ("TP-Link", "iot", "🔌"), "c0:06:c3": ("TP-Link", "iot", "🔌"),
    "c4:e9:84": ("TP-Link", "iot", "🔌"), "d8:07:b6": ("TP-Link", "iot", "🔌"),
    "e8:de:27": ("TP-Link", "iot", "🔌"), "ec:08:6b": ("TP-Link", "iot", "🔌"),
    "f4:ec:38": ("TP-Link", "iot", "🔌"), "f8:1a:67": ("TP-Link", "iot", "🔌"),
    "fc:ec:da": ("TP-Link", "iot", "🔌"),

    # Espressif (ESP8266/ESP32 — DIY IoT, ESPHome, Tasmota)
    "10:52:1c": ("Espressif", "iot", "🔌"), "18:fe:34": ("Espressif", "iot", "🔌"),
    "24:0a:c4": ("Espressif", "iot", "🔌"), "24:6f:28": ("Espressif", "iot", "🔌"),
    "2c:f4:32": ("Espressif", "iot", "🔌"), "30:ae:a4": ("Espressif", "iot", "🔌"),
    "34:86:5d": ("Espressif", "iot", "🔌"), "3c:61:05": ("Espressif", "iot", "🔌"),
    "3c:71:bf": ("Espressif", "iot", "🔌"), "40:f5:20": ("Espressif", "iot", "🔌"),
    "48:3f:da": ("Espressif", "iot", "🔌"), "4c:11:ae": ("Espressif", "iot", "🔌"),
    "4c:75:25": ("Espressif", "iot", "🔌"), "50:02:91": ("Espressif", "iot", "🔌"),
    "54:43:54": ("Espressif", "iot", "🔌"), "58:bf:25": ("Espressif", "iot", "🔌"),
    "5c:cf:7f": ("Espressif", "iot", "🔌"), "60:01:94": ("Espressif", "iot", "🔌"),
    "68:c6:3a": ("Espressif", "iot", "🔌"), "70:03:9f": ("Espressif", "iot", "🔌"),
    "78:21:84": ("Espressif", "iot", "🔌"), "7c:87:ce": ("Espressif", "iot", "🔌"),
    "84:0d:8e": ("Espressif", "iot", "🔌"), "84:cc:a8": ("Espressif", "iot", "🔌"),
    "84:f3:eb": ("Espressif", "iot", "🔌"), "8c:aa:b5": ("Espressif", "iot", "🔌"),
    "90:97:d5": ("Espressif", "iot", "🔌"), "94:3c:c6": ("Espressif", "iot", "🔌"),
    "98:f4:ab": ("Espressif", "iot", "🔌"), "a0:20:a6": ("Espressif", "iot", "🔌"),
    "a4:7b:9d": ("Espressif", "iot", "🔌"), "a4:cf:12": ("Espressif", "iot", "🔌"),
    "a4:e5:7c": ("Espressif", "iot", "🔌"), "ac:67:b2": ("Espressif", "iot", "🔌"),
    "b4:e6:2d": ("Espressif", "iot", "🔌"), "bc:dd:c2": ("Espressif", "iot", "🔌"),
    "c4:4f:33": ("Espressif", "iot", "🔌"), "c8:2b:96": ("Espressif", "iot", "🔌"),
    "cc:50:e3": ("Espressif", "iot", "🔌"), "d4:8a:fc": ("Espressif", "iot", "🔌"),
    "d8:a0:1d": ("Espressif", "iot", "🔌"), "dc:06:75": ("Espressif", "iot", "🔌"),
    "dc:4f:22": ("Espressif", "iot", "🔌"), "e0:98:06": ("Espressif", "iot", "🔌"),
    "e4:83:26": ("Espressif", "iot", "🔌"), "e8:06:90": ("Espressif", "iot", "🔌"),
    "e8:db:84": ("Espressif", "iot", "🔌"), "ec:62:60": ("Espressif", "iot", "🔌"),
    "ec:fa:bc": ("Espressif", "iot", "🔌"), "f0:08:d1": ("Espressif", "iot", "🔌"),
    "f4:cf:a2": ("Espressif", "iot", "🔌"), "fc:f5:c4": ("Espressif", "iot", "🔌"),

    # Roku (additional OUIs)
    "50:06:f5": ("Roku", "tv", "📺"), "cc:fd:f7": ("Roku", "tv", "📺"),
    "ac:ae:19": ("Roku", "tv", "📺"), "b0:a7:37": ("Roku", "tv", "📺"),
    "08:05:81": ("Roku", "tv", "📺"), "d8:31:34": ("Roku", "tv", "📺"),

    # Amazon Echo/Echo Show (additional OUIs)
    "50:d4:5c": ("Amazon", "amazon", "📦"), "b0:8b:a8": ("Amazon", "amazon", "📦"),
    "f0:d2:f1": ("Amazon", "amazon", "📦"), "74:c2:46": ("Amazon", "amazon", "📦"),
    "44:65:0d": ("Amazon", "amazon", "📦"), "a4:08:f5": ("Amazon", "amazon", "📦"),
    "cc:9e:a2": ("Amazon", "amazon", "📦"), "40:b4:cd": ("Amazon", "amazon", "📦"),
    "34:d2:70": ("Amazon", "amazon", "📦"), "ac:63:be": ("Amazon", "amazon", "📦"),

    # Ring
    "00:62:6e": ("Ring", "iot", "🔔"), "24:2f:d0": ("Ring", "iot", "🔔"),
    "34:f6:4b": ("Ring", "iot", "🔔"), "a4:da:32": ("Ring", "iot", "🔔"),
    "18:7f:88": ("Ring", "iot", "🔔"), "fc:99:47": ("Ring", "iot", "🔔"),

    # Ecobee
    "44:61:32": ("Amazon/Ecobee", "iot", "🌡️"), "bc:ae:c5": ("Ecobee", "iot", "🌡️"),
    "54:4a:16": ("Ecobee", "iot", "🌡️"),

    # Sonos
    "00:0e:58": ("Sonos", "iot", "🔊"), "34:7e:5c": ("Sonos", "iot", "🔊"),
    "48:a6:b8": ("Sonos", "iot", "🔊"), "54:2a:1b": ("Sonos", "iot", "🔊"),
    "58:6d:8f": ("Sonos", "iot", "🔊"), "5c:aa:fd": ("Sonos", "iot", "🔊"),
    "78:28:ca": ("Sonos", "iot", "🔊"), "94:9f:3e": ("Sonos", "iot", "🔊"),
    "b8:e9:37": ("Sonos", "iot", "🔊"),

    # Nest/Google Nest
    "18:b4:30": ("Nest", "iot", "🌡️"), "64:16:66": ("Nest", "iot", "🌡️"),
    "d4:f5:47": ("Nest", "iot", "🌡️"),

    # Ubiquiti
    "00:15:6d": ("Ubiquiti", "network", "🌐"), "00:27:22": ("Ubiquiti", "network", "🌐"),
    "04:18:d6": ("Ubiquiti", "network", "🌐"), "0c:e2:1a": ("Ubiquiti", "network", "🌐"),
    "18:e8:29": ("Ubiquiti", "network", "🌐"), "24:a4:3c": ("Ubiquiti", "network", "🌐"),
    "24:a4:3c": ("Ubiquiti", "network", "🌐"), "44:d9:e7": ("Ubiquiti", "network", "🌐"),
    "48:2c:a0": ("Ubiquiti", "network", "🌐"), "60:22:32": ("Ubiquiti", "network", "🌐"),
    "68:d7:9a": ("Ubiquiti", "network", "🌐"), "6a:f1:8f": ("Ubiquiti", "network", "🌐"),
    "74:83:c2": ("Ubiquiti", "network", "🌐"), "78:8a:20": ("Ubiquiti", "network", "🌐"),
    "80:2a:a8": ("Ubiquiti", "network", "🌐"), "9c:05:d6": ("Ubiquiti", "network", "🌐"),
    "a4:4e:31": ("Ubiquiti", "network", "🌐"), "ac:8b:a9": ("Ubiquiti", "network", "🌐"),
    "b4:fb:e4": ("Ubiquiti", "network", "🌐"), "dc:9f:db": ("Ubiquiti", "network", "🌐"),
    "e0:63:da": ("Ubiquiti", "network", "🌐"), "e4:38:83": ("Ubiquiti", "network", "🌐"),
    "f0:9f:c2": ("Ubiquiti", "network", "🌐"), "fc:ec:da": ("Ubiquiti", "network", "🌐"),

    # Cisco
    "00:00:0c": ("Cisco", "network", "🌐"), "00:01:42": ("Cisco", "network", "🌐"),
    "00:01:64": ("Cisco", "network", "🌐"), "00:01:96": ("Cisco", "network", "🌐"),
    "00:01:c7": ("Cisco", "network", "🌐"), "00:02:17": ("Cisco", "network", "🌐"),
    "00:04:c0": ("Cisco", "network", "🌐"), "00:05:00": ("Cisco", "network", "🌐"),
    "00:06:7c": ("Cisco", "network", "🌐"), "00:07:50": ("Cisco", "network", "🌐"),
    "00:08:a3": ("Cisco", "network", "🌐"), "00:09:b7": ("Cisco", "network", "🌐"),
    "00:0a:41": ("Cisco", "network", "🌐"), "00:0a:8a": ("Cisco", "network", "🌐"),
    "00:0b:46": ("Cisco", "network", "🌐"), "00:0c:85": ("Cisco", "network", "🌐"),
    "00:0d:28": ("Cisco", "network", "🌐"), "00:0d:bc": ("Cisco", "network", "🌐"),
    "00:0e:08": ("Cisco", "network", "🌐"), "00:0e:38": ("Cisco", "network", "🌐"),
    "00:0f:23": ("Cisco", "network", "🌐"), "00:0f:8f": ("Cisco", "network", "🌐"),
    "00:0f:f7": ("Cisco", "network", "🌐"), "00:10:07": ("Cisco", "network", "🌐"),
    "00:10:79": ("Cisco", "network", "🌐"), "00:10:f6": ("Cisco", "network", "🌐"),
    "00:11:5c": ("Cisco", "network", "🌐"), "00:11:92": ("Cisco", "network", "🌐"),
    "00:12:00": ("Cisco", "network", "🌐"), "00:12:43": ("Cisco", "network", "🌐"),
    "00:12:7f": ("Cisco", "network", "🌐"), "00:13:10": ("Cisco", "network", "🌐"),
    "00:13:5f": ("Cisco", "network", "🌐"), "00:13:c3": ("Cisco", "network", "🌐"),
    "00:14:1b": ("Cisco", "network", "🌐"), "00:14:69": ("Cisco", "network", "🌐"),
    "00:14:a9": ("Cisco", "network", "🌐"), "00:14:f1": ("Cisco", "network", "🌐"),
    "00:15:2b": ("Cisco", "network", "🌐"), "00:15:63": ("Cisco", "network", "🌐"),
    "00:16:46": ("Cisco", "network", "🌐"), "00:16:9d": ("Cisco", "network", "🌐"),
    "00:16:c7": ("Cisco", "network", "🌐"), "00:17:0e": ("Cisco", "network", "🌐"),
    "00:17:59": ("Cisco", "network", "🌐"), "00:17:94": ("Cisco", "network", "🌐"),
    "00:17:df": ("Cisco", "network", "🌐"), "00:18:19": ("Cisco", "network", "🌐"),
    "00:18:b9": ("Cisco", "network", "🌐"), "00:19:06": ("Cisco", "network", "🌐"),
    "00:19:2f": ("Cisco", "network", "🌐"), "00:19:55": ("Cisco", "network", "🌐"),
    "00:19:a9": ("Cisco", "network", "🌐"), "00:1a:2f": ("Cisco", "network", "🌐"),
    "00:1a:6c": ("Cisco", "network", "🌐"), "00:1a:a1": ("Cisco", "network", "🌐"),
    "00:1b:0c": ("Cisco", "network", "🌐"), "00:1b:2a": ("Cisco", "network", "🌐"),
    "00:1b:54": ("Cisco", "network", "🌐"), "00:1b:8f": ("Cisco", "network", "🌐"),
    "00:1b:d5": ("Cisco", "network", "🌐"), "00:1c:10": ("Cisco", "network", "🌐"),
    "00:1c:57": ("Cisco", "network", "🌐"), "00:1c:b0": ("Cisco", "network", "🌐"),
    "00:1c:f6": ("Cisco", "network", "🌐"), "00:1d:45": ("Cisco", "network", "🌐"),
    "00:1d:70": ("Cisco", "network", "🌐"), "00:1d:a1": ("Cisco", "network", "🌐"),
    "00:1d:e5": ("Cisco", "network", "🌐"), "00:1e:13": ("Cisco", "network", "🌐"),
    "00:1e:49": ("Cisco", "network", "🌐"), "00:1e:6b": ("Cisco", "network", "🌐"),
    "00:1e:be": ("Cisco", "network", "🌐"), "00:1e:f7": ("Cisco", "network", "🌐"),
    "00:1f:27": ("Cisco", "network", "🌐"), "00:1f:6c": ("Cisco", "network", "🌐"),
    "00:1f:9e": ("Cisco", "network", "🌐"), "00:1f:ca": ("Cisco", "network", "🌐"),
    "00:20:35": ("Cisco", "network", "🌐"), "00:21:1b": ("Cisco", "network", "🌐"),
    "00:21:55": ("Cisco", "network", "🌐"), "00:21:a0": ("Cisco", "network", "🌐"),
    "00:22:0c": ("Cisco", "network", "🌐"), "00:22:55": ("Cisco", "network", "🌐"),
    "00:22:90": ("Cisco", "network", "🌐"), "00:22:bd": ("Cisco", "network", "🌐"),
    "00:23:04": ("Cisco", "network", "🌐"), "00:23:33": ("Cisco", "network", "🌐"),
    "00:23:5e": ("Cisco", "network", "🌐"), "00:23:ac": ("Cisco", "network", "🌐"),
    "00:23:eb": ("Cisco", "network", "🌐"), "00:24:13": ("Cisco", "network", "🌐"),
    "00:24:50": ("Cisco", "network", "🌐"), "00:24:97": ("Cisco", "network", "🌐"),
    "00:24:c4": ("Cisco", "network", "🌐"), "00:25:45": ("Cisco", "network", "🌐"),
    "00:25:83": ("Cisco", "network", "🌐"), "00:25:b4": ("Cisco", "network", "🌐"),
    "00:26:0a": ("Cisco", "network", "🌐"), "00:26:51": ("Cisco", "network", "🌐"),
    "00:26:99": ("Cisco", "network", "🌐"), "00:26:ca": ("Cisco", "network", "🌐"),
    "00:27:0d": ("Cisco", "network", "🌐"),

    # Netgear
    "00:09:5b": ("Netgear", "network", "🌐"), "00:0f:b5": ("Netgear", "network", "🌐"),
    "00:14:6c": ("Netgear", "network", "🌐"), "00:18:4d": ("Netgear", "network", "🌐"),
    "00:1b:2f": ("Netgear", "network", "🌐"), "00:1e:2a": ("Netgear", "network", "🌐"),
    "00:22:3f": ("Netgear", "network", "🌐"), "00:24:b2": ("Netgear", "network", "🌐"),
    "00:26:f2": ("Netgear", "network", "🌐"), "04:a1:51": ("Netgear", "network", "🌐"),
    "08:02:8e": ("Netgear", "network", "🌐"), "08:36:c9": ("Netgear", "network", "🌐"),
    "0c:80:63": ("Netgear", "network", "🌐"), "10:0c:6b": ("Netgear", "network", "🌐"),
    "10:da:43": ("Netgear", "network", "🌐"), "20:0c:c8": ("Netgear", "network", "🌐"),
    "20:4e:7f": ("Netgear", "network", "🌐"), "28:c6:8e": ("Netgear", "network", "🌐"),
    "2c:b0:5d": ("Netgear", "network", "🌐"), "30:46:9a": ("Netgear", "network", "🌐"),
    "44:94:fc": ("Netgear", "network", "🌐"), "4c:60:de": ("Netgear", "network", "🌐"),
    "6c:b0:ce": ("Netgear", "network", "🌐"), "74:44:01": ("Netgear", "network", "🌐"),
    "9c:d6:43": ("Netgear", "network", "🌐"), "a0:40:a0": ("Netgear", "network", "🌐"),
    "a4:11:62": ("Netgear", "network", "🌐"), "b0:39:56": ("Netgear", "network", "🌐"),
    "c0:3f:0e": ("Netgear", "network", "🌐"), "c4:3d:c7": ("Netgear", "network", "🌐"),
    "c4:04:15": ("Netgear", "network", "🌐"), "e0:46:9a": ("Netgear", "network", "🌐"),
    "e0:91:f5": ("Netgear", "network", "🌐"),

    # Synology (NAS)
    "00:11:32": ("Synology", "nas", "🗄️"), "00:50:43": ("Synology", "nas", "🗄️"),
    "90:09:d0": ("Synology", "nas", "🗄️"), "bc:5f:f4": ("Synology", "nas", "🗄️"),
    "c8:86:4f": ("Synology", "nas", "🗄️"),

    # QNAP (NAS)
    "00:08:9b": ("QNAP", "nas", "🗄️"), "24:5e:be": ("QNAP", "nas", "🗄️"),
    "70:85:c2": ("QNAP", "nas", "🗄️"), "d8:50:e6": ("QNAP", "nas", "🗄️"),

    # Lutron
    "00:17:7f": ("Lutron", "iot", "💡"), "28:43:fc": ("Lutron", "iot", "💡"),
    "a4:b8:a7": ("Lutron", "iot", "💡"), "e0:92:8f": ("Lutron", "iot", "💡"),

    # Philips Hue / Signify
    "00:17:88": ("Philips Hue", "iot", "💡"), "ec:b5:fa": ("Philips Hue", "iot", "💡"),

    # Wemo / Belkin
    "58:ef:68": ("Belkin/Wemo", "iot", "🔌"), "94:10:3e": ("Belkin/Wemo", "iot", "🔌"),
    "b4:75:0e": ("Belkin/Wemo", "iot", "🔌"), "c4:41:1e": ("Belkin/Wemo", "iot", "🔌"),
    "e8:9f:80": ("Belkin/Wemo", "iot", "🔌"),

    # Nintendo
    "00:09:bf": ("Nintendo", "gaming", "🎮"), "00:16:56": ("Nintendo", "gaming", "🎮"),
    "00:17:ab": ("Nintendo", "gaming", "🎮"), "00:19:1d": ("Nintendo", "gaming", "🎮"),
    "00:1a:e9": ("Nintendo", "gaming", "🎮"), "00:1b:ea": ("Nintendo", "gaming", "🎮"),
    "00:1c:be": ("Nintendo", "gaming", "🎮"), "00:1e:35": ("Nintendo", "gaming", "🎮"),
    "00:1f:32": ("Nintendo", "gaming", "🎮"), "00:22:4c": ("Nintendo", "gaming", "🎮"),
    "00:22:d7": ("Nintendo", "gaming", "🎮"), "00:24:44": ("Nintendo", "gaming", "🎮"),
    "00:24:f3": ("Nintendo", "gaming", "🎮"), "00:26:59": ("Nintendo", "gaming", "🎮"),
    "0c:ef:af": ("Nintendo", "gaming", "🎮"), "18:2a:7b": ("Nintendo", "gaming", "🎮"),
    "40:d2:8a": ("Nintendo", "gaming", "🎮"), "58:2f:40": ("Nintendo", "gaming", "🎮"),
    "7c:bb:8a": ("Nintendo", "gaming", "🎮"), "8c:56:c5": ("Nintendo", "gaming", "🎮"),
    "9c:e6:35": ("Nintendo", "gaming", "🎮"), "a4:c0:e1": ("Nintendo", "gaming", "🎮"),
    "b8:ae:6e": ("Nintendo", "gaming", "🎮"), "d8:6b:f7": ("Nintendo", "gaming", "🎮"),
    "e0:66:78": ("Nintendo", "gaming", "🎮"),

    # Sony PlayStation
    "00:04:1f": ("Sony PlayStation", "gaming", "🎮"),
    "00:13:15": ("Sony PlayStation", "gaming", "🎮"),
    "00:15:c1": ("Sony PlayStation", "gaming", "🎮"),
    "00:19:c5": ("Sony PlayStation", "gaming", "🎮"),
    "00:1d:0d": ("Sony PlayStation", "gaming", "🎮"),
    "00:24:8d": ("Sony PlayStation", "gaming", "🎮"),
    "00:26:43": ("Sony PlayStation", "gaming", "🎮"),
    "28:3f:69": ("Sony PlayStation", "gaming", "🎮"),
    "78:c6:81": ("Sony PlayStation", "gaming", "🎮"),
    "bc:60:a7": ("Sony PlayStation", "gaming", "🎮"),
    "f8:46:1c": ("Sony PlayStation", "gaming", "🎮"),

    # Xbox / Microsoft
    "00:0d:3a": ("Microsoft/Xbox", "gaming", "🎮"),
    "00:17:fa": ("Microsoft/Xbox", "gaming", "🎮"),
    "00:1d:d8": ("Microsoft/Xbox", "gaming", "🎮"),
    "00:22:48": ("Microsoft/Xbox", "gaming", "🎮"),
    "00:25:ae": ("Microsoft/Xbox", "gaming", "🎮"),
    "00:50:f2": ("Microsoft", "windows", "🖥️"),
    "28:18:78": ("Microsoft/Xbox", "gaming", "🎮"),
    "30:59:b7": ("Microsoft/Xbox", "gaming", "🎮"),
    "60:45:cb": ("Microsoft/Xbox", "gaming", "🎮"),
    "7c:ed:8d": ("Microsoft/Xbox", "gaming", "🎮"),
    "98:5f:d3": ("Microsoft/Xbox", "gaming", "🎮"),

    # Intel (common in laptops/PCs)
    "00:02:b3": ("Intel", "pc", "🖥️"), "00:03:47": ("Intel", "pc", "🖥️"),
    "00:04:23": ("Intel", "pc", "🖥️"), "00:07:e9": ("Intel", "pc", "🖥️"),
    "00:0c:f1": ("Intel", "pc", "🖥️"), "00:0e:0c": ("Intel", "pc", "🖥️"),
    "00:11:11": ("Intel", "pc", "🖥️"), "00:12:f0": ("Intel", "pc", "🖥️"),
    "00:13:02": ("Intel", "pc", "🖥️"), "00:13:20": ("Intel", "pc", "🖥️"),
    "00:13:e8": ("Intel", "pc", "🖥️"), "00:14:38": ("Intel", "pc", "🖥️"),
    "00:15:17": ("Intel", "pc", "🖥️"), "00:16:76": ("Intel", "pc", "🖥️"),
    "00:16:ea": ("Intel", "pc", "🖥️"), "00:16:eb": ("Intel", "pc", "🖥️"),
    "00:18:de": ("Intel", "pc", "🖥️"), "00:19:d1": ("Intel", "pc", "🖥️"),
    "00:1b:21": ("Intel", "pc", "🖥️"), "00:1c:c0": ("Intel", "pc", "🖥️"),
    "00:1d:e0": ("Intel", "pc", "🖥️"), "00:1e:64": ("Intel", "pc", "🖥️"),
    "00:1e:65": ("Intel", "pc", "🖥️"), "00:1f:3a": ("Intel", "pc", "🖥️"),
    "00:1f:3b": ("Intel", "pc", "🖥️"), "00:1f:3c": ("Intel", "pc", "🖥️"),
    "00:21:6a": ("Intel", "pc", "🖥️"), "00:21:6b": ("Intel", "pc", "🖥️"),
    "00:22:fa": ("Intel", "pc", "🖥️"), "00:22:fb": ("Intel", "pc", "🖥️"),
    "00:23:14": ("Intel", "pc", "🖥️"), "00:24:d7": ("Intel", "pc", "🖥️"),
    "00:26:c7": ("Intel", "pc", "🖥️"), "10:02:b5": ("Intel", "pc", "🖥️"),
    "18:cf:5e": ("Intel", "pc", "🖥️"), "1c:69:7a": ("Intel", "pc", "🖥️"),
    "20:16:d8": ("Intel", "pc", "🖥️"), "38:de:ad": ("Intel", "pc", "🖥️"),
    "40:a8:f0": ("Intel", "pc", "🖥️"), "44:85:00": ("Intel", "pc", "🖥️"),
    "48:51:b7": ("Intel", "pc", "🖥️"), "4c:80:93": ("Intel", "pc", "🖥️"),
    "54:27:1e": ("Intel", "pc", "🖥️"), "5c:f9:dd": ("Intel", "pc", "🖥️"),
    "60:57:18": ("Intel", "pc", "🖥️"), "60:67:20": ("Intel", "pc", "🖥️"),
    "64:5d:86": ("Intel", "pc", "🖥️"), "68:05:ca": ("Intel", "pc", "🖥️"),
    "6c:88:14": ("Intel", "pc", "🖥️"), "70:5a:b6": ("Intel", "pc", "🖥️"),
    "74:e5:f9": ("Intel", "pc", "🖥️"), "78:92:9c": ("Intel", "pc", "🖥️"),
    "7c:5c:f8": ("Intel", "pc", "🖥️"), "80:19:34": ("Intel", "pc", "🖥️"),
    "84:3a:4b": ("Intel", "pc", "🖥️"), "84:7b:eb": ("Intel", "pc", "🖥️"),
    "88:53:95": ("Intel", "pc", "🖥️"), "8c:8d:28": ("Intel", "pc", "🖥️"),
    "90:e2:ba": ("Intel", "pc", "🖥️"), "94:65:9c": ("Intel", "pc", "🖥️"),
    "98:4f:ee": ("Intel", "pc", "🖥️"), "9c:eb:e8": ("Intel", "pc", "🖥️"),
    "a0:36:9f": ("Intel", "pc", "🖥️"), "a0:88:b4": ("Intel", "pc", "🖥️"),
    "a4:4e:31": ("Intel", "pc", "🖥️"), "a4:c3:f0": ("Intel", "pc", "🖥️"),
    "ac:72:89": ("Intel", "pc", "🖥️"), "b0:35:9f": ("Intel", "pc", "🖥️"),
    "b8:ae:ed": ("Intel", "pc", "🖥️"), "bc:0f:9a": ("Intel", "pc", "🖥️"),
    "c4:8e:8f": ("Intel", "pc", "🖥️"), "c8:d9:d2": ("Intel", "pc", "🖥️"),
    "cc:3d:82": ("Intel", "pc", "🖥️"), "d0:50:99": ("Intel", "pc", "🖥️"),
    "d4:be:d9": ("Intel", "pc", "🖥️"), "d8:fc:93": ("Intel", "pc", "🖥️"),
    "e0:06:e6": ("Intel", "pc", "🖥️"), "e8:b4:70": ("Intel", "pc", "🖥️"),
    "ec:08:6b": ("Intel", "pc", "🖥️"), "f4:06:69": ("Intel", "pc", "🖥️"),
    "f8:16:54": ("Intel", "pc", "🖥️"), "f8:63:3f": ("Intel", "pc", "🖥️"),

    # Realtek (common in PCs)
    "00:01:2e": ("Realtek", "pc", "🖥️"), "00:01:6c": ("Realtek", "pc", "🖥️"),
    "00:e0:4c": ("Realtek", "pc", "🖥️"), "10:7b:44": ("Realtek", "pc", "🖥️"),
    "2c:4d:54": ("Realtek", "pc", "🖥️"), "40:16:9f": ("Realtek", "pc", "🖥️"),
    "44:a8:42": ("Realtek", "pc", "🖥️"), "4c:cc:6a": ("Realtek", "pc", "🖥️"),
    "52:54:00": ("Realtek/QEMU", "linux", "🐧"), "54:04:a6": ("Realtek", "pc", "🖥️"),
    "80:fa:5b": ("Realtek", "pc", "🖥️"),

    # Lenovo
    "00:26:b9": ("Lenovo", "pc", "🖥️"), "04:7d:7b": ("Lenovo", "pc", "🖥️"),
    "10:93:e9": ("Lenovo", "pc", "🖥️"), "18:5e:0f": ("Lenovo", "pc", "🖥️"),
    "20:89:84": ("Lenovo", "pc", "🖥️"), "28:d2:44": ("Lenovo", "pc", "🖥️"),
    "40:8d:5c": ("Lenovo", "pc", "🖥️"), "44:37:e6": ("Lenovo", "pc", "🖥️"),
    "48:a4:72": ("Lenovo", "pc", "🖥️"), "4c:79:6e": ("Lenovo", "pc", "🖥️"),
    "50:7b:9d": ("Lenovo", "pc", "🖥️"), "54:ee:75": ("Lenovo", "pc", "🖥️"),
    "5c:f3:70": ("Lenovo", "pc", "🖥️"), "60:02:92": ("Lenovo", "pc", "🖥️"),
    "64:00:6a": ("Lenovo", "pc", "🖥️"), "6c:40:08": ("Lenovo", "pc", "🖥️"),
    "74:04:f1": ("Lenovo", "pc", "🖥️"), "78:2b:46": ("Lenovo", "pc", "🖥️"),
    "80:5e:c0": ("Lenovo", "pc", "🖥️"), "84:2b:2b": ("Lenovo", "pc", "🖥️"),
    "88:70:8c": ("Lenovo", "pc", "🖥️"), "8c:8d:28": ("Lenovo", "pc", "🖥️"),
    "90:2b:34": ("Lenovo", "pc", "🖥️"), "94:65:9c": ("Lenovo", "pc", "🖥️"),
    "98:fa:9b": ("Lenovo", "pc", "🖥️"), "a4:4e:31": ("Lenovo", "pc", "🖥️"),
    "c0:a5:e8": ("Lenovo", "pc", "🖥️"), "c0:b9:62": ("Lenovo", "pc", "🖥️"),
    "d4:81:d7": ("Lenovo", "pc", "🖥️"), "d8:bb:c1": ("Lenovo", "pc", "🖥️"),
    "e8:6a:64": ("Lenovo", "pc", "🖥️"), "f8:16:54": ("Lenovo", "pc", "🖥️"),
    "f8:a9:63": ("Lenovo", "pc", "🖥️"),

    # Dell
    "00:06:5b": ("Dell", "pc", "🖥️"), "00:08:74": ("Dell", "pc", "🖥️"),
    "00:0b:db": ("Dell", "pc", "🖥️"), "00:0d:56": ("Dell", "pc", "🖥️"),
    "00:0f:1f": ("Dell", "pc", "🖥️"), "00:10:18": ("Dell", "pc", "🖥️"),
    "00:11:43": ("Dell", "pc", "🖥️"), "00:12:3f": ("Dell", "pc", "🖥️"),
    "00:13:72": ("Dell", "pc", "🖥️"), "00:14:22": ("Dell", "pc", "🖥️"),
    "00:15:c5": ("Dell", "pc", "🖥️"), "00:16:f0": ("Dell", "pc", "🖥️"),
    "00:18:8b": ("Dell", "pc", "🖥️"), "00:19:b9": ("Dell", "pc", "🖥️"),
    "00:1a:4b": ("Dell", "pc", "🖥️"), "00:1b:fc": ("Dell", "pc", "🖥️"),
    "00:1c:23": ("Dell", "pc", "🖥️"), "00:1d:09": ("Dell", "pc", "🖥️"),
    "00:1e:4f": ("Dell", "pc", "🖥️"), "00:1f:d0": ("Dell", "pc", "🖥️"),
    "00:21:70": ("Dell", "pc", "🖥️"), "00:22:19": ("Dell", "pc", "🖥️"),
    "00:23:ae": ("Dell", "pc", "🖥️"), "00:24:e8": ("Dell", "pc", "🖥️"),
    "00:25:64": ("Dell", "pc", "🖥️"), "00:26:b9": ("Dell", "pc", "🖥️"),
    "08:00:27": ("Dell/VirtualBox", "pc", "🖥️"),
    "10:65:30": ("Dell", "pc", "🖥️"), "10:7d:1a": ("Dell", "pc", "🖥️"),
    "14:18:77": ("Dell", "pc", "🖥️"), "14:58:d0": ("Dell", "pc", "🖥️"),
    "14:fe:b5": ("Dell", "pc", "🖥️"), "18:03:73": ("Dell", "pc", "🖥️"),
    "18:66:da": ("Dell", "pc", "🖥️"), "18:a9:9b": ("Dell", "pc", "🖥️"),
    "1c:40:24": ("Dell", "pc", "🖥️"), "20:04:0f": ("Dell", "pc", "🖥️"),
    "20:47:47": ("Dell", "pc", "🖥️"), "24:b6:fd": ("Dell", "pc", "🖥️"),
    "28:92:4a": ("Dell", "pc", "🖥️"), "2c:76:8a": ("Dell", "pc", "🖥️"),
    "34:17:eb": ("Dell", "pc", "🖥️"), "34:48:ed": ("Dell", "pc", "🖥️"),
    "38:63:bb": ("Dell", "pc", "🖥️"), "3c:a9:f4": ("Dell", "pc", "🖥️"),
    "40:a8:f0": ("Dell", "pc", "🖥️"), "44:a8:42": ("Dell", "pc", "🖥️"),
    "48:4d:7e": ("Dell", "pc", "🖥️"), "4c:ed:fb": ("Dell", "pc", "🖥️"),
    "50:9a:4c": ("Dell", "pc", "🖥️"), "54:bf:64": ("Dell", "pc", "🖥️"),
    "58:8a:5a": ("Dell", "pc", "🖥️"), "5c:26:0a": ("Dell", "pc", "🖥️"),
    "60:03:08": ("Dell", "pc", "🖥️"), "60:57:18": ("Dell", "pc", "🖥️"),
    "64:00:6a": ("Dell", "pc", "🖥️"), "68:05:ca": ("Dell", "pc", "🖥️"),
    "6c:2b:59": ("Dell", "pc", "🖥️"), "74:86:7a": ("Dell", "pc", "🖥️"),
    "74:e6:e2": ("Dell", "pc", "🖥️"), "78:45:c4": ("Dell", "pc", "🖥️"),
    "80:18:44": ("Dell", "pc", "🖥️"), "84:7b:eb": ("Dell", "pc", "🖥️"),
    "90:b1:1c": ("Dell", "pc", "🖥️"), "98:90:96": ("Dell", "pc", "🖥️"),
    "9c:eb:e8": ("Dell", "pc", "🖥️"), "a0:36:9f": ("Dell", "pc", "🖥️"),
    "a4:1f:72": ("Dell", "pc", "🖥️"), "b0:83:fe": ("Dell", "pc", "🖥️"),
    "b8:ac:6f": ("Dell", "pc", "🖥️"), "bc:30:5b": ("Dell", "pc", "🖥️"),
    "c0:f8:7f": ("Dell", "pc", "🖥️"), "c8:1f:66": ("Dell", "pc", "🖥️"),
    "d4:be:d9": ("Dell", "pc", "🖥️"), "d8:9e:f3": ("Dell", "pc", "🖥️"),
    "dc:53:60": ("Dell", "pc", "🖥️"), "e0:db:55": ("Dell", "pc", "🖥️"),
    "e4:b9:7a": ("Dell", "pc", "🖥️"), "e8:b4:70": ("Dell", "pc", "🖥️"),
    "ec:f4:bb": ("Dell", "pc", "🖥️"), "f0:1f:af": ("Dell", "pc", "🖥️"),
    "f8:b1:56": ("Dell", "pc", "🖥️"), "f8:db:88": ("Dell", "pc", "🖥️"),
    "fc:15:b4": ("Dell", "pc", "🖥️"),

    # HP
    "00:01:e6": ("HP", "pc", "🖥️"), "00:02:a5": ("HP", "pc", "🖥️"),
    "00:04:ea": ("HP", "pc", "🖥️"), "00:08:02": ("HP", "pc", "🖥️"),
    "00:0b:cd": ("HP", "pc", "🖥️"), "00:0e:7f": ("HP", "pc", "🖥️"),
    "00:10:83": ("HP", "pc", "🖥️"), "00:11:0a": ("HP", "pc", "🖥️"),
    "00:12:79": ("HP", "pc", "🖥️"), "00:13:21": ("HP", "pc", "🖥️"),
    "00:14:38": ("HP", "pc", "🖥️"), "00:15:60": ("HP", "pc", "🖥️"),
    "00:16:35": ("HP", "pc", "🖥️"), "00:17:08": ("HP", "pc", "🖥️"),
    "00:18:71": ("HP", "pc", "🖥️"), "00:19:bb": ("HP", "pc", "🖥️"),
    "00:1a:4b": ("HP", "pc", "🖥️"), "00:1b:78": ("HP", "pc", "🖥️"),
    "00:1c:c4": ("HP", "pc", "🖥️"), "00:1d:c0": ("HP", "pc", "🖥️"),
    "00:1e:0b": ("HP", "pc", "🖥️"), "00:1f:29": ("HP", "pc", "🖥️"),
    "00:20:e0": ("HP", "pc", "🖥️"), "00:21:5a": ("HP", "pc", "🖥️"),
    "00:22:64": ("HP", "pc", "🖥️"), "00:23:7d": ("HP", "pc", "🖥️"),
    "00:24:81": ("HP", "pc", "🖥️"), "00:25:b3": ("HP", "pc", "🖥️"),
    "00:26:55": ("HP", "pc", "🖥️"), "10:60:4b": ("HP", "pc", "🖥️"),
    "14:02:ec": ("HP", "pc", "🖥️"), "18:a9:05": ("HP", "pc", "🖥️"),
    "1c:c1:de": ("HP", "pc", "🖥️"), "20:16:b9": ("HP", "pc", "🖥️"),
    "24:be:05": ("HP", "pc", "🖥️"), "28:92:4a": ("HP", "pc", "🖥️"),
    "2c:23:3a": ("HP", "pc", "🖥️"), "30:e1:71": ("HP", "pc", "🖥️"),
    "34:64:a9": ("HP", "pc", "🖥️"), "38:ea:a7": ("HP", "pc", "🖥️"),
    "3c:d9:2b": ("HP", "pc", "🖥️"), "40:b0:34": ("HP", "pc", "🖥️"),
    "48:0f:cf": ("HP", "pc", "🖥️"), "4c:39:09": ("HP", "pc", "🖥️"),
    "5c:b9:01": ("HP", "pc", "🖥️"), "64:51:06": ("HP", "pc", "🖥️"),
    "68:b5:99": ("HP", "pc", "🖥️"), "6c:3b:e5": ("HP", "pc", "🖥️"),
    "74:46:a0": ("HP", "pc", "🖥️"), "78:ac:c0": ("HP", "pc", "🖥️"),
    "7c:e9:d3": ("HP", "pc", "🖥️"), "80:ce:62": ("HP", "pc", "🖥️"),
    "84:34:97": ("HP", "pc", "🖥️"), "88:51:fb": ("HP", "pc", "🖥️"),
    "8c:dc:d4": ("HP", "pc", "🖥️"), "90:18:7c": ("HP", "pc", "🖥️"),
    "94:57:a5": ("HP", "pc", "🖥️"), "98:e7:f4": ("HP", "pc", "🖥️"),
    "9c:8e:99": ("HP", "pc", "🖥️"), "a0:1d:48": ("HP", "pc", "🖥️"),
    "a4:5d:36": ("HP", "pc", "🖥️"), "a8:26:d9": ("HP", "pc", "🖥️"),
    "ac:16:2d": ("HP", "pc", "🖥️"), "b0:5a:da": ("HP", "pc", "🖥️"),
    "b4:99:ba": ("HP", "pc", "🖥️"), "b8:ca:3a": ("HP", "pc", "🖥️"),
    "bc:ea:fa": ("HP", "pc", "🖥️"), "c4:34:6b": ("HP", "pc", "🖥️"),
    "c8:d3:ff": ("HP", "pc", "🖥️"), "d0:bf:9c": ("HP", "pc", "🖥️"),
    "d4:c9:ef": ("HP", "pc", "🖥️"), "d8:d3:85": ("HP", "pc", "🖥️"),
    "dc:4a:3e": ("HP", "pc", "🖥️"), "e0:07:1b": ("HP", "pc", "🖥️"),
    "e4:11:5b": ("HP", "pc", "🖥️"), "e8:39:35": ("HP", "pc", "🖥️"),
    "ec:b1:d7": ("HP", "pc", "🖥️"), "f0:92:1c": ("HP", "pc", "🖥️"),
    "f4:39:09": ("HP", "pc", "🖥️"), "f8:b1:56": ("HP", "pc", "🖥️"),
    "fc:15:b4": ("HP", "pc", "🖥️"),

    # Eero (Amazon mesh)
    "20:c0:47": ("Eero", "network", "🌐"), "30:94:d2": ("Eero", "network", "🌐"),
    "50:91:e3": ("Eero", "network", "🌐"), "54:83:3a": ("Eero", "network", "🌐"),
    "68:c6:3a": ("Eero", "network", "🌐"),

    # Sense (home energy)
    "00:00:5e": ("Sense", "iot", "⚡"),

    # LG Electronics
    "00:05:cd": ("LG", "tv", "📺"), "00:1c:62": ("LG", "tv", "📺"),
    "00:1e:75": ("LG", "tv", "📺"), "00:24:83": ("LG", "tv", "📺"),
    "00:26:e2": ("LG", "tv", "📺"), "04:b1:67": ("LG", "tv", "📺"),
    "10:68:3f": ("LG", "tv", "📺"), "14:c9:13": ("LG", "tv", "📺"),
    "18:3d:a2": ("LG", "tv", "📺"), "1c:08:c1": ("LG", "tv", "📺"),
    "28:cd:c1": ("LG", "tv", "📺"), "30:df:18": ("LG", "tv", "📺"),
    "34:d1:21": ("LG", "tv", "📺"), "38:8c:50": ("LG", "tv", "📺"),
    "3c:bd:d8": ("LG", "tv", "📺"), "40:b0:fa": ("LG", "tv", "📺"),
    "48:59:29": ("LG", "tv", "📺"), "4c:0f:6e": ("LG", "tv", "📺"),
    "50:c7:bf": ("LG", "tv", "📺"), "54:4a:16": ("LG", "tv", "📺"),
    "58:ef:68": ("LG", "tv", "📺"), "5c:49:79": ("LG", "tv", "📺"),
    "60:6b:ff": ("LG", "tv", "📺"), "64:99:5d": ("LG", "tv", "📺"),
    "6c:40:08": ("LG", "tv", "📺"), "70:2b:e8": ("LG", "tv", "📺"),
    "78:5d:c8": ("LG", "tv", "📺"), "7c:1c:68": ("LG", "tv", "📺"),
    "80:6c:1b": ("LG", "tv", "📺"), "84:80:de": ("LG", "tv", "📺"),
    "88:36:6c": ("LG", "tv", "📺"), "8c:3c:4a": ("LG", "tv", "📺"),
    "90:61:0c": ("LG", "tv", "📺"), "94:0c:e1": ("LG", "tv", "📺"),
    "a8:16:d0": ("LG", "tv", "📺"), "a8:23:fe": ("LG", "tv", "📺"),
    "ac:f1:df": ("LG", "tv", "📺"), "b4:e6:2d": ("LG", "tv", "📺"),
    "bc:f5:ac": ("LG", "tv", "📺"), "c0:97:27": ("LG", "tv", "📺"),
    "c4:36:6c": ("LG", "tv", "📺"), "c4:4e:ac": ("LG", "tv", "📺"),
    "cc:2d:8c": ("LG", "tv", "📺"), "d8:55:a3": ("LG", "tv", "📺"),
    "e8:5b:5b": ("LG", "tv", "📺"), "ec:9b:5b": ("LG", "tv", "📺"),
    "f4:4e:fd": ("LG", "tv", "📺"), "f8:0c:f3": ("LG", "tv", "📺"),
    "f8:95:c7": ("LG", "tv", "📺"),

    # HP Printers
    "00:01:e7": ("HP Printer", "printer", "🖨️"),
    "00:04:ea": ("HP Printer", "printer", "🖨️"),
    "00:11:85": ("HP Printer", "printer", "🖨️"),
    "00:12:79": ("HP Printer", "printer", "🖨️"),
    "00:13:21": ("HP Printer", "printer", "🖨️"),
    "00:14:38": ("HP Printer", "printer", "🖨️"),
    "00:17:08": ("HP Printer", "printer", "🖨️"),
    "00:1b:78": ("HP Printer", "printer", "🖨️"),
    "00:21:5a": ("HP Printer", "printer", "🖨️"),
    "64:51:06": ("HP Printer", "printer", "🖨️"),
    "9c:8e:99": ("HP Printer", "printer", "🖨️"),
    "a0:d3:c1": ("HP Printer", "printer", "🖨️"),
    "b8:ca:3a": ("HP Printer", "printer", "🖨️"),
    "e0:07:1b": ("HP Printer", "printer", "🖨️"),
    "f4:ce:46": ("HP Printer", "printer", "🖨️"),

    # Canon Printers
    "00:00:85": ("Canon Printer", "printer", "🖨️"),
    "00:1e:8f": ("Canon Printer", "printer", "🖨️"),
    "00:1f:a9": ("Canon Printer", "printer", "🖨️"),
    "04:2e:4e": ("Canon Printer", "printer", "🖨️"),
    "14:49:bc": ("Canon Printer", "printer", "🖨️"),
    "80:92:95": ("Canon Printer", "printer", "🖨️"),
    "84:71:27": ("Canon Printer", "printer", "🖨️"),
    "8c:9c:13": ("Canon Printer", "printer", "🖨️"),

    # Epson Printers
    "00:00:48": ("Epson Printer", "printer", "🖨️"),
    "00:1b:a9": ("Epson Printer", "printer", "🖨️"),
    "00:26:ab": ("Epson Printer", "printer", "🖨️"),
    "44:d2:44": ("Epson Printer", "printer", "🖨️"),
    "64:eb:8c": ("Epson Printer", "printer", "🖨️"),

    # Brother Printers
    "00:1b:a9": ("Brother Printer", "printer", "🖨️"),
    "00:80:77": ("Brother Printer", "printer", "🖨️"),
    "1c:f1:ee": ("Brother Printer", "printer", "🖨️"),
    "30:05:5c": ("Brother Printer", "printer", "🖨️"),
    "3c:2a:f4": ("Brother Printer", "printer", "🖨️"),

    # pfSense / Netgate
    "00:25:90": ("Netgate", "network", "🌐"),

    # Proxmox / VMware virtual
    "00:0c:29": ("VMware", "linux", "🐧"),
    "00:50:56": ("VMware", "linux", "🐧"),
    "00:1c:14": ("VMware", "linux", "🐧"),

    # QEMU/KVM
    "52:54:00": ("QEMU/KVM", "linux", "🐧"),

    # Hyper-V
    "00:15:5d": ("Hyper-V", "windows", "🖥️"),

    # Generic IoT / unknown Tuya/BEKEN chips
    "d0:c9:07": ("Tuya IoT", "iot", "🔌"),
    "60:fb:00": ("Tuya IoT", "iot", "🔌"),
    "84:72:07": ("Tuya IoT", "iot", "🔌"),
    "7c:87:ce": ("Tuya IoT", "iot", "🔌"),
    "f0:f1:2f": ("Tuya IoT", "iot", "🔌"),
}

# Device type display config: (label, CSS color)
DEVICE_TYPE_DISPLAY = {
    "apple":       ("Apple",       "#a8a8a8"),
    "android":     ("Android",     "#a4c639"),
    "windows":     ("Windows",     "#00a4ef"),
    "linux":       ("Linux",       "#e95420"),
    "amazon":      ("Amazon",      "#ff9900"),
    "iot":         ("IoT",         "#00b4d8"),
    "tv":          ("Smart TV",    "#9b59b6"),
    "printer":     ("Printer",     "#7f8c8d"),
    "nas":         ("NAS",         "#16a085"),
    "network":     ("Network",     "#27ae60"),
    "voip":        ("VoIP",        "#2980b9"),
    "gaming":      ("Gaming",      "#e74c3c"),
    "raspberry_pi":("Raspberry Pi","#c7053d"),
    "google":      ("Google",      "#4285f4"),
    "pc":          ("PC",          "#3498db"),
    "unknown":     ("Unknown",     "#555555"),
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
    "Apple":            "apple",
    "Apple TV":         "appletv",
    "Android":          "android",  # hostname detected
    "Samsung":          "samsung",
    "Amazon":           "amazon",
    "Amazon/Ecobee":    "amazon",
    "Eero":             "amazon",
    "Google":           "google",
    "Raspberry Pi":     "raspberrypi",
    "Roku":             "roku",
    "Ring":             "ring",
    "Sonos":            "sonos",
    "Ubiquiti":         "ubiquiti",
    "Cisco":            "cisco",
    "Netgear":          "netgear",
    "Synology":         "synology",
    "QNAP":             "qnap",
    "Philips Hue":      "philipshue",
    "TP-Link":          "tplink",
    "Nintendo":         "nintendo",
    "Sony PlayStation": "playstation",
    "Microsoft":        "microsoft",
    "Microsoft/Xbox":   "xbox",
    "Hyper-V":          "microsoft",
    "Dell":             "dell",
    "Dell/VirtualBox":  "dell",
    "HP":               "hp",
    "HP Printer":       "hp",
    "Lenovo":           "lenovo",
    "Intel":            "intel",
    "LG":               "lg",
    "Epson Printer":    "epson",
    "Brother Printer":  "brother",
    "Canon Printer":    "canon",
    "Lutron":           "lutron",
    "Nest":             "googlenest",
    "Espressif":        "espressif",
    "VMware":           "vmware",
    "Realtek/QEMU":     "qemu",
    "QEMU/KVM":         "qemu",
    "Netgate":          "netgate",
    "Meross":           "meross",
    "Ecobee":           "ecobee",
    "Belkin/Wemo":      "belkin",
    "Tuya IoT":         "tuya",
}

extensions.ICONS_BUNDLED_DIR = "/opt/jen/static/icons/brands"
extensions.ICONS_CUSTOM_DIR  = "/opt/jen/static/icons/custom"

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
        from jen.models.db import get_jen_db
        db = get_jen_db()
        with db.cursor() as cur:
            placeholders = ",".join(["%s"] * len(normalized))
            cur.execute(f"""
                SELECT LOWER(mac) AS mac,
                       COALESCE(manufacturer_override, manufacturer) AS manufacturer,
                       COALESCE(device_type_override, device_type) AS device_type,
                       COALESCE(device_icon_override, device_icon) AS device_icon,
                       manufacturer_override IS NOT NULL AS is_manual
                FROM devices WHERE LOWER(mac) IN ({placeholders})
            """, normalized)
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
        db.close()
    except Exception as e:
        logger.error(f"get_device_info_map error: {e}")
    return result
# ─────────────────────────────────────────
