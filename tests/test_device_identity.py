"""
tests/test_device_identity.py
─────────────────────────────
Trusted-device identification (v4.3.0): user-agent parsing and the
friendly description format used for MFA trusted devices.
"""

from jen.services.fingerprint import friendly_user_agent, describe_client_device


IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) "
          "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1")
WINDOWS_CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")
WINDOWS_EDGE = WINDOWS_CHROME + " Edg/147.0.0.0"
MAC_SAFARI = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15")
LINUX_FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
ANDROID_CHROME = ("Mozilla/5.0 (Linux; Android 15; Pixel 9) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36")


class TestFriendlyUserAgent:

    def test_iphone_safari(self):
        assert friendly_user_agent(IPHONE) == "iPhone (iOS 18.7) · Safari"

    def test_windows_chrome(self):
        assert friendly_user_agent(WINDOWS_CHROME) == "Windows · Chrome 147"

    def test_edge_not_mistaken_for_chrome(self):
        assert friendly_user_agent(WINDOWS_EDGE) == "Windows · Edge 147"

    def test_mac_safari_not_mistaken_for_chrome(self):
        assert friendly_user_agent(MAC_SAFARI) == "Mac · Safari"

    def test_linux_firefox(self):
        assert friendly_user_agent(LINUX_FIREFOX) == "Linux · Firefox 128"

    def test_android_chrome(self):
        assert friendly_user_agent(ANDROID_CHROME) == "Android 15 · Chrome 146"

    def test_empty_and_garbage(self):
        assert friendly_user_agent("") == "Unknown device"
        assert friendly_user_agent("   ") == "Unknown device"
        assert friendly_user_agent("curl/8.5.0") == "Unknown device"


class TestDescribeClientDevice:

    def test_without_hostname_falls_back_to_ua(self, monkeypatch):
        import jen.services.fingerprint as fp
        monkeypatch.setattr(fp, "client_hostname", lambda ip: "")
        assert describe_client_device("10.0.0.5", WINDOWS_CHROME) == "Windows · Chrome 147"

    def test_with_hostname_prefixes_it(self, monkeypatch):
        import jen.services.fingerprint as fp
        monkeypatch.setattr(fp, "client_hostname", lambda ip: "kojak-pc")
        assert describe_client_device("10.0.0.5", WINDOWS_CHROME) == "kojak-pc — Windows · Chrome 147"

    def test_result_capped_at_200_chars(self, monkeypatch):
        import jen.services.fingerprint as fp
        monkeypatch.setattr(fp, "client_hostname", lambda ip: "h" * 300)
        assert len(describe_client_device("10.0.0.5", WINDOWS_CHROME)) <= 200


class TestHealResilience:
    """v4.3.1: heal must catch 'Unknown' anywhere in the name, prefer live UA,
    fall back to stored UA, and never replace a name with a worse one."""

    CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")

    @staticmethod
    def _heal(name, stored_ua, live_ua, hostname_result):
        from jen.services.fingerprint import friendly_user_agent
        needs_heal = (not name.strip() or "unknown" in name.lower()
                      or "Mozilla/" in name)
        if not needs_heal:
            return name
        heal_ua = live_ua or stored_ua
        friendly = friendly_user_agent(heal_ua)
        candidate = (f"{hostname_result} — {friendly}"
                     if hostname_result else friendly)
        if "unknown" not in candidate.lower() or not name.strip():
            return candidate
        return name

    def test_frozen_unknown_row_not_thrashed_without_ua(self):
        assert self._heal("halifax — Unknown device", "", "", "halifax") \
            == "halifax — Unknown device"

    def test_frozen_unknown_row_heals_with_live_ua(self):
        assert self._heal("halifax — Unknown device", "", self.CHROME, "halifax") \
            == "halifax — Windows · Chrome 147"

    def test_heals_from_stored_ua_when_live_missing(self):
        assert self._heal("halifax — Unknown device", self.CHROME, "", "halifax") \
            == "halifax — Windows · Chrome 147"

    def test_raw_ua_legacy_row_parses(self):
        assert self._heal(self.CHROME[:80], "", self.CHROME, "") \
            == "Windows · Chrome 147"

    def test_good_name_never_degraded(self):
        assert self._heal("halifax — Windows · Chrome 147", self.CHROME, "", "halifax") \
            == "halifax — Windows · Chrome 147"


class TestWerkzeugUserAgentTrap:
    """v4.3.3: werkzeug 2.1+ UserAgent.__bool__ keys off the parsed .browser
    field, which is always None without a UA-parser plugin — so the object is
    ALWAYS falsy even when the header is present. The idiom
    `request.user_agent.string if request.user_agent else ""` therefore
    silently returns "" for every request. Read the header directly."""

    UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")

    def test_useragent_object_is_falsy_despite_header(self):
        from werkzeug.user_agent import UserAgent
        ua = UserAgent(self.UA)
        assert ua.string == self.UA
        assert not ua, "if this ever becomes truthy, the trap is gone upstream"

    def test_direct_header_read_returns_ua(self):
        from werkzeug.test import EnvironBuilder
        from werkzeug.wrappers import Request
        req = Request(EnvironBuilder(headers={"User-Agent": self.UA}).get_environ())
        assert req.headers.get("User-Agent", "") == self.UA

    def test_banned_idiom_absent_from_codebase(self):
        """Grep guard: `request.user_agent` must not appear anywhere in jen/."""
        import os
        offenders = []
        for root, _, files in os.walk("jen"):
            for f in files:
                if f.endswith(".py"):
                    p = os.path.join(root, f)
                    if "request.user_agent" in open(p).read():
                        offenders.append(p)
        assert not offenders, f"banned idiom found in: {offenders}"
