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
