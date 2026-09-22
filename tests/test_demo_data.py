"""
tests/test_demo_data.py
─────────────────────────
v5.56.1 (Q68e) — tests/e2e/demo_data.py's fictional homelab paired each
hostname with an INDEPENDENTLY random vendor, so the README's own
screenshots showed a printer badged Roku and an access point badged
Amazon. Pure (no DB, no Playwright) so it runs without JEN_E2E_DATASET=demo.
"""

from tests.e2e import demo_data


class TestHostnameVendorPairing:
    def test_every_paired_vendor_is_a_known_vendor(self):
        unknown = [(h, v) for h, v in demo_data.HOSTNAMES if v not in demo_data.VENDOR_PREFIXES]
        assert unknown == []

    def test_no_duplicate_hostnames(self):
        names = [h for h, _ in demo_data.HOSTNAMES]
        assert len(names) == len(set(names))

    def test_the_vendors_the_bug_report_named_are_fixed(self):
        # v5.56.0-beta.1's phone-leases.png showed printer-office/downstairs-ap
        # badged Roku, switch-core badged Amazon, pixel-guest badged Apple.
        pairs = dict(demo_data.HOSTNAMES)
        assert pairs["printer-office"] == "Brother Printer"
        assert pairs["printer-2f"] == "Brother Printer"
        assert pairs["downstairs-ap"] == "Ubiquiti"
        assert pairs["upstairs-ap"] == "Ubiquiti"
        assert pairs["switch-core"] == "Ubiquiti"
        assert pairs["pixel-guest"] == "Google"

    def test_active_leases_carry_their_paired_vendor(self):
        leased = dict(demo_data.HOSTNAMES)
        for lease in demo_data.active_leases():
            assert lease["vendor"] == leased[lease["hostname"]]
