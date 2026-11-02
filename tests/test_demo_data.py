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


class TestTheOneClientClass:
    """Q209 - the Explain capture needs a class step to show. The demo dataset's fake Kea config carries ONE client class
    whose test reads the featured client's hostname; the default dataset's config (the 22 journeys) carries none."""

    def test_the_demo_config_gets_exactly_one_class_and_the_default_config_none(self):
        from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, build_dhcp4_config

        classes = demo_data.client_classes()
        assert len(classes) == 1
        demo = build_dhcp4_config(demo_data.SUBNETS, demo_data.SUBNET_ROUTERS, client_classes=classes)
        assert demo["client-classes"] == classes
        assert "client-classes" not in TWO_SUBNET_DHCP4
        assert "client-classes" not in build_dhcp4_config(demo_data.SUBNETS, demo_data.SUBNET_ROUTERS)

    def test_the_class_matches_the_featured_client_by_the_hostname_it_has(self):
        from jen.services import dhcp_explain

        (cls,) = demo_data.client_classes()
        featured = demo_data.featured_client()
        missing: set[str] = set()
        verdict = dhcp_explain.evaluate(
            dhcp_explain.parse_expression(cls["test"]), {"hostname": featured["hostname"]}, {}, missing
        )
        assert verdict is True and not missing

    def test_the_class_is_deterministic(self):
        assert demo_data.client_classes() == demo_data.client_classes()
