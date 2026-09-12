"""
tests/test_kea_ddns.py
────────────────────────
v5.23.0 (Q19) — jen/services/kea_ddns.py: pure mutation of D2's own
config (kea-dhcp-ddns.conf, top-level "DhcpDdns"), separate from
kea_config_edit.py's Dhcp4/Dhcp6 shape.
"""

import copy

from jen.services import kea_ddns as d2


class TestAddDdnsDomain:
    def test_creates_forward_domain(self):
        cfg, code = d2.add_ddns_domain({}, "forward", "example.com.", "tsig1", [("10.0.0.53", 53)])
        assert code == "ok"
        domain = cfg["DhcpDdns"]["forward-ddns"]["ddns-domains"][0]
        assert domain["name"] == "example.com."
        assert domain["key-name"] == "tsig1"
        assert domain["dns-servers"] == [{"ip-address": "10.0.0.53", "port": 53}]

    def test_creates_reverse_domain_in_its_own_block(self):
        cfg, code = d2.add_ddns_domain({}, "reverse", "1.168.192.in-addr.arpa.", None, [("10.0.0.53", 53)])
        assert code == "ok"
        assert "forward-ddns" not in cfg["DhcpDdns"]
        assert cfg["DhcpDdns"]["reverse-ddns"]["ddns-domains"][0]["name"] == "1.168.192.in-addr.arpa."

    def test_no_key_name_omits_the_field(self):
        cfg, code = d2.add_ddns_domain({}, "forward", "example.com.", None, [("10.0.0.53", 53)])
        assert code == "ok"
        assert "key-name" not in cfg["DhcpDdns"]["forward-ddns"]["ddns-domains"][0]

    def test_multiple_dns_servers(self):
        cfg, code = d2.add_ddns_domain({}, "forward", "example.com.", None, [("10.0.0.53", 53), ("10.0.0.54", 53)])
        assert code == "ok"
        assert len(cfg["DhcpDdns"]["forward-ddns"]["ddns-domains"][0]["dns-servers"]) == 2

    def test_replaces_an_existing_domain_by_name(self):
        cfg, _ = d2.add_ddns_domain({}, "forward", "example.com.", "old-key", [("10.0.0.53", 53)])
        cfg, code = d2.add_ddns_domain(cfg, "forward", "example.com.", "new-key", [("10.0.0.99", 53)])
        assert code == "ok"
        domains = cfg["DhcpDdns"]["forward-ddns"]["ddns-domains"]
        assert len(domains) == 1
        assert domains[0]["key-name"] == "new-key"

    def test_does_not_mutate_the_caller_dict(self):
        original = {"DhcpDdns": {"forward-ddns": {"ddns-domains": []}}}
        snapshot = copy.deepcopy(original)
        d2.add_ddns_domain(original, "forward", "example.com.", None, [("10.0.0.53", 53)])
        assert original == snapshot


class TestRemoveDdnsDomain:
    def test_removes_by_name(self):
        cfg, _ = d2.add_ddns_domain({}, "forward", "example.com.", None, [("10.0.0.53", 53)])
        cfg, code = d2.remove_ddns_domain(cfg, "forward", "example.com.")
        assert code == "ok"
        assert cfg["DhcpDdns"]["forward-ddns"]["ddns-domains"] == []

    def test_missing_domain_is_notfound(self):
        cfg, code = d2.remove_ddns_domain({}, "forward", "ghost.")
        assert code == "notfound"

    def test_only_removes_from_the_named_direction(self):
        cfg, _ = d2.add_ddns_domain({}, "forward", "example.com.", None, [("10.0.0.53", 53)])
        cfg, _ = d2.add_ddns_domain(cfg, "reverse", "1.168.192.in-addr.arpa.", None, [("10.0.0.53", 53)])
        cfg, code = d2.remove_ddns_domain(cfg, "forward", "example.com.")
        assert code == "ok"
        assert cfg["DhcpDdns"]["reverse-ddns"]["ddns-domains"][0]["name"] == "1.168.192.in-addr.arpa."


class TestSetTsigKey:
    def test_creates_a_key(self):
        cfg, code = d2.set_tsig_key({}, "tsig1", "hmac-sha256", "s3cr3t")
        assert code == "ok"
        assert cfg["DhcpDdns"]["tsig-keys"][0] == {"name": "tsig1", "algorithm": "hmac-sha256", "secret": "s3cr3t"}

    def test_replaces_an_existing_key_by_name(self):
        cfg, _ = d2.set_tsig_key({}, "tsig1", "hmac-sha256", "old-secret")
        cfg, code = d2.set_tsig_key(cfg, "tsig1", "hmac-sha512", "new-secret")
        assert code == "ok"
        keys = cfg["DhcpDdns"]["tsig-keys"]
        assert len(keys) == 1
        assert keys[0] == {"name": "tsig1", "algorithm": "hmac-sha512", "secret": "new-secret"}

    def test_does_not_mutate_the_caller_dict(self):
        original = {"DhcpDdns": {}}
        snapshot = copy.deepcopy(original)
        d2.set_tsig_key(original, "tsig1", "hmac-sha256", "s3cr3t")
        assert original == snapshot


class TestRemoveTsigKey:
    def test_removes_an_unreferenced_key(self):
        cfg, _ = d2.set_tsig_key({}, "tsig1", "hmac-sha256", "s3cr3t")
        cfg, code = d2.remove_tsig_key(cfg, "tsig1")
        assert code == "ok"
        assert cfg["DhcpDdns"]["tsig-keys"] == []

    def test_missing_key_is_notfound(self):
        cfg, code = d2.remove_tsig_key({}, "ghost")
        assert code == "notfound"

    def test_refused_while_referenced_by_a_forward_domain(self):
        cfg, _ = d2.set_tsig_key({}, "tsig1", "hmac-sha256", "s3cr3t")
        cfg, _ = d2.add_ddns_domain(cfg, "forward", "example.com.", "tsig1", [("10.0.0.53", 53)])
        _cfg2, code = d2.remove_tsig_key(cfg, "tsig1")
        assert code == "referenced"

    def test_refused_while_referenced_by_a_reverse_domain(self):
        cfg, _ = d2.set_tsig_key({}, "tsig1", "hmac-sha256", "s3cr3t")
        cfg, _ = d2.add_ddns_domain(cfg, "reverse", "1.168.192.in-addr.arpa.", "tsig1", [("10.0.0.53", 53)])
        _cfg2, code = d2.remove_tsig_key(cfg, "tsig1")
        assert code == "referenced"

    def test_removable_once_the_referencing_domain_is_gone(self):
        cfg, _ = d2.set_tsig_key({}, "tsig1", "hmac-sha256", "s3cr3t")
        cfg, _ = d2.add_ddns_domain(cfg, "forward", "example.com.", "tsig1", [("10.0.0.53", 53)])
        cfg, _ = d2.remove_ddns_domain(cfg, "forward", "example.com.")
        _cfg2, code = d2.remove_tsig_key(cfg, "tsig1")
        assert code == "ok"


class TestSuggestReverseZone:
    def test_slash_24(self):
        assert d2.suggest_reverse_zone("192.168.1.0/24") == "1.168.192.in-addr.arpa."

    def test_slash_16(self):
        assert d2.suggest_reverse_zone("172.16.0.0/16") == "16.172.in-addr.arpa."

    def test_slash_8(self):
        assert d2.suggest_reverse_zone("10.0.0.0/8") == "10.in-addr.arpa."

    def test_classless_prefix_returns_none(self):
        assert d2.suggest_reverse_zone("192.168.1.0/25") is None
        assert d2.suggest_reverse_zone("192.168.1.0/30") is None

    def test_ipv6_returns_none(self):
        assert d2.suggest_reverse_zone("2001:db8::/32") is None

    def test_unparsable_returns_none(self):
        assert d2.suggest_reverse_zone("not-a-cidr") is None
        assert d2.suggest_reverse_zone("") is None

    def test_non_network_aligned_host_bits_still_resolve_via_the_network_address(self):
        # strict=False — a host address with the /24 mask still yields
        # the containing network's reverse zone, same as ipaddress does
        # elsewhere in this codebase (kea_authoring._pool_for_cidr).
        assert d2.suggest_reverse_zone("192.168.1.55/24") == "1.168.192.in-addr.arpa."
