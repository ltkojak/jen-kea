# Real-world dhcpd.conf fixtures

Drop sanitized ISC `dhcpd.conf` files here (`*.conf`). `tests/test_isc_dhcp_import.py`
parses every one and asserts the importer never raises and yields scopes or
warnings.

Sanitize before committing: replace real hostnames, MACs, public IPs, keys and
secrets (`key`/`secret` statements, DDNS `key` blocks). Private ranges are fine.

`synthetic-dhcpd.conf` is a copy of `tests/fixtures/dhcpd.conf` (the harness's
first case).
