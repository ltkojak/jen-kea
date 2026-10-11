"""Item 2 (Q172): the device inventory update is `alerts.update_device_inventory(leases)` (extracted from `check_alerts` so it can be tested): a lease
whose hardware address is not six bytes is skipped with one warning, and never rolls back the rest."""

from jen.services import alerts


def _lease(ip, hwaddr, hostname="h", subnet_id=1):
    return {"ip": ip, "hwaddr": hwaddr, "hostname": hostname, "subnet_id": subnet_id}


def _clean(db):
    with db.cursor() as cur:
        cur.execute("DELETE FROM devices WHERE mac LIKE 'aa:bb:cc:dd:ee:%'")
    db.commit()


class TestALongHardwareAddressDoesNotStopTheFleet:
    def test_six_byte_rows_are_upserted_beside_a_twenty_byte_one(self, db, caplog):
        _clean(db)
        leases = [
            _lease("10.0.0.1", bytes.fromhex("aabbccddee01")),
            _lease("10.0.0.2", bytes(20)),
            _lease("10.0.0.3", bytes.fromhex("aabbccddee03")),
        ]
        with caplog.at_level("WARNING"):
            result = alerts.update_device_inventory(leases)
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT mac FROM devices WHERE mac LIKE 'aa:bb:cc:dd:ee:%' ORDER BY mac")
            macs = [r["mac"] for r in cur.fetchall()]
        assert macs == ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:03"]
        assert result["skipped"] == 1 and result["updated"] == 2 and "not six bytes" in caplog.text
        assert caplog.text.count("not six bytes") == 1, "one warning per sweep, with the count"
        _clean(db)

    def test_a_lease_with_no_hardware_address_is_skipped_too(self, db):
        _clean(db)
        result = alerts.update_device_inventory(
            [_lease("10.0.0.9", None), _lease("10.0.0.1", bytes.fromhex("aabbccddee05"))]
        )
        assert result["skipped"] == 1 and result["updated"] == 1
        _clean(db)

    def test_one_row_that_fails_does_not_roll_back_the_others(self, db):
        _clean(db)
        leases = [
            _lease("10.0.0.1", bytes.fromhex("aabbccddee11")),
            _lease("10.0.0.2", bytes.fromhex("aabbccddee12"), hostname="x" * 600),
            _lease("10.0.0.3", bytes.fromhex("aabbccddee13")),
        ]
        result = alerts.update_device_inventory(leases)
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT mac FROM devices WHERE mac LIKE 'aa:bb:cc:dd:ee:1%' ORDER BY mac")
            macs = [r["mac"] for r in cur.fetchall()]
        assert "aa:bb:cc:dd:ee:11" in macs and "aa:bb:cc:dd:ee:13" in macs, (
            "the good rows landed although a neighbour failed"
        )
        assert result["failed"] == 1
        _clean(db)

    def test_the_batch_commits_every_two_hundred_rows(self):
        import inspect

        assert alerts.DEVICE_COMMIT_EVERY == 200
        assert "DEVICE_COMMIT_EVERY" in inspect.getsource(alerts.update_device_inventory)
