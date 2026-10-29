
"""
NetGuardian - Step 436
Isolated capture health integration tests.

Tests the actual packet callback and sniffer worker,
with mocked Scapy and database operations.

No real packet capture.
No production database writes.
No router operations.
"""

from types import SimpleNamespace
from unittest.mock import patch

import capture.packet_capture as capture
from capture.worker_health import CaptureWorkerHealth


print("=" * 60)
print("STEP 436: CAPTURE HEALTH INTEGRATION TEST")
print("=" * 60)

passed = 0


def check(name, condition):
    global passed
    assert condition, "FAIL: " + name
    passed += 1
    print("PASS:", name)


# The identity of these sentinel objects lets us
# simulate only an IPv4 packet without using Scapy.
FAKE_IP = object()


class FakePacket:
    def haslayer(self, layer):
        return layer is FAKE_IP

    def getlayer(self, layer):
        if layer is FAKE_IP:
            return SimpleNamespace(
                src="192.168.8.102",
                dst="8.8.8.8"
            )
        return None

    def __len__(self):
        return 128


health = CaptureWorkerHealth(
    max_write_age_seconds=75
)

# All external I/O paths are replaced by mocks.
with (
    patch.object(capture, "capture_health", health),
    patch.object(capture, "SCAPY_AVAILABLE", True),
    patch.object(capture, "IP", FAKE_IP),
    patch.object(capture, "get_protocol", return_value="TCP"),
    patch.object(capture, "get_local_ip", return_value=None),
    patch.object(capture, "get_local_mac", return_value=None),
    patch.object(
        capture,
        "get_device_by_ip",
        return_value={"id": 2}
    ),
    patch.object(capture, "save_traffic_record") as stats_save,
    patch.object(capture, "log_traffic") as core_save,
    patch.object(capture, "create_traffic_table")
):

    print("\n=== PACKET CALLBACK TESTS ===")

    health.start()

    capture.process_packet(FakePacket())

    snapshot = health.snapshot()

    check(
        "Packet reception tracked",
        snapshot["packets_received"] == 1
    )

    check(
        "Successful database persistence tracked",
        snapshot["traffic_records_persisted"] == 1
    )

    check(
        "Healthy candidate reported after persistence",
        snapshot["status"] == "CAPTURING"
    )

    check(
        "Core database writer called",
        core_save.call_count == 1
    )

    check(
        "Statistics writer called",
        stats_save.call_count == 1
    )

    print("\n=== DATABASE WRITE FAILURE TEST ===")

    core_save.side_effect = RuntimeError(
        "Synthetic SQLite write failure"
    )

    capture.process_packet(FakePacket())

    snapshot = health.snapshot()

    check(
        "Write failure tracked",
        snapshot["persistence_failures"] == 1
    )

    check(
        "Failed write not counted as persisted",
        snapshot["traffic_records_persisted"] == 1
    )

    check(
        "Failed write produces unhealthy state",
        snapshot["status"] == "WRITE_ERROR"
        and not snapshot["heartbeat_candidate"]
    )

    print("\n=== RECOVERY TEST ===")

    core_save.side_effect = None

    capture.process_packet(FakePacket())

    snapshot = health.snapshot()

    check(
        "Successful write after failure tracked",
        snapshot["traffic_records_persisted"] == 2
        and snapshot["persistence_failures"] == 1
    )

    # Both operations use the real monotonic clock.
    # The test is expected to complete within a second,
    # but a later focused test can simulate exact times.
    check(
        "Healthy candidate restored",
        snapshot["status"] == "CAPTURING"
    )

    print("\n=== NORMAL WORKER EXIT ===")

    health.stop()
    health.start()

    with patch.object(capture, "sniff", side_effect=lambda **kwargs: capture._stop_capture.set()) as fake_sniff:
        capture._sniff_worker("TEST_INTERFACE")

        check(
            "Normal sniffer invocation attempted",
            fake_sniff.call_count == 1
        )

    check(
        "Normal worker exit clears healthy status",
        health.snapshot()["status"] == "STOPPED"
    )

    capture._stop_capture.clear()

    print("\n=== SNIFFER EXCEPTION ===")

    with patch.object(
        capture,
        "sniff",
        side_effect=RuntimeError("Synthetic sniff failure")
    ):
        capture._sniff_worker("TEST_INTERFACE")

    snapshot = health.snapshot()

    check(
        "Worker exception leaves worker stopped",
        snapshot["status"] == "STOPPED"
        and snapshot["running"] is False
    )

    check(
        "Worker exception type retained",
        snapshot["worker_error"] == "RuntimeError"
    )

print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)

print("Passed:", passed)
print("Failed:", 14 - passed)
print("Overall:", "PASS" if passed == 14 else "FAIL")
print("Production database writes: NONE")
print("Real packet capture started: NO")
print("Router operations: NONE")

assert passed == 14
