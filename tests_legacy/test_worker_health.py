
"""
NetGuardian - Step 434

Isolated worker-health unit tests.

No Scapy capture, SQLite access, or router operations.
"""

from capture.worker_health import CaptureWorkerHealth

print("=" * 60)
print("STEP 434: CAPTURE WORKER HEALTH TEST")
print("=" * 60)

passed = 0


def check(name, condition):
    global passed
    assert condition, "FAIL: " + name
    passed += 1
    print("PASS:", name)


health = CaptureWorkerHealth(
    max_write_age_seconds=75
)

check(
    "Initially stopped",
    health.snapshot(now=100)["status"] == "STOPPED"
)

health.start(now=100)

check(
    "Worker start alone does not prove capture",
    health.snapshot(now=100)["status"] == "UNVERIFIED"
)

health.packet_received(now=110)

check(
    "Received packet alone does not prove persistence",
    health.snapshot(now=110)["status"] == "UNVERIFIED"
)

health.traffic_persisted(now=112)

check(
    "Successful persistence permits healthy candidate",
    health.snapshot(now=120)["status"] == "CAPTURING"
)

check(
    "Persistence counter correct",
    health.snapshot(now=120)["traffic_records_persisted"] == 1
)

check(
    "Stale persistence is not healthy",
    health.snapshot(now=200)["status"] == "UNVERIFIED"
)

health.persistence_failed(
    error=RuntimeError("Synthetic database failure"),
    now=205
)

check(
    "Database write failure detected",
    health.snapshot(now=206)["status"] == "WRITE_ERROR"
)

health.traffic_persisted(now=210)

check(
    "Subsequent successful write clears active failure",
    health.snapshot(now=211)["status"] == "CAPTURING"
)

check(
    "Counters retain write failure history",
    health.snapshot(now=211)["persistence_failures"] == 1
)

health.stop(error=RuntimeError("Synthetic sniff error"))

check(
    "Stopped worker cannot report healthy",
    health.snapshot(now=212)["status"] == "STOPPED"
    and not health.snapshot(now=212)["heartbeat_candidate"]
)

health.start(now=300)

check(
    "Restart resets stale healthy state",
    health.snapshot(now=300)["status"] == "UNVERIFIED"
)

health.packet_received(now=305)

check(
    "Restarted worker requires new successful persistence",
    health.snapshot(now=306)["status"] == "UNVERIFIED"
)

try:
    CaptureWorkerHealth(max_write_age_seconds=0)
except ValueError:
    check("Invalid write-age threshold rejected", True)
else:
    raise AssertionError("Invalid threshold accepted")

print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)
print("Passed:", passed)
print("Failed:", 13 - passed)
print("Overall:", "PASS" if passed == 13 else "FAIL")
print("Production database changes: NONE")
print("Packet capture modified: NO")
print("Heartbeat database writes: NONE")
print("Router operations: NONE")
