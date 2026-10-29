
from analytics.identity_guard import (
    verify_identity_snapshots
)

print("=" * 60)
print("STEP 406: IDENTITY CHANGE SAFETY TEST")
print("=" * 60)

original = {
    "id": 2,
    "ip_address": "192.168.8.102",
    "mac_address": "02:11:22:33:44:66"
}

checks = {}


def verify_change(changes, expected):
    modified = dict(original)
    modified.update(changes)

    safe, reason = verify_identity_snapshots(
        original, modified
    )

    return safe is False and reason == expected


safe, reason = verify_identity_snapshots(
    original, dict(original)
)

checks["Unchanged identity accepted"] = (
    safe is True
    and reason == "IDENTITY_VERIFIED"
)

checks["IP change rejected"] = verify_change(
    {"ip_address": "192.168.8.110"},
    "IP_CHANGED"
)

checks["MAC change rejected"] = verify_change(
    {"mac_address": "02:AA:BB:CC:DD:EE"},
    "MAC_CHANGED"
)

checks["Device ID change rejected"] = verify_change(
    {"id": 999999},
    "DEVICE_ID_CHANGED"
)

checks["Missing device rejected"] = (
    verify_identity_snapshots(original, None)
    == (False, "DEVICE_NOT_FOUND")
)

invalid = dict(original)
invalid["mac_address"] = "AUTO-CAPTURED"

checks["Invalid MAC rejected"] = (
    verify_identity_snapshots(invalid, invalid)
    == (False, "INVALID_MAC")
)

invalid = dict(original)
invalid["ip_address"] = "not-an-ip"

checks["Invalid IP rejected"] = (
    verify_identity_snapshots(invalid, invalid)
    == (False, "INVALID_IP")
)

print("\n=== TEST RESULTS ===")

for name, passed in checks.items():
    print(
        f"{'PASS' if passed else 'FAIL'} | {name}"
    )

passed = sum(checks.values())
failed = len(checks) - passed

print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)
print("Passed:", passed)
print("Failed:", failed)
print("Overall:", "PASS" if failed == 0 else "FAIL")

assert failed == 0

print("No production database changes.")
print("No router operations.")
