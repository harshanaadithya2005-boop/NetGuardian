
from datetime import datetime

from analytics.collection_schedule import (
    get_safe_completed_window_end
)

print("=" * 60)
print("STEP 412: COLLECTION SAFETY DELAY TEST")
print("=" * 60)

tests = [
    (
        "Before safety delay",
        datetime(2026, 10, 25, 10, 46),
        datetime(2026, 10, 25, 10, 40)
    ),
    (
        "Exactly two minutes after window",
        datetime(2026, 10, 25, 10, 47),
        datetime(2026, 10, 25, 10, 45)
    ),
    (
        "Later within same collection period",
        datetime(2026, 10, 25, 10, 49),
        datetime(2026, 10, 25, 10, 45)
    ),
    (
        "Next eligible window",
        datetime(2026, 10, 25, 10, 52),
        datetime(2026, 10, 25, 10, 50)
    ),
    (
        "Hour boundary",
        datetime(2026, 10, 25, 11, 1),
        datetime(2026, 10, 25, 10, 55)
    ),
]

passed = 0

for name, current_time, expected in tests:
    actual = get_safe_completed_window_end(
        now=current_time,
        delay_minutes=2
    )

    success = actual == expected

    print(
        f"{'PASS' if success else 'FAIL'} | "
        f"{name} | "
        f"Selected: {actual.strftime('%H:%M')}"
    )

    assert success
    passed += 1


print("\n=== INVALID SETTINGS ===")

try:
    get_safe_completed_window_end(
        delay_minutes=-1
    )
except ValueError:
    print("PASS | Negative delay rejected")
    passed += 1
else:
    raise AssertionError("Negative delay accepted")


print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)

print("Passed:", passed)
print("Failed:", 6 - passed)
print("Overall:", "PASS" if passed == 6 else "FAIL")

print("Production database changes: None")
print("Router operations: None")
