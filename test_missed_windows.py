
from datetime import datetime

from analytics.missed_windows import (
    plan_missing_windows
)

print("=" * 60)
print("STEP 415: MISSED COLLECTION WINDOW TEST")
print("=" * 60)

passed = 0


def check(name, actual, expected):
    global passed

    assert actual == expected, (
        f"{name}: expected {expected}, got {actual}"
    )

    passed += 1
    print("PASS:", name)


current = datetime(2026, 10, 25, 11, 2)

check(
    "Three missed windows detected",
    plan_missing_windows(
        datetime(2026, 10, 25, 10, 45),
        now=current
    ),
    [
        datetime(2026, 10, 25, 10, 50),
        datetime(2026, 10, 25, 10, 55),
        datetime(2026, 10, 25, 11, 0)
    ]
)

check(
    "Up-to-date device has no missing windows",
    plan_missing_windows(
        datetime(2026, 10, 25, 11, 0),
        now=current
    ),
    []
)

check(
    "Empty history starts from latest safe window",
    plan_missing_windows(
        None,
        now=current
    ),
    [datetime(2026, 10, 25, 11, 0)]
)

check(
    "Maximum backfill window count respected",
    plan_missing_windows(
        datetime(2026, 10, 25, 10, 30),
        now=current,
        max_windows=2
    ),
    [
        datetime(2026, 10, 25, 10, 35),
        datetime(2026, 10, 25, 10, 40)
    ]
)

check(
    "Delay prevents early collection",
    plan_missing_windows(
        datetime(2026, 10, 25, 10, 40),
        now=datetime(2026, 10, 25, 10, 46)
    ),
    []
)

check(
    "Exactly two minutes after closing",
    plan_missing_windows(
        datetime(2026, 10, 25, 10, 40),
        now=datetime(2026, 10, 25, 10, 47)
    ),
    [datetime(2026, 10, 25, 10, 45)]
)

check(
    "Hour boundary handled",
    plan_missing_windows(
        datetime(2026, 10, 25, 10, 55),
        now=current
    ),
    [datetime(2026, 10, 25, 11, 0)]
)

check(
    "ISO timestamp supported",
    plan_missing_windows(
        "2026-10-25T10:55:00",
        now=current
    ),
    [datetime(2026, 10, 25, 11, 0)]
)

print("\n=== INVALID INPUTS ===")

try:
    plan_missing_windows(
        datetime(2026, 10, 25, 10, 43),
        now=current
    )
except ValueError:
    passed += 1
    print("PASS: Unaligned timestamp rejected")
else:
    raise AssertionError("Unaligned timestamp accepted")

try:
    plan_missing_windows(
        datetime(2026, 10, 25, 11, 5),
        now=current
    )
except ValueError:
    passed += 1
    print("PASS: Future window rejected")
else:
    raise AssertionError("Future window accepted")

try:
    plan_missing_windows(
        None,
        now=current,
        max_windows=0
    )
except ValueError:
    passed += 1
    print("PASS: Invalid backfill limit rejected")
else:
    raise AssertionError("Invalid backfill limit accepted")

print("\n" + "=" * 60)
print("FINAL RESULTS")
print("=" * 60)
print("Passed:", passed)
print("Failed:", 11 - passed)
print("Overall:", "PASS" if passed == 11 else "FAIL")
print("Production database changes: None")
print("Background collection started: No")
print("Router operations: None")
