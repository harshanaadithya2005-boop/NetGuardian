from database.models import add_or_update_device
from datetime import datetime

current_time = datetime.now().isoformat(timespec="seconds")

add_or_update_device(
    ip_address="192.168.8.250",
    mac_address="AA:BB:CC:DD:EE:FF",
    hostname="Test-Device",
    device_name="NetGuardian Test Device",
    device_type="Test",
    timestamp=current_time
)

print("Test device saved successfully.")