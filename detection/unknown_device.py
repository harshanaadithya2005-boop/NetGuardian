def is_unknown_device(device_ip, known_devices):
    return device_ip not in known_devices
known_devices = [
    "192.168.1.1",
    "192.168.1.5",
    "192.168.1.8"
]

device = "192.168.1.20"

if is_unknown_device(device, known_devices):
    print("Unknown device detected")

def is_trusted_device(device_ip, trusted_devices):

 device_ip in trusted_devices

def check_unknown_device(device_ip, trusted_devices):
    if device_ip not in trusted_devices:
        return {
            "type": "unknown_device",
            "ip_address": device_ip,
            "message": "Unknown device detected"
        }

    return None