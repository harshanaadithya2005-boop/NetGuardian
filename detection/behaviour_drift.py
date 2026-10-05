def detect_traffic_spike(normal_mb, current_mb, multiplier=5):
    return current_mb >= normal_mb * multiplier