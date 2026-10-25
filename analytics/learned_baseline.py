"""Read qualified history without overwriting configured behavior profiles."""
from datetime import timedelta
from statistics import median
from database.db import get_connection


def get_learned_baseline(device_id, mac, window_start, minimum_windows=12):
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT h.* FROM behaviour_window_history_v2 h
            WHERE h.device_id=? AND h.mac_address=? AND h.quality_status='QUALIFIED'
              AND h.window_end <= ? AND h.window_start >= ?
              AND NOT EXISTS (
                  SELECT 1 FROM alerts a WHERE a.device_id=h.device_id
                    AND a.alert_type IN ('port_scan','dns_anomaly','traffic_spike','behaviour_drift')
                    AND datetime(a.timestamp) >= datetime(h.window_start)
                    AND datetime(a.timestamp) < datetime(h.window_end, '+5 minutes')
              )
            ORDER BY h.window_end DESC LIMIT 288
        """, (device_id, str(mac).upper(), window_start.isoformat(timespec="seconds"),
              (window_start-timedelta(days=7)).isoformat(timespec="seconds"))).fetchall()
        from datetime import datetime
        if rows and datetime.fromisoformat(rows[0]['window_end']) < window_start-timedelta(minutes=60):
            return None,0
        if len(rows) < minimum_windows:
            return None, len(rows)
        return {
            "normal_bandwidth": max(0.05, median(r["data_mb"] for r in rows)),
            "normal_dns_rate": max(5, median(r["dns_requests"] for r in rows)),
            "normal_dest_ips": max(3, median(r["distinct_ips"] for r in rows)),
            "normal_port_count": max(3, median(r["distinct_ports"] for r in rows)),
        }, len(rows)
    finally:
        conn.close()
