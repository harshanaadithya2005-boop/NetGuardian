from flask import Flask, render_template_string
from database.db import get_connection

app = Flask(__name__)

PAGE = """
<h1>NetGuardian</h1>
<p><a href="/">Home</a> | <a href="/devices">Devices</a> | <a href="/alerts">Alerts</a></p>
<hr>
{{ body|safe }}
"""

@app.route("/")
def home():
    conn = get_connection()
    devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.close()
    return render_template_string(PAGE, body=f"<p>Devices: {devices}</p><p>Alerts: {alerts}</p>")

@app.route("/devices")
def devices():
    conn = get_connection()
    rows = conn.execute("SELECT ip_address, mac_address, hostname, status FROM devices").fetchall()
    conn.close()
    html = "<table border=1 cellpadding=6><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Status</th></tr>"
    for r in rows:
        html += f"<tr><td>{r['ip_address']}</td><td>{r['mac_address']}</td><td>{r['hostname']}</td><td>{r['status']}</td></tr>"
    html += "</table>"
    return render_template_string(PAGE, body=html)

@app.route("/alerts")
def alerts():
    conn = get_connection()
    rows = conn.execute("SELECT alert_type, risk_score, severity, status, time FROM alerts ORDER BY id DESC").fetchall()
    conn.close()
    html = "<table border=1 cellpadding=6><tr><th>Type</th><th>Risk</th><th>Severity</th><th>Status</th><th>Time</th></tr>"
    for r in rows:
        html += f"<tr><td>{r['alert_type']}</td><td>{r['risk_score']}</td><td>{r['severity']}</td><td>{r['status']}</td><td>{r['time']}</td></tr>"
    html += "</table>"
    return render_template_string(PAGE, body=html)

if __name__ == "__main__":
    app.run(debug=True)