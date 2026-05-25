"""
Dashboard module for BBAT.
Flask-based HTML dashboard backed by SQLite.
"""

import os

# Optional dependency
try:
    from flask import Flask, render_template_string, jsonify, request
    FLASK_AVAILABLE = True
    app = Flask(__name__)
except ImportError:
    FLASK_AVAILABLE = False

from modules.db import BBATDatabase

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
m    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BBAT Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background: #0f172a; color: #e2e8f0; }
        .header { background: #1e293b; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; }
        .header h1 { color: #38bdf8; font-size: 1.8rem; }
        .container { padding: 40px; max-width: 1400px; margin: 0 auto; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #1e293b; padding: 20px; border-radius: 8px; border: 1px solid #334155; }
        .stat-card h3 { color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; margin-bottom: 8px; }
        .stat-card .value { font-size: 2rem; font-weight: 700; color: #38bdf8; }
        .stat-card.critical .value { color: #ef4444; }
        .stat-card.high .value { color: #f59e0b; }
        .section { background: #1e293b; border-radius: 8px; border: 1px solid #334155; margin-bottom: 20px; overflow: hidden; }
        .section-header { padding: 16px 20px; background: #252f47; border-bottom: 1px solid #334155; }
        .section-header h2 { font-size: 1.1rem; color: #f8fafc; }
        .section-content { padding: 20px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
        .badge-critical { background: #ef444422; color: #ef4444; border: 1px solid #ef4444; }
        .badge-high { background: #f59e0b22; color: #f59e0b; border: 1px solid #f59e0b; }
        .badge-medium { background: #eab30822; color: #eab308; border: 1px solid #eab308; }
        .badge-info { background: #3b82f622; color: #3b82f6; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; font-size: 0.85rem; }
        th { color: #94a3b8; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }
        tr:hover td { background: #252f47; }
        .empty { text-align: center; color: #64748b; padding: 40px; }
        .nav { position: fixed; left: 0; top: 0; bottom: 0; width: 240px; background: #1e293b; border-right: 1px solid #334155; padding: 20px; }
        .nav h2 { color: #38bdf8; margin-bottom: 20px; }
        .nav a { display: block; color: #94a3b8; text-decoration: none; padding: 8px 12px; border-radius: 4px; margin-bottom: 4px; font-size: 0.9rem; }
        .nav a:hover { background: #252f47; color: #f8fafc; }
        .main-content { margin-left: 260px; }
    </style>
</head>
<body>
    <div class="nav">
        <h2>🐛 BBAT</h2>
        <a href="/">Overview</a>
        <a href="/?view=findings">Findings</a>
        <a href="/?view=endpoints">Endpoints</a>
        <a href="/?view=subdomains">Subdomains</a>
        <a href="/?view=technologies">Technologies</a>
    </div>
    <div class="main-content">
        <div class="header"><h1>BBAT Dashboard</h1></div>
        <div class="container">
            <div class="stats">
                <div class="stat-card"><h3>Total Scans</h3><div class="value">{{ stats.total_scans }}</div></div>
                <div class="stat-card critical"><h3>Critical</h3><div class="value">{{ stats.critical }}</div></div>
                <div class="stat-card high"><h3>High</h3><div class="value">{{ stats.high }}</div></div>
                <div class="stat-card"><h3>Medium</h3><div class="value">{{ stats.medium }}</div></div>
                <div class="stat-card"><h3>Endpoints</h3><div class="value">{{ stats.endpoints }}</div></div>
                <div class="stat-card"><h3>Subdomains</h3><div class="value">{{ stats.subdomains }}</div></div>
            </div>
            <div class="section">
                <div class="section-header"><h2>Recent Findings</h2></div>
                <div class="section-content">
                    {% if findings %}
                    <table>
                        <tr><th>Severity</th><th>Type</th><th>Description</th><th>Source</th></tr>
                        {% for f in findings[:50] %}
                        <tr>
                            <td><span class="badge badge-{{ f.severity|lower }}">{{ f.severity }}</span></td>
                            <td>{{ f.type }}</td>
                            <td>{{ f.description[:100] }}{% if f.description|length > 100 %}...{% endif %}</td>
                            <td><code>{{ f.source }}</code></td>
                        </tr>
                        {% endfor %}
                    </table>
                    {% else %}
                    <div class="empty">No findings recorded yet.</div>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
</body>
</html>
"""


def _load_db() -> BBATDatabase:
    return BBATDatabase()


if FLASK_AVAILABLE:
    @app.route("/")
    def index():
        db = _load_db()
        stats = db.get_stats()
        findings = db.get_findings(limit=1000)
        return render_template_string(DASHBOARD_TEMPLATE, stats=stats, findings=findings)

    @app.route("/api/stats")
    def api_stats():
        db = _load_db()
        return jsonify(db.get_stats())

    @app.route("/api/findings")
    def api_findings():
        db = _load_db()
        return jsonify(db.get_findings(limit=5000))

    @app.route("/api/endpoints")
    def api_endpoints():
        db = _load_db()
        return jsonify(db.get_endpoints(limit=5000))

    @app.route("/api/subdomains")
    def api_subdomains():
        db = _load_db()
        return jsonify(db.get_subdomains())


if __name__ == "__main__":
    if FLASK_AVAILABLE:
        print("[*] Starting BBAT Dashboard on http://127.0.0.1:5000")
        app.run(host="127.0.0.1", port=5000, debug=False)
    else:
        print("[!] Flask is not installed. Install with: pip install flask")
