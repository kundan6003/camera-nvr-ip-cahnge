#!/usr/bin/env python3
"""One-shot merge helper: inserts the Google Sheet sync API into
bulk_device_config_web.py after the discover endpoint (idempotent)."""
import io
import sys

PATH = "bulk_device_config_web.py"
ANCHOR = '    return jsonify({"ip": ip, "port": port, "channels": channels})\n'
NEW_ROUTE = '''

@app.route("/api/tiandy/sync_sheet", methods=["POST"])
def api_tiandy_sync_sheet():
    """Push one NVR + its discovered cameras to a Google Sheet.

    Uses a Google Apps Script Web App URL as a simple webhook, so no Google
    Cloud project / OAuth / service-account JSON is needed - the user just
    pastes a script into their own Sheet once (Extensions -> Apps Script),
    deploys it as a Web App, and pastes the resulting URL into this tool.
    This tool never talks to Google's API directly; it just POSTs JSON to
    that URL and the Apps Script (running under the sheet owner's account)
    writes the rows."""
    if not REQUESTS_AVAILABLE:
        return jsonify({"error": "requests library missing - pip install requests"}), 400
    data = request.get_json(force=True)
    webhook_url = (data.get("webhook_url") or "").strip()
    nvr = data.get("nvr") or {}
    cameras = data.get("cameras") or []
    if not webhook_url:
        return jsonify({"error": "Paste your Google Sheet webhook URL first (see the setup guide)"}), 400
    if not webhook_url.startswith("https://script.google.com/"):
        return jsonify({"error": "That doesn't look like a Google Apps Script Web App URL "
                                 "(should start with https://script.google.com/macros/...)"}), 400
    if not cameras:
        return jsonify({"error": "No discovered cameras to sync - run Discover Cameras first"}), 400

    payload = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "nvr_ip": nvr.get("ip", ""),
        "nvr_port": nvr.get("web_port", ""),
        "nvr_username": nvr.get("username", ""),
        "nvr_password": nvr.get("current_password", ""),
        "branch_name": nvr.get("branch_name", ""),
        "cameras": [
            {
                "channel": c.get("channel", ""),
                "name": c.get("name", ""),
                "ip": c.get("ip", ""),
                "port": c.get("admin_port", ""),
                "username": c.get("cam_user", ""),
                "password": c.get("cam_pass", ""),
                "online": bool(c.get("online")),
            }
            for c in cameras
        ],
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=20, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Could not reach the Google Sheet webhook: {e}"}), 502
    # Apps Script Web Apps often answer with a 200 that contains a small JSON
    # or text body - treat any non-2xx as failure and surface the body.
    if resp.status_code >= 300:
        return jsonify({"error": f"Google Sheet webhook returned HTTP {resp.status_code}: "
                                 f"{resp.text[:300]}"}), 502
    return jsonify({"ok": True, "rows_added": len(cameras) + 1, "response": resp.text[:300]})
'''

with io.open(PATH, "r", encoding="utf-8") as f:
    src = f.read()

if "api_tiandy_sync_sheet" in src:
    print("sync_sheet route already present - nothing to do")
    sys.exit(0)

if ANCHOR not in src:
    print("ANCHOR NOT FOUND - aborting, file unchanged")
    sys.exit(1)

src = src.replace(ANCHOR, ANCHOR + NEW_ROUTE, 1)

with io.open(PATH, "w", encoding="utf-8") as f:
    f.write(src)
print("sync_sheet route inserted OK")
