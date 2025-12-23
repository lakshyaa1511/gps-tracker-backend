import os
import datetime
import json
from functools import wraps

import requests

from flask import (
    Blueprint,
    render_template,
    session,
    jsonify,
    request,
    redirect,
    url_for,
    flash,
    current_app,
)

# Optionally used later if you want context
from models import User, Device  # keep if used elsewhere

import io
from io import StringIO, BytesIO
import csv
from flask import send_file, make_response
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

# --- CONFIGURATION ---

traccar = Blueprint("traccar", __name__)

# Your Traccar server URL (example default)
TRACCAR_URL = os.environ.get("TRACCAR_URL", "http://localhost:8082")

# Service-side credentials for calling Traccar APIs directly
TRACCAR_USER = os.environ.get("TRACCAR_USER")
TRACCAR_PASS = os.environ.get("TRACCAR_PASS")


# --- SESSION / LOGIN HELPERS ---

def session_login_required(view):
    """Reuse the same session-based auth you use in app.py."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def get_traccar_auth_token():
    """Retrieves the Traccar JSESSIONID from the Flask session."""
    return session.get("traccar_auth_token")


def get_traccar_devices():
    """
    Fetches device list from Traccar API using the JSESSIONID cookie
    stored when the user logs in through /traccar/login.
    Returns a list (possibly empty) of device dicts.
    """
    auth_token = get_traccar_auth_token()
    if not auth_token:
        return []

    try:
        response = requests.get(
            f"{TRACCAR_URL}/api/devices",
            headers={"Cookie": f"JSESSIONID={auth_token}"},
            timeout=5,
        )
        if response.status_code == 200:
            return response.json()

        # If Traccar returns unauthorized, clear the session token
        if response.status_code in (401, 403):
            session.pop("traccar_auth_token", None)
            flash("Traccar session expired. Please log in to Traccar again.", "danger")

    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Error fetching Traccar devices: {e}")
        flash("Could not connect to Traccar server.", "danger")

    return []


# --- TRACCAR LOGIN & MAP PAGES ---

@traccar.route("/login", methods=["GET", "POST"])
#@session_login_required
def traccar_login():
    """Handles the login process to the Traccar API (user enters Traccar email/pass)."""
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        try:
            response = requests.post(
                f"{TRACCAR_URL}/api/session",
                data={"email": email, "password": password},
                timeout=5,
            )

            if response.status_code == 200:
                # Extract the JSESSIONID cookie
                session_cookie = response.cookies.get("JSESSIONID")
                if session_cookie:
                    session["traccar_auth_token"] = session_cookie
                    flash("✅ Successfully logged into Traccar!", "success")
                    return redirect(url_for("traccar.map"))
                else:
                    flash("Login successful but failed to get session token.", "danger")
            else:
                flash("Invalid Traccar credentials or Traccar server unreachable.", "danger")

        except requests.exceptions.RequestException as e:
            current_app.logger.error(f"Error connecting to Traccar server: {e}")
            flash("Error connecting to Traccar server. Check the URL and server status.", "danger")

    return render_template("traccar_login.html")


@traccar.route("/map")
@session_login_required
def map():
    """
    Displays the main map with all live devices.
    Optional query param ?device_id=<traccar id> to pre-select a device later.
    """
    devices = get_traccar_devices()
    selected_device_id = request.args.get("device_id")
    return render_template(
        "map.html",
        devices=devices,
        selected_device_id=selected_device_id,
    )


@traccar.route("/history/<device_id>")
@session_login_required
def history(device_id):
    """Displays the history map for a single device."""
    devices = get_traccar_devices()
    device = next((d for d in devices if str(d.get("id")) == str(device_id)), None)

    if not device:
        flash("Device not found.", "danger")
        return redirect(url_for("traccar.map"))

    # Turn the dict into a simple object so Jinja can use dot notation
    device_obj = type("DeviceObject", (object,), device)

    return render_template(
        "device_history.html",  # matches the template name you provided
        device=device_obj,
    )


# --- API: LIVE POSITIONS FOR ALL DEVICES ---

@traccar.route('/api/traccar/live_positions', methods=['GET'])
@session_login_required
def api_traccar_live_positions():
    """
    Return latest positions for all Traccar devices as a clean array:
    [
      {"id": <deviceId>, "name": <name>, "latitude": ..., "longitude": ..., "speed": ...},
      ...
    ]
    """
    if not TRACCAR_USER or not TRACCAR_PASS:
        current_app.logger.error("TRACCAR_USER / TRACCAR_PASS are not set")
        return jsonify([]), 200  # avoid frontend alerts

    auth = (TRACCAR_USER, TRACCAR_PASS)

    try:
        # 1) fetch devices
        dev_resp = requests.get(f"{TRACCAR_URL}/api/devices", auth=auth, timeout=5)
        # 2) fetch positions
        pos_resp = requests.get(f"{TRACCAR_URL}/api/positions", auth=auth, timeout=5)

        if dev_resp.status_code != 200 or pos_resp.status_code != 200:
            current_app.logger.error(
                "Traccar fetch failed: devices=%s positions=%s",
                dev_resp.status_code,
                pos_resp.status_code,
            )
            return jsonify([]), 200  # no data, but no big popup

        devices = {d["id"]: d for d in dev_resp.json()}
        positions = pos_resp.json()

        results = []
        for p in positions:
            dev = devices.get(p.get("deviceId"))
            if not dev:
                continue

            lat = p.get("latitude")
            lng = p.get("longitude")
            if lat in (None, 0) and lng in (None, 0):
                continue

            results.append(
                {
                    "id": dev.get("id"),
                    "name": dev.get("name"),
                    "latitude": lat,
                    "longitude": lng,
                    "speed": p.get("speed", 0),
                }
            )

        return jsonify(results), 200

    except Exception as e:
        current_app.logger.exception("Error talking to Traccar in live_positions: %s", e)
        return jsonify([]), 200


# --- API: HISTORY ROUTE DATA ---
'''
@traccar.route('/api/traccar/route/<device_id>', methods=['GET'])
@session_login_required
def api_traccar_route(device_id):
    """
    Return position history (JSON) for a device between 'from' and 'to' ISO timestamps.
    Uses basic auth (TRACCAR_USER/TRACCAR_PASS).
    """
    from_time_iso = request.args.get('from')
    to_time_iso = request.args.get('to')

    if not from_time_iso or not to_time_iso:
        return jsonify({"error": "Missing time parameters."}), 400

    if not TRACCAR_USER or not TRACCAR_PASS:
        return jsonify({"error": "Traccar credentials are not configured on the server."}), 500

    positions_url = f"{TRACCAR_URL}/api/positions"
    params = {
        "deviceId": device_id,
        "from": from_time_iso,
        "to": to_time_iso
    }

    try:
        resp = requests.get(positions_url, auth=(TRACCAR_USER, TRACCAR_PASS), params=params, timeout=20)
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Network error when fetching positions: {e}")
        return jsonify({"error": f"Network or connection error connecting to Traccar: {e}"}), 500

    # If Traccar returns auth problems
    if resp.status_code in (401, 403):
        return jsonify({"error": "Traccar rejected the credentials (401/403). Check TRACCAR_USER/TRACCAR_PASS on server."}), resp.status_code

    # If Traccar returned success, try to parse JSON
    if resp.status_code == 200:
        try:
            data = resp.json()
            # data is expected to be a list of position objects
            return jsonify(data), 200
        except ValueError:
            current_app.logger.error("api_traccar_route: Traccar returned non-JSON for positions. Raw: %s", resp.text[:500])
            return jsonify({"error": "Traccar returned invalid data for positions (non-JSON)."}), 500

    # Any other HTTP error from Traccar
    current_app.logger.error("api_traccar_route: Traccar returned status %s", resp.status_code)
    return jsonify({"error": f"Traccar API returned status code {resp.status_code}. Response: {resp.text[:200]}"}), resp.status_code
'''

@traccar.route("/api/traccar/route/<device_id>")
@session_login_required
def api_traccar_route(device_id):
    """
    Returns JSON positions for history playback.
    Uses /api/positions (NOT reports).
    """

    from_iso = request.args.get("from")
    to_iso = request.args.get("to")

    if not from_iso or not to_iso:
        return jsonify({"error": "Missing from/to"}), 400

    auth_token = session.get("traccar_auth_token")
    if not auth_token:
        return jsonify({"error": "Traccar session expired"}), 401

    try:
        resp = requests.get(
            f"{TRACCAR_URL}/api/positions",
            headers={"Cookie": f"JSESSIONID={auth_token}"},
            params={
                "deviceId": device_id,
                "from": from_iso,
                "to": to_iso,
            },
            timeout=15
        )

        if resp.status_code != 200:
            return jsonify({"error": "Traccar error"}), resp.status_code

        data = resp.json()  # ✅ THIS WILL WORK
        return jsonify(data), 200

    except Exception as e:
        current_app.logger.exception("History fetch failed")
        return jsonify({"error": str(e)}), 500


# --- CSV / PDF download endpoints (route reports or JSON fallback) ---

@traccar.route("/download/csv/<device_id>")
@session_login_required
def download_csv(device_id):
    from_time_iso = request.args.get('from')
    to_time_iso = request.args.get('to')

    if not from_time_iso or not to_time_iso:
        flash("Please select a valid From/To range before downloading.", "warning")
        return redirect(url_for('traccar.history', device_id=device_id))

    if not TRACCAR_USER or not TRACCAR_PASS:
        flash("Server Traccar credentials not configured.", "danger")
        return redirect(url_for('traccar.history', device_id=device_id))

    report_url = f"{TRACCAR_URL}/api/reports/route"
    params = {"deviceId": device_id, "from": from_time_iso, "to": to_time_iso}

    try:
        resp = requests.get(report_url, auth=(TRACCAR_USER, TRACCAR_PASS), params=params, timeout=20)
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Error fetching Traccar route for CSV: {e}")
        flash("Network error while fetching history from Traccar.", "danger")
        return redirect(url_for('traccar.history', device_id=device_id))

    ctype = resp.headers.get("Content-Type", "")
    if resp.status_code == 200 and ("application/json" not in ctype and not resp.text.strip().startswith("[")):
        # Serve binary as-is
        return send_file(
            io.BytesIO(resp.content),
            as_attachment=True,
            download_name=f"traccar_route_device_{device_id}.bin",
            mimetype=ctype or "application/octet-stream"
        )

    if resp.status_code != 200:
        current_app.logger.error("Traccar route CSV fetch failed: %s %s", resp.status_code, resp.text[:200])
        flash("Could not fetch history from Traccar.", "danger")
        return redirect(url_for('traccar.history', device_id=device_id))

    try:
        data = resp.json()
    except ValueError:
        current_app.logger.error("Traccar returned invalid data for CSV: %s", resp.text[:300])
        flash("Traccar returned invalid data when generating CSV.", "danger")
        return redirect(url_for('traccar.history', device_id=device_id))

    if not isinstance(data, list) or not data:
        flash("No history data for this period.", "info")
        return redirect(url_for('traccar.history', device_id=device_id))

    # Generate CSV in-memory
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["fixTime", "latitude", "longitude", "speed", "deviceId", "attributes"])
    for p in data:
        cw.writerow([
            p.get("fixTime") or p.get("serverTime") or p.get("deviceTime") or "",
            p.get("latitude", ""),
            p.get("longitude", ""),
            p.get("speed", ""),
            p.get("deviceId", ""),
            json.dumps(p.get("attributes", {}))
        ])

    buf = io.BytesIO(si.getvalue().encode('utf-8'))
    buf.seek(0)
    return send_file(
        buf,
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"history_device_{device_id}_{from_time_iso}_{to_time_iso}.csv"
    )


@traccar.route("/download/pdf/<device_id>")
@session_login_required
def download_pdf(device_id):
    from_time_iso = request.args.get('from')
    to_time_iso = request.args.get('to')

    if not from_time_iso or not to_time_iso:
        flash("Please select a valid From/To range before downloading.", "warning")
        return redirect(url_for('traccar.history', device_id=device_id))

    if not TRACCAR_USER or not TRACCAR_PASS:
        flash("Server Traccar credentials not configured.", "danger")
        return redirect(url_for('traccar.history', device_id=device_id))

    report_url = f"{TRACCAR_URL}/api/reports/route"
    params = {"deviceId": device_id, "from": from_time_iso, "to": to_time_iso}

    try:
        resp = requests.get(report_url, auth=(TRACCAR_USER, TRACCAR_PASS), params=params, timeout=20)
    except requests.exceptions.RequestException as e:
        current_app.logger.error(f"Error fetching Traccar route for PDF: {e}")
        flash("Network error while fetching history from Traccar.", "danger")
        return redirect(url_for('traccar.history', device_id=device_id))

    ctype = resp.headers.get("Content-Type", "")
    if resp.status_code == 200 and ("application/json" not in ctype and not resp.text.strip().startswith("[")):
        # If Traccar already returned a binary PDF/XLSX, pass it through
        return send_file(
            io.BytesIO(resp.content),
            as_attachment=True,
            download_name=f"traccar_route_device_{device_id}.bin",
            mimetype=ctype or "application/octet-stream"
        )

    if resp.status_code != 200:
        current_app.logger.error("Traccar route PDF fetch failed: %s %s", resp.status_code, resp.text[:200])
        flash("Could not fetch history from Traccar.", "danger")
        return redirect(url_for('traccar.history', device_id=device_id))

    try:
        data = resp.json()
    except ValueError:
        current_app.logger.error("Traccar returned invalid data for PDF: %s", resp.text[:300])
        flash("Traccar returned invalid data when generating PDF.", "danger")
        return redirect(url_for('traccar.history', device_id=device_id))

    if not isinstance(data, list) or not data:
        flash("No history data for this period.", "info")
        return redirect(url_for('traccar.history', device_id=device_id))

    # Build a simple PDF: table with timestamp, lat, lng, speed
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []
    elements.append(Paragraph(f"Device ID: {device_id} — Route report {from_time_iso} to {to_time_iso}", styles['Heading2']))

    table_data = [["Timestamp", "Latitude", "Longitude", "Speed"]]
    for p in data:
        table_data.append([
            p.get("fixTime") or p.get("serverTime") or p.get("deviceTime") or "",
            str(p.get("latitude", "")),
            str(p.get("longitude", "")),
            str(p.get("speed", ""))
        ])

    table = Table(table_data, colWidths=[A4[0] * 0.25] * 4)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4c51bf")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
    ]))
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"history_device_{device_id}_{from_time_iso}_{to_time_iso}.pdf"
    )


@traccar.route("/clear/history/<device_id>", methods=["POST"])
@session_login_required
def clear_history(device_id):
    """Placeholder for clearing device history."""
    flash(f"History for device ID {device_id} has been simulated to be cleared.", "warning")
    return redirect(url_for("traccar.map"))


# Compatibility alias (some code may import this)
#get_traccar_devices = traccar_get_devices
