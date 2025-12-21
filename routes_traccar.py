from flask import Blueprint, jsonify
import requests

traccar_bp = Blueprint('traccar', __name__)

TRACCAR_URL = "http://127.0.0.1:8082"
TRACCAR_EMAIL = "lakshyaa.otp@gmail.com"
TRACCAR_PASSWORD = "Lakshyaa@Dhyey0911"  # 👈 replace with actual Traccar password

# Initialize a persistent session
session = requests.Session()

# Login once to Traccar
login_resp = session.post(
    f"{TRACCAR_URL}/api/session",
    data={"email": TRACCAR_EMAIL, "password": TRACCAR_PASSWORD},
    headers={"Content-Type": "application/x-www-form-urlencoded"}
)

print("Traccar login:", login_resp.status_code)

@traccar_bp.route('/traccar/devices')
def get_devices():
    r = session.get(f"{TRACCAR_URL}/api/devices")
    try:
        return jsonify(r.json())
    except Exception:
        return jsonify({"error": "Invalid response from Traccar", "text": r.text}), 500

@traccar_bp.route('/traccar/positions/<int:device_id>')
def get_positions(device_id):
    r = session.get(f"{TRACCAR_URL}/api/positions", params={"deviceId": device_id})
    try:
        return jsonify(r.json())
    except Exception:
        return jsonify({"error": "Invalid response from Traccar", "text": r.text}), 500
