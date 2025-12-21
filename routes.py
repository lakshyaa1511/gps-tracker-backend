from flask import Blueprint, jsonify
import requests

traccar_bp = Blueprint('traccar', __name__)

TRACCAR_URL = "http://127.0.0.1:8082"
TRACCAR_EMAIL = "lakshyaa.otp@gmail.com"
TRACCAR_PASSWORD = "your_password_here"  # replace with your actual traccar password

session = requests.Session()

# login once
login = session.post(f"{TRACCAR_URL}/api/session", data={
    "email": TRACCAR_EMAIL,
    "password": TRACCAR_PASSWORD
})
print("Traccar login:", login.status_code)

@traccar_bp.route('/traccar/devices')
def get_devices():
    r = session.get(f"{TRACCAR_URL}/api/devices")
    return jsonify(r.json())

@traccar_bp.route('/traccar/positions/<int:device_id>')
def get_positions(device_id):
    r = session.get(f"{TRACCAR_URL}/api/positions", params={"deviceId": device_id})
    return jsonify(r.json())
