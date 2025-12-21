# traccar_client.py
import os
import requests
from datetime import datetime

BASE_URL = os.environ.get("TRACCAR_URL", "http://127.0.0.1:8082")
TRACCAR_USER = os.environ.get("TRACCAR_USER")
TRACCAR_PASS = os.environ.get("TRACCAR_PASS")

session = requests.Session()
session.headers.update({"Accept": "application/json"})

def login():
    """
    Login to Traccar and keep session cookie in `session`.
    Uses JSON first, falls back to form-encoded if needed.
    """
    if not (TRACCAR_USER and TRACCAR_PASS):
        raise RuntimeError("Set TRACCAR_USER and TRACCAR_PASS environment variables")

    url = f"{BASE_URL}/api/session"

    # Try JSON
    r = session.post(url, json={"email": TRACCAR_USER, "password": TRACCAR_PASS}, timeout=6)
    if r.status_code == 200:
        return True

    # fallback to form-encoded
    r = session.post(url, data={"email": TRACCAR_USER, "password": TRACCAR_PASS},
                     headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=6)
    if r.status_code == 200:
        return True

    r.raise_for_status()

def ensure_login():
    """Try a quick GET to see if session is valid, otherwise login."""
    try:
        r = session.get(f"{BASE_URL}/api/session", timeout=4)
        if r.status_code == 200:
            return True
    except Exception:
        pass
    return login()

def get_devices():
    """Return list of Traccar devices (dicts)"""
    ensure_login()
    r = session.get(f"{BASE_URL}/api/devices", timeout=8)
    r.raise_for_status()
    return r.json()

def get_positions_for_device(traccar_device_id, limit=100):
    """Return positions for a given Traccar device id (note: Traccar's api query param is deviceId)"""
    ensure_login()
    params = {"deviceId": traccar_device_id, "limit": limit}
    r = session.get(f"{BASE_URL}/api/positions", params=params, timeout=10)
    r.raise_for_status()
    return r.json()

def get_position_by_id(position_id):
    ensure_login()
    r = session.get(f"{BASE_URL}/api/positions/{position_id}", timeout=6)
    r.raise_for_status()
    return r.json()
