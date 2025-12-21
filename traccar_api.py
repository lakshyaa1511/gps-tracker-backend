import requests

TRACCAR_URL = "http://3.109.158.100:8082"
TRACCAR_EMAIL = "lakshyaa.otp@gmail.com"   # your admin email
TRACCAR_PASSWORD = "Lakshyaa@Dhyey0911"     # your admin password

session = requests.Session()

def login_traccar():
    payload = {
        "email": TRACCAR_EMAIL,
        "password": TRACCAR_PASSWORD
    }
    response = session.post(f"{TRACCAR_URL}/api/session", data=payload)
    if response.status_code == 200:
        print("✅ Logged in to Traccar API successfully.")
    else:
        print("❌ Login failed:", response.text)

def get_devices():
    response = session.get(f"{TRACCAR_URL}/api/devices")
    if response.status_code == 200:
        return response.json()
    else:
        print("⚠️ Failed to fetch devices:", response.text)
        return []

def get_positions(device_id):
    response = session.get(f"{TRACCAR_URL}/api/positions", params={"deviceId": device_id})
    if response.status_code == 200:
        return response.json()
    else:
        print("⚠️ Failed to fetch positions:", response.text)
        return []

if __name__ == "__main__":
    login_traccar()
    devices = get_devices()
    print("Devices:", devices)
    if devices:
        print("Positions:", get_positions(devices[0]['id']))
