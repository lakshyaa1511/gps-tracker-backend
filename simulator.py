import time
import random
import requests

API_URL = "http://127.0.0.1:5000/api/location"

# Change this to one of your real device names and IDs
DEVICE_NAME = "mycar"
DEVICE_ID = 6  # 👈 replace with your actual device ID from dashboard

# Start location (random point around a city)
latitude = 23.0225   # Example: Ahmedabad
longitude = 72.5714

while True:
    # Simulate small random movement
    latitude += random.uniform(-0.0005, 0.0005)
    longitude += random.uniform(-0.0005, 0.0005)

    data = {
        "device_id": DEVICE_ID,
        "latitude": latitude,
        "longitude": longitude
    }

    try:
        response = requests.post(API_URL, json=data)
        if response.status_code == 201:
            print(f"✅ Sent new location: {latitude:.6f}, {longitude:.6f}")
        else:
            print(f"⚠️ Error: {response.text}")
    except Exception as e:
        print("❌ Failed to send location:", e)

    time.sleep(5)  # wait 5 seconds before next update
# End of file