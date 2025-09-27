import random
import time

def get_fake_location():
    # Random location near India
    lat = random.uniform(20.0, 28.0)   # between latitude 20 and 28
    lon = random.uniform(72.0, 85.0)   # longitude range
    return {"lat": lat, "lon": lon, "time": time.strftime("%H:%M:%S")}
