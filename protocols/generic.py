import re
from datetime import datetime

# Try to handle common formats:
# 1) CSV: IMEI,YYYYMMDD,HHMMSS,lat,lon,...
# 2) KV pairs: "imei:12345;lat:12.34;lon:56.78"
# 3) "123456789012345,1,120320,095959,12.3456,56.7890,..." (many trackers)

csv_re = re.compile(r'^\s*(?P<imei>\d{6,20})\s*[,\s]\s*(?P<d>\d{6,8})[,\s].*?(?P<lat>-?\d+\.\d+)[,\s]+(?P<lon>-?\d+\.\d+)', re.IGNORECASE)
kv_re = re.compile(r'(imei|id)[:=]\s*(?P<imei>\d{6,20}).*?lat[:=]\s*(?P<lat>-?\d+\.\d+).*?lon[:=]\s*(?P<lon>-?\d+\.\d+)', re.IGNORECASE)
simple_coords = re.compile(r'lat[:=]?\s*(?P<lat>-?\d+\.\d+)[,;\s]+lon[:=]?\s*(?P<lon>-?\d+\.\d+)', re.IGNORECASE)

def parse(line: str):
    if not line:
        return None
    # try kv
    m = kv_re.search(line)
    if m:
        return {"imei": m.group("imei"), "latitude": float(m.group("lat")), "longitude": float(m.group("lon"))}
    # try csv-like
    m = csv_re.search(line)
    if m:
        return {"imei": m.group("imei"), "latitude": float(m.group("lat")), "longitude": float(m.group("lon"))}
    # try simple coords + imei somewhere
    m = simple_coords.search(line)
    if m:
        # try to find imei numeric in line
        imei = None
        all_nums = re.findall(r'\d{6,20}', line)
        if all_nums:
            imei = all_nums[0]
        return {"imei": imei, "latitude": float(m.group("lat")), "longitude": float(m.group("lon"))}
    return None
