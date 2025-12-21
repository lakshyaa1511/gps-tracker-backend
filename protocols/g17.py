import re

# G17 devices often send messages like:
#  "imei:359710051234567,tracker,110620,102233,12.34567,N,077.12345,E,...."
# This is an illustrative pattern — please capture a real sample and refine.

g17_re = re.compile(
    r'(?:imei[:=])?(?P<imei>\d{6,20})[^\d]+(?P<lat>-?\d+\.\d+)[^\d\w\.\-]+(?P<lon>-?\d+\.\d+)',
    re.IGNORECASE
)

def parse(line: str):
    if not line:
        return None
    m = g17_re.search(line)
    if m:
        return {"imei": m.group("imei"), "latitude": float(m.group("lat")), "longitude": float(m.group("lon"))}
    return None
