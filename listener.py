#!/usr/bin/env python3
"""
Final production-grade listener for GT06-like GPS devices (ported/borrowed
decoding logic patterns from Traccar decoders, adapted to Python).

Features:
- Handles login (0x01), GPS (0x12), heartbeat (0x13), extended (0x20/0x79)
- Robust IMEI extraction (BCD nibble + fallback)
- Timestamp parsing (yy mm dd hh mm ss) and timezone assumptions (UTC)
- Out-of-order / noisy point detection using time/distance/speed rules
- Smooth marker updates are done client-side; this sends only validated points to Flask
- Non-blocking HTTP forwarding to API using ThreadPoolExecutor and Session with retries
- Thread-per-client socket server (simple, reliable)
- Configurable constants at top
"""

import socket
import threading
import datetime
import time
import math
import requests
from requests.adapters import HTTPAdapter, Retry
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Tuple, Dict

# --------------------- CONFIG ---------------------
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5001

# Flask API endpoint — update if needed
API_URL = "http://127.0.0.1:5000/api/update_location"

# Safety / filtering settings (tweak to taste)
MAX_REASONABLE_SPEED_KMH = 250.0  # unrealistic speeds above considered invalid
MAX_JUMP_KM = 5.0                 # very large single jumps considered invalid
MIN_TIME_DIFF_SECONDS = 1.0       # minimum seconds between distinct valid points
MIN_REPORT_INTERVAL_SECONDS = 0.5 # if device floods with high-rate duplicates
IGNORE_OLDER_THAN_SECONDS = 60 * 60 * 24 * 7  # ignore timestamps older than 7 days

# ACK bytes (kept from your earlier code; devices expect these exact sequences)
ACK_BY_PROTO = {
    0x01: bytes.fromhex("78 78 05 01 00 01 D9 DC 0D 0A"),  # login
    0x12: bytes.fromhex("78 78 05 12 00 01 D9 DC 0D 0A"),  # gps
    0x13: bytes.fromhex("78 78 05 13 00 01 D9 DC 0D 0A"),  # heartbeat
    0x20: bytes.fromhex("79 79 05 20 00 01 D9 DC 0D 0A"),  # ext (79 header)
    0x79: bytes.fromhex("79 79 05 20 00 01 D9 DC 0D 0A"),  # ext (79 header)
}

# Thread pool for HTTP posting (so socket handling is fast)
HTTP_POOL = ThreadPoolExecutor(max_workers=8)

# requests Session with retries
session = requests.Session()
retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retries)
session.mount("http://", adapter)
session.mount("https://", adapter)

# Small in-memory per-device cache for last accepted point
# Structure: imei -> {"lat": float, "lng": float, "ts": datetime, "speed": float, "last_sent_at": float}
last_points: Dict[str, Dict] = {}

# --------------------- UTILITIES ---------------------
def log(msg: str):
    now = datetime.datetime.utcnow().replace(microsecond=0).isoformat()
    print(f"[{now}] {msg}", flush=True)

def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2.0) ** 2
    return 2.0 * R * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

def bcd_to_imei(b: bytes) -> str:
    s = ""
    for byte in b:
        hi = (byte >> 4) & 0x0F
        lo = byte & 0x0F
        if 0 <= hi <= 9:
            s += str(hi)
        if 0 <= lo <= 9:
            s += str(lo)
    if len(s) >= 15:
        return s[-15:]
    return s

def extract_imei(frame: bytes) -> str:
    """
    Try common patterns:
    - bytes 4..11 as BCD (8 bytes -> sometimes 15 or 16 digits)
    - fallback: find any 15-digit sequence in hex->digits
    """
    if len(frame) >= 12:
        try:
            imei = bcd_to_imei(frame[4:12])
            if imei:
                return imei
        except Exception:
            pass
    # fallback: extract digits from raw hex
    raw_digits = "".join(ch for ch in frame.hex() if ch.isdigit())
    if len(raw_digits) >= 15:
        return raw_digits[-15:]
    return ""

def safe_parse_gt06_timestamp(frame: bytes, base_index: int = 4) -> datetime.datetime:
    """
    GT06-like timestamp: yy mm dd hh mm ss starting at index base_index
    Build timezone-naive UTC datetime (we assume device sends UTC or local in device)
    """
    try:
        if len(frame) >= base_index + 6:
            yy = int(frame[base_index])
            mm = int(frame[base_index + 1])
            dd = int(frame[base_index + 2])
            hh = int(frame[base_index + 3])
            mi = int(frame[base_index + 4])
            ss = int(frame[base_index + 5])
            year = 2000 + yy
            return datetime.datetime(year, mm, dd, hh, mi, ss)
    except Exception:
        pass
    return datetime.datetime.utcnow()

def send_ack(sock: socket.socket, proto: int):
    try:
        if proto in ACK_BY_PROTO:
            sock.sendall(ACK_BY_PROTO[proto])
    except Exception as e:
        log(f"send_ack error: {e}")

# --------------------- PARSERS ---------------------
def parse_0x12(frame: bytes) -> Optional[Tuple[float, float, int, datetime.datetime]]:
    """
    Parse typical GT06/0x12 packet.
    Many devices use:
      - frame[4..9] time (yy mm dd hh mm ss)
      - frame[10:14] or 11:15 latitude raw
      - frame[14:18] or 15:19 longitude raw
      - one byte speed
    We'll attempt both offsets robustly.
    Returns: (lat, lon, speed, timestamp) or None
    """
    try:
        if len(frame) < 20:
            return None
        # timestamp commonly at [4..9]
        ts = safe_parse_gt06_timestamp(frame, 4)

        # Try lat/lon offsets used in many logs:
        # Option A: lat = bytes 11..14, lon = 15..18, speed at 19
        lat = lon = None
        speed = 0
        def attempt(offset_lat, offset_lon, offset_speed):
            try:
                lat_raw = int.from_bytes(frame[offset_lat:offset_lat+4], "big", signed=False)
                lon_raw = int.from_bytes(frame[offset_lon:offset_lon+4], "big", signed=False)
                sp = int(frame[offset_speed]) if len(frame) > offset_speed else 0
                lat_v = lat_raw / 1800000.0
                lon_v = lon_raw / 1800000.0
                if -90 <= lat_v <= 90 and -180 <= lon_v <= 180:
                    return lat_v, lon_v, sp
            except Exception:
                pass
            return None

        for (la, lo, sp) in ((11,15,19),(10,14,18),(12,16,20)):
            res = attempt(la, lo, sp)
            if res:
                lat, lon, speed = res
                break

        if lat is None or lon is None:
            return None

        return float(lat), float(lon), int(speed), ts
    except Exception as e:
        log(f"parse_0x12 exception: {e}")
        return None

def parse_0x20_or_0x79(frame: bytes) -> Optional[Tuple[float, float, int, datetime.datetime]]:
    """
    Updated parser for your device's 0x20 extended packet (matches your latest logs).
    """
    try:
        if len(frame) < 30:
            return None

        # Try to locate timestamp region
        ts = safe_parse_gt06_timestamp(frame, 5)  # guess timestamp after length bytes

        # Try to locate latitude/longitude
        # Based on your frame structure: after IMEI (4..11) + some padding (~12 bytes)
        lat_raw = int.from_bytes(frame[14:18], "big", signed=False)
        lon_raw = int.from_bytes(frame[18:22], "big", signed=False)
        speed = frame[22] if len(frame) > 22 else 0

        lat = lat_raw / 1800000.0
        lon = lon_raw / 1800000.0

        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            # Try shifted positions
            lat_raw = int.from_bytes(frame[15:19], "big", signed=False)
            lon_raw = int.from_bytes(frame[19:23], "big", signed=False)
            lat = lat_raw / 1800000.0
            lon = lon_raw / 1800000.0

        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return None

        return float(lat), float(lon), int(speed), ts
    except Exception as e:
        log(f"parse_0x20_or_0x79 error: {e}")
        return None

# --------------------- VALIDATION / FILTERING ---------------------
def validate_point(imei: str, lat: float, lon: float, speed: float, ts: datetime.datetime) -> Tuple[bool, str]:
    # range checks
    if lat is None or lon is None:
        return False, "missing coords"
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        return False, "coords out of range"
    if abs(lat) < 1e-8 and abs(lon) < 1e-8:
        return False, "zero coordinates"

    now = datetime.datetime.utcnow()
    # too old
    if (now - ts).total_seconds() > IGNORE_OLDER_THAN_SECONDS:
        return False, "timestamp too old"

    last = last_points.get(imei)
    if last:
        last_ts: datetime.datetime = last["ts"]
        if ts <= last_ts:
            return False, f"out-of-order timestamp (last={last_ts}, new={ts})"
        dt = (ts - last_ts).total_seconds()
        if dt <= 0:
            return False, "zero dt"

        # distance/time implied speed and small-interval duplicate suppression
        dist_km = haversine_km(lat, lon, last["lat"], last["lon"])
        implied_kmh = (dist_km / max(dt, 1e-6)) * 3600.0

        # if device is sending many reports in < MIN_TIME_DIFF_SECONDS and coord change tiny -> treat as duplicate
        if dt < MIN_TIME_DIFF_SECONDS and dist_km < 0.00001:  # < ~1.0 m
            return False, "duplicate/too-frequent"

        if dist_km > MAX_JUMP_KM and dt < 5.0:
            return False, f"unreasonable jump {dist_km:.2f} km in {dt:.1f}s"

        if implied_kmh > MAX_REASONABLE_SPEED_KMH:
            return False, f"implied speed too high {implied_kmh:.1f} km/h"
    return True, ""

# --------------------- HTTP FORWARD ---------------------
def post_location(payload: dict):
    """
    Called on a worker thread. Posts to the Flask API.
    Flask expected keys: imei, lat, lng, speed, timestamp (ISO string)
    Adjust if your API needs different names.
    """
    try:
        # set short timeout; retry via session adapter
        r = session.post(API_URL, json=payload, timeout=5)
        log(f"API {r.status_code} {r.text.strip()}")
    except Exception as e:
        log(f"HTTP post failed: {e}")

# --------------------- CLIENT HANDLER ---------------------
def handle_client(conn: socket.socket, addr):
    conn.settimeout(180)
    imei_cached: Optional[str] = None
    log(f"Client connected {addr}")
    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                log(f"Client disconnected {addr}")
                break
            buf += chunk
            # Most GT06 frames are self-delimited with 0x78....0x0D0A or 0x79.. ..0x0D0A
            # We will try to process each full frame found by scanning start bytes and end pattern.
            while True:
                if len(buf) < 5:
                    break
                # find start either 0x78 or 0x79
                start_idx = None
                for i, b in enumerate(buf):
                    if b in (0x78, 0x79):
                        start_idx = i
                        break
                if start_idx is None:
                    buf = b""  # garbage
                    break
                if start_idx > 0:
                    buf = buf[start_idx:]
                # now attempt to find end (0x0d0a) - many frames end with 0x0d0a
                end_marker = b"\x0d\x0a"
                end_idx = buf.find(end_marker)
                if end_idx == -1:
                    # haven't received full frame yet
                    break
                frame = buf[:end_idx+2]
                buf = buf[end_idx+2:]
                # process frame
                try:
                    # protective: minimal length
                    if len(frame) < 5:
                        continue
                    proto = frame[3]
                    proto_hex = f"{proto:02X}"
                    hex_str = " ".join(f"{b:02X}" for b in frame)
                    log(f"RAW {addr} proto={proto_hex} len={len(frame)} hex={hex_str}")

                    # LOGIN
                    if proto == 0x01:
                        imei_cached = extract_imei(frame)
                        log(f"LOGIN IMEI={imei_cached}")
                        send_ack(conn, proto)

                    # HEARTBEAT
                    elif proto == 0x13:
                        log("Heartbeat")
                        send_ack(conn, proto)

                    # GPS (0x12)
                    elif proto == 0x12:
                        parsed = parse_0x12(frame)
                        send_ack(conn, proto)
                        if not parsed:
                            log("Could not parse 0x12 packet")
                            continue
                        lat, lon, sp, ts = parsed
                        imei = imei_cached or extract_imei(frame) or ""
                        if not imei:
                            log("No IMEI for 0x12 frame; skipping")
                            continue
                        valid, reason = validate_point(imei, lat, lon, sp, ts)
                        if not valid:
                            log(f"Ignored {imei}: {reason} -> {lat:.6f},{lon:.6f} @ {ts}")
                            continue
                        # accept & push
                        last_points[imei] = {"lat": lat, "lon": lon, "ts": ts, "speed": sp, "sent_at": time.time()}
                        payload = {
                            "imei": imei,
                            "lat": lat,
                            "lng": lon,
                            "speed": sp,
                            "timestamp": ts.isoformat()
                        }
                        log(f"Accept {imei}: {lat:.6f},{lon:.6f} speed={sp} ts={ts.isoformat()} (forwarding)")
                        HTTP_POOL.submit(post_location, payload)

                    # EXTENDED (0x20 / 0x79 often)
                    elif proto in (0x20, 0x79):
                        parsed = parse_0x20_or_0x79(frame)
                        send_ack(conn, proto)
                        if not parsed:
                            log("Could not parse extended packet")
                            continue
                        lat, lon, sp, ts = parsed
                        imei = imei_cached or extract_imei(frame) or ""
                        if not imei:
                            log("No IMEI for extended frame; skipping")
                            continue
                        valid, reason = validate_point(imei, lat, lon, sp, ts)
                        if not valid:
                            log(f"Ignored ext {imei}: {reason}")
                            continue
                        last_points[imei] = {"lat": lat, "lon": lon, "ts": ts, "speed": sp, "sent_at": time.time()}
                        payload = {
                            "imei": imei,
                            "lat": lat,
                            "lng": lon,
                            "speed": sp,
                            "timestamp": ts.isoformat()
                        }
                        log(f"Accept EXT {imei}: {lat:.6f},{lon:.6f} speed={sp} ts={ts.isoformat()} (forwarding)")
                        HTTP_POOL.submit(post_location, payload)

                    else:
                        log(f"Unhandled proto {proto_hex}")
                except Exception as e:
                    log(f"Error processing frame: {e}")

    except socket.timeout:
        log(f"Connection timed out {addr}")
    except Exception as e:
        log(f"Exception for {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        log(f"Connection closed {addr}")

# --------------------- SERVER ---------------------
def start_server():
    log(f"Listening for GPS devices on {SERVER_HOST}:{SERVER_PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((SERVER_HOST, SERVER_PORT))
    s.listen(16)
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        log("Shutting down listener (KeyboardInterrupt)")
    except Exception as e:
        log(f"Server exception: {e}")
    finally:
        try:
            s.close()
        except:
            pass

if __name__ == "__main__":
    start_server()
