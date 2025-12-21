#!/usr/bin/env python3
"""
Simple TCP/UDP listener that dispatches incoming text lines to protocol parsers.
On successful parse it will POST to your Flask API (/api/location) with:
    {"device_imei": "<imei>", "latitude": <float>, "longitude": <float>}
You can change endpoint, port, or add authentication as needed.
"""
import socketserver
import threading
import requests
import json
import os
from importlib import import_module
from glob import glob

LISTEN_HOST = "0.0.0.0"
TCP_PORT = int(os.environ.get("DEVICE_PORT", 5001))
API_URL = os.environ.get("API_URL", "http://127.0.0.1:5000/api/location")
# Optional API key header if you want to secure the endpoint
API_KEY = os.environ.get("API_KEY", "")

# Load protocol modules from ./protocols/*.py (they must define parse(message:str) -> dict or None)
protocols = []
for path in glob("protocols/*.py"):
    name = path.replace("/", ".").replace("\\", ".")[:-3]
    if name.endswith("__init__"):
        continue
    try:
        m = import_module(name)
        if hasattr(m, "parse"):
            protocols.append(m)
            print("Loaded protocol:", name)
    except Exception as e:
        print("Failed loading protocol", name, e)

def try_parse(line):
    line = line.strip()
    for p in protocols:
        try:
            parsed = p.parse(line)
            if parsed:
                return parsed
        except Exception as e:
            print("Protocol", p, "raised", e)
    return None

def post_to_api(imei, lat, lon):
    payload = {"device_imei": imei, "latitude": lat, "longitude": lon}
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"
    try:
        r = requests.post(API_URL, json=payload, headers=headers, timeout=5)
        print("POST", payload, "->", r.status_code, r.text[:200])
        return r.status_code == 201 or r.status_code == 200
    except Exception as e:
        print("Failed to POST to API:", e)
        return False

class TCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        client = self.client_address
        print(f"TCP connection from {client}")
        for line in self.rfile:
            try:
                text = line.decode(errors="ignore").strip()
            except:
                text = str(line)
            if not text:
                continue
            print("RX:", text)
            parsed = try_parse(text)
            if parsed:
                imei = parsed.get("imei") or parsed.get("device_id")
                lat = parsed.get("latitude")
                lon = parsed.get("longitude")
                if imei and lat is not None and lon is not None:
                    post_to_api(imei, lat, lon)
                else:
                    print("Parsed but missing coords/imei:", parsed)
            else:
                print("Could not parse message")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

def run_tcp():
    with ThreadedTCPServer((LISTEN_HOST, TCP_PORT), TCPHandler) as server:
        print("TCP server listening on", LISTEN_HOST, TCP_PORT)
        server.serve_forever()

if __name__ == "__main__":
    run_tcp()
