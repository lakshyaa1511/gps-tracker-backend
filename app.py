import os
import io
import csv
from datetime import datetime as _dt, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask import send_file
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
import smtplib
from email.message import EmailMessage

import requests

TRACCAR_URL = "http://localhost:8082"
TRACCAR_USER = "lakshyaa.otp@gmail.com"
TRACCAR_PASS = "Lakshyaa@Dhyey0911"  # replace with your actual password

# persistent session to hold cookies
traccar_session = requests.Session()

'''def traccar_login():
    """Logs into Traccar and stores session cookies."""
    try:
        data = {
            "email": TRACCAR_USER,
            "password": TRACCAR_PASS
        }
        resp = traccar_session.post(f"{TRACCAR_URL}/api/session", data=data)
        print(f"🔐 Traccar login: {resp.status_code}")
        if resp.status_code == 200:
            print("✅ Traccar session established.")
            return True
        else:
            print(f"❌ Login failed: {resp.text}")
            return False
    except Exception as e:
        print(f"⚠️ Traccar login error: {e}")
        return False'''
def traccar_login():
    """Logs into Traccar and stores session cookies."""
    try:
        data = {
            "email": TRACCAR_USER,       # ✅ Use correct variable names
            "password": TRACCAR_PASS
        }
        resp = traccar_session.post(f"{TRACCAR_URL}/api/session", data=data)
        print(f"🔐 Traccar login: {resp.status_code}")
        if resp.status_code == 200:
            print("✅ Traccar session established.")
            return True
        else:
            print(f"❌ Login failed: {resp.text}")
            return False
    except Exception as e:
        print(f"⚠️ Traccar login error: {e}")
        return False


def traccar_get_devices():
    """Fetch devices directly from the Traccar server."""
    try:
        response = requests.get(
            f"{TRACCAR_URL}/api/devices",
            auth=(TRACCAR_USER, TRACCAR_PASS),
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
        else:
            print(f"❌ Traccar device fetch failed: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        print(f"⚠️ Error connecting to Traccar: {e}")
        return []


from models import db, User, Device, Location, OTP, PasswordResetToken
from sqlalchemy import or_
#from routes import routes

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///gps_tracker.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

from routes_traccar import traccar_bp
#app.register_blueprint(routes)
app.register_blueprint(traccar_bp)

# Default session lifetime
app.permanent_session_lifetime = timedelta(minutes=30)

db.init_app(app)
print("SMTP DEBUG:", os.environ.get("SMTP_HOST"), os.environ.get("SMTP_USER"))

def send_email(to_email: str, subject: str, body: str) -> bool:
    """
    Sends email using SMTP environment variables. Returns True if sent.
    If SMTP not configured, log to server and return False.
    Required env vars: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS (SMTP_PORT optional)
    """
    host = os.environ.get("SMTP_HOST")
    port = os.environ.get("SMTP_PORT", "587")
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASS")

    if not (host and user and password):
        app.logger.info("SMTP not configured - email content:\nTo: %s\nSubject: %s\n\n%s", to_email, subject, body)
        return False

    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = user
        msg["To"] = to_email
        msg.set_content(body)

        with smtplib.SMTP(host, int(port)) as smtp:
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(msg)
        return True
    except Exception as e:
        app.logger.exception("Failed to send email: %s", e)
        return False


@app.route("/")
def home():
    return render_template("home.html", logged_in=('user_id' in session))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "warning")
            return redirect(url_for("register"))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists.", "danger")
            return redirect(url_for("register"))

        hashed = generate_password_hash(password)
        user = User(username=username, email=email, password=hashed, is_verified=False)
        db.session.add(user)
        db.session.commit()

        # create OTP
        otp_entry = OTP.create_for_user(user.id, expiry_minutes=10)
        db.session.add(otp_entry)
        db.session.commit()

        # Send OTP by email (or log it if SMTP not configured)
        subject = "Your GPS Tracker verification code"
        body = f"Hi {username},\n\nYour verification code is: {otp_entry.code}\nIt will expire at {otp_entry.expires_at.isoformat()} UTC.\n\nIf you did not request this, ignore."
        sent = send_email(email, subject, body)

        if sent:
            flash("Verification code sent to your email. Please check and verify your account.", "info")
        else:
            # For development: we do NOT flash the OTP to the browser, only log it to server.
            app.logger.info("OTP for %s (user id=%s): %s", email, user.id, otp_entry.code)
            flash("Verification code could not be sent by email (SMTP not configured). Check server logs for the code.", "warning")

        return redirect(url_for("verify_otp", user_id=user.id))

    return render_template("register.html")


@app.route("/verify/<int:user_id>", methods=["GET", "POST"])
def verify_otp(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_verified:
        flash("Account already verified. Please login.", "info")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        otp = OTP.query.filter_by(user_id=user.id, code=code, used=False).first()
        if otp and otp.expires_at > datetime.utcnow():
            user.is_verified = True
            otp.used = True
            db.session.commit()
            flash("Your account is verified — you can now log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Invalid or expired OTP. Please request a new code.", "danger")
            return redirect(url_for("verify_otp", user_id=user.id))

    return render_template("verify.html", user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username', "").strip()
        password = request.form.get('password', "")
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()

        if user and check_password_hash(user.password, password):
            if not user.is_verified:
                flash("Please verify your email before logging in.", "warning")
                return redirect(url_for("verify_otp", user_id=user.id))

            session['user_id'] = user.id
            flash("Logged in successfully.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

# ---- PASSWORD RESET ----
@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    reset = PasswordResetToken.query.filter_by(token=token, used=False).first()

    if not reset or reset.expires_at < datetime.utcnow():
        flash("❌ Invalid or expired reset link.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_pass = request.form.get("new_password")
        if not new_pass or len(new_pass) < 6:
            flash("⚠️ Password must be at least 6 characters.", "warning")
            return redirect(url_for("reset_password", token=token))

        user = User.query.get(reset.user_id)
        user.password = generate_password_hash(new_pass)
        reset.used = True
        db.session.commit()

        flash("✅ Password reset successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username")
        user = User.query.filter_by(username=username).first()

        if not user:
            flash("❌ No account found with that username.", "danger")
            return redirect(url_for("forgot_password"))

        # Generate token (30 min expiry by default)
        reset_entry = PasswordResetToken.create(user_id=user.id)
        token = reset_entry.token

        # Normally send via email – for now just display in flash
        flash(f"🔑 Use this reset link: {url_for('reset_password', token=token, _external=True)}", "info")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


# --- other routes (unchanged logic, trimmed here for brevity) ---
# Copy your other existing routes for dashboard, devices, map, etc.
# Ensure imports at top include Device, Location, PasswordResetToken, OTP as included above.
# (For brevity I am not repeating all map/history routes here — keep the same content you had,
#  but ensure you're importing OTP & PasswordResetToken as shown above.)

# Example minimal dashboard stub (keep your full implementation)
'''@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in.", "warning")
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    # build devices list as you already do in your working app
    devices = []
    for d in Device.query.filter_by(user_id=user.id).all():
        last_location = Location.query.filter_by(device_id=d.id).order_by(Location.timestamp.desc()).first()
        devices.append({
            "id": d.id,
            "name": d.name,
            "is_online": bool(last_location),
            "last_location": {"timestamp": last_location.timestamp.strftime("%Y-%m-%d %H:%M:%S") if last_location else "Never"}
        })
    return render_template("dashboard.html", devices=devices)'''
'''@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in.", "warning")
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])

    # local devices (existing logic)
    devices = []
    for d in Device.query.filter_by(user_id=user.id).all():
        last_location = Location.query.filter_by(device_id=d.id).order_by(Location.timestamp.desc()).first()
        devices.append({
            "id": d.id,
            "name": d.name,
            "is_online": bool(last_location),
            "last_location": {"timestamp": last_location.timestamp.strftime("%Y-%m-%d %H:%M:%S") if last_location else "Never"}
        })

    # --- NEW: fetch Traccar devices and show link/online/status ---
    traccar_devices = []
    try:
        remote = traccar_get_devices()
        for rd in remote:
            # match by uniqueId -> local Device. Adjust field if your local field is imei or unique id
            local = Device.query.filter(or_(Device.imei == rd.get("uniqueId"), Device.imei == rd.get("uniqueId"))).first()
            traccar_devices.append({
                "traccar_id": rd.get("id"),
                "name": rd.get("name") or rd.get("uniqueId"),
                "uniqueId": rd.get("uniqueId"),
                "status": rd.get("status"),
                "lastUpdate": rd.get("lastUpdate"),
                "positionId": rd.get("positionId"),
                "linked_device_id": local.id if local else None,
                "linked": bool(local)
            })
    except Exception as e:
        app.logger.exception("Failed to fetch Traccar devices: %s", e)
        flash("Could not fetch Traccar devices (check logs).", "warning")

    return render_template("dashboard.html", devices=devices, traccar_devices=traccar_devices)'''


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    # Fetch Traccar devices
    try:
        traccar_devices = traccar_get_devices()
    except Exception as e:
        app.logger.error(f"Failed to fetch Traccar devices: {e}")
        traccar_devices = []

    # --- Merge logic ---
    final_devices = []
    added_imeis = set()

    # Prefer Traccar version if exists
    for rd in traccar_devices:
        imei = str(rd.get("uniqueId"))
        added_imeis.add(imei)
        final_devices.append({
            "id": rd.get("id"),
            "name": rd.get("name"),
            "uniqueId": imei,
            "status": rd.get("status"),
            "lastUpdate": rd.get("lastUpdate"),
            "linked": True
        })

    # Add local devices only if not already fetched from Traccar
    for local in Device.query.filter_by(user_id=user.id).all():
        if str(local.imei) not in added_imeis:
            last_location = Location.query.filter_by(device_id=local.id).order_by(Location.timestamp.desc()).first()
            final_devices.append({
                "id": local.id,
                "name": local.name,
                "uniqueId": local.imei,
                "status": "online" if last_location else "offline",
                "lastUpdate": last_location.timestamp.strftime("%Y-%m-%d %H:%M:%S") if last_location else "Never",
                "linked": True
            })

    devices = final_devices
    return render_template("dashboard.html", devices=devices)


# ---- DEVICES LIST ----
@app.route("/devices")
def devices():
    if "user_id" not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session['user_id'])

    devices_data = []
    for device in user.devices:
        last_location = Location.query.filter_by(device_id=device.id).order_by(Location.timestamp.desc()).first()
        is_online = False
        if last_location and last_location.timestamp:
            if datetime.utcnow() - last_location.timestamp < timedelta(minutes=2):
                is_online = True
        devices_data.append({
            "id": device.id,
            "name": device.name,
            "last_location": {
                "latitude": last_location.latitude if last_location else None,
                "longitude": last_location.longitude if last_location else None,
                "timestamp": last_location.timestamp if last_location else None
            }
        })

    return render_template("devices.html", devices=devices_data)

# ---- LOGOUT ----
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# ---- MAP ROUTES ----
@app.route("/integrations/traccar/link", methods=["POST"])
def link_traccar_device():
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    traccar_id = request.form.get("traccar_id")
    uniqueId = request.form.get("uniqueId")
    name = request.form.get("name") or f"traccar-{uniqueId}"

    if not uniqueId:
        return jsonify({"error": "missing uniqueId"}), 400

    if Device.query.filter_by(imei=uniqueId).first():
        return jsonify({"error": "already linked"}), 400

    new_device = Device(user_id=session["user_id"], imei=uniqueId, name=name)
    db.session.add(new_device)
    db.session.commit()
    return jsonify({"status": "ok", "device_id": new_device.id})
# Show all devices on the map
@app.route("/map")
def map_all_devices():
    if 'user_id' not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session['user_id'])
    devices_data = []
    devices = Device.query.filter_by(user_id=user.id).all()

    for d in devices:
        last = (
            Location.query
            .filter_by(device_id=d.id)
            .order_by(Location.timestamp.desc())
            .first()
        )
        devices_data.append({
            "id": d.id,
            "name": d.name,
            "type": d.type or "car",  # default fallback
            "latitude": float(last.latitude) if last else None,
            "longitude": float(last.longitude) if last else None,
            "timestamp": last.timestamp.isoformat() if last and last.timestamp else None
        })

    if not devices_data:
        flash("No devices with location data yet.", "info")
        return redirect(url_for("dashboard"))

    return render_template("map.html", devices=devices_data, logged_in=True)

# Show a single device
@app.route("/map/device/<int:device_id>")
def map_device(device_id):
    if "user_id" not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    device = Device.query.filter_by(id=device_id, user_id=session["user_id"]).first()
    if not device:
        flash("Device not found", "danger")
        return redirect(url_for("dashboard"))

    try:
        positions = get_positions_for_device(1)  # Traccar’s numeric ID, not IMEI
        if not positions:
            flash("No map data available for this device yet.", "info")
            return render_template("map.html", device=device, positions=[])

        # pick the last known position
        pos = positions[-1]
        lat = pos.get("latitude")
        lng = pos.get("longitude")

        print(f"📍 Latest position for device {device_id}: ({lat}, {lng})")

        return render_template(
            "map.html",
            device=device,
            positions=positions,
            latitude=lat,
            longitude=lng
        )
    except Exception as e:
        app.logger.exception(f"Map fetch error: {e}")
        flash("Error fetching map data.", "danger")
        return redirect(url_for("dashboard"))


# ---- API: Receive device location ----
"""@app.route("/api/location", methods=["POST"])
def api_location():
    data = request.get_json() or {}
    imei = data.get("imei")
    latitude = data.get("latitude")
    longitude = data.get("longitude")

    if not all([imei, latitude, longitude]):
        return jsonify({"error": "Missing fields"}), 400

    device = Device.query.filter_by(imei=imei).first()
    if not device:
        return jsonify({"error": "Device not found"}), 404

    loc = Location(device_id=device.id, latitude=latitude, longitude=longitude)
    db.session.add(loc)
    db.session.commit()

    return jsonify({"status": "ok"})"""
@app.route("/api/location", methods=["POST"])
def api_location():
    data = request.get_json(force=True, silent=True) or {}

    print("📩 Received data from listener:", data, flush=True)

    # Try to handle both 'lat'/'lng' or 'latitude'/'longitude'
    imei = data.get("imei") or data.get("device_imei")
    latitude = data.get("latitude") or data.get("lat")
    longitude = data.get("longitude") or data.get("lng")

    if not imei or not latitude or not longitude:
        return jsonify({"error": "Missing fields", "received": data}), 400

    device = Device.query.filter_by(imei=imei).first()
    if not device:
        return jsonify({"error": "Device not found"}), 404

    loc = Location(device_id=device.id, latitude=latitude, longitude=longitude)
    db.session.add(loc)
    db.session.commit()

    print(f"✅ Location saved for IMEI {imei} at ({latitude}, {longitude})", flush=True)
    return jsonify({"status": "ok"})


@app.route("/api/update_location", methods=["POST"])
def update_location():
    data = request.get_json() or {}

    imei = data.get("imei")
    lat = data.get("lat")
    lng = data.get("lng")
    speed = data.get("speed")

    if not imei or lat is None or lng is None:
        return jsonify({"error": "Missing fields"}), 400

    device = Device.query.filter_by(imei=str(imei)).first()
    if not device:
        return jsonify({"error": "Device not found"}), 404

    # Update device info
    device.last_lat = float(lat)
    device.last_lng = float(lng)
    device.last_update = datetime.utcnow()

    db.session.commit()

    # Also save full location log
    #loc = Location(device_id=device.id, lat=lat, lng=lng, speed=speed, timestamp=datetime.utcnow())
    loc = Location(device_id=device.id, latitude=lat, longitude=lng, speed=speed, timestamp=datetime.utcnow())
    db.session.add(loc)
    db.session.commit()

    return jsonify({"message": "Location updated successfully"}), 200

@app.route("/api/live_feed", methods=["GET"])
def live_feed():
    """Return latest location data for all devices belonging to the logged-in user."""
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session["user_id"]
    devices = Device.query.filter_by(user_id=user_id).all()

    live_data = []
    for d in devices:
        last = (
            Location.query
            .filter_by(device_id=d.id)
            .order_by(Location.timestamp.desc())
            .first()
        )
        if last:
            live_data.append({
                "imei": d.imei,
                "name": d.name,
                "latitude": float(last.latitude),
                "longitude": float(last.longitude),
                "speed": getattr(last, "speed", 0),
                "timestamp": last.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })

    return jsonify(live_data)


# ---- ADD DEVICE ----
"""@app.route("/add_device", methods=["GET", "POST"])
def add_device():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        imei = request.form.get("imei", "").strip()
        name = request.form.get("name", "").strip()

        if not imei or not name:
            flash("IMEI and Name are required.", "danger")
            return redirect(url_for("add_device"))

        existing = Device.query.filter_by(imei=imei).first()
        if existing:
            flash("⚠️ Device with this IMEI already exists.", "warning")
            return redirect(url_for("add_device"))

        new_device = Device(user_id=session["user_id"], imei=imei, name=name)
        db.session.add(new_device)
        db.session.commit()

        flash("✅ Device added successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_device.html")"""
@app.route("/add_device", methods=["POST"])
def add_device():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    device_name = request.form.get("device_name", "").strip()
    device_imei = request.form.get("device_imei", "").strip()

    if not device_name or not device_imei:
        flash("All fields are required!", "danger")
        return redirect(url_for("dashboard"))

    # check if IMEI already exists
    existing = Device.query.filter_by(imei=device_imei).first()
    if existing:
        flash("⚠️ A device with that IMEI already exists.", "warning")
        return redirect(url_for("dashboard"))

    new_device = Device(name=device_name, imei=device_imei, user_id=session["user_id"])
    db.session.add(new_device)
    db.session.commit()

    flash("✅ Device added successfully!", "success")
    return redirect(url_for("dashboard"))


# Delete a device
@app.route("/devices/delete/<int:device_id>", methods=["POST"])
def delete_device(device_id):
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    device = Device.query.get_or_404(device_id)
    if device.user_id != session["user_id"]:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("devices"))

    db.session.delete(device)
    db.session.commit()
    flash("🗑️ Device deleted successfully!", "success")
    return redirect(url_for("devices"))


# Edit device name and type
@app.route("/devices/edit/<int:device_id>", methods=["GET", "POST"])
def edit_device(device_id):
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    device = Device.query.get_or_404(device_id)
    if device.user_id != session["user_id"]:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("devices"))

    if request.method == "POST":
        new_name = request.form.get("name")
        new_type = request.form.get("type", device.type)
        if new_name:
            # check for duplicates
            existing_device = Device.query.filter_by(user_id=session["user_id"], name=new_name).first()
            if existing_device and existing_device.id != device.id:
                flash("⚠️ Another device already has that name.", "warning")
            else:
                device.name = new_name
                device.type = new_type
                db.session.commit()
                flash("✅ Device updated successfully!", "success")


                return redirect(url_for("devices"))

    return render_template("edit_device.html", device=device)

@app.route("/api/devices", methods=["GET"])
def api_devices():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.get(session['user_id'])
    devices_data = []
    for d in user.devices:
        last = (
            Location.query
            .filter_by(device_id=d.id)
            .order_by(Location.timestamp.desc())
            .first()
        )
        devices_data.append({
            "id": d.id,
            "name": d.name,
            "latitude": float(last.latitude) if last else None,
            "longitude": float(last.longitude) if last else None,
            "timestamp": last.timestamp.isoformat() if last and last.timestamp else None
        })

    return jsonify(devices_data)

# ==============================
# Device history page (HTML view)
# ==============================
""" @app.route("/map/history/<int:device_id>")
def map_history(device_id):
    if "user_id" not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    device = Device.query.get_or_404(device_id)
    if device.user_id != session["user_id"]:
        flash("Unauthorized access to this device.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("map_history.html", device=device)
 """

# ==============================
# API: Fetch location history
# ==============================
# ---- API: Fetch location history (with optional start/end datetime filters) ----
# avoid clash with existing import name

@app.route("/api/history/<int:device_id>")
def api_history(device_id):
    """
    Fetch filtered, ordered GPS history for a device.
    Supports ?from= and ?to= query params (ISO8601 or yyyy-mm-ddTHH:MM).
    If no range provided, defaults to last 24 hours.
    """

    from datetime import datetime, timedelta

    # Parse input time filters
    def parse_time(t):
        if not t:
            return None
        for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(t, fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(t)
        except Exception:
            return None

    from_time = request.args.get("from")
    to_time = request.args.get("to")

    now = datetime.utcnow()
    from_dt = parse_time(from_time) or (now - timedelta(hours=24))
    to_dt = parse_time(to_time) or now

    query = (
        Location.query
        .filter_by(device_id=device_id)
        .filter(Location.timestamp >= from_dt, Location.timestamp <= to_dt)
        .order_by(Location.timestamp.asc())
    )

    data = query.all()

    clean_data = []
    last_point = None
    for loc in data:
        if not loc.latitude or not loc.longitude:
            continue
        if not (-90 <= loc.latitude <= 90 and -180 <= loc.longitude <= 180):
            continue
        if last_point and (loc.latitude == last_point["latitude"] and loc.longitude == last_point["longitude"]):
            # Skip duplicates to keep the line clean
            continue
        clean_data.append({
            "latitude": float(loc.latitude),
            "longitude": float(loc.longitude),
            "timestamp": loc.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "speed": float(getattr(loc, "speed", 0) or 0),
        })
        last_point = clean_data[-1]

    return jsonify(clean_data)


'''@app.route("/map/history/<int:device_id>")
def view_history(device_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        now = datetime.utcnow()
        start_time = (now - timedelta(days=1)).isoformat() + "Z"
        end_time = now.isoformat() + "Z"

        response = traccar_session.get(
            f"{TRACCAR_URL}/api/reports/route",
            params={"deviceId": device_id, "from": start_time, "to": end_time},
            auth=(TRACCAR_USER, TRACCAR_PASS)
        )
        if response.status_code == 200:
            data = response.json()
            return render_template("history.html", history=data, device_id=device_id)
        flash("Failed to fetch history data.", "warning")
        return redirect(url_for("dashboard"))
    except Exception as e:
        app.logger.error(f"History fetch error: {e}")
        flash("Error fetching history.", "danger")
        return redirect(url_for("dashboard"))'''

@app.route("/map/history/<int:device_id>")
def view_history(device_id):
    if "user_id" not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    # Get device info from DB
    device = Device.query.filter_by(id=device_id, user_id=session["user_id"]).first()
    if not device:
        flash("Device not found.", "danger")
        return redirect(url_for("dashboard"))

    try:
        positions = get_positions_for_device(device_id)
        if not positions:
            flash("No history found for this device yet.", "info")
            return render_template("map_history.html", device=device, positions=[])
        return render_template("map_history.html", device=device, positions=positions)
    except Exception as e:
        app.logger.exception(f"History fetch error: {e}")
        flash("Error fetching history.", "danger")
        return redirect(url_for("dashboard"))


@app.route("/map/history/clear/<int:device_id>", methods=["POST"])
def clear_history(device_id):
    if "user_id" not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    device = Device.query.get_or_404(device_id)
    if device.user_id != session["user_id"]:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("dashboard"))

    # Delete all location entries for this device
    Location.query.filter_by(device_id=device.id).delete()
    db.session.commit()

    flash("🧹 Trip history cleared successfully!", "success")
    return redirect(url_for("view_history", device_id=device.id))

from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    if request.method == "POST":
        new_pass = request.form.get("new_password")
        if len(new_pass) < 6:
            flash("Password must be at least 6 characters.", "danger")
        else:
            user.password = generate_password_hash(new_pass)
            db.session.commit()
            flash("✅ Password updated successfully!", "success")
            return redirect(url_for("profile"))

    return render_template("profile.html", user=user)

# ==========================
# Download Trip Report (CSV)
# ==========================
@app.route("/map/history/csv/<int:device_id>")
def download_csv(device_id):
    if "user_id" not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    device = Device.query.get_or_404(device_id)
    if device.user_id != session["user_id"]:
        flash("Unauthorized access.", "danger")
        return redirect(url_for("dashboard"))

    locations = Location.query.filter_by(device_id=device.id).order_by(Location.timestamp.asc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Latitude", "Longitude", "Timestamp"])
    for loc in locations:
        writer.writerow([loc.latitude, loc.longitude, loc.timestamp])

    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"{device.name}_trip.csv"
    )


# ==========================
# Download Trip Report (PDF)
# ==========================
@app.route("/map/history/pdf/<int:device_id>")
def download_pdf(device_id):
    if "user_id" not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    device = Device.query.get_or_404(device_id)
    if device.user_id != session["user_id"]:
        flash("Unauthorized access.", "danger")
        return redirect(url_for("dashboard"))

    locations = Location.query.filter_by(device_id=device.id).order_by(Location.timestamp.asc()).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()

    elements.append(Paragraph(f"Trip Report - {device.name}", styles["Title"]))

    data = [["Latitude", "Longitude", "Timestamp"]]
    for loc in locations:
        data.append([loc.latitude, loc.longitude, loc.timestamp.strftime("%Y-%m-%d %H:%M:%S")])

    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.lightblue),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold')
    ]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"{device.name}_trip.pdf"
    )

# password reset / other utilities: ensure you use PasswordResetToken.create() when generating tokens.

@app.route("/integrations/traccar/link", methods=["POST"])
def link_traccar_device_v2():
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    traccar_id = request.form.get("traccar_id")
    uniqueId = request.form.get("uniqueId")
    name = request.form.get("name") or f"traccar-{uniqueId}"

    if not uniqueId:
        return jsonify({"error": "missing uniqueId"}), 400

    if Device.query.filter_by(imei=uniqueId).first():
        return jsonify({"error": "already linked"}), 400

    new_device = Device(user_id=session["user_id"], imei=uniqueId, name=name)
    db.session.add(new_device)
    db.session.commit()
    return jsonify({"status": "ok", "device_id": new_device.id})

'''def get_positions_for_device(device_id, limit=500):
    """Fetch latest positions from Traccar for a specific device safely."""
    try:
        resp = traccar_session.get(f"{TRACCAR_URL}/api/positions", timeout=10)
        if resp.status_code != 200:
            print(f"⚠️ Traccar positions fetch failed: {resp.status_code} - {resp.text}")
            return []

        # Some Traccar setups return dict with 'id' key instead of a list
        data = resp.json()
        if isinstance(data, dict):
            data = [data]

        # Filter positions by this device ID
        positions = [p for p in data if p.get("deviceId") == device_id]
        return positions[-limit:] if positions else []
    except Exception as e:
        print(f"⚠️ Error fetching positions: {e}")
        return []'''

def get_positions_for_device(device_id, limit=1):
    """Fetch latest positions from Traccar for a specific device."""
    try:
        resp = traccar_session.get(f"{TRACCAR_URL}/api/positions", timeout=10)
        if resp.status_code != 200:
            print(f"⚠️ Traccar positions fetch failed: {resp.status_code} - {resp.text}")
            return []

        data = resp.json()
        if isinstance(data, dict):
            data = [data]

        # Filter by matching Traccar's deviceId (not IMEI)
        filtered = [p for p in data if str(p.get("deviceId")) == str(device_id)]

        if not filtered:
            print(f"ℹ️ No position data found for device {device_id}")
            return []

        # Sort newest last
        filtered.sort(key=lambda x: x.get("fixTime", ""))
        print(f"✅ Got {len(filtered)} positions for Traccar device {device_id}")
        return filtered[-limit:]
    except Exception as e:
        print(f"⚠️ Error fetching positions: {e}")
        return []


@app.route("/integrations/traccar/positions/<int:traccar_device_id>")
def proxy_positions(traccar_device_id):
    try:
        positions = get_positions_for_device(traccar_device_id)
        if not positions:
            print(f"ℹ️ No Traccar positions found for device {traccar_device_id}")
            return jsonify([])

        # Normalize data for the frontend
        cleaned = []
        for p in positions:
            cleaned.append({
                "id": p.get("id"),
                "deviceId": p.get("deviceId"),
                "latitude": p.get("latitude"),
                "longitude": p.get("longitude"),
                "speed": p.get("speed"),
                "course": p.get("course"),
                "fixTime": p.get("fixTime"),
                "deviceTime": p.get("deviceTime"),
                "serverTime": p.get("serverTime")
            })
        return jsonify(cleaned)
    except Exception as e:
        app.logger.exception(f"Map fetch error: {e}")
        return jsonify([]), 500

traccar_login()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
