from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from models import db, User, Device, Location  # 🔥 Added Location
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask import send_file
import csv
import os
import io
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet




app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")  # ✅ safer
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gps_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Default session lifetime (when "Remember Me" is unchecked)
app.permanent_session_lifetime = timedelta(minutes=30)  # 30 min timeout

db.init_app(app)

@app.route('/')
def home():
    return render_template('home.html', logged_in=('user_id' in session))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Validation
        if not username or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "warning")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for("register"))

        # Store password securely
        hashed_password = generate_password_hash(password)
        user = User(username=username, password=hashed_password)

        db.session.add(user)
        db.session.commit()

        flash("✅ Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# ---- LOGIN ----
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get("remember")  # ✅ checkbox

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session.permanent = bool(remember)  # ✅ If checked, session is permanent
            if session.permanent:
                app.permanent_session_lifetime = timedelta(days=7)  # 7-day login
            else:
                app.permanent_session_lifetime = timedelta(minutes=30)  # Normal timeout

            flash("✅ Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("❌ Invalid username or password, please try again.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

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





# ---- DASHBOARD ----
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    if request.method == "POST":
        device_name = request.form.get("name")
        if not device_name:
            flash("Device name cannot be empty.", "danger")
        else:
            existing_device = Device.query.filter_by(name=device_name, user_id=user.id).first()
            if existing_device:
                flash("A device with this name already exists.", "warning")
            else:
                new_device = Device(name=device_name, user_id=user.id)
                db.session.add(new_device)
                db.session.commit()
                flash("Device added successfully!", "success")

        return redirect(url_for("dashboard"))

    # 👉 build device list with last_location
    devices = []
    for d in Device.query.filter_by(user_id=user.id).all():
        last_location = Location.query.filter_by(device_id=d.id).order_by(Location.timestamp.desc()).first()
        devices.append({
            "id": d.id,
            "name": d.name,
            "is_online": True if last_location else False,
            "last_location": {
                "timestamp": last_location.timestamp.strftime("%Y-%m-%d %H:%M:%S") if last_location else "Never",
                "latitude": last_location.latitude if last_location else None,
                "longitude": last_location.longitude if last_location else None
            }
        })


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

    location = Location.query.filter_by(device_id=device.id).order_by(Location.timestamp.desc()).first()
    if not location:
        flash("No location data for this device yet", "warning")
        return redirect(url_for("dashboard"))

    return render_template("map.html", devices=[{
        "id": device.id,
        "name": device.name,
        "latitude": location.latitude,
        "longitude": location.longitude
    }], logged_in=True)




""" @app.route("/map/<device_name>")
def map_device(device_name):
    device = Device.query.filter_by(name=device_name).first()
    if not device:
        flash("Device not found", "danger")
        return redirect(url_for("dashboard"))

    location = Location.query.filter_by(device_id=device.id).order_by(Location.timestamp.desc()).first()

    if not location:
        flash("No location data for this device yet", "warning")
        return redirect(url_for("dashboard"))

    return render_template("map.html", device=device, latitude=location.latitude, longitude=location.longitude)
 """
@app.route('/api/location', methods=['POST'])
def add_location():
    data = request.json
    device_id = data.get('device_id')
    latitude = data.get('latitude')
    longitude = data.get('longitude')

    if not all([device_id, latitude, longitude]):
        return jsonify({"error": "Missing fields"}), 400

    device = Device.query.get(device_id)
    if not device:
        return jsonify({"error": "Device not found"}), 404

    # Save location
    location = Location(latitude=latitude, longitude=longitude, device_id=device.id)
    db.session.add(location)
    db.session.commit()

    return jsonify({"message": "Location added successfully"}), 201


@app.route("/add_device", methods=["POST"])
def add_device():
    if "user_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("login"))

    device_name = request.form.get("device_name")
    if not device_name:
        flash("Device name cannot be empty.", "danger")
        return redirect(url_for("dashboard"))

    new_device = Device(name=device_name, user_id=session["user_id"])
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


# Edit device name
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
        if new_name:
            # check for duplicates
            existing_device = Device.query.filter_by(user_id=session["user_id"], name=new_name).first()
            if existing_device and existing_device.id != device.id:
                flash("⚠️ Another device already has that name.", "warning")
            else:
                device.name = new_name
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
@app.route("/api/history/<int:device_id>")
def api_history(device_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    device = Device.query.get_or_404(device_id)
    if device.user_id != session["user_id"]:
        return jsonify({"error": "Unauthorized"}), 403

    locations = (
        Location.query
        .filter_by(device_id=device.id)
        .order_by(Location.timestamp.asc())
        .all()
    )

    history = [
        {
            "latitude": float(loc.latitude),
            "longitude": float(loc.longitude),
            "timestamp": loc.timestamp.isoformat() if loc.timestamp else None
        }
        for loc in locations
    ]
    return jsonify(history)


@app.route("/map/history/<int:device_id>")
def view_history(device_id):
    if "user_id" not in session:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    device = Device.query.get_or_404(device_id)
    if device.user_id != session["user_id"]:
        flash("Unauthorized access.", "danger")
        return redirect(url_for("dashboard"))

    return render_template("map_history.html", device=device)

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

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)