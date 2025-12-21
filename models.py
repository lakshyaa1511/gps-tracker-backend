from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import secrets


db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)   # ✅ new
    created_at = db.Column(db.DateTime, default=datetime.utcnow)   # ✅ new
    is_verified = db.Column(db.Boolean, default=False)  # ✅ add this
    devices = db.relationship("Device", backref="user", lazy=True)


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    imei = db.Column(db.String(50), unique=True, nullable=False)
    type = db.Column(db.String(50), default="car")
    last_lat = db.Column(db.Float)
    last_lng = db.Column(db.Float)
    last_update = db.Column(db.DateTime)
    locations = db.relationship("Location", backref="device", lazy=True)


"""class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)"""
class Location(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    speed = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)



# 🔑 For password reset tokens
class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def generate_token():
        return secrets.token_hex(32)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(minutes=5))
    used = db.Column(db.Boolean, default=False)

    @staticmethod
    def generate_otp(user_id):
        code = str(secrets.randbelow(999999)).zfill(6)
        otp = OTP(user_id=user_id, code=code)
        db.session.add(otp)
        db.session.commit()
        return otp

    @classmethod
    def create_for_user(cls, user_id, expiry_minutes=10):
        import secrets
        from datetime import datetime, timedelta
        code = secrets.token_hex(3)  # e.g. "a1b2c3"
        expires = datetime.utcnow() + timedelta(minutes=expiry_minutes)
        return cls(user_id=user_id, code=code, expires_at=expires)
