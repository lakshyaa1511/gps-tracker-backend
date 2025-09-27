from app import app, db
from models import User, Device

with app.app_context():
    # check if user exists
    u = User.query.filter_by(username="testuser").first()
    if not u:
        u = User(username="testuser", password="password123")
        db.session.add(u)
        db.session.commit()
        print("✅ New user added:", u.username)
    else:
        print("ℹ️ User already exists:", u.username)

    # check if device exists
    d = Device.query.filter_by(name="Device 1", user_id=u.id).first()
    if not d:
        d = Device(name="Device 1", user_id=u.id)
        db.session.add(d)
        db.session.commit()
        print("✅ New device added:", d.name)
    else:
        print("ℹ️ Device already exists:", d.name)
