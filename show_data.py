from app import app, db
from models import User, Device

with app.app_context():
    users = User.query.all()
    for u in users:
        print("User:", u.username)
        devices = Device.query.filter_by(user_id=u.id).all()
        for d in devices:
            print("  Device:", d.name)
