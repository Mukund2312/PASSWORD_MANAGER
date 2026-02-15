from flask_login import UserMixin
from extensions import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    passwords = db.relationship("Vault", backref="owner", lazy=True)

class Vault(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(200), nullable=False)
    encrypted_password = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
