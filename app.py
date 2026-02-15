from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

from config import Config
from extensions import db, login_manager
from models import User, Vault

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = "login"

# ---------------- ENCRYPTION KEY ----------------
if not os.path.exists("secret.key"):
    key = Fernet.generate_key()
    with open("secret.key", "wb") as f:
        f.write(key)
else:
    with open("secret.key", "rb") as f:
        key = f.read()

cipher = Fernet(key)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if User.query.filter_by(username=username).first():
            flash("User already exists")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)

        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully!")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials")

    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    if request.method == "POST":
        website = request.form["website"]
        password = request.form["password"]

        encrypted = cipher.encrypt(password.encode()).decode()

        new_entry = Vault(
            website=website,
            encrypted_password=encrypted,
            user_id=current_user.id
        )

        db.session.add(new_entry)
        db.session.commit()

        flash("Password saved!")

    entries = Vault.query.filter_by(user_id=current_user.id).all()

    for entry in entries:
        entry.decrypted = cipher.decrypt(entry.encrypted_password.encode()).decode()

    return render_template("dashboard.html", entries=entries)

@app.route("/delete/<int:id>")
@login_required
def delete(id):
    entry = Vault.query.get_or_404(id)

    if entry.user_id != current_user.id:
        return "Unauthorized"

    db.session.delete(entry)
    db.session.commit()
    flash("Deleted successfully")

    return redirect(url_for("dashboard"))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.errorhandler(404)
def not_found(e):
    return "Page not found", 404

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
