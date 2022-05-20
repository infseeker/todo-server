from flask import request, jsonify
from flask_login import current_user, login_user, login_required, logout_user
from werkzeug.exceptions import *
from app import app, db
from ..models.User import *
from ..auth.basic import *


# Auth: Flask-login (Basic)
# OAuth: Google, Yandex, VK, Apple
@app.route("/todo/api/user/getcsrf", methods=["GET"])
def get_csrf():
    token = generate_csrf()
    response = jsonify({"detail": "CSRF cookie set", "token": token})
    response.headers.set("X-CSRFToken", token)
    return response


@app.route("/todo/api/user/hash", methods=["POST"])
def generate_hash():
    password = request.json.get("password")
    return (
        jsonify({"hash": generate_password_hash(password)})
        if password
        else "sorry bro..."
    )


@app.route("/todo/api/user/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    user = User.query.filter((User.name == username) | (User.email == username)).first()

    if user and user.verify_password(password):
        login_user(user)
        return jsonify({"login": True})

    return jsonify({"login": False})

@app.route("/todo/api/user/data", methods=["GET"])
@login_required
# @admin.require(403)
def user_data():
    user = get_user(current_user.id)
    return user_schema.dump(user)


@app.route("/todo/api/user/getsession", methods=["GET"])
def check_session():
    if current_user.is_authenticated:
        return jsonify({"login": True})

    return jsonify({"login": False})


@app.route("/todo/api/user/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"logout": True})
