from flask import request, jsonify
from werkzeug.exceptions import *
from webbrowser import get
from app import app, db
from ..models.User import *
from ..auth.basic import *


# Auth: Flask-login (Basic)
# OAuth: Google, Yandex, VK, Apple
@app.route("/todo/api/user/login", methods=["POST"])
def login():
    return "api [user]: login"


@app.route("/todo/api/user/register", methods=["POST"])
def register():
    return "api [user]: register"


@app.route("/todo/api/user/restore", methods=["POST"])
def restore():
    return "api [user]: restore"


@app.route("/todo/api/user/logout", methods=["POST"])
def logout():
    return "api [user]: logout"
