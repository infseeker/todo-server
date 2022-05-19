from app import app, db
from models.User import *


@app.route("/todo/api/user/register", methods=["POST"])
def register():
    return "api [user]: register"


@app.route("/todo/api/user/auth", methods=["POST"])
def auth():
    return "api [user]: auth"


@app.route("/todo/api/user/restore", methods=["POST"])
def restore():
    return "api [user]: restore"


@app.route("/todo/api/user/logout", methods=["POST"])
def logout():
    return "api [user]: logout"
