# Auth: Flask-login (Basic)
# OAuth: Google, Yandex, VK, Apple

import os

from flask_cors import CORS
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect, generate_csrf

from app import app
from ..models.User import *

app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"

# CSRF
csrf = CSRFProtect(app)

# CORS
cors = CORS(
    app,
    resources={r"*": {"origins": "http://localhost:3000"}},
    expose_headers=["Content-Type", "X-CSRFToken"],
    supports_credentials=True,
)


@login_manager.user_loader
def get_user(id):
    return User.query.get(id)
