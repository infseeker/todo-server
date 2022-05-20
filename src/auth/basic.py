# Auth: Flask-login (Basic)
# OAuth: Google, Yandex, VK, Apple

import os

from flask_cors import CORS
from flask_login import LoginManager, current_user
from flask_principal import (
    Principal,
    Permission,
    Identity,
    AnonymousIdentity,
    identity_loaded,
    RoleNeed,
    UserNeed,
)
from flask_wtf.csrf import CSRFProtect, generate_csrf

from app import app
from ..models.User import *

app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# CSRF
csrf = CSRFProtect(app)

# CORS
cors = CORS(
    app,
    resources={r"*": {"origins": "http://localhost:3000"}},
    expose_headers=["Content-Type", "X-CSRFToken"],
    supports_credentials=True,
)

# authentication
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"


@login_manager.user_loader
def get_user(id):
    return User.query.get(id)


# authorization
principals = Principal(app)
admin = Permission(RoleNeed("admin"))


@principals.identity_loader
def read_identity_from_flask_login():
    if current_user.is_authenticated:
        return Identity(current_user.id)
    return AnonymousIdentity()


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    if not isinstance(identity, AnonymousIdentity):
        identity.provides.add(UserNeed(identity.id))

        if current_user.is_admin:
            identity.provides.add(RoleNeed("admin"))
