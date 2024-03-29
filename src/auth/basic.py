import os
from flask import jsonify

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
    SECRET_KEY=os.environ['SECRET_KEY'],
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=eval(os.environ['SESSION_COOKIE_SECURE']),
)

# CSRF Protection
csrf = CSRFProtect(app)
app.config['WTF_CSRF_TIME_LIMIT'] = None

# CORS
cors = CORS(
    app,
    resources={
        r'*': {
            'origins': [
                'http://192.168.0.2:3000',
                'http://127.0.0.1:3000',
                'http://localhost:3000',
                'https://infseeker.ru',
                'https://react.infseeker.ru',
                'https://todo.infseeker.ru',
            ]
        }
    },
    expose_headers=['Content-Type', 'X-CSRFToken'],
    supports_credentials=True,
)

# authentication
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = 'strong'
app.config.update(
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE='Lax',
    REMEMBER_COOKIE_SECURE=eval(os.environ['SESSION_COOKIE_SECURE']),
)


@login_manager.unauthorized_handler
def unauthorized():
    response = {'message': 'You are not authenticated', 'code': 401}
    return jsonify(response), 401


@app.errorhandler(403)
def forbidden():
    response = {'message': 'You do not have permissions', 'code': 403}
    return jsonify(response), 403


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(session_id=user_id).first()


# authorization
principals = Principal(app)
admin = Permission(RoleNeed('admin'))


@principals.identity_loader
def read_identity_from_flask_login():
    if current_user.is_authenticated:
        return Identity(current_user.id)
    return AnonymousIdentity()


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    if not isinstance(identity, AnonymousIdentity):
        identity.provides.add(UserNeed(identity.id))

        if current_user.admin:
            identity.provides.add(RoleNeed('admin'))
