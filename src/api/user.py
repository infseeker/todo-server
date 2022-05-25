import json
import re
from flask import request, jsonify
from marshmallow import ValidationError
from sqlalchemy import exc
from flask_login import current_user, login_user, login_required, logout_user
from werkzeug.exceptions import *
from app import app, db
from ..models.User import *
from ..auth.basic import *


# Auth: Flask-login (Basic)
# OAuth: Google, Yandex, VK, Apple


@app.route('/todo/api/user/validate-username', methods=['POST'])
def check_username():
    data = request.json

    if not data.get('username'):
        response = {'success': False, 'message': "JSON: Failed: username field not found or empty"}
        return jsonify(response), 400
    else:
        username = data.get('username').strip()

        # username pattern (min: 3, max: 15, chars: a-z, A-Z)
        pattern = re.compile('^[a-zA-Z]{3,15}$')

        if not pattern.match(username):
            response = {
                'success': False,
                'message': f"Failed: username {username} contents wrong characters (a-z, A-Z) / too short (3 min) / too long (15 max)",
            }
            return jsonify(response), 400
        else:
            user = User.query.filter(
                db.func.lower(User.username) == db.func.lower(username)
            ).first()

            if user:
                response = {
                    'success': False,
                    'message': f"Failed: username {username} is already in use",
                }
                return jsonify(response), 400

    response = {'success': True, 'message': f"Success: username {username} is free"}
    return jsonify(response), 200


@app.route('/todo/api/user/validate-email', methods=['POST'])
def check_email():
    data = request.json

    if not data.get('email'):
        response = {'success': False, 'message': "JSON: Failed: email field not found or empty"}
        return jsonify(response), 400
    else:
        email = data.get('email').strip().lower()

        # email pattern (user@mail.com)
        pattern = re.compile('(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)')

        if not pattern.match(email):
            response = {'success': False, 'message': f"Failed: email {email} has an invalid format"}
            return jsonify(response), 400
        else:
            user = User.query.filter(db.func.lower(User.email) == db.func.lower(email)).first()

            if user:
                response = {'success': False, 'message': f"Failed: email {email} is already in use"}
                return jsonify(response), 400

    response = {'success': True, 'message': f"Success: email {email} is free"}
    return jsonify(response), 200


@app.route('/todo/api/user/validate-password', methods=['POST'])
def check_password():
    data = request.json
    if not data.get('password'):
        response = {'success': False, 'message': "JSON: Failed: password field not found or empty"}
        return jsonify(response), 400
    else:
        password = data.get('password')

        # password pattern ()
        pattern = re.compile('^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,15}$')

        if not pattern.match(password):
            response = {'success': False, 'message': f"Failed: password has an invalid format"}
            return jsonify(response), 400

    response = {'success': True, 'message': f"Success: password format is valid"}
    return jsonify(response), 200


@app.route('/todo/api/user/register', methods=['POST'])
def register():
    if (
        check_username()[0].json['success']
        and check_email()[0].json['success']
        and check_password()[0].json['success']
    ):
        data = request.json

        try:
            new_user = user_schema.load(data, session=db.session)
        except ValidationError:
            response = {
                'success': False,
                'message': f"Failed: new user creation validation error, check your data",
            }
            return jsonify(response), 400

        try:
            db.session.add(new_user)
            db.session.commit()

            email = data.get('email').lower()
            response = {'success': True, 'message': f"Success: email has been sent on {email}"}
            return jsonify(response), 200
        except exc.IntegrityError:
            db.session.rollback()

            response = {
                'success': False,
                'message': "Failed: user with such username or email is already exists",
            }
            return jsonify(response), 400
    else:
        if not check_username()[0].json['success']:
            return check_username()
        elif not check_email()[0].json['success']:
            return check_email()
        elif not check_password()[0].json['success']:
            return check_password()


@app.route('/todo/api/user/csrf', methods=['GET'])
def get_csrf():
    token = generate_csrf()
    response = jsonify({
            'success': True,
            'message': f"Success: CSRF cookie set",
            'token': token
        })
    response.headers.set('X-CSRFToken', token)
    return response, 200


@app.route('/todo/api/user/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    db.func.lower(User.username) == db.func.lower(username)
    user = User.query.filter(
        (db.func.lower(User.username) == db.func.lower(username))
        | (db.func.lower(User.email) == db.func.lower(username))
    ).first()

    if user and user.verify_password(password):
        login_user(user)
        response = {
            'success': True,
            'message': f"Success: you are logged in",
        }
        return jsonify(response), 200

    response = {
        'success': False,
        'message': f"Failed: invalid username or password",
    }
    return jsonify(response), 400


@app.route('/todo/api/user/session', methods=['GET'])
def check_session():
    if not current_user.is_authenticated:
        response = {
            'success': False,
            'message': f"Failed: you are not authenticated",
        }
        return jsonify(response), 401

    response = {
        'success': True,
        'message': f"Success: you are logged in",
    }
    return jsonify(response), 200


@app.route('/todo/api/user/user-data', methods=['GET'])
@login_required
def get_user_data():
    response = {
        'success': True,
        'message': f"Success: you are logged in",
        'user-data': user_schema.dump(current_user)
    }
    return jsonify(response), 200


@app.route('/todo/api/user/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    response = {
        'success': True,
        'message': f"Success: you are logged out",
    }
    return jsonify(response)
