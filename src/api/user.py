import json
import re
from flask import request, jsonify
from sqlalchemy import exc
from flask_login import current_user, login_user, login_required, logout_user
from psycopg2 import IntegrityError
from werkzeug.exceptions import *
from app import app, db
from ..models.User import *
from ..auth.basic import *


# Auth: Flask-login (Basic)
# OAuth: Google, Yandex, VK, Apple


@app.route('/todo/api/user/check-username', methods=['POST'])
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


@app.route('/todo/api/user/check-email', methods=['POST'])
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


@app.route('/todo/api/user/check-password', methods=['POST'])
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
    data = request.json
    new_user = user_schema.load(data, session=db.session)

    

    if (
        check_username()[0].json['success']
        and check_email()[0].json['success']
        and check_password()[0].json['success']
    ):
        try:
            db.session.add(new_user)
            db.session.commit()

            email = data.get('email')
            response = {'success': True, 'message': f"Success: email has been sent on {email}"}
            return jsonify(response), 200
        except exc.IntegrityError:
            db.session.rollback()

            response = {'success': False, 'message': "Failed: user with such username or email is already exists"}
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
    response = jsonify({'detail': 'CSRF cookie set', 'token': token})
    response.headers.set('X-CSRFToken', token)
    return response


@app.route('/todo/api/user/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter((User.username == username) | (User.email == username)).first()

    if user and user.verify_password(password):
        login_user(user)
        return jsonify({'login': True})

    return jsonify({'login': False})


@app.route('/todo/api/user/session', methods=['GET'])
def check_session():
    if current_user.is_authenticated:
        return jsonify({'login': True})

    return jsonify({'login': False})


@app.route('/todo/api/user/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({'logout': True})


@app.route('/todo/api/user/data', methods=['GET'])
@login_required
def user_data():
    user = get_user(current_user.id)
    if not user.is_authenticated:
        message = "You are not authenticated"
        return jsonify({'success': False, 'message': message}), 401
    else:
        return jsonify({'success': True, 'data': user_schema.dump(current_user)}), 200
