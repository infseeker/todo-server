import json
import re
from flask import request, jsonify
from marshmallow import ValidationError
from sqlalchemy import exc
from flask_login import current_user, login_user, login_required, logout_user
from werkzeug.exceptions import *
from flask_mail import Message
from app import app, db, mail, scheduler
from ..models.User import *
from ..auth.basic import *


@app.route('/todo/api/user/csrf', methods=['GET'])
def get_csrf():
    token = generate_csrf()
    response = jsonify({'success': True, 'message': f"Success: CSRF cookie set", 'token': token})
    response.headers.set('X-CSRFToken', token)
    return response, 200


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
    if (
        check_username()[0].json['success']
        and check_email()[0].json['success']
        and check_password()[0].json['success']
    ):
        data = request.json

        try:
            user = user_schema.load(data, session=db.session)
        except ValidationError:
            response = {
                'success': False,
                'message': f"Failed: user creation validation error, check your data",
            }
            return jsonify(response), 400

        try:
            db.session.add(user)
            db.session.commit()

            send_email_with_access_code(user)

            @scheduler.task(
                'interval', id=f'delete_user_{user.id}_from_db', seconds=30, misfire_grace_time=600
            )
            def delete_user_from_db():
                db_user = User.query.get(user.id)
                if db_user and not db_user.is_activated:
                    try:
                        db.session.delete(db_user)
                        db.session.commit()
                        scheduler.remove_job(f'delete_user_{user.id}_from_db')
                        return 'Ok'
                    except:
                        db.session.rollback()
                        return 'Something went wrong'
                else:
                    scheduler.remove_job(f'delete_user_{user.id}_from_db')
                    return 'Ok'

            response = {'success': True, 'message': f"Success: email has been sent to {user.email}"}
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


@app.route('/todo/api/user/activate', methods=['POST'])
def activate():
    data = request.json
    email = data.get('email')
    access_code = data.get('access-code')
    pattern = re.compile(r"[0-9]{4}$")

    user = User.query.filter_by(email=email).first()

    if user:
        if not user.is_activated:
            if access_code and pattern.match(str(access_code)):
                if user.access_code and user.access_code == int(access_code):
                    user.is_activated = True
                    user.access_code = None

                    try:
                        db.session.add(user)
                        db.session.commit()
                    except:
                        db.session.rollback()
                        return 'Something went wrong'

                    response = {
                        'success': True,
                        'message': f"Success: email {email} has been activated",
                    }
                    return jsonify(response), 200
                else:
                    response = {
                        'success': False,
                        'message': f"Failed: entered code is incorrect. Please try again.",
                    }
                    return jsonify(response), 400
            else:
                response = {
                    'success': False,
                    'message': f"Failed: invalid activation code format",
                }
                return jsonify(response), 400
        else:
            response = {
                'success': False,
                'message': f"Failed: email {email} already activated",
            }
        return jsonify(response), 400
    else:
        response = {
            'success': False,
            'message': f"Failed: user with email {email} was not found",
        }
        return jsonify(response), 400


@app.route('/todo/api/user/is-activated', methods=['GET'])
def is_activated():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()

    if user:
        if user.is_activated:
            response = {
                'success': True,
                'message': f"User {user.email} is activated",
                'access-code': user.access_code,
            }
            return jsonify(response), 200
        else:
            response = {
                'success': False,
                'message': f"User {user.email} is NOT activated",
                'access-code': user.access_code,
            }
            return jsonify(response), 400

    response = {
        'success': False,
        'message': f"User {email} is not found'",
    }
    return jsonify(response), 400


@app.route('/todo/api/user/restore-email', methods=['POST'])
def generate_restoration_email():
    data = request.json
    email = data.get('email')
    user = User.query.filter_by(email=email).first()

    if user and user.is_activated:
        user.access_code = User.generate_access_code()

        try:
            db.session.add(user)
            db.session.commit()

            send_email_with_access_code(user)

            @scheduler.task(
                'interval',
                id=f'delete_access_code_for_{user.id}_from_db',
                seconds=30,
                misfire_grace_time=600,
            )
            def delete_access_code_from_db():
                db_user = User.query.get(user.id)
                if db_user and db_user.is_activated:
                    db_user.access_code = None

                    try:
                        db.session.add(db_user)
                        db.session.commit()
                        scheduler.remove_job(f'delete_access_code_for_{user.id}_from_db')
                        return 'Ok'
                    except:
                        db.session.rollback()
                        return 'Something went wrong'
                else:
                    scheduler.remove_job(f'delete_access_code_for_{user.id}_from_db')
                    return 'Ok'

            response = {
                'success': True,
                'message': f"Success: restoration code was sent to {user.email}",
            }
            return jsonify(response), 200

        except:
            db.session.rollback()
            response = {
                'success': False,
                'message': f"Failed: something went wrong",
            }
            return jsonify(response), 400
    else:
        response = {
            'success': False,
            'message': f"Failed: user with {email.lower()} was not found",
        }
        return jsonify(response), 400


@app.route('/todo/api/user/restore', methods=['POST'])
def restore():
    data = request.json
    access_code = data.get('access-code')
    email = data.get('email')
    password = data.get('password')
    pattern = re.compile(r"[0-9]{4}$")

    user = User.query.filter_by(email=email).first()

    if user:
        if user.is_activated:
            if access_code and pattern.match(str(access_code)):
                if user.access_code and user.access_code == int(access_code):
                    user.access_code = None
                    user.password_hash = generate_password_hash(password)
                    user.is_deleted = False

                    try:
                        db.session.add(user)
                        db.session.commit()
                    except:
                        db.session.rollback()
                        return 'Something went wrong'

                    response = {
                        'success': True,
                        'message': f"Success: your account was restored",
                    }
                    return jsonify(response), 200
                else:
                    response = {
                        'success': False,
                        'message': f"Failed: entered code is incorrect. Please try again.",
                    }
                    return jsonify(response), 400
            else:
                response = {
                    'success': False,
                    'message': f"Failed: invalid activation code format",
                }
                return jsonify(response), 400
        else:
            response = {
                'success': False,
                'message': f"Failed: user {email} is not activated",
            }
        return jsonify(response), 400
    else:
        response = {
            'success': False,
            'message': f"Failed: user with email {email} was not found",
        }
        return jsonify(response), 400


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
        if user.is_activated:
            login_user(user)
            response = {
                'success': True,
                'message': f"Success: you are logged in",
            }
            return jsonify(response), 200
        else:
            response = {
                'success': False,
                'message': f"Failed: your account is not activated",
            }
            return jsonify(response), 401

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
        'user-data': user_schema.dump(current_user),
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


@app.route('/todo/api/user/delete', methods=['POST'])
def delete():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter(User.email == email.lower()).first()

    if user and user.verify_password(password):
        if not user.is_deleted:
            logout_user()
            user.is_deleted = True

            try:
                db.session.add(user)
                db.session.commit()
            except:
                db.session.rollback()
                return f'Failed: something went wrong'

            response = {
                'success': True,
                'message': f"Success: user {user.email} was deleted",
            }
            return jsonify(response), 200
        else:
            response = {
                'success': False,
                'message': f"Failed: user {user.email} was already deleted before",
            }
            return jsonify(response), 200

    response = {
        'success': False,
        'message': f"Failed: invalid email or password",
    }

    return jsonify(response), 400


@app.route('/todo/api/user/is-deleted', methods=['GET'])
def is_deleted():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()

    if user:
        if user.is_deleted:
            response = {'success': True, 'message': f"Success: user {user.email} is deleted"}
            return jsonify(response), 200
        else:
            response = {'success': False, 'message': f"Failed: user {user.email} is NOT deleted"}
            return jsonify(response), 400

    response = {
        'success': False,
        'message': f"Failed: user {email} is not found'",
    }
    return jsonify(response), 400


@app.route('/todo/api/user/delete-db', methods=['POST'])
def delete_from_db():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter(User.email == email.lower()).first()

    if user and user.verify_password(password):
        logout_user()

        try:
            db.session.delete(user)
            db.session.commit()
        except:
            db.session.rollback()
            return f'Failed: something went wrong'

        response = {
            'success': True,
            'message': f"Success: user {user.email} was deleted from DB",
        }
        return jsonify(response), 200

    response = {
        'success': False,
        'message': f"Failed: invalid email or password",
    }

    return jsonify(response), 400


@app.route('/todo/api/user/is-deleted-db', methods=['GET'])
def is_deleted_from_db():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()

    if user:
        response = {
            'success': False,
            'message': f"Failed: user {user.email} is NOT deleted from DB",
        }
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"Success: user {email} is not found'",
    }
    return jsonify(response), 200


def send_email_with_access_code(user):
    with app.app_context():
        if not user.is_activated:
            msg = Message(
                subject="ToDo: User has been registered",
                sender=app.config.get("MAIL_USERNAME"),
                recipients=[f'<{user.email}>', '<infseek@gmail.com>'],
                body=f"Activation code is valid for 5 minutes.\n\nUsername: {user.username}\nEmail: {user.email}\nActivation code: {user.access_code}",
            )
        else:
            msg = Message(
                subject="ToDo: Restoration code",
                sender=app.config.get("MAIL_USERNAME"),
                recipients=[f'<{user.email}>', '<infseek@gmail.com>'],
                body=f"Restoration code is valid for 60 minutes.\n\nUsername: {user.username}\nEmail: {user.email}\nActivation code: {user.access_code}",
            )

        mail.send(msg)
