import re
from flask import request, jsonify
from marshmallow import ValidationError
from flask_login import current_user, login_user, login_required, logout_user
from werkzeug.exceptions import *
from flask_mail import Message
import requests
from app import app, db, mail, scheduler
from ..models.User import *
from ..auth.basic import *


@app.route('/todo/api/user/csrf', methods=['GET'])
def get_csrf():
    token = generate_csrf()
    response = jsonify({'message': f"CSRF cookie set", 'token': token, 'code': 200})
    response.headers.set('X-CSRFToken', token)
    return response, 200


@app.route('/todo/api/user/check-username', methods=['POST'])
def check_username():
    data = request.json

    if not data.get('username'):
        response = {
            'message': "JSON: Username field not found or empty",
            'code': 400,
        }
        return jsonify(response), 400
    else:
        username = str(data.get('username')).strip()

        # username pattern (min: 3, max: 15, chars: a-z, A-Z)
        pattern = re.compile('^[a-zA-Z]{3,15}$')

        if not pattern.match(username):
            response = {
                'message': f"Username {username} contents wrong characters (a-z, A-Z) / too short (3 min) / too long (15 max)",
                'code': 400,
            }
            return jsonify(response), 400
        else:
            user = User.query.filter(
                db.func.lower(User.username) == db.func.lower(username)
            ).first()

            if user:
                response = {
                    'message': f"Username {username} is already in use",
                    'code': 409,
                }
                return jsonify(response), 409

    response = {'message': f"Username {username} is free", 'code': 200}
    return jsonify(response), 200


@app.route('/todo/api/user/check-email', methods=['POST'])
def check_email():
    data = request.json

    if not data.get('email'):
        response = {
            'message': "JSON: email field not found or empty",
            'code': 400,
        }
        return jsonify(response), 400
    else:
        email = str(data.get('email')).lower().strip()

        # email pattern (user@mail.com)
        pattern = re.compile('(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)')

        if not pattern.match(email):
            response = {
                'message': f"Email {email} has an invalid format",
                'code': 400,
            }
            return jsonify(response), 400
        else:
            user = User.query.filter(db.func.lower(User.email) == db.func.lower(email)).first()

            if user:
                response = {
                    'message': f"Email {email} is already in use",
                    'code': 409,
                }
                return jsonify(response), 409

    response = {'message': f"Email {email} is free", 'code': 200}
    return jsonify(response), 200


@app.route('/todo/api/user/check-password', methods=['POST'])
def check_password():
    data = request.json
    if not data.get('password'):
        response = {
            'message': "JSON: Password field not found or empty",
            'code': 400,
        }
        return jsonify(response), 400
    else:
        password = str(data.get('password'))

        # password pattern ()
        pattern = re.compile('^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@\-$!%*#?&]{8,15}$')

        if not pattern.match(password):
            response = {'message': f"Password has an invalid format", 'code': 400}
            return jsonify(response), 400

    response = {'message': f"Password format is valid", 'code': 200}
    return jsonify(response), 200


@app.route('/todo/api/user/register', methods=['POST'])
def register():
    if (
        check_username()[0].json['code'] == 200
        and check_email()[0].json['code'] == 200
        and check_password()[0].json['code'] == 200
    ):
        data = request.json
        token = data.get('token')

        if token:
            success, message = verify_recaptcha_token(token)
            if not success:
                response = {'message': message, 'code': 403}
                return jsonify(response), 403

        try:
            user = user_schema.load(data, session=db.session)
        except (ValidationError, TypeError):
            response = {
                'message': f"User creation validation error, check your data",
                'code': 400,
            }
            return jsonify(response), 400

        success, message = user.create()

        if not success:
            response = {'message': message, 'code': 400}
            return jsonify(response), 400

        send_email_with_access_code(user)

        @scheduler.task('interval', id=f'delete_user_{user.id}_from_db', minutes=15)
        def delete_user_from_db():
            db_user = User.query.get(user.id)
            if db_user and not db_user.is_activated:
                db_user.delete()
            scheduler.remove_job(f'delete_user_{user.id}_from_db')

        response = {
            'message': f"Email has been sent to {user.email}",
            'code': 200,
        }
        return jsonify(response), 200
    else:
        if not check_username()[0].json['code'] == 200:
            return check_username()
        elif not check_email()[0].json['code'] == 200:
            return check_email()
        elif not check_password()[0].json['code'] == 200:
            return check_password()


@app.route('/todo/api/user/activate', methods=['POST'])
def activate():
    data = request.json
    email = data.get('email')
    access_code = data.get('access_code')
    pattern = re.compile(r"[0-9]{4}$")
    token = data.get('token')

    if token:
        success, message = verify_recaptcha_token(token)
        if not success:
            response = {'message': message, 'code': 403}
            return jsonify(response), 403

    if not email or not email.strip():
        response = {
            'message': f"Email field must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    user = User.get_user_by_email(email)

    if user:
        if not user.is_activated:
            if access_code and pattern.match(str(access_code)):
                if user.access_code and user.access_code == int(access_code):
                    user.is_activated = True
                    user.access_code = None

                    success, message = user.update()

                    if success:
                        response = {
                            'message': f"User with email {email} has been activated",
                            'code': 200,
                        }
                        return jsonify(response), 200
                    else:
                        response = {'message': message, 'code': 400}
                        return jsonify(response), 400
                else:
                    response = {
                        'message': f"Entered code is incorrect or expired",
                        'code': 400,
                    }
                    return jsonify(response), 400
            else:
                response = {
                    'message': f"Invalid activation code format",
                    'code': 400,
                }
                return jsonify(response), 400
        else:
            response = {
                'message': f"User with email {email} already activated",
                'code': 409,
            }
        return jsonify(response), 409
    else:
        response = {
            'message': f"User with email {email} was not found",
            'code': 404,
        }
        return jsonify(response), 404


@app.route('/todo/api/user/is-activated', methods=['GET'])
def is_activated():
    email = request.json.get('email')
    user = User.get_user_by_email(email)

    if user:
        if user.is_activated:
            response = {
                'message': f"User with email {user.email} is activated",
                'access_code': user.access_code,
                'code': 200,
            }
            return jsonify(response), 200
        else:
            response = {
                'message': f"User with email {user.email} is NOT activated",
                'access_code': user.access_code,
                'code': 403,
            }
            return jsonify(response), 403

    response = {'message': f"User with email {email} is not found'", 'code': 404}
    return jsonify(response), 404


@app.route('/todo/api/user/restore-email', methods=['POST'])
def generate_restoration_email():
    data = request.json
    email = data.get('email')
    token = data.get('token')

    if token:
        success, message = verify_recaptcha_token(token)
        if not success:
            response = {'message': message}
            return jsonify(response), 403

    if not email or not email.strip():
        response = {
            'message': f"Email field must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    email = email.strip()
    user = User.get_user_by_email(email)

    if not user:
        response = {
            'message': f"User with {email.lower()} was not found",
            'code': 404,
        }
        return jsonify(response), 404

    if not user.is_activated:
        response = {
            'message': f"User with {email.lower()} is not activated",
            'code': 403,
        }
        return jsonify(response), 403

    user.access_code = User.generate_access_code()

    success, message = user.update()

    if not success:
        response = {
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    send_email_with_access_code(user)

    @scheduler.task(
        'interval',
        id=f'delete_access_code_for_{user.id}_from_db',
        minutes=15,
    )
    def delete_access_code_from_db():
        db_user = User.query.get(user.id)

        if db_user and db_user.is_activated:
            db_user.access_code = None
            db_user.update()

        scheduler.remove_job(f'delete_access_code_for_{user.id}_from_db')

    response = {
        'message': f"Restoration code was sent to {user.email}",
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/user/restore', methods=['POST'])
def restore():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    access_code = data.get('access_code')
    pattern = re.compile(r"[0-9]{4}$")
    token = data.get('token')

    if token:
        success, message = verify_recaptcha_token(token)
        if not success:
            response = {'message': message, 'code': 403}
            return jsonify(response), 403

    if not email or not email.strip():
        response = {
            'message': f"Email field must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    if not password:
        response = {'message': f"Password field must not be empty", 'code': 400}
        return jsonify(response), 400

    if not access_code or not access_code.strip():
        response = {
            'message': f"Access code field must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    user = User.get_user_by_email(email.strip())

    if user:
        if user.is_activated:
            if not check_password()[0].json['code'] == 200:
                return check_password()

            if access_code and pattern.match(str(access_code)):
                if user.access_code and user.access_code == int(access_code):
                    user.access_code = None
                    user.password_hash = generate_password_hash(password)
                    user.is_deleted = False

                    success, message = user.update()
                    if success:
                        response = {
                            'message': f"Your account was restored",
                            'code': 200,
                        }
                        return jsonify(response), 200
                    else:
                        response = {'message': message, 'code': 400}
                        return jsonify(response), 400
                else:
                    response = {
                        'message': f"Entered code is incorrect",
                        'code': 400,
                    }
                    return jsonify(response), 400
            else:
                response = {
                    'message': f"Activation code format is invalid",
                    'code': 400,
                }
                return jsonify(response), 400
        else:
            response = {'message': f"User {email} is not activated", 'code': 403}
        return jsonify(response), 403
    else:
        response = {'message': f"User with email {email} not found", 'code': 404}
        return jsonify(response), 404


@app.route('/todo/api/user/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    token = data.get('token')

    if token:
        success, message = verify_recaptcha_token(token)
        if not success:
            response = {'message': message, 'code': 403}
            return jsonify(response), 403

    if not username or not username.strip():
        response = {'message': f"Username field must not be empty", 'code': 400}
        return jsonify(response), 400

    if not password:
        response = {'message': f"Password field must not be empty", 'code': 400}
        return jsonify(response), 400

    username = username.strip()

    user = User.query.filter(
        (db.func.lower(User.username) == db.func.lower(username))
        | (db.func.lower(User.email) == db.func.lower(username))
    ).first()

    if user and user.verify_password(password):
        if user.is_activated:
            if not user.is_deleted:

                login_user(user, remember=True)

                success, message = user.login()

                if success:
                    response = {
                        'message': f"You are logged in",
                        'email': user.email,
                        'admin': user.is_admin,
                        'code': 200,
                    }
                    return jsonify(response), 200
                else:
                    response = {'message': message, 'code': 400}
                    return jsonify(response), 400
            else:
                response = {
                    'message': f"Your account was deleted",
                    'deleted': True,
                    'email': user.email,
                    'code': 403,
                }
                return jsonify(response), 403
        else:
            response = {
                'message': f"Your account is not activated",
                'inactive': True,
                'email': user.email,
                'code': 403,
            }
            return jsonify(response), 403

    response = {
        'message': f"Invalid username or password",
        'code': 400,
    }
    return jsonify(response), 400


@app.route('/todo/api/user/session', methods=['GET'])
def check_session():
    if not current_user.is_authenticated:
        response = {
            'message': f"You are not authenticated",
            'login': False,
            'code': 401,
        }
        return jsonify(response), 401

    if not current_user.is_admin:
        response = {
            'message': f"You are logged in",
            'login': True,
            'email': current_user.email,
            'code': 200,
        }
        return jsonify(response), 200

    response = {
        'message': f"You are logged in",
        'login': True,
        'admin': True,
        'email': current_user.email,
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/user/user-data', methods=['GET'])
@login_required
def get_user_data():
    response = {
        'message': f"You are logged in",
        'data': user_schema.dump(current_user),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/user/update', methods=['PUT'])
@login_required
def update():
    data = request.json
    user = current_user

    password = data.get('password')
    if password:
        if not check_password()[0].json['code'] == 200:
            return check_password()

        user.password_hash = generate_password_hash(password)

    success, message = user.update()

    if not success:
        response = {'message': message, 'code': 400}
        return jsonify(response), 400

    response = {
        'message': f"Current user has been updated",
        'data': user_schema.dump(user),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/user/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    response = {'message': f"You are logged out", 'code': 200}
    return jsonify(response), 200


@app.route('/todo/api/user/delete', methods=['DELETE'])
@login_required
def delete():
    data = request.json
    password = data.get('password')
    user = User.query.get(current_user.id)

    if not password:
        response = {
            'message': f"Password field must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    if user and user.verify_password(password):
        if not user.is_deleted:
            logout_user()
            user.is_deleted = True

            success, message = user.update()

            if success:
                response = {
                    'message': f"User {user.email} was deleted",
                    'code': 200,
                }
                return jsonify(response), 200
            else:
                response = {'message': message, 'code': 400}
                return jsonify(response), 400
        else:
            response = {
                'message': f"User {user.email} was already deleted before",
                'code': 403,
            }
            return jsonify(response), 403

    response = {'message': f"Invalid password", 'code': 400}

    return jsonify(response), 400


@app.route('/todo/api/user/is-deleted', methods=['GET'])
def is_deleted():
    email = request.json.get('email')
    user = User.get_user_by_email(email)

    if user:
        if user.is_deleted:
            response = {'message': f"user {user.email} is deleted", 'code': 200}
            return jsonify(response), 200
        else:
            response = {
                'message': f"user {user.email} is NOT deleted",
                'code': 400,
            }
            return jsonify(response), 400

    response = {
        'message': f"User {email.strip()} not found",
        'code': 404,
    }
    return jsonify(response), 404


@app.route('/todo/api/user/delete-db', methods=['DELETE'])
def delete_from_db():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = User.get_user_by_email(email)

    if user and user.verify_password(password):
        logout_user()

        success, message = user.delete()
        if success:
            response = {
                'message': f"User {user.email} was deleted from DB",
                'code': 200,
            }
            return jsonify(response), 200
        else:
            response = {
                'message': message,
                'code': 400,
            }
            return jsonify(response), 400

    response = {
        'message': f"Invalid email or password",
        'code': 400,
    }

    return jsonify(response), 400


@app.route('/todo/api/user/is-deleted-db', methods=['GET'])
def is_deleted_from_db():
    email = request.json.get('email')
    user = User.get_user_by_email(email)

    if user:
        response = {
            'message': f"User {user.email} is NOT deleted from DB",
            'code': 400,
        }
        return jsonify(response), 400

    response = {'message': f"User with email {email} not found'", 'code': 200}
    return jsonify(response), 200


@app.route('/todo/api/user/all', methods=['GET'])
def get_all_users():
    users = User.query.all()
    response = {
        'message': "All users",
        'data': users_schema.dump(users),
        'code': 200,
    }
    return jsonify(response)


def send_email_with_access_code(user):
    with app.app_context():
        if not user.is_activated:
            msg = Message(
                subject="ToDo: Пользователь зарегистрирован",
                sender=app.config.get("MAIL_USERNAME"),
                recipients=[f'<{user.email}>', '<infseek@gmail.com>'],
                body=f"Код активации действителен в течение 15 минут.\nИмя пользователя: {user.username}\nEmail: {user.email}\nКод активации: {user.access_code}",
            )
        else:
            msg = Message(
                subject="ToDo: Восстановление доступа",
                sender=app.config.get("MAIL_USERNAME"),
                recipients=[f'<{user.email}>', '<infseek@gmail.com>'],
                body=f"Код восстановления действителен в течение 15 минут.\nИмя пользователя: {user.username}\nEmail: {user.email}\nКод восстановления: {user.access_code}",
            )

        mail.send(msg)


def verify_recaptcha_token(token):
    secret = app.config['RECAPTCHA_SECRET_KEY']
    request = {'secret': secret, 'response': token}

    try:
        recaptcha = requests.post(
            'https://www.google.com/recaptcha/api/siteverify', data=request
        ).json()

        if not recaptcha or not recaptcha['score'] or recaptcha['score'] < 0.4:
            return False, f"ReCaptcha verification failed"

        return True, f"ReCaptcha verification passed"

    except:
        return False, "reCaptcha: something went wrong"
