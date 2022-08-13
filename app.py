import os
from dotenv import load_dotenv
from sched import scheduler

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
from flask_mail import Mail
from flask_apscheduler import APScheduler


# instantiate the app
app = Flask(__name__)
app.config.from_object(__name__)

for env_file in ('.env', '.flaskenv'):
    env = os.path.join(os.getcwd(), env_file)
    if os.path.exists(env):
        load_dotenv(env)

# json to utf-8
app.config['JSON_AS_ASCII'] = False

# data handling
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL'].replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_SORT_KEYS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)
migrate = Migrate(app, db)


# mail config
mail_settings = {
    'MAIL_SERVER': os.environ['EMAIL_SERVER'],
    'MAIL_PORT': 465,
    'MAIL_USE_TLS': False,
    'MAIL_USE_SSL': True,
    'MAIL_USERNAME': os.environ['EMAIL_USER'],
    'MAIL_PASSWORD': os.environ['EMAIL_PASSWORD'],
}

app.config.update(mail_settings)
mail = Mail(app)


# reCaptcha config
app.config['RECAPTCHA_SECRET_KEY'] = os.environ['RECAPTCHA_SECRET_KEY']


# user images folder
app.config['USER_IMGS_PATH'] = os.environ['USER_IMGS_PATH']
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 2678400


# scheduler
scheduler_settings = {'SCHEDULER_API_ENABLED': True}
app.config.update(scheduler_settings)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()


# handler for all unhandled 400's code error exceptions
@app.errorhandler(400)
def forbidden(e):
    response = {'message': e.description, 'code': 400}
    return jsonify(response), 400


# init api
from src.api import *


# init admin panel
from src.models.Admin import admin


# actions for initial routes
@app.route('/', methods=['GET'])
def index():
    response = {
        'message': "ToDo Project Index Page",
        'path': '/',
        'data': {'action': 'index'},
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api', methods=['GET'])
def api():
    response = {
        'message': "ToDo Project API",
        'path': '/todo/api',
        'data': {'action': 'api'},
        'code': 200,
    }
    return jsonify(response), 200


# run app
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
