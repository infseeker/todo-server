import os
from sched import scheduler
from boto.s3.connection import S3Connection

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
from flask_mail import Mail
from flask_apscheduler import APScheduler


# configuration
DEBUG = True

# instantiate the app
app = Flask(__name__)
app.config.from_object(__name__)

# Heroku connection
s3 = S3Connection(
    os.environ['DATABASE_URL'],
    os.environ['CLIENT_ORIGIN'],
    os.environ['EMAIL_USER'],
    os.environ['EMAIL_PASSWORD'],
    os.environ['RECAPTCHA_SECRET_KEY'],
)

# data handling
app.config[
    'SQLALCHEMY_DATABASE_URI'
] = os.environ['DATABASE_URL']

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_SORT_KEYS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)
migrate = Migrate(app, db)


# mail config
mail_settings = {
    'MAIL_SERVER': 'smtp.mail.ru',
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


# scheduler
scheduler_settings = {'SCHEDULER_API_ENABLED': True}
app.config.update(scheduler_settings)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# init api
from src.api import *


@app.route('/', methods=['GET'])
def index():
    response = {
        'success': True,
        'message': "ToDo Project Index URL",
        'path': '/',
        'data': {'action': 'index'},
    }
    return jsonify(response), 200


@app.route('/todo/api', methods=['GET'])
def api():
    response = {
        'success': True,
        'message': "ToDo Project API",
        'path': '/todo/api',
        'data': {'action': 'api'},
    }
    return jsonify(response), 200


# run app
if __name__ == '__main__':
    app.run()


# source env/bin/activate
# export FLASK_ENV=development
# flask run --host=0.0.0.0 --port=8080

# ngrok start frontend backend
