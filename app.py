import os
from sched import scheduler

from flask import Flask
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


# data handling
app.config[
    'SQLALCHEMY_DATABASE_URI'
] = 'postgresql://{db_user_name}:{db_user_password}@{db_host}/{db_name}'.format(
    db_user_name=os.environ['DB_USER_NAME'],
    db_user_password=os.environ['DB_USER_PASSWORD'],
    db_host=os.environ['DB_HOST'],
    db_name=os.environ['DB_NAME'],
)

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
    'MAIL_PASSWORD': os.environ['EMAIL_PASSWORD']
}

app.config.update(mail_settings)
mail = Mail(app)


# scheduler
scheduler_settings = {
    'SCHEDULER_API_ENABLED': True
}
app.config.update(scheduler_settings)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# init api
from src.api import *


@app.route('/', methods=['GET'])
def index():
    return "ToDo Project API"


# run app
if __name__ == '__main__':
    app.run()


# source env/bin/activate
# export FLASK_ENV=development
# flask run --host=0.0.0.0

# Auth: Flask-login (Basic)
# OAuth: Google, Yandex, VK, Apple