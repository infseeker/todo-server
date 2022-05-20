import os

from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate


# configuration
DEBUG = True

# instantiate the app
app = Flask(__name__)
app.config.from_object(__name__)

# data handling
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "postgresql://{db_user_name}:{db_user_password}@{db_host}/{db_name}".format(
    db_user_name=os.environ["DB_USER_NAME"],
    db_user_password=os.environ["DB_USER_PASSWORD"],
    db_host=os.environ["DB_HOST"],
    db_name=os.environ["DB_NAME"],
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JSON_SORT_KEYS"] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)
migrate = Migrate(app, db)


# init api
from src.api import *


@app.route("/", methods=["GET"])
def index():
    return 'ToDo Project API'


# run app
if __name__ == "__main__":
    app.run()


# source env/bin/activate
# export FLASK_ENV=development
# flask run --host=0.0.0.0
