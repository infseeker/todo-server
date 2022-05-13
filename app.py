import os

from flask import Flask, render_template, request, jsonify
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

from flask_cors import CORS


# configuration
DEBUG = True

# instantiate the app
app = Flask(__name__)
app.config.from_object(__name__)

# database connection string
app.config[
    'SQLALCHEMY_DATABASE_URI'
] = 'postgresql://{db_user_name}:{db_user_password}@{db_host}/{db_name}'.format(
    db_user_name=os.environ["DB_USER_NAME"],
    db_user_password=os.environ["DB_USER_PASSWORD"],
    db_host=os.environ["DB_HOST"],
    db_name=os.environ["DB_NAME"],
)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# import models
from models import *

@app.route("/", methods=["GET"])
def index():
    return "Hello!"


if __name__ == "__main__":
    app.run()
