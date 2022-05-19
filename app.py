import os

from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from flask_migrate import Migrate
from flask_cors import CORS


# configuration
DEBUG = True

# instantiate the app
app = Flask(__name__)
app.config.from_object(__name__)

# database connection string
app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "postgresql://{db_user_name}:{db_user_password}@{db_host}/{db_name}".format(
    db_user_name=os.environ["DB_USER_NAME"],
    db_user_password=os.environ["DB_USER_PASSWORD"],
    db_host=os.environ["DB_HOST"],
    db_name=os.environ["DB_NAME"],
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config ['JSON_SORT_KEYS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)
migrate = Migrate(app, db)

# enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})

from api import *

if __name__ == "__main__":
    app.run()

# export FLASK_ENV=development
