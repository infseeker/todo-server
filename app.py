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

db = SQLAlchemy(app)
ma = Marshmallow(app)
migrate = Migrate(app, db)

# enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# import models
from models import *

# model schemas
user_schema = UserSchema()
list_schema = ListSchema()
list_item_schema = ListItemSchema()

@app.route("/", methods=["GET"])
def index():
    test_user = User("someUser", "mail@mail.com", "asdf", "/some/path", 123)
    db.session.add(test_user)

    try:
      db.session.commit()
    except:
      db.session.rollback()

      duplicate_user = User.query.filter_by(email="mail@mail.com").first()
      return user_schema.dump(duplicate_user)
    
    return user_schema.dump(test_user)


if __name__ == "__main__":
    app.run()
