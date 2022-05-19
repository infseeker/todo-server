from app import app, db
from flask import jsonify
from models.User import *
from models.List import *
from models.ListItem import *


@app.route("/", methods=["GET"])
def index():
    # Testing code below
    

    # test_user = User("someUser3", "mail@mail3.com", "asdf3", "/some/path3", 1233)
    # db.session.add(test_user)

    # try:
    #   db.session.commit()
    # except:
    #   db.session.rollback()

    #   duplicate_user = User.query.filter_by(email="mail@mail3.com").first()
    #   return user_schema.dump(duplicate_user)

    # return user_schema.dump(test_user)
    one_user = user_schema.dump(User.query.first())
    all_users = user_schema.dump(User.query.all(), many=True)
    return {"users": all_users, "first_user": one_user}
