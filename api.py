
from app import app, db
from models.User import *
from models.List import *
from models.ListItem import *


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