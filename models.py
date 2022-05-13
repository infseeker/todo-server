from app import db


class User(db.Model):
    __tablename__ = "users"
    id = db.Column("user_id", db.Integer, primary_key=True, nullable=False)
    name = db.Column("username", db.String(32))
    password = db.Column(db.String(32))
    email = db.Column(db.String(64))
    user_image_path = db.Column(db.String(256))
    social_id = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean)
    creation_date = db.Column(db.DateTime)
    is_deleted = db.Column(db.Boolean)

    def __init__(
        self,
        name=None,
        email=None,
        password=None,
        user_image_path=None,
        social_id=None,
        is_admin=False,
        creation_date=None,
        is_deleted=False,
    ):
        self.name = name
        self.email = email
        self.password = password
        self.user_image_path = user_image_path
        self.social_id = social_id
        self.is_admin = is_admin
        self.creation_date = creation_date
        self.is_deleted = is_deleted


class ListItem(db.Model):
    __tablename__ = "list_items"
    id = db.Column("list_item_id", db.Integer, primary_key=True, nullable=False)
    content = db.Column(db.Text)
    is_done = db.Column(db.Boolean)
    is_liked = db.Column(db.Boolean)
    position = db.Column(db.Integer)
    creation_date = db.Column(db.DateTime)
    is_deleted = db.Column(db.Boolean)

    def __init__(
        self,
        content=None,
        is_done=False,
        is_liked=False,
        position=0,
        creation_date=None,
        is_deleted=False,
    ):
        self.content = content
        self.is_done = is_done
        self.is_liked = is_liked
        self.position = position
        self.creation_date = creation_date
        self.is_deleted = is_deleted
