from datetime import datetime
from email.policy import default
from app import db


class User(db.Model):
    __tablename__ = "users"
    id = db.Column("user_id", db.Integer, primary_key=True, nullable=False)
    name = db.Column("username", db.String(32), nullable=False)
    password = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(64), nullable=False)
    user_image_path = db.Column(db.String(256))
    social_id = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    created = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), server_onupdate=db.func.now())
    is_deleted = db.Column(db.Boolean, nullable=False)

    def __init__(
        self,
        name=None,
        email=None,
        password=None,
        user_image_path=None,
        social_id=None,
        is_admin=False,
        created=None,
        is_deleted=False,
    ):
        self.name = name
        self.email = email
        self.password = password
        self.user_image_path = user_image_path
        self.social_id = social_id
        self.is_admin = is_admin
        self.created = created
        self.is_deleted = is_deleted


class List(db.Model):
    __tablename__ = "lists"
    id = db.Column("list_id", db.Integer, primary_key=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
    name = db.Column(db.Text, nullable=False)
    is_liked = db.Column(db.Boolean, nullable=False)
    position = db.Column(db.Integer)
    created = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), server_onupdate=db.func.now())
    is_deleted = db.Column(db.Boolean)

    def __init__(
        self,
        name=None,
        is_liked=False,
        position=0,
        created=None,
        is_deleted=False,
    ):
        self.name = name
        self.is_liked = is_liked
        self.position = position
        self.created = created
        self.is_deleted = is_deleted


class ListItem(db.Model):
    __tablename__ = "list_items"
    id = db.Column("list_item_id", db.Integer, primary_key=True, nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey(List.id), nullable=False)
    name = db.Column(db.Text)
    is_done = db.Column(db.Boolean)
    is_liked = db.Column(db.Boolean)
    position = db.Column(db.Integer)
    created = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated = db.Column(db.DateTime, nullable=False, server_default=db.func.now(), server_onupdate=db.func.now())
    is_deleted = db.Column(db.Boolean)

    def __init__(
        self,
        name=None,
        is_done=False,
        is_liked=False,
        position=0,
        created=None,
        is_deleted=False,
    ):
        self.name = name
        self.is_done = is_done
        self.is_liked = is_liked
        self.position = position
        self.created = created
        self.is_deleted = is_deleted
