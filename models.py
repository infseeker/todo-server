from app import db
from app import ma
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema

class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        db.UniqueConstraint('username', 'email', 'social_id', name='users_unique_fields'),
    )

    id = db.Column("user_id", db.Integer, primary_key=True, nullable=False)
    name = db.Column("username", db.String(32), nullable=False)
    password = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(64), nullable=False)
    user_image_path = db.Column(db.String(256))
    social_id = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    created = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now(),
        server_onupdate=db.func.now(),
    )
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(
        self,
        name=None,
        email=None,
        password=None,
        user_image_path=None,
        social_id=None,
    ):
        self.name = name
        self.email = email
        self.password = password
        self.user_image_path = user_image_path
        self.social_id = social_id


class UserSchema(SQLAlchemyAutoSchema):
  class Meta:
    model = User

class List(db.Model):

    __tablename__ = "lists"
    id = db.Column("list_id", db.Integer, primary_key=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
    title = db.Column(db.Text, nullable=False, default="New List")
    is_liked = db.Column(db.Boolean, nullable=False, default=False)
    created = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now(),
        server_onupdate=db.func.now(),
    )
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, title=None, is_liked=False):
        self.title = title
        self.is_liked = is_liked


class ListSchema(SQLAlchemyAutoSchema):
  class Meta:
    model = List
    include_fk = True

class ListItem(db.Model):
    __tablename__ = "list_items"

    id = db.Column("list_item_id", db.Integer, primary_key=True, nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey(List.id), nullable=False)
    title = db.Column(db.Text, nullable=False, default="New List Item")
    is_done = db.Column(db.Boolean, nullable=False, default=False)
    is_liked = db.Column(db.Boolean, nullable=False, default=False)
    position = db.Column(db.Float, nullable=False, default=0)
    created = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now(),
        server_onupdate=db.func.now(),
    )
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(
        self,
        title=None,
        is_done=False,
        is_liked=False,
        position=0,
        is_deleted=False,
    ):
        self.title = title
        self.is_done = is_done
        self.is_liked = is_liked
        self.position = position
        self.is_deleted = is_deleted


class ListItemSchema(SQLAlchemyAutoSchema):
  class Meta:
    model = ListItem
    include_fk = True