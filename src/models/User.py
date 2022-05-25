from app import db
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema, auto_field
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    __table_args__ = (
        db.UniqueConstraint('username', 'email', 'social_id', name='users_unique_fields'), 
    )

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(16), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False)
    image_path = db.Column(db.String(4096))
    social_id = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    created = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now(),
        server_onupdate=db.func.now(),
    )
    is_active = db.Column(db.Boolean, nullable=False, default=False)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(
        self,
        username=None,
        email=None,
        password=None,
        image_path=None,
        social_id=None,
    ):
        self.username = username
        self.email = db.func.lower(email)
        self.password = generate_password_hash(password)
        self.image_path = image_path
        self.social_id = social_id

    def verify_password(self, password):
        return check_password_hash(self.password, password)


class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        ordered = True
        include_relationships = True
        load_instance = True
    password = auto_field(load_only=True)

user_schema = UserSchema(exclude=['social_id', 'is_admin', 'created', 'updated', 'is_active', 'is_deleted'])
