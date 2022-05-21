from app import db
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    __table_args__ = (
        db.UniqueConstraint('name', 'email', 'social_id', name='users_unique_fields'),
    )

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String(32), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(64), nullable=False)
    image_path = db.Column(db.String(256))
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
        image_path=None,
        social_id=None,
    ):
        self.name = name
        self.email = email
        self.password_hash = generate_password_hash(password)
        self.image_path = image_path
        self.social_id = social_id

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get_user_by_username(login: str):
        return User.query.filter((User.name == login) | (User.email == login)).first()


class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        ordered = True


user_schema = UserSchema(
    exclude=['password_hash', 'created', 'updated', 'is_deleted']
)
