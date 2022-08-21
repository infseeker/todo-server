import random
import uuid

from app import db
from sqlalchemy import exc
from marshmallow import EXCLUDE
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema, auto_field
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    __table_args__ = (
        db.UniqueConstraint('username', 'email', 'session_id', name='users_unique_fields'),
    )

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(16), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False)
    image = db.Column(db.String(256))
    locale = db.Column(db.String(16), nullable=False, default='sy')
    session_id = db.Column(db.String(256), nullable=False)
    created = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now(),
        server_onupdate=db.func.now(),
    )
    last_login = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    access_code = db.Column(db.Integer, default=None)
    is_activated = db.Column(db.Boolean, nullable=False, default=False)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(
        self,
        username=None,
        email=None,
        password_hash=None,
        image=None,
        locale=None,
        is_activated=None,
        is_deleted=None,
        is_admin=None,
    ):
        self.username = username
        self.email = db.func.lower(email)
        self.password_hash = generate_password_hash(password_hash)
        self.image = image
        self.locale = locale
        self.session_id = uuid.uuid4()
        self.access_code = (User.generate_access_code(),)
        self.is_activated = is_activated
        self.is_deleted = is_deleted
        self.is_admin = is_admin

    def get_id(self):
        return str(self.session_id)

    def create(self):
        try:
            db.session.add(self)
            db.session.commit()
            return True, "User has been created"
        except exc.IntegrityError:
            db.session.rollback()
            return False, "User with such username or email is already exists"
        except:
            db.session.rollback()
            return False, "Something went wrong"

    def update(self):
        self.updated = db.func.now()
        try:
            db.session.add(self)
            db.session.commit()
            return True, "User has been updated"
        except:
            db.session.rollback()
            return False, "Something went wrong"

    def delete(self):
        try:
            db.session.delete(self)
            db.session.commit()
            return True, "User has been deleted"
        except:
            db.session.rollback()
            return False, "Something went wrong"

    def login(self):
        self.last_login = db.func.now()

        try:
            db.session.add(self)
            db.session.commit()
            return True, "User has been logged"
        except:
            db.session.rollback()
            return False, "Something went wrong"

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def generate_access_code():
        return random.randint(1000, 9999)

    @staticmethod
    def get_user_by_email(email):
        return User.query.filter_by(email=email.lower().strip()).first()


class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_fk = True
        include_relationships = True
        load_instance = True
        ordered = True
        unknown = EXCLUDE
        exclude = ('password_hash',)

    id = auto_field(dump_only=True)
    username = auto_field()
    email = auto_field()
    password = auto_field('password_hash', load_only=True)
    image = auto_field()
    locale = auto_field()
    session_id = auto_field(dump_only=True)
    access_code = auto_field(dump_only=True)
    created = auto_field(dump_only=True)
    updated = auto_field(dump_only=True)
    last_login = auto_field(dump_only=True)
    is_activated = auto_field(dump_only=True)
    is_deleted = auto_field(dump_only=True)
    is_admin = auto_field(dump_only=True)


user_schema = UserSchema(
    exclude=[
        'created',
        'updated',
        'last_login',
        'access_code',
        'session_id',
    ]
)

short_users_schema = UserSchema(
    exclude=[
        'password_hash',
        'locale',
        'created',
        'updated',
        'last_login',
        'access_code',
        'session_id',
        'is_activated',
        'is_deleted',
        'is_admin',
    ],
    many=True,
)
