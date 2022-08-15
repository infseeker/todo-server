from app import db
from marshmallow import EXCLUDE
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema, auto_field
from ..models.User import User


class List(db.Model):

    __tablename__ = 'lists'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id, ondelete='CASCADE'), nullable=False)
    users = db.relationship('User')
    title = db.Column(db.Text, nullable=False, default='New List')
    created = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now(),
        server_onupdate=db.func.now(),
    )

    def __init__(self, title=None):
        self.title = title or None

    def create(self):
        try:
            db.session.add(self)
            db.session.commit()
            return True, "List has been created"
        except:
            db.session.rollback()
            return False, "Something went wrong"

    def update(self):
        self.updated = db.func.now()
        try:
            db.session.add(self)
            db.session.commit()
            return True, "List has been updated"
        except:
            db.session.rollback()
            return False, "Something went wrong"

    def delete(self):
        try:
            db.session.delete(self)
            db.session.commit()
            return True, "List has been deleted"
        except:
            db.session.rollback()
            return False, "Something went wrong"


class ListSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = List
        include_fk = True
        include_relationships = True
        load_instance = True
        ordered = True
        unknown = EXCLUDE

    id = auto_field(dump_only=True)
    user_id = auto_field(dump_only=True)
    title = auto_field()
    created = auto_field(dump_only=True)
    updated = auto_field(dump_only=True)


list_schema = ListSchema(exclude=['updated'])
lists_schema = ListSchema(exclude=['updated'], many=True)


class AdminListSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = List
        include_fk = True
        include_relationships = True
        load_instance = True
        ordered = True
        unknown = EXCLUDE

    id = auto_field(dump_only=True)
    user_id = auto_field(dump_only=True)
    title = auto_field()
    created = auto_field(dump_only=True)
    updated = auto_field(dump_only=True)