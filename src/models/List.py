from app import db
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema, auto_field
from ..models.User import User


class List(db.Model):

    __tablename__ = 'lists'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id, ondelete='CASCADE'), nullable=False)
    title = db.Column(db.Text, nullable=False, default='New List')
    is_liked = db.Column(db.Boolean, nullable=False, default=False)
    created = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    updated = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.now(),
        server_onupdate=db.func.now(),
    )

    def __init__(self, title=None, is_liked=False):
        self.title = title or None
        self.is_liked = is_liked

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
        ordered = True
        include_relationships = True
        load_instance = True
    id = auto_field(dump_only=True)
    user_id = auto_field(dump_only=True)
    created = auto_field(dump_only=True)
    updated = auto_field(dump_only=True)


list_schema = ListSchema(exclude=['user_id', 'updated'])
lists_schema = ListSchema(exclude=['user_id', 'updated'], many=True)
