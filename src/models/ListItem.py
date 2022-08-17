from app import db
from marshmallow import EXCLUDE
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema, auto_field
from .List import List


class ListItem(db.Model):
    __tablename__ = 'list_items'

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey(List.id, ondelete='CASCADE'), nullable=False)
    lists = db.relationship('List')
    title = db.Column(db.Text, nullable=False, default='New List Item')
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

    def __init__(
        self,
        title=None,
        is_done=False,
        is_liked=False,
        position=0,
    ):
        self.title = title.strip() or None
        self.is_done = is_done
        self.is_liked = is_liked
        self.position = position

    def create(self):
        try:
            db.session.add(self)
            db.session.commit()
            return True, "List item has been created"
        except:
            db.session.rollback()
            return False, "Something went wrong"

    def update(self):
        self.updated = db.func.now()
        try:
            db.session.add(self)
            db.session.commit()
            return True, "List item has been updated"
        except:
            db.session.rollback()
            return False, "Something went wrong"

    def delete(self):
        try:
            db.session.delete(self)
            db.session.commit()
            return True, "List item has been deleted"
        except:
            db.session.rollback()
            return False, "Something went wrong"

    @staticmethod
    def createAll(items):
        try:
            db.session.add_all(items)
            db.session.commit()
            return True, "List items have been created"
        except:
            db.session.rollback()
            return False, "Something went wrong"


class ListItemSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ListItem
        include_fk = True
        include_relationships = True
        load_instance = True
        ordered = True
        unknown = EXCLUDE

    id = auto_field(dump_only=True)
    list_id = auto_field(dump_only=True)
    title = auto_field()
    is_done = auto_field()
    is_liked = auto_field()
    position = auto_field()
    created = auto_field(dump_only=True)
    updated = auto_field(dump_only=True)


list_item_schema = ListItemSchema(exclude=['updated'])
list_items_schema = ListItemSchema(exclude=['updated'], many=True)


class AdminListItemSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ListItem
        include_fk = True
        include_relationships = True
        load_instance = True
        ordered = True
        unknown = EXCLUDE

    id = auto_field(dump_only=True)
    list_id = auto_field(dump_only=True)
    title = auto_field()
    is_done = auto_field()
    is_liked = auto_field()
    position = auto_field()
    created = auto_field(dump_only=True)
    updated = auto_field(dump_only=True)
