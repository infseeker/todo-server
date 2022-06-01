from app import db
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from ..models.List import List


class ListItem(db.Model):
    __tablename__ = 'list_items'

    id = db.Column(db.Integer, primary_key=True, nullable=False)
    list_id = db.Column(db.Integer, db.ForeignKey(List.id, ondelete='CASCADE'), nullable=False)
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
        self.title = title
        self.is_done = is_done
        self.is_liked = is_liked
        self.position = position

    def create(self):
        try:
            db.session.add(self)
            db.session.commit()
        except:
            db.session.rollback()
            return "Failed: something went wrong"

    def update(self):
        self.updated = db.func.now()
        try:
            db.session.add(self)
            db.session.commit()
        except:
            db.session.rollback()
            return "Failed: something went wrong"

    def delete(self):
        try:
            db.session.delete(self)
            db.session.commit()
        except:
            db.session.rollback()
            return "Failed: something went wrong"

class ListItemSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ListItem
        include_fk = True
        ordered = True


list_item_schema = ListItemSchema(exclude=['created', 'updated'])
