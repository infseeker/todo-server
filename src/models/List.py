from app import db
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from ..models.User import User


class List(db.Model):

    __tablename__ = "lists"
    id = db.Column(db.Integer, primary_key=True, nullable=False)
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
        ordered = True


list_schema = ListSchema(exclude=["created", "updated", "is_deleted"])
