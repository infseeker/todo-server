from app import db


class ListUser(db.Model):
    __tablename__ = 'lists_users'
    list_id = db.Column(db.Integer, db.ForeignKey('lists.id'), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
