from ast import Not
import uuid

from app import app, db
from flask import redirect
from flask_login import current_user
from werkzeug.security import generate_password_hash

from src.models.User import User
from src.models.List import List
from src.models.ListItem import ListItem

from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink

# admin
app.config['FLASK_ADMIN_SWATCH'] = 'united'


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect('/login')

    def is_visible(self):
        return False


class DefaultModelView(ModelView):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect('/login')


class UserView(DefaultModelView):
    column_default_sort = ('id', False)

    column_sortable_list = [
        ('id', User.id),
        'username',
        'email',
        'image',
        'locale',
        'access_code',
        'is_admin',
        'is_deleted',
        'is_activated',
        'created',
        'updated',
        'last_login',
    ]

    column_list = [
        'id',
        'username',
        'email',
        'image',
        'locale',
        'access_code',
        'is_admin',
        'is_deleted',
        'is_activated',
        'created',
        'updated',
        'last_login',
    ]

    form_create_rules = [
        'username',
        'password_hash',
        'email',
        'image',
        'locale',
        'access_code',
        'is_activated',
        'is_deleted',
        'is_admin',
    ]

    form_edit_rules = [
        'username',
        'email',
        'image',
        'locale',
        'is_admin',
        'access_code',
        'is_activated',
        'is_deleted',
    ]

    def on_model_change(self, form, user, is_created):
        if is_created:
            user.session_id = uuid.uuid4()
            user.password_hash = generate_password_hash(form.password_hash.data)

    column_labels = dict(password_hash='Password')

    column_searchable_list = ['username', 'email']


class ListView(DefaultModelView):
    column_default_sort = ('user_id', False)

    column_list = [
        'id',
        'user_id',
        'title',
        'created',
        'updated',
    ]

    column_sortable_list = [
        ('id', List.id),
        ('user_id', List.user_id),
        'title',
        'created',
        'updated',
    ]

    form_create_rules = [
        'users',
        'title',
    ]

    form_edit_rules = [
        'users',
        'title',
    ]

    column_searchable_list = ['user_id', 'title']


class ListItemView(DefaultModelView):
    column_default_sort = ('list_id', False)
    
    column_list = [
        'id',
        'list_id',
        'title',
        'is_done',
        'is_liked',
        'position',
        'created',
        'updated',
    ]

    column_sortable_list = [
        ('id', ListItem.id),
        ('list_id', ListItem.list_id),
        'title',
        'is_done',
        'is_liked',
        'position',
        'created',
        'updated',
    ]

    form_create_rules = [
        'lists',
        'title',
        'is_done',
        'is_liked',
    ]

    form_edit_rules = [
        'lists',
        'title',
        'is_done',
        'is_liked',
    ]
    column_searchable_list = ['list_id', 'title']

    def on_model_change(self, form, list_item, is_created):
        if is_created:
            last_list_item = (
                db.session.query(ListItem)
                .filter_by(list_id=list_item.lists.id)
                .order_by(ListItem.position.desc())
                .first()
            )
            list_item.position = last_list_item.position + 1 if last_list_item else 1


admin = Admin(
    app,
    url="/todo/api/admin",
    name='todo',
    template_mode='bootstrap3',
    index_view=MyAdminIndexView(url='/todo/api/admin'),
)
admin.add_link(MenuLink(name='Profile', category='', url='/profile'))

admin.add_view(UserView(User, db.session, name="User"))
admin.add_view(ListView(List, db.session, name="List"))
admin.add_view(ListItemView(ListItem, db.session, name="List item"))
