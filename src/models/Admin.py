import os
import uuid

from app import app, db
from flask import redirect, flash, send_from_directory
from flask_login import current_user, login_required
from src.auth.basic import admin
from werkzeug.security import generate_password_hash

from .User import User
from .List import List
from .ListItem import ListItem
from .ListUser import ListUser

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

    page_size = 50
    extra_css = ['/todo/api/admin/static/admin.css']

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect('/login')


@login_required
@admin.require(403)
@app.route('/todo/api/admin/static/admin.css', methods=['GET'])
def get_admin_css():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../static/')
    return send_from_directory(path, 'admin.css')


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
        'is_activated',
        'is_deleted',
        'is_admin',
    ]
    form_edit_rules = [
        'username',
        'email',
        'is_activated',
        'is_deleted',
        'is_admin',
    ]
    column_labels = dict(password_hash='Password')
    column_searchable_list = ['username', 'email']

    def on_model_change(self, form, user, is_created):
        if is_created:
            user.session_id = uuid.uuid4()
            user.password_hash = generate_password_hash(form.password_hash.data)

        else:
            if user.id == current_user.id and user.is_admin == False:
                user.is_admin = True
                flash("You can't take away admin permissions of yourself")

    def delete_model(self, user):
        if user.id == current_user.id:
            flash("You cant't delete yourself")
            return False

        try:
            self.on_model_delete(user)
            self.session.delete(user)
            self.session.commit()
        except Exception as ex:
            if not self.handle_view_exception(ex):
                flash('Failed to delete user')
            self.session.rollback()
            return False
        else:
            self.after_model_delete(user)

        return True

    def on_model_delete(self, user):
        shared_lists = ListUser.query.filter_by(user_id=user.id)
        if shared_lists.first():
            shared_lists.delete()
            self.session.commit()

        owned_lists = List.query.filter_by(user_id=user.id)
        if owned_lists.first():
            for list in owned_lists:
                list.shared_with = []
            self.session.commit()

class ListView(DefaultModelView):
    column_default_sort = ('user_id', False)
    column_list = [
        'id',
        'user_id',
        'title',
        'shared_with',
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
        'shared_with',
    ]
    form_edit_rules = [
        'users',
        'title',
        'shared_with',
    ]
    column_searchable_list = ['user_id', 'title']

    def on_model_change(self, form, list_model, is_created):
        list_owner = form.data['users']
        if list_owner in list_model.shared_with:
            list_model.shared_with = list(
                filter(lambda user: user != list_owner, list_model.shared_with)
            )
            flash("You can't share list with its owner")


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
    name='Todo',
    template_mode='bootstrap3',
    index_view=MyAdminIndexView(url='/todo/api/admin'),
)

admin.add_link(MenuLink(name='Profile', category='', url='/profile'))

admin.add_view(UserView(User, db.session, name="User"))
admin.add_view(ListView(List, db.session, name="List"))
admin.add_view(ListItemView(ListItem, db.session, name="List item"))
