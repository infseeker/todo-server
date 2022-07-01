from app import app, db
from flask import request, jsonify
from flask_login import current_user, login_required
from marshmallow import ValidationError
from ..models.User import *
from ..models.List import *
from ..models.ListItem import *
from ..auth.basic import *
from ..api.user import check_username, check_email, check_password


@app.route('/todo/api/admin/users', methods=['GET'])
@login_required
@admin.require(403)
def get_users():
    users = User.query.order_by('id').all()

    if not users:
        response = {
            'success': False,
            'message': "No users found",
            'code': 404,
        }
        return jsonify(response), 404

    response = {
        'success': True,
        'message': "All users",
        'data': AdminUserSchema(many=True).dump(users),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/admin/users', methods=['POST'])
@login_required
@admin.require(403)
def create_user():
    if (
        check_username()[0].json['success']
        and check_email()[0].json['success']
        and check_password()[0].json['success']
    ):
        data = request.json

        try:
            user = AdminUserSchema().load(data, session=db.session)
        except (ValidationError, TypeError):
            response = {
                'success': False,
                'message': f"User creation validation error, check your data",
                'code': 400,
            }
            return jsonify(response), 400

        success, message = user.create()

        if not success:
            response = {
                'success': False,
                'message': message,
                'code': 400,
            }
            return jsonify(response), 400

        user.access_code = None

        success, message = user.update()
        if not success:
            response = {
                'success': False,
                'message': message,
                'code': 400,
            }
            return jsonify(response), 400

        response = {
            'success': True,
            'message': f"User #{user.id} has been created",
            'data': AdminUserSchema().dump(user),
            'code': 200,
        }
        return jsonify(response), 200
    else:
        if not check_username()[0].json['success']:
            return check_username()
        elif not check_email()[0].json['success']:
            return check_email()
        elif not check_password()[0].json['success']:
            return check_password()


@app.route('/todo/api/admin/users/<int:user_id>', methods=['GET'])
@login_required
@admin.require(403)
def get_user(user_id):
    user = User.query.get(user_id)

    if not user:
        response = {
            'success': False,
            'message': f"User #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    response = {
        'success': True,
        'message': f"User #{user.id}",
        'data': AdminUserSchema().dump(user),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/admin/users/<int:user_id>', methods=['PUT'])
@login_required
@admin.require(403)
def update_user(user_id):
    data = request.json
    user = User.query.get(user_id)

    if not user:
        response = {
            'success': False,
            'message': f"User #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    username = data.get('username') or user.username
    email = data.get('email') or user.email

    if not user.username == username.strip() and not check_username()[0].json['success']:
        return check_username()

    if not user.email == email.strip() and not check_email()[0].json['success']:
        return check_email()

    try:
        user = AdminUserSchema(exclude=['password']).load(
            data, instance=user, session=db.session, partial=True
        )
    except (ValidationError, TypeError):
        response = {
            'success': False,
            'message': f"User updating validation error, check your data",
            'code': 400,
        }
        return jsonify(response), 400

    user.username = user.username.strip()
    user.email = user.email.strip()

    if user.id == current_user.id and not user.is_admin:
        response = {
            'success': False,
            'message': "You can't remove your own admin permissions",
            'code': 403,
        }
        return jsonify(response), 403

    success, message = user.update()

    if not success:
        response = {
            'success': True,
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"User #{user.id} has been updated",
        'data': AdminUserSchema().dump(user),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin.require(403)
def delete_user(user_id):
    user = User.query.get(user_id)

    if not user:
        response = {
            'success': False,
            'message': f"User #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    if user.id == current_user.id:
        response = {
            'success': False,
            'message': f"You can't delete yourself",
            'code': 403,
        }
        return jsonify(response), 403

    success, message = user.delete()

    if not success:
        response = {
            'success': False,
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"User #{user.id} has been deleted",
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/admin/users/<int:user_id>/lists', methods=['GET'])
@login_required
@admin.require(403)
def get_user_lists(user_id):
    user = User.query.get(user_id)

    if not user:
        response = {
            'success': False,
            'message': f"User #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    lists = List.query.filter_by(user_id=user.id).order_by('id')
    response = {
        'success': True,
        'message': f"Lists of user #{user.id}",
        'user_id': user.id,
        'data': AdminListSchema(many=True).dump(lists),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/admin/users/<int:user_id>/lists', methods=['POST'])
@login_required
@admin.require(403)
def create_user_list(user_id):
    data = request.json
    user = User.query.get(user_id)

    if not user:
        response = {
            'success': False,
            'message': f"User #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    try:
        list = AdminListSchema().load(data, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'success': False,
            'message': f"List creation validation error, check your data",
            'code': 400,
        }
        return jsonify(response), 400

    list.user_id = user.id

    if not list.title or not list.title.strip():
        response = {
            'success': False,
            'message': f"List title must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    list.title = list.title.strip()

    success, message = list.create()

    if not success:
        response = {
            'success': False,
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List #{list.id} for user #{user.id} has been created",
        'data': AdminListSchema().dump(list),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/admin/users/<int:user_id>/lists/<int:list_id>', methods=['PUT'])
@login_required
@admin.require(403)
def update_user_list(user_id, list_id):
    data = request.json
    user = User.query.get(user_id)

    if not user:
        response = {
            'success': False,
            'message': f"User #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    list = List.query.filter((List.user_id == user_id) & (List.id == list_id)).first()

    if not list:
        response = {
            'success': False,
            'message': f"List #{list_id} for user #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    try:
        list = AdminListSchema().load(data, instance=list, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'success': False,
            'message': f"List updating validation error, check your data",
            'code': 400,
        }
        return jsonify(response), 400

    if not list.title or not list.title.strip():
        response = {
            'success': False,
            'message': f"List title must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    list.title = list.title.strip()

    success, message = list.update()

    if not success:
        response = {
            'success': False,
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List #{list.id} for user #{user.id} has been updated",
        'data': AdminListSchema().dump(list),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/admin/users/<int:user_id>/lists/<int:list_id>', methods=['DELETE'])
@login_required
@admin.require(403)
def delete_user_list(user_id, list_id):
    user = User.query.get(user_id)

    if not user:
        response = {
            'success': False,
            'message': f"User #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    list = List.query.filter((List.id == list_id) & (List.user_id == user.id)).first()

    if not list:
        response = {
            'success': False,
            'message': f"List #{list_id} for user #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    success, message = list.delete()

    if not success:
        response = {
            'success': True,
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List #{list.id} has been deleted",
        'data': AdminListSchema().dump(list),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/admin/users/<int:user_id>/lists/<int:list_id>', methods=['GET'])
@login_required
@admin.require(403)
def get_user_list(user_id, list_id):
    user = User.query.get(user_id)

    if not user:
        response = {
            'success': False,
            'message': f"User #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    list = List.query.filter((List.id == list_id) & (List.user_id == user.id)).first()

    if not list:
        response = {
            'success': False,
            'message': f"List #{list_id} for user #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    list_items = ListItem.query.filter(ListItem.list_id == list.id)

    response = {
        'success': True,
        'message': f"List items for list #{list.id}",
        'user_id': user.id,
        'list_id': list.id,
        'data': AdminListItemSchema(many=True).dump(list_items),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/admin/users/<int:user_id>/lists/<int:list_id>', methods=['POST'])
@login_required
@admin.require(403)
def create_user_list_item(user_id, list_id):
    data = request.json
    user = User.query.get(user_id)

    if not user:
        response = {
            'success': False,
            'message': f"User #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    list = List.query.filter((List.id == list_id) & (List.user_id == user.id)).first()

    if not list:
        response = {
            'success': False,
            'message': f"List #{list_id} for user #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    try:
        list_item = AdminListItemSchema().load(data, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'success': False,
            'message': f"List item creation validation error, check your data",
            'code': 400,
        }
        return jsonify(response), 400

    list_item.list_id = list.id

    if not list_item.title or not list_item.title.strip():
        response = {
            'success': False,
            'message': f"List item title must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    list_item.title = list_item.title.strip()

    success, message = list_item.create()

    if not success:
        response = {
            'success': False,
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List item #{list_item.id} of list #{list.id} for user #{user.id} has been created",
        'data': AdminListItemSchema().dump(list_item),
        'code': 200,
    }
    return jsonify(response), 200


@app.route(
    '/todo/api/admin/users/<int:user_id>/lists/<int:list_id>/<int:list_item_id>',
    methods=['PUT'],
)
@login_required
@admin.require(403)
def update_user_list_item(user_id, list_id, list_item_id):
    data = request.json
    user = User.query.get(user_id)

    if not user:
        response = {
            'success': False,
            'message': f"User #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    list = List.query.filter((List.id == list_id) & (List.user_id == user.id)).first()

    if not list:
        response = {
            'success': False,
            'message': f"List #{list_id} for user #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    list_item = ListItem.query.filter(
        (ListItem.id == list_item_id) & (ListItem.list_id == list.id)
    ).first()

    if not list_item:
        response = {
            'success': False,
            'message': f"List item #{list_item_id} of list #{list_id} for user #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    try:
        list_item = AdminListItemSchema().load(data, instance=list_item, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'success': False,
            'message': f"List item creation validation error, check your data",
            'code': 400,
        }
        return jsonify(response), 400

    if not list_item.title or not list_item.title.strip():
        response = {
            'success': False,
            'message': f"List item title must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    list_item.title = list_item.title.strip()

    success, message = list_item.update()

    if not success:
        response = {
            'success': False,
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List item #{list_item.id} of list #{list.id} for user #{user.id} has been updated",
        'data': AdminListItemSchema().dump(list_item),
        'code': 200,
    }
    return jsonify(response), 200


@app.route(
    '/todo/api/admin/users/<int:user_id>/lists/<int:list_id>/<int:list_item_id>',
    methods=['DELETE'],
)
@login_required
@admin.require(403)
def delete_user_list_item(user_id, list_id, list_item_id):
    user = User.query.get(user_id)

    if not user:
        response = {
            'success': False,
            'message': f"User #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    list = List.query.filter((List.id == list_id) & (List.user_id == user.id)).first()

    if not list:
        response = {
            'success': False,
            'message': f"List #{list_id} for user #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    list_item = ListItem.query.filter(
        (ListItem.id == list_item_id) & (ListItem.list_id == list.id)
    ).first()

    if not list_item:
        response = {
            'success': False,
            'message': f"List item #{list_item_id} of list #{list_id} for user #{user_id} not found",
            'code': 404,
        }
        return jsonify(response), 404

    success, message = list_item.delete()

    if not success:
        response = {
            'success': True,
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List item #{list_item.id} of list #{list.id} has been deleted",
        'data': AdminListItemSchema().dump(list_item),
        'code': 200,
    }
    return jsonify(response), 200
