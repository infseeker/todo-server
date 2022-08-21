import functools

from flask import request, jsonify
from sqlalchemy import or_
from marshmallow import ValidationError
from flask_login import current_user, login_required
from flask_socketio import disconnect
from werkzeug.exceptions import *

from app import app, db, socketio
from ..models.User import *
from ..models.List import *
from ..models.ListItem import *
from ..auth.basic import *


@app.route('/todo/api/lists', methods=['GET'])
@login_required
def get_lists():
    user_lists_query = List.query.filter_by(user_id=current_user.id)
    shared_lists_query = List.query.filter(List.shared_with.any(User.id == current_user.id))

    lists = user_lists_query.union(shared_lists_query)

    response = {
        'message': f"Lists of current user",
        'data': lists_schema.dump(lists),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/lists', methods=['POST'])
@login_required
def create_list():
    data = request.json
    items = data.get('items')

    try:
        list = list_schema.load(data, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'message': f"List creation validation error, check your data",
            'code': 400,
        }
        return jsonify(response), 400

    list.user_id = current_user.id

    if not list.title or not list.title.strip():
        response = {
            'message': f"List title must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    list.title = list.title.strip()

    success, message = list.create()

    if not success:
        response = {
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    if items:
        try:
            items = list_items_schema.load(items, session=db.session)
            for item in items:
                item.list_id = list.id
        except (ValidationError, TypeError):
            response = {
                'message': f"List items creation validation error, check your data",
                'code': 400,
            }
            return jsonify(response), 400

        success, message = ListItem.createAll(items)

    response = {
        'message': f"List has been created",
        'data': list_schema.dump(list),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>', methods=['PUT'])
@login_required
def update_list(list_id):
    data = request.json
    list = List.query.filter((List.id == list_id) & (List.user_id == current_user.id)).first()

    if not list:
        response = {
            'message': f"List not found",
            'code': 404,
        }
        return jsonify(response), 404

    try:
        list = list_schema.load(data, instance=list, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'message': f"List updating validation error, check your data",
            'code': 400,
        }
        return jsonify(response), 400

    if not list.title or not list.title.strip():
        response = {
            'message': f"List title must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    list.title = list.title.strip()

    success, message = list.update()

    if not success:
        response = {
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'message': f"List #{list.id} has been updated",
        'data': list_schema.dump(list),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>', methods=['DELETE'])
@login_required
def delete_list(list_id):
    list = List.query.filter((List.id == list_id) & (List.user_id == current_user.id)).first()

    if not list:
        response = {
            'message': f"List not found",
            'code': 404,
        }
        return jsonify(response), 404

    success, message = list.delete()

    if not success:
        response = {
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'message': f"List #{list.id} has been deleted",
        'data': list_schema.dump(list),
        'code': 200,
    }
    return jsonify(response), 200


# check user session for websocket
def auth_required(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            disconnect()
        else:
            return f(*args, **kwargs)

    return wrapped


@socketio.on('check')
@auth_required
def handle_my_custom_event(data):
    socketio.emit(
        'my response', {'message': '{0} has joined'.format(current_user.username)}, broadcast=True
    )


@app.route('/todo/api/lists/<int:list_id>', methods=['GET'])
@login_required
def get_list(list_id):
    list = List.query.filter(
        (List.id == list_id)
        & or_(List.user_id == current_user.id, List.shared_with.any(User.id == current_user.id))
    ).first()

    if not list:
        response = {
            'message': f"List not found",
            'code': 404,
        }
        return jsonify(response), 404

    list_items = ListItem.query.filter(ListItem.list_id == list_id)
    list_owner = User.query.get(list.user_id)

    response = {
        'message': f"List items for list #{list.id}",
        'owner': {
            'id': list.user_id,
            'username': list_owner.username,
            'email': list_owner.email,
            'image': list_owner.image,
        },
        'shared': short_users_schema.dump(list.shared_with),
        'list_id': list.id,
        'data': list_items_schema.dump(list_items),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>', methods=['POST'])
@login_required
def create_list_item(list_id):
    data = request.json
    list = List.query.filter((List.id == list_id) & (List.user_id == current_user.id)).first()

    if not list:
        response = {
            'message': f"List not found",
            'code': 404,
        }
        return jsonify(response), 404

    try:
        list_item = list_item_schema.load(data, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'message': f"List item creation validation error, check your data",
            'code': 400,
        }
        return jsonify(response), 400

    if not list_item.title or not list_item.title.strip():
        response = {
            'message': f"List item title must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    list_item.list_id = list_id

    success, message = list_item.create()
    if not success:
        response = {
            'message': message,
            'code': 200,
        }
        return jsonify(response), 400

    response = {
        'message': f"List item created for #{list.id}",
        'data': list_item_schema.dump(list_item),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>/<int:list_item_id>', methods=['PUT'])
@login_required
def update_list_item(list_id, list_item_id):
    data = request.json
    list = List.query.filter((List.id == list_id) & (List.user_id == current_user.id)).first()
    list_item = ListItem.query.filter(
        (ListItem.list_id == list_id) & (ListItem.id == list_item_id)
    ).first()

    if not list:
        response = {
            'message': f"List not found",
            'code': 404,
        }
        return jsonify(response), 404

    if not list_item:
        response = {
            'message': f"List item not found",
            'code': 404,
        }
        return jsonify(response), 404

    try:
        list = list_item_schema.load(data, instance=list_item, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'message': f"List updating validation error, check your data",
            'code': 400,
        }
        return jsonify(response), 400

    if not list_item.title or not list_item.title.strip():
        response = {
            'message': f"List item title must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    list_item.title = list_item.title.strip()

    success, message = list_item.update()

    if not success:
        response = {
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'message': f"List item #{list_item.id} of list #{list.id} has been updated",
        'data': list_item_schema.dump(list),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>/<int:list_item_id>', methods=['DELETE'])
@login_required
def delete_list_item(list_id, list_item_id):
    list = List.query.filter((List.id == list_id) & (List.user_id == current_user.id)).first()
    list_item = ListItem.query.filter(
        (ListItem.list_id == list_id) & (ListItem.id == list_item_id)
    ).first()

    if not list:
        response = {
            'message': f"List not found",
            'code': 404,
        }
        return jsonify(response), 404

    if not list_item:
        response = {
            'message': f"List item not found",
            'code': 404,
        }
        return jsonify(response), 404

    success, message = list_item.delete()

    if not success:
        response = {
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'message': f"List item #{list_item.id} of list #{list.id} has been deleted",
        'data': list_item_schema.dump(list_item),
        'code': 200,
    }
    return jsonify(response), 200
