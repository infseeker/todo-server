import functools

from flask import request, jsonify
from sqlalchemy import or_
from marshmallow import ValidationError
from flask_login import current_user, login_required
from flask_socketio import send, emit, disconnect
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
    lists_query = user_lists_query.union(shared_lists_query)

    lists = list(
        map(
            lambda l: {
                'id': l.id,
                'title': l.title,
                'owner': short_user_schema.dump(User.query.get(l.user_id)),
                'shared': short_users_schema.dump(l.shared_with),
            },
            lists_query,
        )
    )

    response = {
        'message': f"Lists of current user",
        'data': lists,
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

    list = list_schema.dump(list)
    list['owner'] = short_user_schema.dump(User.query.get(current_user.id))

    response = {
        'message': f"List has been created",
        'data': list,
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


@app.route('/todo/api/lists/<int:list_id>/share', methods=['PUT'])
@login_required
def share_list(list_id):
    data = request.json
    email = data['email']
    list = List.query.get(list_id)

    if not list or list.user_id != current_user.id:
        response = {
            'message': f"List #{list_id} was not found",
            'code': 404,
        }
        return jsonify(response), 404

    if not email or not email.strip():
        response = {
            'message': f"User email field must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    email = email.strip().lower()

    if current_user.email == email:
        response = {
            'message': f"List #{list.id} has owned by {email}",
            'code': 409,
        }
        return jsonify(response), 409

    for u in list.shared_with:
        if u.email == email:
            response = {
                'message': f"List #{list.id} already shared with {email}",
                'code': 409,
            }
            return jsonify(response), 409

    user = User.get_user_by_email(email)

    if not user or not user.is_activated or user.is_deleted:
        response = {
            'message': f"User with email {email} was not found",
            'code': 404,
        }
        return jsonify(response), 404

    try:
        list.shared_with.append(user)
    except:
        response = {
            'message': f"Something went wrong",
            'code': 400,
        }
        return jsonify(response), 400

    success, message = list.update()

    if not success:
        response = {
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'data': short_user_schema.dump(user),
        'message': f"List #{list.id} has been shared with user {user.email}",
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>/share', methods=['DELETE'])
@login_required
def unshare_list(list_id):
    data = request.json
    email = data['email']
    list = List.query.get(list_id)

    if not list:
        response = {
            'message': f"List #{list_id} was not found",
            'code': 404,
        }
        return jsonify(response), 404

    if not email or not email.strip():
        response = {
            'message': f"User email field must not be empty",
            'code': 400,
        }
        return jsonify(response), 400

    unshared_user = None
    email = email.strip().lower()

    for shared_user in list.shared_with:
        if shared_user.email == email:
            unshared_user = shared_user

    if not current_user.id == list.user_id and not current_user == unshared_user:
        response = {
            'message': f"Can't unshare list #{list.id} with {email}, user not found",
            'code': 404,
        }
        return jsonify(response), 404

    try:
        list.shared_with.remove(unshared_user)
    except:
        response = {
            'message': f"Something went wrong",
            'code': 400,
        }
        return jsonify(response), 400

    success, message = list.update()

    if not success:
        response = {
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'message': f"List #{list.id} has been unshared with {unshared_user.email}",
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


@socketio.on('user_connect')
@auth_required
def user_connect(data):
    list_owner_id = data['data']['owner']['id']
    if current_user.id == list_owner_id:
        response = {
            'data': data,
            'message': f'{current_user.email} has joined',
            'code': 200,
        }
        socketio.emit('my response', response)


@socketio.on('user_disconnect')
@auth_required
def user_disconnect(data):
    response = {
        'data': data,
        'message': f'{current_user.email} has unjoined',
        'code': 200,
    }
    socketio.emit('my response', response)
    disconnect()
    
    
@socketio.on('list_title_rename')
@auth_required
def list_title_rename(data):
    response = {
        'data': data,
        'message': f'List owner has changed list title',
        'code': 200,
    }
    socketio.emit('list_title_renaming', response)

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

    response = {
        'list_id': list.id,
        'data': list_items_schema.dump(list_items),
        'code': 200,
        'message': f"List items for list #{list.id}",
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
