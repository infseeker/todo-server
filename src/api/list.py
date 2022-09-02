import functools

from flask import request, jsonify
from sqlalchemy import or_
from marshmallow import ValidationError
from flask_login import current_user, login_required
from flask_socketio import disconnect, join_room, rooms
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

    email = email.strip().lower()
    unshared_user = None

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
        'data': short_user_schema.dump(unshared_user),
        'message': f"List #{list.id} has been unshared with {unshared_user.email}",
        'code': 200,
    }
    return jsonify(response), 200


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
    list = List.query.filter(List.id == list_id).first()
    user = current_user if current_user.id == list.user_id else None

    if not user:
        for shared_user in list.shared_with:
            if shared_user.id == current_user.id:
                user = current_user

    if not list and not user:
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

    list_item.list_id = list.id

    last_list_item = (
        ListItem.query.filter_by(list_id=list.id).order_by(ListItem.position.desc()).first()
    )
    list_item.position = last_list_item.position + 1 if last_list_item else 1

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
    list = List.query.filter_by(id=list_id).first()
    list_item = ListItem.query.filter_by(list_id=list_id, id=list_item_id).first()
    user = current_user if current_user.id == list.user_id else None

    if not user:
        for shared_user in list.shared_with:
            if shared_user.id == current_user.id:
                user = current_user

    if not list and not user:
        response = {
            'message': f"List not found",
            'code': 404,
        }
        return jsonify(response), 404

    if not list_item and not user:
        response = {
            'message': f"List item not found",
            'code': 404,
        }
        return jsonify(response), 404

    try:
        list_item = list_item_schema.load(data, instance=list_item, session=db.session)
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

    # list item ranging
    previous_list_item_id = data['previous_list_item_id']
    if previous_list_item_id or previous_list_item_id == 0:
        list_item.position = setListItemPosition(list, previous_list_item_id)

    success, message = list_item.update()

    if not success:
        response = {
            'message': message,
            'code': 400,
        }
        return jsonify(response), 400

    response = {
        'message': f"List item #{list_item.id} of list #{list.id} has been updated",
        'data': list_item_schema.dump(list_item),
        'code': 200,
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>/<int:list_item_id>', methods=['DELETE'])
@login_required
def delete_list_item(list_id, list_item_id):
    list = List.query.filter_by(id=list_id).first()
    list_item = ListItem.query.filter_by(list_id=list_id, id=list_item_id).first()
    user = current_user if current_user.id == list.user_id else None

    if not user:
        for shared_user in list.shared_with:
            if shared_user.id == current_user.id:
                user = current_user

    if not list and not user:
        response = {
            'message': f"List not found",
            'code': 404,
        }
        return jsonify(response), 404

    if not list_item and not user:
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


# check user session for websocket
def auth_required(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            disconnect()
        else:
            return f(*args, **kwargs)

    return wrapped


@socketio.on('connect')
@auth_required
def user_connect(data):
    list_id = data['list_id']
    list = List.query.get(list_id)

    if not list:
        disconnect()
        return

    list_shared_user = None
    for shared_user in list.shared_with:
        if shared_user.id == current_user.id:
            list_shared_user = current_user

    if not current_user.id == list.user_id and not list_shared_user:
        disconnect()
        return

    room = list.id
    join_room(room)

    response = {
        'data': short_user_schema.dump(current_user),
        'room': room,
        'message': f'{current_user.email} has connected',
        'code': 200,
    }
    socketio.emit('connected', response, to=room)


@socketio.on('user_disconnect')
@auth_required
def user_disconnect(data):
    response = {
        'data': short_user_schema.dump(current_user),
        'message': f'{current_user.email} has disconnected',
        'code': 200,
    }
    socketio.emit('disconnected', response)
    disconnect()


@socketio.on('list_title_rename')
@auth_required
def list_title_rename(data):
    list_id = data['list_id']
    response = {
        'data': data,
        'user': short_user_schema.dump(current_user),
        'message': f'List owner has changed list title',
        'code': 200,
    }
    socketio.emit('list_title_renamed', response, to=list_id)


@socketio.on('create_list_item')
@auth_required
def create_list_item(data):
    list_id = data['list_id']

    response = {
        'data': data,
        'user': short_user_schema.dump(current_user),
        'message': f'Add list item',
        'code': 200,
    }
    socketio.emit('list_item_created', response, to=list_id)


@socketio.on('edit_list_item_title')
@auth_required
def edit_list_item_title(data):
    list_id = data['list_id']

    response = {
        'data': data,
        'user': short_user_schema.dump(current_user),
        'message': f'Edit list item title',
        'code': 200,
    }
    socketio.emit('list_item_title_edited', response, to=list_id)


@socketio.on('check_list_item')
@auth_required
def check_list_item(data):
    list_id = data['list_id']

    response = {
        'data': data,
        'user': short_user_schema.dump(current_user),
        'message': f'Check list item',
        'code': 200,
    }
    socketio.emit('list_item_checked', response, to=list_id)


@socketio.on('like_list_item')
@auth_required
def like_list_item(data):
    list_id = data['list_id']

    response = {
        'data': data,
        'user': short_user_schema.dump(current_user),
        'message': f'Like list item',
        'code': 200,
    }
    socketio.emit('list_item_liked', response, to=list_id)


@socketio.on('range_list_item')
@auth_required
def range_list_item(data):
    list_id = data['list_id']

    response = {
        'data': data,
        'user': short_user_schema.dump(current_user),
        'message': f'Range list item',
        'code': 200,
    }
    socketio.emit('list_item_ranged', response, to=list_id)


@socketio.on('delete_list_item')
@auth_required
def delete_list_item(data):
    list_id = data['list_id']

    response = {
        'data': data,
        'user': short_user_schema.dump(current_user),
        'message': f'Delete list item',
        'code': 200,
    }
    socketio.emit('list_item_deleted', response, to=list_id)


@socketio.on('share_list')
@auth_required
def delete_list(data):
    list_id = data['list_id']

    response = {
        'data': data['data'],
        'user': short_user_schema.dump(current_user),
        'message': f'List has shared',
        'code': 200,
    }
    socketio.emit('list_shared', response, to=list_id)


@socketio.on('unshare_list')
@auth_required
def delete_list(data):
    list_id = data['list_id']

    response = {
        'data': data['data'],
        'user': short_user_schema.dump(current_user),
        'message': f'List has unshared',
        'code': 200,
    }
    socketio.emit('list_unshared', response, to=list_id)


@socketio.on('delete_list')
@auth_required
def delete_list(data):
    list_id = data['list_id']

    response = {
        'data': data,
        'user': short_user_schema.dump(current_user),
        'message': f'Delete list',
        'code': 200,
    }
    socketio.emit('list_deleted', response, to=list_id)


def setListItemPosition(list, previous_list_item_id):
    if previous_list_item_id == 0:
        next_list_item = (
            ListItem.query.filter_by(list_id=list.id).order_by(ListItem.position.asc()).first()
        )
        if next_list_item and next_list_item.position:
            next_list_item.position
            return next_list_item.position / 2
    else:
        previous_list_item = ListItem.query.filter_by(
            id=previous_list_item_id, list_id=list.id
        ).first()
        if previous_list_item:
            next_list_item = (
                ListItem.query.filter_by(list_id=list.id)
                .order_by(ListItem.position.asc())
                .filter(ListItem.position > previous_list_item.position)
                .first()
            )
            if next_list_item:
                return (previous_list_item.position + next_list_item.position) / 2
            else:
                return previous_list_item.position + 1
