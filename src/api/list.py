import re
from this import d
from flask import request, jsonify
from sqlalchemy import asc, desc
from marshmallow import ValidationError
from flask_login import current_user, login_required
from werkzeug.exceptions import *
from flask_mail import Message
from app import app, db
from ..models.User import *
from ..models.List import *
from ..models.ListItem import *
from ..auth.basic import *


@app.route('/todo/api/lists', methods=['GET'])
@login_required
def get_lists():
    lists = List.query.filter_by(user_id=current_user.id).order_by('id')
    response = {
        'success': True,
        'message': f"Lists of current user",
        'user_id': current_user.id,
        'data': lists_schema.dump(lists),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists', methods=['POST'])
@login_required
def create_list():
    data = request.json

    try:
        list = list_schema.load(data, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'success': False,
            'message': f"List creation validation error, check your data",
        }
        return jsonify(response), 400

    list.user_id = current_user.id

    if not list.title or not list.title.strip():
        response = {
            'success': False,
            'message': f"List title must not be empty",
        }
        return jsonify(response), 400

    list.title = list.title.strip()

    success, message = list.create()

    if not success:
        response = {'success': False, 'message': message}
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List has been created",
        'data': list_schema.dump(list),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>', methods=['PUT'])
@login_required
def update_list(list_id):
    data = request.json
    list = List.query.filter((List.id == list_id) & (List.user_id == current_user.id)).first()

    if not list:
        response = {'success': False, 'message': f"List not found"}
        return jsonify(response), 404

    try:
        list = list_schema.load(data, instance=list, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'success': False,
            'message': f"List updating validation error, check your data",
        }
        return jsonify(response), 400

    if not list.title or not list.title.strip():
        response = {'success': False, 'message': f"List title must not be empty"}
        return jsonify(response), 400

    list.title = list.title.strip()

    success, message = list.update()

    if not success:
        response = {'success': True, 'message': message}
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List #{list.id} has been updated",
        'data': list_schema.dump(list),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>', methods=['DELETE'])
@login_required
def delete_list(list_id):
    list = List.query.filter((List.id == list_id) & (List.user_id == current_user.id)).first()

    if not list:
        response = {'success': False, 'message': f"List not found"}
        return jsonify(response), 404

    success, message = list.delete()

    if not success:
        response = {'success': True, 'message': message}
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List #{list.id} has been deleted",
        'data': list_schema.dump(list),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>', methods=['GET'])
@login_required
def get_list(list_id):
    list = List.query.filter((List.id == list_id) & (List.user_id == current_user.id)).first()

    if not list:
        response = {'success': False, 'message': f"List not found"}
        return jsonify(response), 404

    list_items = ListItem.query.filter(ListItem.list_id == list_id)

    response = {
        'success': True,
        'message': f"List items for list #{list.id}",
        'user_id': current_user.id,
        'list_id': list.id,
        'data': list_items_schema.dump(list_items),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>', methods=['POST'])
@login_required
def create_list_item(list_id):
    data = request.json
    list = List.query.filter((List.id == list_id) & (List.user_id == current_user.id)).first()

    if not list:
        response = {'success': False, 'message': f"List not found"}
        return jsonify(response), 404

    try:
        list_item = list_item_schema.load(data, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'success': False,
            'message': f"List item creation validation error, check your data",
        }
        return jsonify(response), 400

    list_item.list_id = list_id

    if not list_item.title or not list_item.title.strip():
        response = {'success': False, 'message': f"List item title must not be empty"}
        return jsonify(response), 400

    list_item.title = list_item.title.strip()

    success, message = list_item.create()
    if not success:
        response = {'success': False, 'message': message}
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List item created for #{list.id}",
        'data': list_item_schema.dump(list_item),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>/<int:list_item_id>', methods=['PUT'])
@login_required
def update_list_item(list_id, list_item_id):
    data = request.json
    list = List.query.filter((List.id == list_id) & (List.user_id == current_user.id)).first()
    list_item = ListItem.query.filter((ListItem.list_id == list_id) & (ListItem.id == list_item_id)).first()

    if not list:
        response = {'success': False, 'message': f"List not found"}
        return jsonify(response), 404

    if not list_item:
        response = {'success': False, 'message': f"List item not found"}
        return jsonify(response), 404

    try:
        list = list_item_schema.load(data, instance=list_item, session=db.session)
    except (ValidationError, TypeError):
        response = {
            'success': False,
            'message': f"List updating validation error, check your data",
        }
        return jsonify(response), 400


    if not list_item.title or not list_item.title.strip():
        response = {'success': False, 'message': f"List item title must not be empty"}
        return jsonify(response), 400

    list_item.title = list_item.title.strip()

    success, message = list_item.update()

    if not success:
        response = {'success': True, 'message': message}
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List item #{list_item.id} of list #{list.id} has been updated",
        'data': list_item_schema.dump(list),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>/<int:list_item_id>', methods=['DELETE'])
@login_required
def delete_list_item(list_id, list_item_id):
    list = List.query.filter((List.id == list_id) & (List.user_id == current_user.id)).first()
    list_item = ListItem.query.filter((ListItem.list_id == list_id) & (ListItem.id == list_item_id)).first()

    if not list:
        response = {'success': False, 'message': f"List not found"}
        return jsonify(response), 404

    if not list_item:
        response = {'success': False, 'message': f"List item not found"}
        return jsonify(response), 404

    success, message = list_item.delete()

    if not success:
        response = {'success': True, 'message': message}
        return jsonify(response), 400

    response = {
        'success': True,
        'message': f"List item #{list_item.id} of list #{list.id} has been deleted",
        'data': list_item_schema.dump(list_item),
    }
    return jsonify(response), 200
