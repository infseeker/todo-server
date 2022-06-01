import re
from flask import request, jsonify
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
    lists = List.query.filter_by(user_id=current_user.id)
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

    list.title = list.title.strip()

    if not list.title:
        response = {'success': False, 'message': f"List title must not be empty"}
        return jsonify(response), 400

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
        'message': f"Success: list #{list.id} has been deleted",
        'data': list_schema.dump(list),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>', methods=['GET'])
@login_required
def get_list(list_id):
    user = current_user
    list = List.query.filter_by(user_id=user.id)
    response = {
        'success': True,
        'message': f"Success: lists of current user",
        'user_id': current_user.id,
        'data': lists_schema.dump(lists),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>', methods=['POST'])
@login_required
def create_list_item(list_id):
    return f'api [list]: create item for list {list_id}'


@app.route('/todo/api/lists/<int:list_id>/<int:list_item_id>', methods=['PUT'])
@login_required
def update_list_item(list_id, list_item_id):
    return f'api [list]: update list item {list_item_id} of list {list_id}'


@app.route('/todo/api/lists/<int:list_id>/<int:list_item_id>', methods=['DELETE'])
@login_required
def delete_list_item(list_id, list_item_id):
    return f'api [list]: delete list item {list_item_id} of list {list_id}'
