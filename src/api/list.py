import re
from flask import request, jsonify
from marshmallow import ValidationError
from sqlalchemy import exc
from flask_login import current_user, login_required
from werkzeug.exceptions import *
from flask_mail import Message
from app import app, db, mail, scheduler
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
        'message': f"Success: lists of current user",
        'user_id': current_user.id,
        'data': lists_schema.dump(lists),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists', methods=['POST'])
@login_required
def create_list():
    data = request.json
    list = list_schema.load(data, session=db.session)
    list.user_id = current_user.id
    list.title = list.title.strip()

    try:
        db.session.add(list)
        db.session.commit()

    except:
        db.session.rollback()
        return "Failed: something went wrong"

    response = {
        'success': True,
        'message': f"Success: list has been created",
        'data': list_schema.dump(list),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>', methods=['PUT'])
@login_required
def update_list(list_id):
    data = request.json
    list = list_schema.load(data, instance=List.query.get(list_id), session=db.session)
    list.title = list.title.strip()

    if not list.user_id == current_user.id:
        response = {'success': False, 'message': f"Failed: access denied"}
        return jsonify(response), 403

    if list.id:
        if list.title:
            try:
                db.session.add(list)
                db.session.commit()

                response = {
                    'success': True,
                    'message': f"Success: list #{list.id} has been updated",
                    'data': list_schema.dump(list),
                }
                return jsonify(response), 200
            except:
                db.session.rollback()
                return "Failed: something went wrong"
        else:
            response = {'success': False, 'message': f"Failed: list title must not be empty"}
            return jsonify(response), 400
    else:
        response = {'success': False, 'message': f"Failed: list #{list_id} not found"}
        return jsonify(response), 404


@app.route('/todo/api/lists/<int:list_id>', methods=['DELETE'])
@login_required
def delete_list(list_id):
    list = List.query.get(list_id)

    if not list.user_id == current_user.id:
        response = {'success': False, 'message': f"Failed: access denied"}
        return jsonify(response), 403

    if not list:
        response = {'success': False, 'message': f"Failed: list #{list_id} not found"}
        return jsonify(response), 404

    try:
        db.session.delete(list)
        db.session.commit()
    except:
        db.session.rollback()
        return "Failed: something went wrong"

    response = {
        'success': True,
        'message': f"Success: list #{list.id} has been deleted",
        'data': list_schema.dump(list),
    }
    return jsonify(response), 200


@app.route('/todo/api/lists/<int:list_id>', methods=['GET'])
@login_required
def get_list(list_id):
    return f'api [list]: get list items of {list_id}'


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
