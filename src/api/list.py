from app import app, db
from ..models.List import *
from ..models.ListItem import *


@app.route("/todo/api/lists", methods=["GET"])
def get_lists():
    return "api [list]: get lists"


@app.route("/todo/api/lists", methods=["POST"])
def create_list():
    return "api [list]: get lists"


@app.route("/todo/api/lists/<int:list_id>", methods=["PUT"])
def update_list(list_id):
    return f"api [list]: update list {list_id}"


@app.route("/todo/api/lists/<int:list_id>", methods=["DELETE"])
def delete_list(list_id):
    return f"api [list]: delete list {list_id}"


@app.route("/todo/api/lists/<int:list_id>", methods=["GET"])
def get_list(list_id):
    return f"api [list]: get list items of {list_id}"


@app.route("/todo/api/lists/<int:list_id>", methods=["POST"])
def create_list_item(list_id):
    return f"api [list]: create item for list {list_id}"


@app.route("/todo/api/lists/<int:list_id>/<int:list_item_id>", methods=["PUT"])
def update_list_item(list_id, list_item_id):
    return f"api [list]: update list item {list_item_id} of list {list_id}"


@app.route("/todo/api/lists/<int:list_id>/<int:list_item_id>", methods=["DELETE"])
def delete_list_item(list_id, list_item_id):
    return f"api [list]: delete list item {list_item_id} of list {list_id}"
