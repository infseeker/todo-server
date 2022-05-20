from app import app, db
from ..models.User import *
from ..models.List import *
from ..models.ListItem import *
from ..auth.basic import *


@app.route("/todo/api/admin/users", methods=["GET"])
@admin.require(403)
def get_users():
    return "api [admin]: get users"


@app.route("/todo/api/admin/users", methods=["POST"])
def create_user():
    return "api [admin]: create user"


@app.route("/todo/api/admin/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    return f"api [admin]: get user {user_id}"


@app.route("/todo/api/admin/users/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    return f"api [admin]: update user {user_id}"


@app.route("/todo/api/admin/users/<int:user_id>/lists", methods=["GET"])
def get_user_lists(user_id):
    return f"api [admin]: get user {user_id} lists"


@app.route("/todo/api/admin/users/<int:user_id>/lists", methods=["POST"])
def create_user_list(user_id):
    return f"api [admin]: create user {user_id} list"


@app.route("/todo/api/admin/users/<int:user_id>/lists/<int:list_id>", methods=["GET"])
def get_user_list(user_id, list_id):
    return f"api [admin]: get list {list_id} of user {user_id}"


@app.route("/todo/api/admin/users/<int:user_id>/lists/<int:list_id>", methods=["PUT"])
def update_user_list(user_id, list_id):
    return f"api [admin]: update list {list_id} of user {user_id}"


@app.route(
    "/todo/api/admin/users/<int:user_id>/lists/<int:list_id>", methods=["DELETE"]
)
def delete_user_list(user_id, list_id):
    return f"api [admin]: delete list {list_id} of user {user_id}"


@app.route("/todo/api/admin/users/<int:user_id>/lists/<int:list_id>", methods=["POST"])
def create_user_list_item(user_id, list_id):
    return f"api [admin]: create item for list {list_id} of user {user_id}"


@app.route(
    "/todo/api/admin/users/<int:user_id>/lists/<int:list_id>/<int:list_item_id>",
    methods=["PUT"],
)
def update_user_list_item(user_id, list_id, list_item_id):
    return f"api [admin]: update list item {list_item_id} for list {list_id} of user {user_id}"


@app.route(
    "/todo/api/admin/users/<int:user_id>/lists/<int:list_id>/<int:list_item_id>",
    methods=["DELETE"],
)
def delete_user_list_item(user_id, list_id, list_item_id):
    return f"api [admin]: delete list item {list_item_id} for list {list_id} of user {user_id}"
