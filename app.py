from flask import Flask, render_template
import flask
import os
from sqlalchemy import func
from flask_cors import CORS
from decimal import Decimal
from werkzeug.security import check_password_hash, generate_password_hash
import json
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import datetime

env = os.environ.get


class Config:
    LOCALE = env("AMPLIFY_LOCALE", 'en_US.utf8')
    SECRET_KEY = env("AMPLIFY_SECRET_KEY",
                     "\xa9\x01\xd2\xc7\x97U\xe7ijo\x1c\xc8\xd8'\x9b-\xf3\xad\x02\x8e\xd2\x16\xc4u\xbfN+')\xfb\x8e\x9a")
    SQLALCHEMY_DATABASE_URI = env(
        "AMPLIFY_SQL_ALCHEMY_DATABASE_URI", "mysql://<user>:<password>@localhost/<db>")
    DEBUG = (env("AMPLIFY_DEBUG", 'True') == 'True')
    BASE_URL = env("AMPLIFY_BASE_URL", "https://amplify.com")
    DEBUG_EMAIL_SEND = (env("AMPLIFY_DEBUG_EMAIL_SEND", 'True') == 'True')
    TEST_EMAIL_ID = env("AMPLIFY_TEST_EMAIL_ID", "abhishekkulkarni706@gmail.com")


class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o)
        return super(DecimalEncoder, self).default(o)

app = Flask(__name__)

app.json_encoder = DecimalEncoder

# app.config.from_pyfile('config.py')

app.config.from_object(Config())

db = SQLAlchemy(app)

db.init_app(app)

cors = CORS(app, allow_headers=[
    "Content-Type", "Authorization", "Access-Control-Allow-Credentials", "withCredentials"],
            supports_credentials=True, resources={r"/*": {"origins": "*"}})


@app.route("/login", methods=["POST"])
def login():
    from models import User
    import datetime
    from sqlalchemy import or_

    if flask.request.method == "POST" and "username" in flask.request.json["post_data"] and "password" in flask.request.json["post_data"]:
        users = db.session.query(User).filter(or_(func.lower(flask.request.json["post_data"]["username"]) == func.lower(User.email), func.lower(flask.request.json["post_data"]["username"]) == func.lower(User.username))).all()
        if len(users) != 0:
            user = users[0]
            if check_password_hash(user.password, flask.request.json["post_data"]["password"]):
                flask.session["user_id"] = user.id
                flask.session["email"] = user.email
                flask.session["first_name"] = user.first_name
                flask.session["last_name"] = user.last_name
                flask.session["username"] = user.username
                flask.session["last_login"] = user.last_login

                temp_dict = dict()
                temp_dict["userId"] = user.id
                temp_dict["userEmail"] = user.email
                temp_dict["userName"] = user.username
                temp_dict["firstName"] = user.first_name
                temp_dict["lastName"] = user.last_name
                temp_dict["last_login"] = str(user.last_login)

                user.last_login = datetime.datetime.now()
                db.session.add(user)
                db.session.commit()

                return flask.jsonify(ok=True, user_data=temp_dict)
            else:
                return flask.jsonify(ok=False, error="No such user or incorrect password")
        else:
            return flask.jsonify(ok=False, error="No such user or incorrect password")
    return flask.jsonify(ok=False, error='')


@app.route("/login_fb_google_sso", methods=["POST"])
def login_fb_google_sso():
    from models import User
    import datetime

    if flask.request.method == "POST" and "email" in flask.request.json["post_data"]:
        user = db.session.query(User).filter(flask.request.json["post_data"]["email"] == User.email, User.provider == flask.request.json["post_data"]["provider"]).first()
        if user:
            flask.session["user_id"] = user.id
            flask.session["email"] = user.email
            flask.session["first_name"] = user.first_name
            flask.session["last_name"] = user.last_name
            flask.session["username"] = user.username
            flask.session["last_login"] = user.last_login

            temp_dict = dict()
            temp_dict["userId"] = user.id
            temp_dict["userEmail"] = user.email
            temp_dict["userName"] = user.username
            temp_dict["firstName"] = user.first_name
            temp_dict["lastName"] = user.last_name
            temp_dict["last_login"] = str(user.last_login)

            user.last_login = datetime.datetime.now()
            db.session.add(user)
            db.session.commit()

            return flask.jsonify(ok=True, user_data=temp_dict)
        else:
            return flask.jsonify(ok=False, error="No such user found")



@app.route("/get_authenticated_user_information")
def get_authenticated_user_information():
    import datetime
    if "user_id" in flask.session and flask.session["user_id"]:
        from models import User
        user = db.session.query(User).get(flask.session["user_id"])

        temp_dict = dict()
        temp_dict["userId"] = user.id
        temp_dict["userEmail"] = user.email
        temp_dict["userName"] = user.username
        temp_dict["firstName"] = user.first_name
        temp_dict["lastName"] = user.last_name
        temp_dict["appThemeColor"] = json.loads(user.extra_data)["app_theme_color"]

        flask.session["first_name"] = user.first_name
        flask.session["last_name"] = user.last_name
        flask.session["user_id"] = user.id
        flask.session["email"] = user.email
        flask.session["username"] = user.username
        db.session.add(user)
        db.session.commit()
        return flask.jsonify(ok=True, user_data=temp_dict, is_logged_in=True)
    else:
        return flask.jsonify(ok=False,is_logged_in=False)


@app.route("/validate_email", methods=["POST"])
def validate_email():
    from models import User

    email = flask.request.json.get("email", "")

    user = db.session.query(User).filter(User.email == email).first()
    if user:
        return flask.jsonify(ok=True)
    else:
        return flask.jsonify(ok=False)

@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    from models import User

    email = flask.request.json.get("email", "")
    password = flask.request.json.get("password", "")
    user = db.session.query(User).filter(User.email == email).first()
    user.password = generate_password_hash(password, salt_length=8)

    db.session.add(user)
    db.session.commit()

    return flask.jsonify(ok=True)

@app.route("/validate_password", methods=["POST"])
def validate_password():
    from models import User

    user = User.query.get(flask.session["user_id"])
    if check_password_hash(user.password, flask.request.json.get("current_password","")):
        return flask.jsonify(ok=True)
    else:
        return flask.jsonify(ok=False)

@app.route("/change_password", methods=["POST"])
def change_password():
    from models import User

    user = User.query.get(flask.session["user_id"])
    if user:
        user.password = generate_password_hash(flask.request.json.get("password",""), salt_length=8)
        db.session.add(user)
        db.session.commit()
        return flask.jsonify(ok=True)
    else:
        return flask.jsonify(ok=False)


@app.route("/logout", methods= ["GET"])
def logout():
    from flask import session

    if "user_id" in flask.session:
        session.clear()
    return flask.jsonify(ok=True)


@app.route("/clear_session/", methods=["GET"])
def clear_session():
    from flask import session

    if "user_id" in flask.session:
        session.clear()

    return flask.jsonify(ok=True)

# User Management Views
@app.route('/usermanagement_data', methods=['GET'])
def usermanagement_data():
    from models import User
    from app import db

    user=[k.to_dict() for k in db.session.query(User).all()]

    return flask.jsonify(ok=True, users=user)


@app.route('/add_user', methods=['POST'])
def add_user():
    from app import db
    from models import User
    import json
    import uuid
    
    post_data = flask.request.json.get('post_data', '')
    validate_email = db.session.query(User).filter(User.email == post_data.get('email', '')).all()
    if len(validate_email) > 0:
        if 'sso' in post_data and post_data['sso']:
            return flask.jsonify(ok=False, error="An Account already exists with this email, you can sign in !")
        else:
            return flask.jsonify(ok=False, error="Email already Exists, please try with a different email !")
    else:
        user = User()
        user.id = str(uuid.uuid4())
        user.password = generate_password_hash(post_data.get('password', ''), salt_length=8)
        user.created_on = datetime.datetime.now()
        user.first_name = post_data.get('first_name', '')
        user.last_name = post_data.get('last_name', '')
        user.username = post_data.get('username', '')
        user.email = post_data.get('email', '')
        user.gender = post_data.get('gender', '')
        user.country = post_data.get('country', '')
        user.sso = post_data.get('sso', False)
        user.provider = post_data.get('provider', '')
        user.profile_picture = post_data.get('profile_picture', '')
        extra_data = {"app_theme_color":"#0097A7"}
        user.extra_data = json.dumps(extra_data)
        db.session.add(user)
        db.session.commit()
        return flask.jsonify(ok=True)

@app.route('/edit_user', methods=['POST'])
def edit_user():
    from app import db
    from models import User
    import json
    
    post_data = flask.request.json.get('post_data', '')
    validate_email = db.session.query(User).filter(User.email == post_data.get('email', '')).all()
    if len(validate_email) > 0:
        return flask.jsonify(ok=False, error="Email already Exists, please try with a different email !")
    user = User.query.get(post_data.get('id', ''))
    user.first_name = post_data.get('first_name', '')
    user.last_name = post_data.get('last_name', '')
    user.username = post_data.get('username', '')
    user.email = post_data.get('email', '')
    user.country = post_data.get('country', '')
    user.gender = post_data.get('gender', '')
    user.profile_picture = post_data.get('profile_picture', '')
    app_theme_color = post_data.get('app_theme_color', '')
    extra_data = {"app_theme_color": app_theme_color}
    user.extra_data = json.dumps(extra_data)
    db.session.add(user)
    db.session.commit()
    return flask.jsonify(ok=True)

@app.route('/delete_user/<int:user_id>',methods=['DELETE'])
def delete_user(user_id):
    from models import User, Todo
    from app import db

    user=User.query.get(user_id)
    todos = db.session.query(Todo).filter(Todo.user_id == user_id).all()
    for todo in todos:
        db.session.delete(todo)
    db.session.delete(user)
    db.session.commit()
    return flask.jsonify(ok=True)


@app.route("/get_user_data/<string:user_id>", methods=["GET"])
def get_user_data(user_id):
    from app import db
    from models import User
    
    user_data = db.session.query(User).get(user_id)
    if user_data:
        user_data = user_data.to_dict()
        return flask.jsonify(ok=True, user_data=user_data)
    else:
        return flask.jsonify(ok=False)

# Todo Views
@app.route('/get_all_todo_data', methods=['GET'])
def get_all_todo_data():
    from models import Todo
    from app import db

    todos=[k.to_dict() for k in db.session.query(Todo).filter(Todo.user_id == flask.session["user_id"]).all()]
    for todo_obj in todos:
        todo_obj["check"] = False

    return flask.jsonify(ok=True, todos=todos)


@app.route('/add_todo', methods=['POST'])
def add_todo():
    from app import db
    from models import Todo, User
    import uuid

    post_data = flask.request.json.get('post_data', '')

    todo = Todo()
    todo.id = str(uuid.uuid4())
    todo.title = post_data.get('title', '')
    todo.user_id = flask.session["user_id"]
    todo.created_on = datetime.datetime.now()
    todo.status = post_data.get('status', False)
    todo.content = post_data.get('content', '')
    todo.alarm_time = post_data.get('alarm_time', None)

    db.session.add(todo)
    db.session.commit()

    return flask.jsonify(ok=True)

@app.route('/edit_todo', methods=['PUT'])
def edit_todo():
    from app import db
    from models import User, Todo
    import json
    
    post_data = flask.request.json.get('post_data', '')

    todo = db.session.query(Todo).get(post_data.get('id', ''))
    todo.title = post_data.get('title', '')
    todo.content = post_data.get('content', '')
    todo.alarm_time = post_data.get('alarm_time', '')
    todo.status = post_data.get('status', False)

    db.session.add(todo)
    db.session.commit()

    return flask.jsonify(ok=True)

@app.route('/delete_todo/<string:todo_id>',methods=['DELETE'])
def delete_todo(todo_id):
    from models import Todo, User
    from app import db

    todo=db.session.query(Todo).get(todo_id)
    db.session.delete(todo)
    db.session.commit()

    return flask.jsonify(ok=True)


@app.route('/delete_selected_todos',methods=['POST'])
def delete_selected_todos():
    from models import Todo, User
    from app import db

    selected_todos = flask.request.json.get('selected_todos', '')
    todo_data = db.session.query(Todo).filter(Todo.id.in_(selected_todos)).all()
    for todo_obj in todo_data:
        db.session.delete(todo_obj)
    db.session.commit()

    return flask.jsonify(ok=True)


@app.route("/get_todo_data/<string:todo_id>", methods=["GET"])
def get_todo_data(todo_id):
    from app import db
    from models import Todo
    
    todo_data = db.session.query(Todo).get(todo_id)
    if todo_data:
        todo_data = todo_data.to_dict()
        return flask.jsonify(ok=True, todo_data=todo_data)
    else:
        return flask.jsonify(ok=False)


if __name__ == '__main__':
    app.run()
