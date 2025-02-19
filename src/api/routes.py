"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)



@api.route('/user', methods=['GET'])
def handle_hello():

    response_body = {
        "msg": "Hello, this is your GET /user response "
    }

    return jsonify(response_body), 200

@api.route('/signup', methods=['POST'])
def signup():
    try:
        request_body=request.json
        user = db.session.execute(db.select(User).filter_by(email=request_body["email"])).scalar_one()
        return jsonify({"msg":"user exist"}), 401
    except:
        user = User(email=request_body["email"], password=request_body["password"],is_active=request_body["is_active"])
        db.session.add(user)
        db.session.commit()
        return jsonify({"msg":"created"}), 201

@api.route("/login", methods=["POST"])
def login():

    email = request.json.get("email", None)
    password = request.json.get("password", None)

    user = db.session.execute(db.select(User).filter_by(email=email)).scalar_one()
    if email != user.email or password != user.password:
        return jsonify({"msg": "Bad email or password"}), 401
    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token)


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@api.route("/favorites", methods=["GET"])
@jwt_required()
def favorites():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200