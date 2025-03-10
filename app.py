# Custom extension for IBM Watson Assistant which provides a
# REST API around a single database table 
#
# The code demonstrates how a simple REST API can be developed and
# then deployed as serverless app to IBM Cloud Code Engine.
#


import os
import ast
from dotenv import load_dotenv
from apiflask import APIFlask, Schema, HTTPTokenAuth, PaginationSchema, pagination_builder, abort
from apiflask.fields import Integer, String, Boolean, Date, List, Nested
from apiflask.validators import Length, Range
# Database access using SQLAlchemy
from flask_sqlalchemy import SQLAlchemy
from flask import abort, request, jsonify, url_for
import html
from datetime import datetime
from sqlalchemy import text, func
from sqlalchemy.sql import union_all
from werkzeug.security import generate_password_hash, check_password_hash


# Set how this API should be titled and the current version
API_TITLE='Events API for Watson Assistant'
API_VERSION='1.0.1'

# create the app
app = APIFlask(__name__, title=API_TITLE, version=API_VERSION)

# load .env if present
load_dotenv()

# the secret API key, plus we need a username in that record
API_TOKEN="{{'{0}':'appuser'}}".format(os.getenv('API_TOKEN'))
#convert to dict:
tokens=ast.literal_eval(API_TOKEN)

# database URI
DB2_URI=os.getenv('DB2_URI')
# optional table arguments, e.g., to set another table schema
ENV_TABLE_ARGS=os.getenv('TABLE_ARGS')
TABLE_ARGS=None
if ENV_TABLE_ARGS:
    TABLE_ARGS=ast.literal_eval(ENV_TABLE_ARGS)


# specify a generic SERVERS scheme for OpenAPI to allow both local testing
# and deployment on Code Engine with configuration within Watson Assistant
app.config['SERVERS'] = [
    {
        'description': 'Code Engine deployment',
        'url': 'https://{appname}.{projectid}.{region}.codeengine.appdomain.cloud',
        'variables':
        {
            "appname":
            {
                "default": "myapp",
                "description": "application name"
            },
            "projectid":
            {
                "default": "projectid",
                "description": "the Code Engine project ID"
            },
            "region":
            {
                "default": "us-south",
                "description": "the deployment region, e.g., us-south"
            }
        }
    },
    {
        'description': 'local test',
        'url': 'http://127.0.0.1:{port}',
        'variables':
        {
            'port':
            {
                'default': "5000",
                'description': 'local port to use'
            }
        }
    }
]


# set how we want the authentication API key to be passed
auth=HTTPTokenAuth(scheme='ApiKey', header='API_TOKEN')

# configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI']=DB2_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Initialize SQLAlchemy for our database
db = SQLAlchemy(app)


# sample records to be inserted after table recreation
sample_users=[
    {
        "name":"Patrick Dlamini",
        "surname":"Dlamini",
        "email":"PD@gmail.com",
        "password":"Password",
        "cellnumber": "0609805147",
        "preferences":"Educational and Economic Support,Health and Well-being Support,Orphans' and Vulnerable Individuals Support,Infrastructure and Basic Needs Support",
        
    },
  

]


# Schema for table "users"
# Set default schema to "users"
class UserModel(db.Model):

    __tablename__ = 'USERS'
    __table_args__ = TABLE_ARGS
    id = db.Column('ID',db.Integer, primary_key=True)
    name = db.Column('NAME',db.String(32))
    surname = db.Column('SURNAME',db.String(32))
    email = db.Column('EMAIL',db.String(50))
    password = db.Column('PASSWORD',db.String(250))
    cellnumber = db.Column('CELLNUMBER', db.String(50))
    preferences = db.Column('PREFERENCES', db.String(1000))
    
# Input schema for user update (similar to UserInSchema but without required fields)
class UserUpdateSchema(Schema):
    name = String()
    surname = String()
    email = String()
    password = String()
    cellnumber = String()
    preferences = String()
    

# the Python output for Certifications
class UserOutSchema(Schema):
    name = String()
    surname = String()
    email = String()
    password =String()
    cellnumber = String()
    preferences = String()
   
    
   

# the Python input for Certifications
class UserInSchema(Schema):
    name = String(required=True)
    surname = String(required=True)
    email = String(required=True)
    password =String(required=True)
    cellnumber = String(required=True)
    preferences = String(required=True)


# Input schema for login
class LoginSchema(Schema):
    email = String(required=True)
    password = String(required=True)
    

# register a callback to verify the token
@auth.verify_token  
def verify_token(token):
    if token in tokens:
        return tokens[token]
    else:
        return None

# User login endpoint
@app.post('/userLogin')
@app.input(LoginSchema, location='json')
@app.output(UserOutSchema)
@app.auth_required(auth)
def user_login(data):
    """User Login
    Authenticate user with email and password
    """
    user = UserModel.query.filter(UserModel.email == data['email']).first()
    
    if not user or not check_password_hash(user.password, data['password']):
        abort(401, message='Invalid email or password')
    
    return user
# Update a user's details
@app.patch('/userupdate/<string:email>')
@app.input(UserUpdateSchema, location='json')
@app.output(UserOutSchema)
@app.auth_required(auth)
def update_user(email, data):
    """Update user details
    Update a user with the given email address with new details
    """
    # Find the user by email
    user = UserModel.query.filter(UserModel.email == email).first()
    
    if not user:
        abort(404, message='User not found')
    
    # Update the user fields that were provided
    if 'name' in data and data['name']:
        user.name = data['name']
    if 'surname' in data and data['surname']:
        user.surname = data['surname']
    if 'email' in data and data['email']:
        # Check if the new email already exists (if email is being changed)
        if data['email'] != email:
            existing_user = UserModel.query.filter(UserModel.email == data['email']).first()
            if existing_user:
                abort(409, message='User with this email already exists')
        user.email = data['email']
    if 'password' in data and data['password']:
        user.password = generate_password_hash(data['password'])
    if 'cellnumber' in data and data['cellnumber']:
        user.cellnumber = data['cellnumber']
    if 'preferences' in data and data['preferences']:
        user.preferences = data['preferences']
    
    # Commit the changes to the database
    db.session.commit()
    
    return user

# Get user by email
@app.get('/users/<string:email>')
@app.output(UserOutSchema)
@app.auth_required(auth)
def get_user_by_email(email):
    """Get user by email
    Retrieve user record with the specified email
    """
    user = UserModel.query.filter(UserModel.email == email).first()
    
    if not user:
        abort(404, message='User not found')
    
    return user

# Create a new user
@app.post('/users')
@app.input(UserInSchema, location='json')
@app.output(UserOutSchema, 201)
@app.auth_required(auth)
def create_user(data):
    """Insert a new user
    Insert a new user with the given attributes. Its new ID is returned.
    """
    # Check if user already exists
    existing_user = UserModel.query.filter(UserModel.email == data['email']).first()
    if existing_user:
        abort(409, message='User with this email already exists')
    
    # Hash the password before storing
    hashed_password = generate_password_hash(data['password'])
    
    # Create new user with hashed password
    user_data = {
        'name': data['name'],
        'surname': data['surname'],
        'email': data['email'],
        'password': hashed_password,
        'cellnumber': data['cellnumber'],
        'preferences': data['preferences']
    }
    
    user = UserModel(**user_data)
    db.session.add(user)
    db.session.commit()
    return user




# (re-)create the users table with sample records
@app.post('/database/recreate')
@app.input({'confirmation': Boolean(load_default=False)}, location='query')
@app.auth_required(auth)
def create_database(query):
    """Recreate the database schema
    Recreate the database schema and insert sample data.
    Request must be confirmed by passing query parameter.
    """
    if query['confirmation'] is True:
        db.drop_all()
        db.create_all()
        for user_data in sample_users:
            # Hash the password before storing
            user_data['password'] = generate_password_hash(user_data['password'])
            user = UserModel(**user_data)
            db.session.add(user)
        db.session.commit()
        return {"message": "database recreated"}
    else:
        abort(400, message='confirmation is missing',
            detail={"error":"check the API for how to confirm"})


# default "homepage", also needed for health check by Code Engine
@app.get('/')
def print_default():
    """ Greeting
    health check
    """
    # returning a dict equals to use jsonify()
    return {'message': 'This is the certifications API server'}


# Start the actual app
# Get the PORT from environment or use the default
port = os.getenv('PORT', '5000')
if __name__ == "__main__":
    app.run(host='0.0.0.0',port=int(port))
