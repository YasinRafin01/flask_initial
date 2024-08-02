from flask import Flask, request, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from enum import Enum
from flasgger import Swagger, swag_from
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:p%40stgress@localhost:5433/flaskdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['MAIL_SERVER'] = 'localhost'  # Dummy server
app.config['MAIL_PORT'] = 8025  # Dummy port
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = ''
app.config['MAIL_PASSWORD'] = ''
app.config['MAIL_DEFAULT_SENDER'] = 'dummy@example.com'

db = SQLAlchemy(app)
jwt = JWTManager(app)
s = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])
mail = Mail(app)

app.config['SWAGGER'] = {
    'title': 'Your API',
    'uiversion': 3,
    'specs_route': '/swagger/',
    'security': [{"JWT": []}],
    'securityDefinitions': {
        "JWT": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\""
        }
    }
}

swagger = Swagger(app)

class Role(Enum):
    ADMIN = 'Admin'
    USER = 'User'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(1000), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.Enum(Role), nullable=False)
    create_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    update_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    active = db.Column(db.Boolean, nullable=False, default=True)

@app.route('/register', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'first_name': {'type': 'string'},
                    'last_name': {'type': 'string'},
                    'password': {'type': 'string'},
                    'email': {'type': 'string'}
                },
                'required': ['username', 'first_name', 'last_name', 'password', 'email']
            }
        }
    ],
    'responses': {
        201: {'description': 'User registered successfully'},
        400: {'description': 'Invalid input'}
    }
})
def register():
    data = request.json
    role_str = data.get('role', 'User').upper()
    if role_str not in Role.__members__:
        return jsonify({"message": "Invalid role"}), 400
    role = Role[role_str]
    hashed_password = generate_password_hash(data['password'])
    new_user = User(
        username=data['username'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        password=hashed_password,
        email=data['email'],
        role=role
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        200: {'description': 'Login successful'},
        401: {'description': 'Invalid credentials'}
    }
})
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/user', methods=['GET'])
@jwt_required()
@swag_from({
    'tags': ['User'],
    'security': [{'JWT': []}],
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'JWT token in the format: Bearer <token>'
        }
    ],
    'responses': {
        200: {
            'description': 'User profile retrieved successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'first_name': {'type': 'string'},
                    'last_name': {'type': 'string'},
                    'email': {'type': 'string'},
                    'role': {'type': 'string'},
                    'active': {'type': 'boolean'}
                }
            }
        },
        401: {'description': 'Unauthorized'}
    }
})
def get_user_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return jsonify({
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "role": user.role.value,
        "active": user.active
    }), 200

@app.route('/user', methods=['PUT'])
@jwt_required()
@swag_from({
    'tags': ['User'],
    'security': [{'JWT': []}],
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'JWT token in the format: Bearer <token>'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'first_name': {'type': 'string'},
                    'last_name': {'type': 'string'},
                    'email': {'type': 'string'}
                }
            }
        }
    ],
    'responses': {
        200: {
            'description': 'User profile updated successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        401: {'description': 'Unauthorized'},
        405: {'description': 'User not allowed to change role'}
    }
})
def update_user_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.json
    if 'role' in data:
        return jsonify({"message": "User not allowed to change role"}), 405
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.email = data.get('email', user.email)
    db.session.commit()
    return jsonify({"message": "User updated successfully"}), 200

def send_reset_email(user):
    token = s.dumps(user.email, salt='password-reset-salt')
    reset_url = url_for('reset_password', token=token, _external=True)
    print(f'Password reset link: {reset_url}') 
    return reset_url

@app.route('/forgot-password', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'id': 'ForgotPassword',
                'required': ['email'],
                'properties': {
                    'email': {'type': 'string'}
                }
            }
        }
    ],
    'responses': {
        200: {'description': 'Password reset email sent'},
        400: {'description': 'Invalid email'}
    }
})
def forgot_password():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()
    if user:
        reset_url = send_reset_email(user)
    return jsonify({"message": "If the email is registered, a password reset link has been sent.","reset_url": reset_url}), 200

@app.route('/reset-password/<token>', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'parameters': [
        {
            'name': 'token',
            'in': 'path',
            'type': 'string',
            'required': True
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'id': 'ResetPassword',
                'required': ['password'],
                'properties': {
                    'password': {'type': 'string'}
                }
            }
        }
    ],
    'responses': {
        200: {'description': 'Password reset successful'},
        400: {'description': 'Invalid or expired token'}
    }
})
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return jsonify({"message": "Invalid or expired token"}), 400

    data = request.json
    user = User.query.filter_by(email=email).first()
    if user:
        user.password = generate_password_hash(data['password'])
        db.session.commit()
        return jsonify({"message": "Password reset successful"}), 200
    return jsonify({"message": "User not found"}), 400


@app.route('/admin/users', methods=['GET'])
@jwt_required()
@swag_from({
    'tags': ['Admin'],
    'security': [{'JWT': []}],
    'responses': {
        200: {'description': 'List of all users'}
    }
})
def admin_get_users():
    current_user = User.query.get(get_jwt_identity())
    if current_user.role != Role.ADMIN:
        return jsonify({"message": "Unauthorized"}), 403
    
    users = User.query.all()
    return jsonify([{
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "active": user.active
    } for user in users]), 200

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@swag_from({
    'tags': ['Admin'],
    'security': [{'JWT': []}],
    'parameters': [
        {'name': 'user_id', 'in': 'path', 'type': 'integer', 'required': True},
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'first_name': {'type': 'string'},
                    'last_name': {'type': 'string'},
                    'email': {'type': 'string'},
                    'role': {'type': 'string'},
                    'active': {'type': 'boolean'}
                }
            }
        }
    ],
    'responses': {
        200: {'description': 'User updated successfully'},
        404: {'description': 'User not found'},
        403: {'description': 'Unauthorized'},
        400: {'description': 'Email already in use'}
    }
})
def admin_update_user(user_id):
    current_user = User.query.get(get_jwt_identity())
    if current_user.role != Role.ADMIN:
        return jsonify({"message": "Unauthorized"}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    # Ensure an admin cannot update or delete another admin
    if user.role == Role.ADMIN and current_user.id != user.id:
        return jsonify({"message": "Unauthorized to manage another admin"}), 403
    
    data = request.json
    new_email = data.get('email', user.email)
    
    # Check for unique email
    if User.query.filter_by(email=new_email).filter(User.id != user_id).first():
        return jsonify({"message": "Email already in use"}), 400
    
    user.username = data.get('username', user.username)
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.email = new_email
    user.role = Role(data.get('role', user.role.value))
    user.active = data.get('active', user.active)
    db.session.commit()
    return jsonify({"message": "Updated successfully"}), 200

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
@swag_from({
    'tags': ['Admin'],
    'security': [{'JWT': []}],
    'parameters': [
        {'name': 'user_id', 'in': 'path', 'type': 'integer', 'required': True}
    ],
    'responses': {
        200: {'description': 'User deleted successfully'},
        404: {'description': 'User not found'},
        403: {'description': 'Unauthorized'}
    }
})
def admin_delete_user(user_id):
    current_user = User.query.get(get_jwt_identity())
    if current_user.role != Role.ADMIN:
        return jsonify({"message": "Unauthorized"}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    # Ensure an admin cannot update or delete another admin
    if user.role == Role.ADMIN and current_user.id != user.id:
        return jsonify({"message": "Unauthorized to manage another admin"}), 403
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "Deleted successfully"}), 200
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)