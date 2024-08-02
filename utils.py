from flask import url_for, current_app
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
from extensions import mail
from werkzeug.security import generate_password_hash
import re

def get_serializer():
    return URLSafeTimedSerializer(current_app.config['JWT_SECRET_KEY'])

def send_reset_email(user):
    s = get_serializer()
    token = s.dumps(user.email, salt='password-reset-salt')
    reset_url = url_for('auth.reset_password', token=token, _external=True)
    
    msg = Message('Password Reset Request',
                  sender=current_app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)
    
    print(f'Password reset link: {reset_url}')  # For demonstration purposes
    return reset_url

def validate_password(password):
    """
    Validate the password strength.
    Returns True if the password is strong enough, False otherwise.
    """
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    return True

def hash_password(password):
    """
    Hash a password for storing.
    """
    return generate_password_hash(password)

def validate_email(email):
    """
    Validate email format.
    Returns True if the email is valid, False otherwise.
    """
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def generate_username(first_name, last_name):
    """
    Generate a username based on first name and last name.
    """
    username = f"{first_name.lower()}.{last_name.lower()}"
    return username

def sanitize_input(input_string):
    """
    Sanitize input to prevent XSS attacks.
    """
    return re.sub(r'[<>]', '', input_string)

def is_valid_uuid(uuid_string):
    """
    Check if a string is a valid UUID.
    """
    pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    return re.match(pattern, uuid_string.lower()) is not None

def format_date(date):
    """
    Format a date object to a string.
    """
    return date.strftime("%Y-%m-%d %H:%M:%S")

def parse_date(date_string):
    """
    Parse a date string to a date object.
    """
    from datetime import datetime
    return datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")

def get_pagination_params(request):
    """
    Get pagination parameters from request args.
    """
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    return page, per_page