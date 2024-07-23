from flask import Blueprint, request, render_template, redirect, url_for, session, flash, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import re
import logging

from .models import User, Room, Message as ChatMessage, Key
from . import mail, mongo

main = Blueprint('main', __name__)
s = URLSafeTimedSerializer(os.getenv('SECRET_KEY'))

@main.route('/')
def index():
    if 'username' in session:
        if session.get('is_admin'):
            return redirect(url_for('main.admin_dashboard'))
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Log input values for debugging
        current_app.logger.debug(f"Attempting login for username: {username}")
        current_app.logger.debug(f"Input password: {password}")

        # Retrieve the user from the database
        user = User.get_user(username)
        
        if not user:
            flash('User not found')
            return render_template('login.html')
        
        # Log stored password for debugging
        stored_password = user.get('password')
        current_app.logger.debug(f"Stored password: {stored_password}")

        # Verify the password (plain text comparison)
        if stored_password != password:
            flash('Incorrect password')
            return render_template('login.html')

        # Set session variables
        session['username'] = username
        session['is_admin'] = user.get('is_admin', False)
        
        # Log session details
        current_app.logger.debug(f"User logged in: {username}, is_admin: {session.get('is_admin', False)}")
        
        # Redirect based on admin status
        if session.get('is_admin'):
            return redirect(url_for('main.admin_dashboard'))
        return redirect(url_for('main.dashboard'))
    
    return render_template('login.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validate password requirements
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', password):
            flash('Password must be at least 8 characters long and contain both letters and numbers')
            return render_template('register.html')

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match!')
            return render_template('register.html')

        # Check if username already exists
        if User.get_user(username):
            flash('Username already exists!')
            return render_template('register.html')

        # Check if email is already registered
        if User.get_user_by_email(email):
            flash('Email already registered!')
            return render_template('register.html')

        # Create the user with plain text password
        User.create_user(username, email, password)

        # Generate email confirmation link
        token = s.dumps(email, salt='email-confirm')
        link = url_for('main.confirm_email', token=token, _external=True)
        msg_body = f'Your link is {link}'
        msg = Message(subject='Confirm Email', recipients=[email], body=msg_body, sender=os.getenv('MAIL_USERNAME'))
        mail.send(msg)

        return f'An email has been sent to {email}. Please confirm your email address to complete the registration.'

    return render_template('register.html')

@main.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'

    user = User.get_user_by_email(email)
    if user:
        mongo.users.update_one({'email': email}, {'$set': {'confirmed': True}})
    return render_template('email_confirmation.html', login_url=url_for('main.login'))

@main.route('/dashboard')
def dashboard():
    if 'username' in session:
        latest_rooms = Room.get_latest_rooms(session['username'])
        user_rooms = Room.get_user_rooms(session['username'])
        users = User.get_all_users()
        users = [user for user in users if user['username'] != session['username'] and not user.get('is_admin', False)]
        return render_template('dashboard.html', username=session['username'], rooms=latest_rooms, user_rooms=user_rooms, users=users, is_admin=session.get('is_admin', False))
    return redirect(url_for('main.index'))

@main.route('/chat')
def chat():
    room = request.args.get('room')
    if 'username' in session and room:
        messages = ChatMessage.get_messages(room)
        user = User.get_user(session['username'])
        decrypted_messages = []
        for msg in messages:
            try:
                decrypted_msg = ChatMessage.decrypt_message(user['private_key'], msg['message'])
                decrypted_messages.append({
                    'username': msg['username'],
                    'message': decrypted_msg,
                    'timestamp': msg['timestamp']
                })
            except Exception as e:
                logging.error(f"Decryption failed for message {msg['message']}: {str(e)}")
                flash('Decryption failed for one or more messages.')
        return render_template('chat.html', username=session['username'], room=room, messages=decrypted_messages)
    return redirect(url_for('main.index'))

@main.route('/rooms')
def get_rooms():
    if 'username' in session:
        rooms = Room.get_latest_rooms(session['username'])
        return jsonify([room['name'] for room in rooms])
    return jsonify([]), 401

@main.route('/create_room', methods=['POST'])
def create_room():
    if 'username' in session:
        room_name = request.json.get('room_name')
        Room.create_room(room_name, room_type='global')
        return jsonify({'status': 'Room created'})
    return jsonify({'status': 'Unauthorized'}), 401

@main.route('/get_users')
def get_users():
    if 'username' in session:
        users = User.get_all_users()
        users = [user for user in users if user['username'] != session['username'] and not user.get('is_admin', False)]
        return jsonify([{'username': user['username']} for user in users])
    return jsonify([]), 401

@main.route('/initiate_chat/<username>', methods=['POST'])
def initiate_chat(username):
    if 'username' not in session:
        return redirect(url_for('main.index'))

    user_a = session['username']
    user_b = username
    room_name = f"{user_a}_{user_b}"
    existing_room = Room.get_room(room_name)

    if not existing_room:
        Room.create_room(room_name, users=[user_a, user_b], room_type='private')
    else:
        mongo.rooms.update_one({'name': room_name}, {'$addToSet': {'users': {'$each': [user_a, user_b]}}})

    # Generate new keys for both users
    key_pairs = {}
    for user in [user_a, user_b]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        key_pairs[user] = (private_pem, public_pem)

    # Email the keys to the users and store them
    for user, (private_pem, public_pem) in key_pairs.items():
        user_info = User.get_user(user)
        recipient = user_b if user == user_a else user_a
        recipient_info = User.get_user(recipient)
        recipient_public_key = key_pairs[recipient][1]

        # Save public key to the recipient's profile
        User.update_public_key(recipient_info['_id'], public_pem)

        # Email the keys
        email_body = (f"Hello {user},\n\n"
                      f"This is your private key:\n{private_pem}\n\n"
                      f"And the public key of the other user ({recipient}):\n{recipient_public_key}\n\n"
                      "Please keep this information secure.")
        msg = Message(subject='Your Encryption Keys', recipients=[user_info['email']], body=email_body, sender=os.getenv('MAIL_USERNAME'))
        mail.send(msg)

        # Save the private key in the user's profile for retrieval
        User.update_private_key(user_info['_id'], private_pem)

    return jsonify({'status': 'Chat initiated', 'room': room_name})

@main.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
    session.pop('public_key', None)  # Clear public key from session
    return redirect(url_for('main.index'))

@main.route('/admin')
def admin_dashboard():
    if 'is_admin' in session and session['is_admin']:
        users = User.get_all_users()
        users = [user for user in users if not user.get('is_admin')]
        rooms = Room.get_all_rooms()
        return render_template('admin_dashboard.html', users=users, rooms=rooms)
    flash('Access denied.')
    return redirect(url_for('main.index'))

@main.route('/admin/delete_user/<username>', methods=['POST'])
def delete_user(username):
    if 'is_admin' in session and session['is_admin']:
        User.delete_user(username)
        return redirect(url_for('main.admin_dashboard'))
    flash('Access denied.')
    return redirect(url_for('main.index'))

@main.route('/admin/delete_room/<name>', methods=['POST'])
def delete_room(name):
    if 'is_admin' in session and session['is_admin']:
        Room.delete_room(name)
        return redirect(url_for('main.admin_dashboard'))
    flash('Access denied.')
    return redirect(url_for('main.index'))

@main.route('/user_rooms')
def user_rooms():
    if 'username' in session:
        user_rooms = Room.get_user_rooms(session['username'])
        return jsonify([room['name'] for room in user_rooms])
    return jsonify([]), 401

@main.route('/get_keys/<room>', methods=['GET'])
def get_keys(room):
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user = session['username']
    room_info = Room.get_room(room)
    if room_info and user in room_info.get('users', []):
        user_info = User.get_user(user)
        # Return the public key of the other user in the room
        for u in room_info['users']:
            if u != user:
                other_user_info = User.get_user(u)
                return jsonify({'public_key': other_user_info['public_key']})

    return jsonify({'error': 'Room not found or access denied'}), 403
