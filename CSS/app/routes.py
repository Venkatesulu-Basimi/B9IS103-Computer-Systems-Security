from flask import Blueprint, request, render_template, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from .models import User, Room, Message as ChatMessage
from . import mail, mongo

import os
import logging
import re

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
        username = request.form['username']
        password = request.form['password']
        user = User.get_user(username)
        if not user:
            flash('User not found')
            return render_template('login.html')
        if not check_password_hash(user['password'], password):
            flash('Incorrect password')
            return render_template('login.html')
        session['username'] = username
        session['is_admin'] = user.get('is_admin', False)
        if session['is_admin']:
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

        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', password):
            flash('Password must be at least 8 characters long and contain both letters and numbers')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match!')
            return render_template('register.html')

        if User.get_user(username):
            flash('Username already exists!')
            return render_template('register.html')

        if User.get_user_by_email(email):
            flash('Email already registered!')
            return render_template('register.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        User.create_user(username, email, hashed_password)
        
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
    
@main.route('/chat')
def chat():
    room = request.args.get('room')
    if 'username' in session and room:
        messages = ChatMessage.get_messages(room)
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
                logging.error("")
                flash('')
        return render_template('chat.html', username=session['username'], room=room, messages=decrypted_messages)
    return redirect(url_for('main.index'))

@main.route('/rooms')
def get_rooms():
    rooms = Room.get_latest_rooms()
    return jsonify([room['name'] for room in rooms])

@main.route('/create_room', methods=['POST'])
def create_room():
    room_name = request.json.get('room_name')
    Room.create_room(room_name)
    return jsonify({'status': 'Room created'})

@main.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
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
