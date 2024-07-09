from flask import Blueprint, request, render_template, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash


import os
import logging
import re


@main.route('/')
def index():
    if 'username' in session:
        if session.get('is_admin'):
            return redirect(url_for('main.admin_dashboard'))
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))

<<<<<<< HEAD
@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.get_user(username)
        if not user:
            flash('User not found')
            return render_template('login.html')
=======

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
>>>>>>> 9e2d5a5c8452bcaf5498554b2c6b053e8e779154
