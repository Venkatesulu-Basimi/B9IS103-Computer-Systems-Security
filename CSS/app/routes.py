from flask import Blueprint, request, render_template, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User, Room, Message as ChatMessage
from . import mail, mongo

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
        if not check_password_hash(user['password'], password):
            flash('Incorrect password')
            return render_template('login.html')
        session['username'] = username
        session['is_admin'] = user.get('is_admin', False)
        if session['is_admin']:
            return redirect(url_for('main.admin_dashboard'))
        return redirect(url_for('main.dashboard'))
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
<<<<<<< HEAD

@main.route('/logout')
def logout():
    session.pop('username', None)
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
