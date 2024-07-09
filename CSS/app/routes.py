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

@main.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('main.index'))
