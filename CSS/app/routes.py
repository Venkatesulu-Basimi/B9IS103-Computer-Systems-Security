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
