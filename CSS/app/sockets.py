from flask_socketio import join_room, leave_room, send, emit
from .models import Message, User
import logging

def init_sockets(socketio):
    @socketio.on('join')
    def handle_join(data):
        username = data['username']
        room = data['room']
        join_room(room)
        emit('status', {'msg': f'{username} has entered the room.'}, room=room)

    @socketio.on('leave')
    def handle_leave(data):
        username = data['username']
        room = data['room']
        leave_room(room)
        emit('status', {'msg': f'{username} has left the room.'}, room=room)

    @socketio.on('message')
    def handle_message(data):
        username = data['username']
        room = data['room']
        message = data['msg']
        
        try:
            # Get recipient's public key
            recipient_user = User.get_user(username)
            encrypted_message = Message.encrypt_message(recipient_user['public_key'], message)
            Message.save_message(username, room, encrypted_message)
            emit('message', {'username': username, 'msg': message}, room=room)
        except Exception as e:
            logging.error(f"Encryption failed: {str(e)}")
            emit('status', {'msg': 'Encryption failed. Message not sent.'}, room=room)

    