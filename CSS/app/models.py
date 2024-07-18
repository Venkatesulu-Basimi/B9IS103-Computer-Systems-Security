from . import mongo
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
from werkzeug.security import generate_password_hash

class Room:
    @classmethod
    def get_latest_rooms(cls):
        return mongo.rooms.find().sort('').limit(5)
    
    @classmethod
    def create_room(cls, name):
        room = {
            'name': name,
            'created_at': datetime.utcnow()
        }
    
    mongo.rooms.insert_one(room)
        return room

    @classmethod
    def delete(cls, name):
        mongo.rooms.delete_one({'name': name})
        mongo.messages.delete_many({'room': name})

class Message:
    @classmethod
    def get_by_room(cls, room):
        return mongo.messages.find({'room': room}).sort('timestamp', 1)

    @classmethod
    def save(cls, username, room, text):
        message = {
            'username': username,
            'room': room,
            'message': text,
            'timestamp': datetime.utcnow()
        }
        mongo.messages.insert_one(message)
        return message
    
   return base64.b64encode(encrypted_message).decode('utf-8')