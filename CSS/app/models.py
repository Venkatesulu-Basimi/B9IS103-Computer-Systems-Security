from . import mongo
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
from werkzeug.security import generate_password_hash

class Room:
    @classmethod
    def get_latest_rooms(cls):
        return mongo.rooms.find().sort('').limit(5)
    
    @classmethod
    def get_all_rooms(cls):
        return mongo.rooms.find()
    
    @classmethod
    def create_room(cls, name):
        room = {
            'name': name,
            'created_at': datetime.utcnow()
        }
        mongo.rooms.insert_one(room)
        return room

    @classmethod
    def delete_room(cls, name):
        mongo.rooms.delete_one({'name': name})
        mongo.messages.delete_many({'room': name})

class Message:
    @classmethod
    def get_message(cls, room):
        return mongo.messages.find({'room': room}).sort('timestamp', 1)

    @classmethod
    def save_message(cls, username, room, text):
        message = {
            'username': username,
            'email': email,
            'room': room,
            'password': password,
            'message': text,
            'timestamp': datetime.utcnow()
        }
        mongo.messages.insert_one(message)
        return message
    
    @classmethod
    def delete_messages_in_room(cls, room):
        return mongo.messages.delete_many({'room': room})
    
    @classmethod
    def encrypt_message(cls, public_key_pem, message):
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        encrypted_message = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_message).decode('utf-8')
    
    @classmethod
    def decrypt_message(cls, private_key_pem, encrypted_message):
        private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
        decrypted_message = private_key.decrypt(
            base64.b64decode(encrypted_message.encode('utf-8')),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode('utf-8')