from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding  # Correct import
from werkzeug.security import generate_password_hash, check_password_hash
from . import mongo
import base64

class User:
    @classmethod
    def get_user(cls, username):
        return mongo.users.find_one({"username": username})

    @classmethod
    def get_user_by_email(cls, email):
        return mongo.users.find_one({"email": email})

    @classmethod
    def create_user(cls, username, email, password, is_admin=False):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
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

        # Store the plain password in this example
        user = {
            'username': username,
            'email': email,
            'password': password,  # Plain text password
            'confirmed': False,
            'public_key': public_pem,
            'is_admin': is_admin
        }
        result = mongo.users.insert_one(user)
        user_id = result.inserted_id

        # Save private key in the new keys table
        Key.create_key(user_id, private_pem)

        return user

    @classmethod
    def get_all_users(cls):
        return list(mongo.users.find())  # Ensure the return type is a list

    @classmethod
    def delete_user(cls, username):
        return mongo.users.delete_one({"username": username})

    @classmethod
    def update_public_key(cls, user_id, public_key_pem):
        mongo.users.update_one({'_id': user_id}, {'$set': {'public_key': public_key_pem}})
        
    @classmethod
    def update_private_key(cls, user_id, private_key_pem):
        mongo.keys.update_one({'user_id': user_id}, {'$set': {'private_key': private_key_pem}}, upsert=True)

class Room:
    @classmethod
    def get_latest_rooms(cls, username):
        return mongo.rooms.find({'type': 'global'}).sort('created_at', -1).limit(5)

    @classmethod
    def get_user_rooms(cls, username):
        return mongo.rooms.find({'users': username}).sort('created_at', -1)

    @classmethod
    def get_all_rooms(cls):
        return mongo.rooms.find()

    @classmethod
    def create_room(cls, name, users=None, room_type='global'):
        room = {
            'name': name,
            'created_at': datetime.utcnow(),
            'users': users or [],
            'type': room_type
        }
        mongo.rooms.insert_one(room)
        return room

    @classmethod
    def get_room(cls, name):
        return mongo.rooms.find_one({"name": name})

    @classmethod
    def delete_room(cls, name):
        mongo.rooms.delete_one({'name': name})
        mongo.messages.delete_many({'room': name})

class Message:
    @classmethod
    def get_messages(cls, room):
        return mongo.messages.find({"room": room}).sort('timestamp', 1)

    @classmethod
    def save_message(cls, username, room, message):
        message = {
            'username': username,
            'room': room,
            'message': message,
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

class Key:
    @classmethod
    def create_key(cls, user_id, private_key_pem):
        key = {
            'user_id': user_id,
            'private_key': private_key_pem,
            'created_at': datetime.utcnow()
        }
        mongo.keys.insert_one(key)
        return key

    @classmethod
    def get_key_by_user(cls, user_id):
        return mongo.keys.find_one({"user_id": user_id})
