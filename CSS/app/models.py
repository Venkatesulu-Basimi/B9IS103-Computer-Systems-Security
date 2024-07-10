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