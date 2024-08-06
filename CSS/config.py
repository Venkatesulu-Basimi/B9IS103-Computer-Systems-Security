import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'thisisthesecretkey')
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb+srv://20025270:20025270@cluster0.6qbv5lm.mongodb.net/cs?retryWrites=true&w=majority&appName=Cluster0')