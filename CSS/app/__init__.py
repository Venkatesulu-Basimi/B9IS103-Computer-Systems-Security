from flask import Flask
from flask_socketio import SocketIO
from flask_mail import Mail
from pymongo import MongoClient
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash

load_dotenv()

socketio = SocketIO()
mail = Mail()
mongo = None

def create_default_admin():
    from .models import User
    admin_username = 'admin'
    admin_email = 'admin@securechat.com'
    admin_password = '1234'

    if not User.get_user(admin_username):
        hashed_password = generate_password_hash(admin_password, method='pbkdf2:sha256')
        User.create_user(admin_username, admin_email, hashed_password, is_admin=True)
        print("Default admin user created.")
    else:
        print("Admin user already exists.")

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS').lower() in ['true', '1', 't']
    app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL').lower() in ['true', '1', 't']

    global mongo
    mongo_uri = os.getenv('MONGO_URI')
    mongo = MongoClient(mongo_uri).get_database()

    socketio.init_app(app)
    mail.init_app(app)

    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .sockets import init_sockets
    init_sockets(socketio)

    with app.app_context():
        create_default_admin()

    return app
