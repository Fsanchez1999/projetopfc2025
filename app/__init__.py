from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate

import os

load_dotenv()

db = SQLAlchemy()
bcrypt = Bcrypt()
migrate = Migrate()

def create_app():
    app = Flask(__name__, static_folder='static')

    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:%40Password123@localhost/pisos_db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'sua_chave_secreta_aqui')

    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)

    from .models import User

    jwt = JWTManager(app)

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.get(int(identity))

    from .routes import bp as routes_bp
    app.register_blueprint(routes_bp, url_prefix='/')

    @app.route('/')
    def index():
        return render_template('index.html')

    print("Blueprint registrado")

    return app