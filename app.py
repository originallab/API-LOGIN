from flask import Flask
from models import db
from auth.auth import auth_bp
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Configuración
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('BD_LOGIN')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'secret-key-default')

# Inicialización de la base de datos
db.init_app(app)

# Registrar blueprints
app.register_blueprint(auth_bp, url_prefix='/api')

# Crear tablas al inicio
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)