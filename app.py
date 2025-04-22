from flask import Flask
from models import db
from auth.auth import auth_bp  # Importa el Blueprint de autenticación

app = Flask(__name__)

# Configuración de la aplicación
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://adminUser:adminUser@theoriginallab_bd_sistema:3306/usuarios'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secret-key'  # Clave secreta para JWT

# Inicializa la base de datos
db.init_app(app)

# Registra el Blueprint, esto sirve para hacer los ednpoints de una manera mas escalable
app.register_blueprint(auth_bp, url_prefix='/api')

# Esta funcion sirve para crear la base de datos en caso de no existir
@app.before_request
def crear_base_de_datos():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
