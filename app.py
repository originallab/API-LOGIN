from flask import Flask
from models import db
from auth.auth import auth_bp  # Importa el Blueprint de autenticación
import os
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
# Configuración de la aplicación
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('BD_LOGIN')
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


#Integracion de las nuevas funciones CRUD (METODO PARA CREAR UN REGISTRO)
def create_values(db: Session, table_name: str, data: dict):
    table, primary_key_column = get_table(table_name)  # Obtener la tabla y la clave primaria
    try:
        result = db.execute(table.insert().values(**data))
        db.commit()
        return result.lastrowid  # Devuelve el ID generado automáticamente
    except SQLAlchemyError as e:
        db.rollback()
        raise Exception(f"Database error: {e}")
    
    
#Integracion de las nuevas funciones CRUD (METODO PARA ACTUALIZAR UN REGISTRO)
def patch_values(db: Session, table_name: str, record_id: int, data: dict):
    table, primary_key_column = get_table(table_name)  # Obtener la tabla y la clave primaria
    try:
        result = db.execute(
            table.update()
            .where(getattr(table.c, primary_key_column) == record_id)
            .values(**data)
        )
        db.commit()
        return result.rowcount
    except SQLAlchemyError as e:
        db.rollback()
        raise Exception(f"Database error: {e}")
    
#Integracion de las nuevas funciones CRUD (METODO PARA ELIMINAR UN REGISTRO)
def delete_values(db: Session, table_name: str, record_id: int):
    table, primary_key_column = get_table(table_name)  # Obtener la tabla y la clave primaria
    try:
        result = db.execute(
            table.delete()
            .where(getattr(table.c, primary_key_column) == record_id)
        )
        db.commit()
        return result.rowcount
    except SQLAlchemyError as e:
        db.rollback()
        raise Exception(f"Database error: {e}")
    
#Integracion de las nuevas funciones CRUD (METODO PARA OBTENER UN REGISTRO)
def get_values(db: Session, table_name: str, record_id: int):
    table, primary_key_column = get_table(table_name)  # Obtener la tabla y la clave primaria
    try:
        result = db.execute(
            table.select()
            .where(getattr(table.c, primary_key_column) == record_id)
        )
        return result.fetchone()
    except SQLAlchemyError as e:
        raise Exception(f"Database error: {e}")