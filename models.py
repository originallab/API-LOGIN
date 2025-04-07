from flask_sqlalchemy import SQLAlchemy

# instanciar la base de datos
db = SQLAlchemy()

# Se define el modelo de la tabla en la base de datos que se usara
class Usuario(db.Model):
    id_usuario = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120),  nullable=False)
    nombre = db.Column(db.String(120), nullable=False)
    clave = db.Column(db.String(120), nullable=False)
    token_validacion = db.Column(db.String(120))
    validado = db.Column(db.Boolean, default=False)
