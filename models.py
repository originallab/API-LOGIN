from flask_sqlalchemy import SQLAlchemy

# instanciar la base de datos
db = SQLAlchemy()

# Se define el modelo de la tabla en la base de datos que se usara
class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120),  nullable=False)
    name = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(120), nullable=True)
    profile_img = db.Column(db.String(120), nullable=True)
    token = db.Column(db.String(120))
    validated = db.Column(db.Boolean, default=False)
