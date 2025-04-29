from flask import Blueprint, request, jsonify, current_app
from models import db, Usuario
import bcrypt
import jwt
import random
import string
from datetime import datetime, timedelta
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


# Estructura modular especialmente de flask, que sirve para la organizacion de las rutas de las apis.
auth_bp = Blueprint('api', __name__)


# Metodo para generar el token
def generar_token():
    """metodo para generar el token de manera aleatoria de 5 caracteres"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=5))

# metodo para hacer un registro (Primer endpoint-POST)
@auth_bp.route('/registrar', methods=['POST'])
def registrar():
     # Datos que se deben de mandar
    data = request.json
    email = data['email'].lower()
    nombre = data['nombre']
    clave = data['clave']
    telefono = data['telefono']
    foto_perfil = data['foto_perfil']
   

    # verificacion si el email ya esta registrado
    if Usuario.query.filter_by(email=email).first():
        return jsonify({'mensaje': 'Este email ya ha sido creado con anterioridad'}), 400

    # Hash de la contraseña
    hash_clave = bcrypt.hashpw(clave.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    token = generar_token()

    # Funcion para crear un nuevo usuario
    nuevo = Usuario(email=email, nombre=nombre, clave=hash_clave,  telefono=telefono,  foto_perfil=foto_perfil, token_validacion=token)
    db.session.add(nuevo)
    db.session.commit()


    MAIL_HOST = os.getenv('MAIL_HOST')
    MAIL_PORT = int(os.getenv('MAIL_PORT'))
    MAIL_SECURE = os.getenv('MAIL_SECURE', 'false').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_SEND = os.getenv('MAIL_SEND')
    BASE_URL = os.getenv('BASE_URL')

    # Configurar destinatario y mensaje
    destinatario = email
    asunto = 'Verifica tu correo - The Original Lab'
    cuerpo = 'Por favor valida tu cuenta haciendo click en el siguiente enlace: \n' + BASE_URL + '?email=' + email + '&token=' + token

    # Crear el mensaje
    mensaje = MIMEMultipart()
    mensaje['From'] = MAIL_SEND
    mensaje['To'] = destinatario
    mensaje['Subject'] = asunto
    mensaje.attach(MIMEText(cuerpo, 'plain'))

    # Enviar el correo
    try:
        servidor = smtplib.SMTP(MAIL_HOST, MAIL_PORT)
        if not MAIL_SECURE:
            servidor.starttls()
        servidor.login(MAIL_USERNAME, MAIL_PASSWORD)
        servidor.send_message(mensaje)
        servidor.quit()
        print("Correo enviado con éxito.")
    except Exception as e:
        print("Error al enviar el correo:", e)




    return jsonify({'mensaje': 'Usuario registrado con exito', 'Token': token})

#  Metodo para hacer la validacion del usuario (Primer endpoint-GET)
@auth_bp.route('/validar', methods=['GET'])
def validar():
    # Pasar parametros
    email = request.args.get('email')
    token = request.args.get('token')

    user = Usuario.query.filter_by(email=email, token_validacion=token).first()
    if not user:
        return jsonify({'mensaje': 'Token inválido'}), 400

    user.validado = True
    db.session.commit()
    return jsonify({'mensaje': 'Cuenta validada correctamente'})

# Metodo para hacer el login del usuario (Primer endpoint-POST)
@auth_bp.route('/login', methods=['POST'])
def login():
    # pasar los parametros
    data = request.json
    email = data['email']
    clave = data['clave']

    # Verificacion de usuario
    user = Usuario.query.filter_by(email=email).first()
    if not user:
        return jsonify({'mensaje': 'Usuario no existe'}), 404

    # Verificacion de contraseña
    if not bcrypt.checkpw(clave.encode('utf-8'), user.clave.encode('utf-8')):
        return jsonify({'mensaje': 'Contraseña incorrecta'}), 401

    # Verificacion de validacion
    if not user.validado:
        return jsonify({'mensaje': 'Cuenta no validada'}), 403

    # Esta parte sirve para ir monitoriando la expiracion del token, en este caso de 1 hr
    payload = {
        'id_usuario': user.id_usuario,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }

    token_jwt = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token_jwt})
