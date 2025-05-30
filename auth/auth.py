from flask import Blueprint, request, jsonify, current_app
from models import db, User
import bcrypt
import jwt
import random
import string
from datetime import datetime, timedelta
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
from functools import wraps

def decode_base64(password_b64):
    try:
        decoded = base64.b64decode(password_b64).decode('utf-8')
        return decoded
    except Exception as e:
        print("Error al decodificar:", e)
        return None

auth_bp = Blueprint('auth', __name__)

# Configuración CORS
@auth_bp.after_request 
def after_request(response):
    header = response.headers
    header['Access-Control-Allow-Origin'] = '*'
    header['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    header['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, OPTIONS'
    return response

# Decorador para verificar token JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split()[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Método para generar token de verificación
def generar_token():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=5))

# ============ ENDPOINTS DE AUTENTICACIÓN ============

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data['email'].lower()
    name = data['name']
    password = data['password']
    phone = data.get('phone', "")
    profile_img = data.get('profile_img', "")
    apps = data.get('apps', "")

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email ya registrado'}), 400

    hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    token = generar_token()

    nuevo = User(
        email=email,
        name=name,
        password=hash_password,
        phone=phone,
        profile_img=profile_img,
        apps=apps,
        token=token,
        validated=False
    )
    
    db.session.add(nuevo)
    db.session.commit()

    # Configuración de correo
    MAIL_HOST = os.getenv('MAIL_HOST')
    MAIL_PORT = int(os.getenv('MAIL_PORT'))
    MAIL_SECURE = os.getenv('MAIL_SECURE', 'false').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_SEND = os.getenv('MAIL_SEND')
    BASE_URL = os.getenv('BASE_URL')
    VALIDATION_PATH = os.getenv('VALIDATION_PATH', '/validacion')

    # Configurar email
    destinatario = email
    asunto = 'Verifica tu correo - The Original Lab'
    cuerpo = f'Por favor valida tu cuenta haciendo click en el siguiente enlace: {BASE_URL}{VALIDATION_PATH}?email={email}&token={token}'

    message = MIMEMultipart()
    message['From'] = MAIL_SEND
    message['To'] = destinatario
    message['Subject'] = asunto
    message.attach(MIMEText(cuerpo, 'plain'))

    # Enviar correo
    try:
        with smtplib.SMTP(MAIL_HOST, MAIL_PORT) as servidor:
            if not MAIL_SECURE:
                servidor.starttls()
            servidor.login(MAIL_USERNAME, MAIL_PASSWORD)
            servidor.send_message(message)
        print("Correo enviado con éxito.")
    except Exception as e:
        print("Error al enviar el correo:", e)

    return jsonify({
        'message': 'Usuario registrado con éxito',
        'token_verificacion': token
    }), 201

@auth_bp.route('/validation', methods=['GET'])
def validation():
    email = request.args.get('email')
    token = request.args.get('token')

    user = User.query.filter_by(email=email, token=token).first()
    if not user:
        return jsonify({'message': 'Token inválido'}), 400

    user.validated = True
    db.session.commit()
    return jsonify({'message': 'Cuenta validada correctamente'})

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data['email']
    encoded_password = data.get("password")
    
    try:
        password = base64.b64decode(encoded_password).decode('utf-8')
    except Exception as e:
        return jsonify({"error": "Formato de contraseña inválido"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Usuario no existe'}), 404

    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'message': 'Contraseña incorrecta'}), 401

    if not user.validated:
        return jsonify({'message': 'Cuenta no validada'}), 403

    token = jwt.encode({
        'user_id': user.user_id,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, current_app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token})

# ============ ENDPOINTS CRUD GENÉRICOS ============

def get_table(table_name: str):
    tables = {
        "users": (User, "user_id"),
        # Agrega aquí otras tablas que necesites
    }
    if table_name not in tables:
        raise ValueError(f"Tabla {table_name} no encontrada")
    return tables[table_name]

@auth_bp.route('/<table_name>', methods=['POST'])
@token_required
def create_record(current_user, table_name):
    try:
        table, _ = get_table(table_name)
        data = request.json
        new_record = table(**data)
        db.session.add(new_record)
        db.session.commit()
        return jsonify({'message': 'Registro creado', 'id': new_record.user_id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@auth_bp.route('/<table_name>/<int:record_id>', methods=['GET'])
@token_required
def get_record(current_user, table_name, record_id):
    try:
        table, pk = get_table(table_name)
        record = table.query.filter_by(**{pk: record_id}).first()
        if not record:
            return jsonify({'error': 'Registro no encontrado'}), 404
        
        return jsonify({
            col.name: getattr(record, col.name)
            for col in record.__table__.columns
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@auth_bp.route('/<table_name>/all', methods=['GET'])
@token_required
def get_all_records(current_user, table_name):
    try:
        table, _ = get_table(table_name)
        records = table.query.all()
        return jsonify([
            {col.name: getattr(record, col.name) for col in record.__table__.columns}
            for record in records
        ])
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@auth_bp.route('/<table_name>/<int:record_id>', methods=['PUT', 'PATCH'])
@token_required
def update_record(current_user, table_name, record_id):
    try:
        table, pk = get_table(table_name)
        record = table.query.filter_by(**{pk: record_id}).first()
        if not record:
            return jsonify({'error': 'Registro no encontrado'}), 404
        
        data = request.json
        for key, value in data.items():
            setattr(record, key, value)
        
        db.session.commit()
        return jsonify({'message': 'Registro actualizado'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400

@auth_bp.route('/<table_name>/<int:record_id>', methods=['DELETE'])
@token_required
def delete_record(current_user, table_name, record_id):
    try:
        table, pk = get_table(table_name)
        record = table.query.filter_by(**{pk: record_id}).first()
        if not record:
            return jsonify({'error': 'Registro no encontrado'}), 404
        
        db.session.delete(record)
        db.session.commit()
        return jsonify({'message': 'Registro eliminado'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400
