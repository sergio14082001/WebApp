from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory,jsonify
from flask_sqlalchemy import SQLAlchemy
from openai import OpenAI
from werkzeug.security import generate_password_hash, check_password_hash
from flask import session
import time
import re
#NUEVO
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import os
import uuid
#NUEVO

app = Flask(__name__, static_folder='Static')
app.config['SECRET_KEY'] = 'Coki2410' #CONTRASEÑA DEL SERVIDOR
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://Sergio:Coki2410#@driveguardian123.mysql.database.azure.com/driveguardian'
#mysql+mysqlconnector://USUARIO:CONTRASEÑA@NOMBRE_DEL_SERVIDOR/NOMBRE_DEL_SCHEMA_DE_BASE_DE_DATOS
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

app.config['MAIL_SERVER'] = 'smtp.mailgun.org'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'postmaster@sandboxe4b0f1d7c35c4ee68998bcde18624910.mailgun.org'
#app.config['MAIL_PASSWORD'] = '9dbea7a532dd56a41dadfa1049265c81-0996409b-986655bc'
app.config['MAIL_PASSWORD'] = 'b13dd2b5cc2c8e87eeb33f4b801b9bed-0996409b-5a818de4'
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@sandboxe4b0f1d7c35c4ee68998bcde18624910.mailgun.org'


mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(252), unique=True, nullable=False)
    password_hash = db.Column(db.String(512))
    session_token = db.Column(db.String(128), nullable=True)# Aumenta la longitud aquí

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
def validar_usuario(username):
    # El nombre de usuario debe tener un máximo de 20 caracteres
    # Debe incluir letras, números y los caracteres especiales permitidos
    # No debe incluir comas, puntos, dos puntos, etc.
    if (len(username) > 20 or
        re.search(r'[,.]', username) is not None or
        re.search(r'^[\w@#$%^&+=]{1,20}$', username) is None):
        return False
    return True


def validar_contraseña(password):
    # La contraseña debe tener al menos una mayúscula, una minúscula, un dígito y un carácter especial
    # No debe comenzar con un número
    # Debe tener al menos una longitud mínima (aquí establecida en 8 caracteres)
    if (re.search(r'[A-Z]', password) is None or
        re.search(r'[a-z]', password) is None or
        re.search(r'\d', password) is None or
        re.search(r'[^A-Za-z0-9]', password) is None or
        password[0].isdigit() or
        len(password) < 8):
        return False
    return True


def validar_email(email):
    email_pattern = re.compile(r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$')
    return email_pattern.match(email)


def generate_reset_token(email):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return s.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def generate_session_token():
    return str(uuid.uuid4())


def send_reset_email(email, token):
    msg = Message('Password Reset Request',
                  sender=app.config['MAIL_DEFAULT_SENDER'],
                  recipients=[email])
    link = url_for('reset_password', token=token, _external=True)
    msg.body = f'''To reset your password, visit the following link:
{link}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route('/reset_request', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            try:
                token = generate_reset_token(user.email)
                user.reset_token = token
                user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
                db.session.commit()
                send_reset_email(user.email, token)
                flash('Un email ha sido enviado con las instrucciones para cambiar la contraseña.', 'info')
                return redirect(url_for('login'))
            except Exception as e:
                app.logger.error(f"Error enviando email: {e}")
                flash('Hubo un error al enviar email. Intentelo mas tarde.', 'danger')
        else:
            flash('Email no encontrado', 'danger')
    return render_template('reset_request.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = s.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=3600)
    except:
        flash('El link de reseteo ha expirado.', 'warning')
        return redirect(url_for('reset_request'))

    user = User.query.filter_by(email=email).first()
    if request.method == 'POST':
        password = request.form['password']

        # Validación de la contraseña
        if not validar_contraseña(password):
            flash('La contraseña debe contener al menos 1 mayúscula, 1 minúscula, 1 número, 1 carácter especial y tener al menos 8 caracteres de longitud. Además, no debe comenzar con un número.')
            return render_template('reset_password.html')

        user.password_hash = generate_password_hash(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        flash('La contraseña fue cambiada!', 'Exito')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user is None:
            flash('Usuario incorrecto')
        else:
            # Obtener los intentos fallidos y el tiempo de bloqueo de la sesión
            failed_attempts = session.get(f'{username}_failed_attempts', 0)
            lockout_until = session.get(f'{username}_lockout_until', None)

            # Comprobar si la cuenta está bloqueada
            if lockout_until and datetime.utcnow() < datetime.strptime(lockout_until, '%Y-%m-%d %H:%M:%S'):
                flash('Cuenta bloqueada por 1 minuto por muchos intentos incorrectos de contraseña.')
            elif not user.check_password(password):
                failed_attempts += 1
                if failed_attempts >= 5:
                    lockout_until = (datetime.utcnow() + timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S')
                    flash('Cuenta bloqueada por 1 minuto por muchos intentos incorrectos de contraseña.')
                    session[f'{username}_lockout_until'] = lockout_until
                else:
                    flash('Contraseña incorrecta')
                session[f'{username}_failed_attempts'] = failed_attempts
            else:
                # Restablecer los intentos fallidos y desbloquear la cuenta
                session[f'{username}_failed_attempts'] = 0
                session.pop(f'{username}_lockout_until', None)

                # Invalidar la sesión anterior si existe
                session_token = str(uuid.uuid4())
                user.session_token = session_token
                db.session.commit()
                session['username'] = user.username
                session['session_token'] = user.session_token
                return redirect(url_for('index'))

    # Para una solicitud GET o si el inicio de sesión falló, simplemente se muestra la página de inicio de sesión.
    return render_template('Login.html')
# with app.app_context():
#     db.drop_all()  # Esto eliminará todas las tablas
#     db.create_all()  # Esto volverá a crear las tablas basadas en tus modelos


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if not validar_usuario(username):
            flash('El nombre de usuario debe tener un máximo de 20 caracteres y solo puede incluir letras, números y los siguientes caracteres especiales: @#$%^&+=. No se permiten comas, puntos, ni dos puntos.')
            return render_template('Register.html')

        if not validar_email(email):
            flash('Por favor, ingrese un correo electrónico válido.')
            return render_template('Register.html')

        if not validar_contraseña(password):
            flash('La contraseña debe contener al menos 1 mayúscula, 1 minúscula, 1 número, 1 carácter especial y tener al menos 8 caracteres de longitud. Además, no debe comenzar con un número.')
            return render_template('Register.html')

        if password != confirm_password:
            flash('Las contraseñas no coinciden.')
            return render_template('Register.html')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('El nombre de usuario ya existe. Por favor elija otro.')
            return render_template('Register.html')

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('El correo electrónico ya existe. Por favor elija otro.')
            return render_template('Register.html')


        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registro exitoso. Ahora puedes iniciar sesión.')
        return redirect(url_for('login'))

    return render_template('Register.html')


@app.route('/index')
def index():
    if 'username' not in session or 'session_token' not in session:
        flash('Por favor, inicia sesión para acceder a esta página.')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username'], session_token=session['session_token']).first()
    if not user:
        flash('Sesión inválida o expirada.')
        return redirect(url_for('login'))

    return render_template('Index.html')


@app.route('/logout')
def logout():
    user = User.query.filter_by(username=session.get('username')).first()
    if user:
        user.session_token = None
        db.session.commit()
    session.pop('username', None)
    session.pop('session_token', None)
    flash('Has cerrado sesión exitosamente', 'success')
    return redirect(url_for('login'))


@app.route('/user', methods=['GET', 'POST'])
def user():

    if 'username' not in session:
        flash('Por favor, inicia sesión para acceder a esta página.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_user = User.query.filter_by(username=session['username']).first()

        if 'update_username' in request.form:
            new_username = request.form['new_username']
            if validar_usuario(new_username):
                existing_user = User.query.filter_by(username=new_username).first()
                if existing_user is None:
                    current_user.username = new_username
                    db.session.commit()
                    session['username'] = new_username  # Actualizar la sesión con el nuevo nombre de usuario
                    flash('Tu nombre de usuario ha sido actualizado.')
                else:
                    flash('Este nombre de usuario ya está en uso. Por favor elige otro.')
            else:
                flash('El nombre de usuario debe tener un máximo de 20 caracteres y solo puede incluir letras, números y los siguientes caracteres especiales: @#$%^&+=. No se permiten comas, puntos, ni dos puntos Asegúrate de que cumpla con los requisitos.')

        if 'update_password' in request.form:
            new_password = request.form['password']
            confirm_password = request.form['confirm_password']
            if validar_contraseña(new_password) and new_password == confirm_password:
                current_user.password_hash = generate_password_hash(new_password)
                db.session.commit()
                flash('Tu contraseña ha sido actualizada.')
            else:
                flash('La contraseña debe contener al menos 1 mayúscula, 1 minúscula, 1 número, 1 carácter especial y tener al menos 8 caracteres de longitud. Además, no debe comenzar con un número. Asegúrate de que cumpla con los requisitos.')

    return render_template('User.html')



# @app.route('/javascript/asistente.js')  # Asegúrate de capturar correctamente el nombre del archivo en la ruta
# def custom_js(filename):
#     return send_from_directory(app.static_folder + '/javascript', filename, mimetype='application/javascript')

# if __name__ == '__main__':
#     app.run()



@app.route('/execute-script', methods=['POST'])
def execute_script():
    data = request.json
    resultado = data.get('resultado_probabilidad')
    tipo_persona = data.get('tipo_persona')
    edad = data.get('edad')
    clima = data.get('clima')
    tipo_vehiculo = data.get('tipo_vehiculo')
    sexo = data.get('sexo')
    mes = data.get('mes')
    dia = data.get('dia')
    marca = data.get('marca')
    avenida_end = data.get('end')
    avenida_start = data.get('start')
    Modalidad_transporte = data.get('v1')
    etapa_dia = data.get('v2')
    zona = data.get('v3')
    perfil_via = data.get('v6')
    superficie = data.get('v7')
    content = f"""Hola. Empezemos las pruebas. Te dare un prompt y debes responder con recomendaciones para evitar los accidentes de transito.\n" + \
                "Te digo que voy a viajar de {avenida_start} hasta {avenida_end}, en Lima, Peru. Soy un {tipo_persona}, tengo {edad} de edad, el clima es {clima}, el tipo de vehiculo es {tipo_vehiculo}.\n" + \
                "El mes es {mes}, soy {sexo}, el dia es {dia}, la marca del auto es {marca}, la etapa del dia es {etapa_dia} y la superficie es {superficie}.\n" + \
                "En base a mi modelo predictivo con estas condiciones, he obtenido que la ruta tiene una probabilidad de {resultado} de sufrir un accidente de tránsito.\n" + \
                "Dame por favor recomendaciones e insights en base a estas condiciones y en base a la base de datos que tienes cargada sobre accidentes de tránsito\n" + \
                "Por favor, sigue el siguiente formato de respuesta:\n" + \
                "Recomendaciones:\n" + \
                "-recomendacion 1\n" + \
                "-recomendacion 2\n" + \
                "-recomendacion 3\n" + \
                "\n" + \
                "Insights para apoyar las recomendaciones:\n" + \
                "-Insight 1\n" + \
                "-Insight 2\n" + \
                "-Insight 3"""
    
    client = OpenAI(api_key='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')
    assistant = client.beta.assistants.retrieve("asst_VcBam9unSdunyrRIj0K3SLDS")
    thread = client.beta.threads.retrieve("thread_mTiWvCPuZu0ODFKf2cLPnbsl")
    message = client.beta.threads.messages.create(
        thread_id=thread.id,
        role="user",
        content = content
    )
    run = client.beta.threads.runs.create(
        thread_id=thread.id,
        assistant_id=assistant.id,
        instructions="Please address the user as User. The user has a premium account.",
    )
    # Polling hasta que el estado cambie a 'completed'
    while run.status != "completed":
        time.sleep(10)  # Espera 10 segundos antes de la próxima verificación
        run = client.beta.threads.runs.retrieve(run_id=run.id, thread_id=thread.id)
        run_status = run.status
        print(f"Run status: {run_status}")
    if run.status == "completed":
        # Procesar la respuesta
        messages = client.beta.threads.messages.list(thread_id=thread.id)
        print("messages: ")
        first_message = messages.data[0] if messages.data else None
        if first_message and first_message.content[0].type == "text":
            print({"role": first_message.role, "message": first_message.content[0].text.value})
            output = {"role": first_message.role, "message": first_message.content[0].text.value}
        return jsonify(output)
    
    return jsonify({"error": "Run no completado"})


@app.route('/eliminar_cuenta', methods=['POST'])
def eliminar_cuenta():
    if 'username' not in session:
        return jsonify({'message': 'Debes iniciar sesión para eliminar tu cuenta.', 'redirect': url_for('login')}), 403

    user = User.query.filter_by(username=session['username']).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        session.pop('username', None)  # Cierra la sesión del usuario
        return jsonify({'message': 'Tu cuenta ha sido eliminada exitosamente.', 'redirect': url_for('login')}), 200
    else:
        return jsonify({'message': 'No se encontró el usuario.', 'redirect': url_for('user_settings')}), 404



class Historial(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    avenida_inicio = db.Column(db.String(50))
    avenida_fin = db.Column(db.String(50))
    porcentaje_prediccion = db.Column(db.String(10))
    fecha_hora = db.Column(db.DateTime, default=db.func.now())


@app.route('/guardar_historial', methods=['POST'])
def guardar_historial():
    if 'username' not in session:
        return jsonify({"status": "error", "message": "No hay sesión iniciada"}), 403
    
    data = request.json
    username = session['username']  # Usa 'USERNAME' para identificar al usuario
    
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"status": "error", "message": "Usuario no encontrado"}), 404
    
    nuevo_historial = Historial(
        user_id=user.id,
        avenida_inicio=data['avenida_inicio'],
        avenida_fin=data['avenida_fin'],
        porcentaje_prediccion=data['porcentaje_prediccion']
    )
    db.session.add(nuevo_historial)
    db.session.commit()
    
    return jsonify({"status": "ok"})



@app.route('/historial', methods=['GET'])
def obtener_historial():
    if 'username' not in session:
        flash("Debes iniciar sesión para ver el historial", "error")
        return redirect(url_for('login'))
    
    username = session['username']
    user = User.query.filter_by(username=username).first()
    if not user:
        flash("Usuario no encontrado", "error")
        return redirect(url_for('login'))
    
    historial = Historial.query.filter_by(user_id=user.id).all()
    return render_template('Historial.html', historial=historial)

@app.route('/feedback')
def feedback():
    return render_template('Feedback.html')  # Asegúrate de tener la página creada

@app.route('/dashboard', methods=['GET'])
def dashboard():
    return render_template('Dashboard.html')

# with app.app_context():
#     db.drop_all()  # Esto eliminará todas las tablas
#     db.create_all()  # Esto volverá a crear las tablas basadas en tus modelos

# def create_tables():
#     with app.app_context():
#         # Verifica si las tablas ya existen
#         if not db.engine.dialect.has_table(db.engine, 'user') and not db.engine.dialect.has_table(db.engine, 'historial'):
#             db.create_all()
#             print("Tablas creadas")
#         else:
#             print("Las tablas ya existen")



if __name__ == '__main__':
    # create_tables()
    app.run(debug=False)
