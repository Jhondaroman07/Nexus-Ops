import os
import zipfile
import logging
import importlib.util
from datetime import datetime, timedelta, time
from functools import wraps
import pytz
import io
import csv
import uuid
from flask import (Flask, render_template, request, send_file, url_for,
                   redirect, flash, Response, g, session)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                       login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# =============================================
# CONFIGURACIÓN INICIAL
# =============================================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# =============================================
# CONFIGURACIÓN DE LA APLICACIÓN
# =============================================
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '981107Jhonda*')
db_user = os.environ.get('DB_USER')
db_password = os.environ.get('DB_PASSWORD')
db_host = os.environ.get('DB_HOST')
db_name = os.environ.get('DB_NAME')

if all([db_user, db_password, db_host, db_name]):
    app.config['SQLALCHEMY_DATABASE_URI'] = \
        f"mysql+pymysql://{db_user}:{db_password}@{db_host}/{db_name}"
    app.config['SQLALCHEMY_POOL_RECYCLE'] = 280
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'database.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploaded_files')
app.config['DOWNLOAD_FOLDER'] = os.path.join(BASE_DIR, 'processed_files')
app.config['USER_DOCS_FOLDER'] = os.path.join(BASE_DIR, 'user_documents')
app.config['ALLOWED_EXTENSIONS'] = {'csv'}
app.config['ALLOWED_DOC_EXTENSIONS'] = {'pdf'}
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

# =============================================
# INICIALIZACIÓN DE EXTENSIONES
# =============================================
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicie sesión para acceder a esta página."
login_manager.login_message_category = "info"
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DOWNLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['USER_DOCS_FOLDER'], exist_ok=True)

# =============================================
# MODELOS DE BASE DE DATOS
# =============================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Agent')
    session_token = db.Column(db.String(36), default=lambda: str(uuid.uuid4()))
    nombre = db.Column(db.String(100), nullable=True)
    apellido = db.Column(db.String(100), nullable=True)
    correo_personal = db.Column(db.String(150), nullable=True)
    tipo_documento = db.Column(db.String(50), nullable=True)
    numero_documento = db.Column(db.String(50), nullable=True)
    numero_celular = db.Column(db.String(25), nullable=True)
    pais_residencia = db.Column(db.String(100), nullable=True)
    ciudad_residencia = db.Column(db.String(100), nullable=True)
    fecha_nacimiento = db.Column(db.Date, nullable=True)
    fecha_ingreso = db.Column(db.Date, nullable=True)
    estado_colaborador = db.Column(db.String(20), nullable=True, default='Activo')
    linkedin_url = db.Column(db.String(255), nullable=True)
    service = db.Column(db.String(100), nullable=True)
    lob = db.Column(db.String(100), nullable=True)
    cargo = db.Column(db.String(100), nullable=True)
    tl = db.Column(db.String(100), nullable=True)
    tm = db.Column(db.String(100), nullable=True)
    documento_identidad_file = db.Column(db.String(255), nullable=True)
    certificado_bancario_file = db.Column(db.String(255), nullable=True)
    contrato_file = db.Column(db.String(255), nullable=True)
    documento_identidad_uploaded_at = db.Column(db.DateTime, nullable=True)
    certificado_bancario_uploaded_at = db.Column(db.DateTime, nullable=True)
    contrato_uploaded_at = db.Column(db.DateTime, nullable=True)
    time_logs = db.relationship('TimeLog', backref='user', lazy=True)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class TimeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Float, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# =============================================
# FUNCIONES DE AYUDA Y DECORADORES
# =============================================
@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

def panel_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['Admin', 'SubGerente', 'Gerente']:
            flash('No tienes permiso para acceder a esta página.', 'error'); return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def editor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ['SubGerente', 'Gerente']:
            flash('No tienes permiso para realizar esta acción.', 'error'); return redirect(url_for('admin_panel'))
        return f(*args, **kwargs)
    return decorated_function

def ejecutor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'Gerente':
            flash('No tienes permiso para acceder al Ejecutor de Scripts.', 'error'); return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def gerente_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'Gerente':
            flash('Solo el Gerente puede realizar esta acción.', 'error'); return redirect(url_for('admin_panel'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/create-tables')
def create_tables():
    with app.app_context():
        db.create_all()
        user = User.query.filter_by(email="jhondavid.076@gmail.com").first()
        if user is None:
            user = User(email="jhondavid.076@gmail.com", nombre="John", apellido="Castaño", role="Gerente")
            user.set_password("981107Jhonda*")
            db.session.add(user)
            db.session.commit()
            return "Tablas y usuario Gerente creados exitosamente."
        else:
            user.role = "Gerente"
            db.session.commit()
            return "Tablas ya existen. Rol de Gerente asegurado."

@app.before_request
def check_session():
    if request.endpoint and request.endpoint not in ['login', 'create_tables', 'static']:
        if current_user.is_authenticated and session.get('user_session_token') != current_user.session_token:
            logout_user()
            flash('Tu sesión ha sido cerrada por un administrador.', 'warning')
            return redirect(url_for('login'))

# =============================================
# RUTAS
# =============================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            session['user_session_token'] = user.session_token
            return redirect(url_for('index'))
        else: flash('Correo o contraseña incorrectos.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('user_session_token', None)
    flash('Has cerrado sesión exitosamente.', 'success')
    response = redirect(url_for('login'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@panel_admin_required
def admin_panel():
    from sqlalchemy import func
    if request.method == 'POST':
        email, password, nombre, apellido, role = (request.form.get(k) for k in ['email', 'password', 'nombre', 'apellido', 'role'])
        if current_user.role == 'Admin' and role in ['Admin', 'SubGerente', 'Gerente']:
            flash('Un Admin solo puede crear roles de Agente.', 'error'); return redirect(url_for('admin_panel'))
        if current_user.role == 'SubGerente' and role in ['SubGerente', 'Gerente']:
            flash('Un SubGerente no puede crear SubGerentes ni Gerentes.', 'error'); return redirect(url_for('admin_panel'))
        if not email or not password or not nombre or not apellido: flash('El nombre, apellido, correo y contraseña son obligatorios.', 'error')
        elif User.query.filter_by(email=email).first(): flash('El correo ya está registrado.', 'error')
        else:
            new_user = User(email=email, nombre=nombre, apellido=apellido, role=role)
            new_user.set_password(password)
            db.session.add(new_user); db.session.commit()
            flash(f'Usuario {email} creado.', 'success')
        return redirect(url_for('admin_panel'))
    
    colombia_tz = pytz.timezone('America/Bogota')
    date_from_str = request.args.get('date_from', datetime.now(colombia_tz).strftime('%Y-%m-%d'))
    date_to_str = request.args.get('date_to', datetime.now(colombia_tz).strftime('%Y-%m-%d'))
    user_ids = request.args.getlist('user_ids')
    
    query = db.session.query(User.nombre, User.apellido, User.email, func.sum(TimeLog.duration).label('total_duration')).join(TimeLog)
    start_date = datetime.strptime(date_from_str, '%Y-%m-%d').date()
    end_date = datetime.strptime(date_to_str, '%Y-%m-%d').date()
    start_dt_utc = colombia_tz.localize(datetime.combine(start_date, time.min)).astimezone(pytz.utc)
    end_dt_utc = colombia_tz.localize(datetime.combine(end_date, time.max)).astimezone(pytz.utc)
    query = query.filter(TimeLog.start_time.between(start_dt_utc, end_dt_utc))
    if user_ids and 'all' not in user_ids:
        query = query.filter(TimeLog.user_id.in_([int(uid) for uid in user_ids]))
    logs_from_db = query.group_by(User.id).all()
    time_logs_formatted = [{'nombre': log.nombre, 'apellido': log.apellido, 'email': log.email,
                            'formatted_duration': str(timedelta(seconds=int(log.total_duration or 0)))}
                           for log in logs_from_db]
    active_users = User.query.join(TimeLog).filter(TimeLog.end_time == None).all()
    users_with_logs = User.query.filter(User.time_logs.any()).order_by(User.nombre).all()
    users = User.query.order_by(User.id).all()
    
    return render_template('admin.html', users=users, time_logs=time_logs_formatted, users_with_logs=users_with_logs, 
                           active_users=active_users, timedelta=timedelta,
                           filters={'date_from': date_from_str, 'date_to': date_to_str, 'user_ids': user_ids})

@app.route('/mis_datos', methods=['GET', 'POST'])
@login_required
def mis_datos():
    user_to_edit = current_user
    if request.method == 'POST':
        user_to_edit.nombre = request.form.get('nombre')
        user_to_edit.apellido = request.form.get('apellido')
        user_to_edit.correo_personal = request.form.get('correo_personal')
        user_to_edit.tipo_documento = request.form.get('tipo_documento')
        user_to_edit.numero_documento = request.form.get('numero_documento')
        user_to_edit.numero_celular = request.form.get('numero_celular')
        user_to_edit.pais_residencia = request.form.get('pais_residencia')
        user_to_edit.ciudad_residencia = request.form.get('ciudad_residencia')
        user_to_edit.linkedin_url = request.form.get('linkedin_url')
        user_to_edit.service = request.form.get('service')
        user_to_edit.lob = request.form.get('lob')
        user_to_edit.cargo = request.form.get('cargo')
        user_to_edit.tl = request.form.get('tl')
        user_to_edit.tm = request.form.get('tm')
        
        if dob_str := request.form.get('fecha_nacimiento'):
            user_to_edit.fecha_nacimiento = datetime.strptime(dob_str, '%Y-%m-%d').date()
        if doi_str := request.form.get('fecha_ingreso'):
            user_to_edit.fecha_ingreso = datetime.strptime(doi_str, '%Y-%m-%d').date()

        db.session.commit()
        flash('Tus datos han sido actualizados correctamente.', 'success')
        return redirect(url_for('mis_datos'))
        
    return render_template('mis_datos.html', user=user_to_edit)

def allowed_doc(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_DOC_EXTENSIONS']

@app.route('/upload_document/<doc_type>', methods=['POST'])
@login_required
def upload_document(doc_type):
    if 'file' not in request.files:
        flash('No se seleccionó ningún archivo.', 'error')
        return redirect(url_for('mis_datos'))
    file = request.files['file']
    if file.filename == '':
        flash('No se seleccionó ningún archivo.', 'error')
        return redirect(url_for('mis_datos'))
    if file and allowed_doc(file.filename):
        filename = f"{current_user.id}_{doc_type}_{int(datetime.now().timestamp())}.pdf"
        file_path = os.path.join(app.config['USER_DOCS_FOLDER'], filename)
        file.save(file_path)
        
        colombia_tz = pytz.timezone('America/Bogota')
        upload_time = datetime.now(colombia_tz)

        if doc_type == 'identidad':
            current_user.documento_identidad_file = filename
            current_user.documento_identidad_uploaded_at = upload_time
        elif doc_type == 'bancario':
            current_user.certificado_bancario_file = filename
            current_user.certificado_bancario_uploaded_at = upload_time
        elif doc_type == 'contrato':
            current_user.contrato_file = filename
            current_user.contrato_uploaded_at = upload_time
        
        db.session.commit()
        flash(f'Documento "{doc_type}" subido correctamente.', 'success')
    else:
        flash('Tipo de archivo no permitido. Solo se aceptan PDF.', 'error')

    return redirect(url_for('mis_datos'))

@app.route('/download_document/<int:user_id>/<doc_type>')
@login_required
@editor_required
def download_document(user_id, doc_type):
    user = User.query.get_or_404(user_id)
    filename = None
    if doc_type == 'identidad': filename = user.documento_identidad_file
    elif doc_type == 'bancario': filename = user.certificado_bancario_file
    elif doc_type == 'contrato': filename = user.contrato_file
    
    if not filename:
        flash('El usuario no ha cargado este documento.', 'error')
        return redirect(url_for('documentos'))
    
    return send_file(os.path.join(app.config['USER_DOCS_FOLDER'], filename), as_attachment=True)

@app.route('/admin/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@editor_required
def edit_user(user_id):
    user_to_edit = User.query.get_or_404(user_id)
    if current_user.role == 'SubGerente' and user_to_edit.role == 'Gerente': 
        flash('No tienes permiso para editar al usuario Gerente.', 'error'); return redirect(url_for('admin_panel'))
    
    if request.method == 'POST':
        user_to_edit.email = request.form.get('email')
        new_role = request.form.get('role')
        if current_user.role == 'SubGerente' and new_role == 'Gerente': 
            flash('No puedes asignar el rol de Gerente.', 'error'); return redirect(url_for('edit_user', user_id=user_id))
        user_to_edit.role = new_role
        if (new_password := request.form.get('password')): user_to_edit.set_password(new_password)
        
        user_to_edit.nombre = request.form.get('nombre'); user_to_edit.apellido = request.form.get('apellido')
        user_to_edit.correo_personal = request.form.get('correo_personal'); user_to_edit.tipo_documento = request.form.get('tipo_documento')
        user_to_edit.numero_documento = request.form.get('numero_documento'); user_to_edit.numero_celular = request.form.get('numero_celular')
        user_to_edit.pais_residencia = request.form.get('pais_residencia'); user_to_edit.ciudad_residencia = request.form.get('ciudad_residencia')
        user_to_edit.estado_colaborador = request.form.get('estado_colaborador'); user_to_edit.linkedin_url = request.form.get('linkedin_url')
        user_to_edit.service = request.form.get('service'); user_to_edit.lob = request.form.get('lob')
        user_to_edit.cargo = request.form.get('cargo'); user_to_edit.tl = request.form.get('tl'); user_to_edit.tm = request.form.get('tm')
        if dob_str := request.form.get('fecha_nacimiento'):
            user_to_edit.fecha_nacimiento = datetime.strptime(dob_str, '%Y-%m-%d').date()
        if doi_str := request.form.get('fecha_ingreso'):
            user_to_edit.fecha_ingreso = datetime.strptime(doi_str, '%Y-%m-%d').date()

        db.session.commit(); flash(f'Usuario {user_to_edit.email} actualizado.', 'success'); return redirect(url_for('admin_panel'))
    
    return render_template('edit_user.html', user=user_to_edit)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@gerente_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.role == 'Gerente': flash('La cuenta del Gerente no puede ser eliminada.', 'error'); return redirect(url_for('admin_panel'))
    db.session.delete(user_to_delete); db.session.commit(); flash(f'Usuario {user_to_delete.email} eliminado.', 'success'); return redirect(url_for('admin_panel'))

@app.route('/admin/force_logout/<int:user_id>', methods=['POST'])
@login_required
@panel_admin_required
def force_logout(user_id):
    user_to_logout = User.query.get_or_404(user_id)
    if current_user.role != 'Gerente' and user_to_logout.role == 'Gerente':
        flash('Solo un Gerente puede cerrar la sesión de otro Gerente.', 'error')
        return redirect(url_for('admin_panel'))
    user_to_logout.session_token = str(uuid.uuid4())
    db.session.commit()
    flash(f'La sesión de {user_to_logout.email} ha sido cerrada.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/force_end_management/<int:user_id>', methods=['POST'])
@login_required
@panel_admin_required
def force_end_management(user_id):
    user_to_affect = User.query.get_or_404(user_id)
    if current_user.role != 'Gerente' and user_to_affect.role == 'Gerente':
        flash('Solo un Gerente puede finalizar la gestión de otro Gerente.', 'error')
        return redirect(url_for('admin_panel'))
    
    active_log = TimeLog.query.filter_by(user_id=user_id, end_time=None).first()
    if active_log:
        end_time_utc = datetime.now(pytz.utc)
        start_time_utc = active_log.start_time.replace(tzinfo=pytz.utc)
        
        duration_delta = end_time_utc - start_time_utc
        active_log.end_time = end_time_utc
        active_log.duration = duration_delta.total_seconds()
        
        db.session.commit()
        flash(f'Gestión de {user_to_affect.email} finalizada por un administrador.', 'success')
    else:
        flash(f'{user_to_affect.email} no tenía una gestión activa.', 'info')
        
    return redirect(url_for('admin_panel'))

@app.route('/admin/bulk_upload', methods=['POST'])
@login_required
@editor_required
def bulk_upload():
    if 'file' not in request.files:
        flash('No se seleccionó ningún archivo.', 'error'); return redirect(url_for('admin_panel'))
    file = request.files['file']
    if file.filename == '' or not file.filename.endswith('.csv'):
        flash('Por favor, sube un archivo CSV válido.', 'error'); return redirect(url_for('admin_panel'))
    try:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        csv_reader = csv.DictReader(stream)
        created_count = 0; skipped_count = 0
        for row in csv_reader:
            email = row.get('email')
            if not email or User.query.filter_by(email=email).first():
                skipped_count += 1; continue
            new_user = User(email=email, nombre=row.get('nombre'), apellido=row.get('apellido'), role='Agent')
            new_user.set_password(row.get('password'))
            db.session.add(new_user); created_count += 1
        db.session.commit()
        flash(f'Carga masiva completada: {created_count} usuarios creados, {skipped_count} omitidos (ya existían).', 'success')
    except Exception as e:
        db.session.rollback(); flash(f'Error durante la carga masiva: {str(e)}', 'error')
    return redirect(url_for('admin_panel'))

@app.route('/admin/export_timelogs', methods=['POST'])
@login_required
@panel_admin_required
def export_timelogs():
    date_from_str = request.form.get('date_from'); date_to_str = request.form.get('date_to')
    user_ids = request.form.getlist('user_ids'); colombia_tz = pytz.timezone('America/Bogota')
    query = db.session.query(TimeLog).join(User).order_by(TimeLog.start_time.desc())
    if user_ids and 'all' not in user_ids:
        query = query.filter(TimeLog.user_id.in_([int(uid) for uid in user_ids]))
    if date_from_str and date_to_str:
        start_date = datetime.strptime(date_from_str, '%Y-%m-%d').date(); end_date = datetime.strptime(date_to_str, '%Y-%m-%d').date()
        start_dt_utc = colombia_tz.localize(datetime.combine(start_date, time.min)).astimezone(pytz.utc)
        end_dt_utc = colombia_tz.localize(datetime.combine(end_date, time.max)).astimezone(pytz.utc)
        query = query.filter(TimeLog.start_time.between(start_dt_utc, end_dt_utc))
    logs = query.all()
    filename = f"reporte_tiempos_{date_from_str}_a_{date_to_str}.csv"
    output = io.StringIO(); writer = csv.writer(output)
    writer.writerow(['ID_Log', 'Nombre', 'Apellido', 'Email', 'Inicio_Gestion', 'Fin_Gestion', 'Duracion_HHMMSS'])
    for log in logs:
        start_time_utc = log.start_time.replace(tzinfo=pytz.utc)
        start_time_local = start_time_utc.astimezone(colombia_tz).strftime('%Y-%m-%d %H:%M:%S')

        if log.end_time:
            end_time_utc = log.end_time.replace(tzinfo=pytz.utc)
            end_time_local = end_time_utc.astimezone(colombia_tz).strftime('%Y-%m-%d %H:%M:%S')
        else:
            end_time_local = 'Activa'
            
        duration_str = str(timedelta(seconds=int(log.duration))) if log.duration else 'N/A'
        
        writer.writerow([log.id, log.user.nombre, log.user.apellido, log.user.email, 
                         start_time_local, end_time_local, duration_str])
                         
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename={filename}"})

# --- NUEVA RUTA PARA GESTIÓN DE DOCUMENTOS ---
@app.route('/documentos')
@login_required
@editor_required
def documentos():
    users_list = User.query.order_by(User.nombre).all()
    return render_template('documentos.html', users=users_list)

@app.route('/')
@login_required
def index():
    from sqlalchemy import func
    colombia_tz = pytz.timezone('America/Bogota'); now_colombia = datetime.now(colombia_tz)
    today_start = now_colombia.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = today_start + timedelta(days=1)
    today_start_utc = today_start.astimezone(pytz.utc); today_end_utc = today_end.astimezone(pytz.utc)
    today_duration_sec = db.session.query(func.sum(TimeLog.duration)).filter(
        TimeLog.user_id == current_user.id, TimeLog.start_time >= today_start_utc, TimeLog.start_time < today_end_utc).scalar() or 0
    today_duration_str = str(timedelta(seconds=int(today_duration_sec)))
    month_start = now_colombia.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    next_month = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1); month_end = next_month
    month_start_utc = month_start.astimezone(pytz.utc); month_end_utc = month_end.astimezone(pytz.utc)
    month_duration_sec = db.session.query(func.sum(TimeLog.duration)).filter(
        TimeLog.user_id == current_user.id, TimeLog.start_time >= month_start_utc, TimeLog.start_time < month_end_utc).scalar() or 0
    month_duration_str = str(timedelta(seconds=int(month_duration_sec)))
    return render_template('index.html', today_duration=today_duration_str, month_duration=month_duration_str)

@app.route('/ejecutor', methods=['GET', 'POST'])
@login_required
@ejecutor_required
def ejecutor():
    if request.method == 'POST':
        files = request.files.getlist('files[]')
        script_name = request.form.get('script_name')
        if not script_name: flash("Debes seleccionar un script.", "error"); return redirect(request.url)
        if not files or all(f.filename == '' for f in files): flash("Debes subir al menos un archivo.", "error"); return redirect(request.url)
        session_folder_name = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
        input_dir = os.path.join(app.config['UPLOAD_FOLDER'], session_folder_name)
        output_dir = os.path.join(app.config['DOWNLOAD_FOLDER'], session_folder_name)
        os.makedirs(input_dir, exist_ok=True); os.makedirs(output_dir, exist_ok=True)
        for file in files:
            if file and file.filename.endswith('.csv'): file.save(os.path.join(input_dir, secure_filename(file.filename)))
        try:
            execute_script(script_name, input_dir, output_dir)
            processed_files = os.listdir(output_dir)
            if not processed_files: raise Exception("El script no generó archivos de salida.")
            zip_filename = f"resultados_{script_name}_{datetime.now().strftime('%Y%m%d')}.zip"
            zip_path = os.path.join(app.config['DOWNLOAD_FOLDER'], zip_filename)
            with zipfile.ZipFile(zip_path, 'w') as zipf:
                for file in processed_files: zipf.write(os.path.join(output_dir, file), arcname=file)
            return render_template('ejecutor.html', success=f"¡{len(processed_files)} archivos procesados!", download_file=zip_filename, scripts=get_scripts_list(), selected_script=script_name)
        except Exception as e:
            logger.error(f"Error al procesar: {str(e)}", exc_info=True); flash(f"Error al procesar: {str(e)}", "error")
    return render_template('ejecutor.html', scripts=get_scripts_list())

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    file_path = os.path.join(app.config['DOWNLOAD_FOLDER'], filename)
    if not os.path.exists(file_path): flash("Archivo no encontrado.", "error"); return redirect(url_for('ejecutor'))
    @after_this_request
    def remove_file(response):
        try: os.remove(file_path)
        except Exception as error: logger.error(f"Error eliminando archivo: {error}")
        return response
    return send_file(file_path, as_attachment=True)

@app.route('/time_track', methods=['GET'])
@login_required
def time_track_page():
    active_log = TimeLog.query.filter_by(user_id=current_user.id, end_time=None).first()
    if active_log:
        colombia_tz = pytz.timezone('America/Bogota')
        start_time_utc = active_log.start_time.replace(tzinfo=pytz.utc)
        active_log.start_time_local = start_time_utc.astimezone(colombia_tz)
        
    return render_template('time_track.html', active_log=active_log)

@app.route('/time_track/start', methods=['POST'])
@login_required
def start_management():
    if TimeLog.query.filter_by(user_id=current_user.id, end_time=None).first():
        flash('Ya tienes una gestión iniciada.', 'error'); return redirect(url_for('time_track_page'))
    start_time_utc = datetime.now(pytz.utc)
    new_log = TimeLog(user_id=current_user.id, start_time=start_time_utc)
    db.session.add(new_log); db.session.commit()
    flash('Gestión iniciada con éxito.', 'success'); return redirect(url_for('time_track_page'))

@app.route('/time_track/end', methods=['POST'])
@login_required
def end_management():
    active_log = TimeLog.query.filter_by(user_id=current_user.id, end_time=None).first()
    if not active_log:
        flash('No tienes ninguna gestión activa para finalizar.', 'error'); return redirect(url_for('time_track_page'))
    
    end_time_utc = datetime.now(pytz.utc)
    start_time_utc = active_log.start_time.replace(tzinfo=pytz.utc)
    duration_delta = end_time_utc - start_time_utc
    
    active_log.end_time = end_time_utc
    active_log.duration = duration_delta.total_seconds()
    
    db.session.commit()
    flash(f'Gestión finalizada. Duración: {str(timedelta(seconds=int(active_log.duration)))}', 'success')
    return redirect(url_for('time_track_page'))

# --- INICIO DE LA NUEVA FUNCIÓN PARA EXPORTAR USUARIOS ---
@app.route('/admin/export_users', methods=['POST'])
@login_required
@panel_admin_required
def export_users():
    user_ids = request.form.getlist('selected_users')
    if not user_ids:
        flash('No seleccionaste ningún usuario para exportar.', 'warning')
        return redirect(url_for('admin_panel'))

    query = User.query.filter(User.id.in_(user_ids)).order_by(User.nombre)
    users_to_export = query.all()

    # Definir las cabeceras del CSV
    headers = [
        'ID', 'Nombre', 'Apellido', 'Correo Corporativo', 'Correo Personal', 
        'Rol', 'Estado', 'Tipo Documento', 'Numero Documento', 'Numero Celular',
        'Fecha Nacimiento', 'Fecha Ingreso', 'País Residencia', 'Ciudad Residencia',
        'URL LinkedIn', 'Service', 'LOB', 'Cargo', 'Team Lead', 'Team Manager'
    ]
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)

    # Escribir los datos de cada usuario
    for user in users_to_export:
        writer.writerow([
            user.id,
            user.nombre,
            user.apellido,
            user.email,
            user.correo_personal,
            user.role,
            user.estado_colaborador,
            user.tipo_documento,
            user.numero_documento,
            user.numero_celular,
            user.fecha_nacimiento.strftime('%Y-%m-%d') if user.fecha_nacimiento else '',
            user.fecha_ingreso.strftime('%Y-%m-%d') if user.fecha_ingreso else '',
            user.pais_residencia,
            user.ciudad_residencia,
            user.linkedin_url,
            user.service,
            user.lob,
            user.cargo,
            user.tl,
            user.tm
        ])

    output.seek(0)
    filename = f"reporte_usuarios_{datetime.now().strftime('%Y%m%d')}.csv"
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )
# --- FIN DE LA NUEVA FUNCIÓN ---
    
def get_scripts_list():
    script_folder = os.path.join(BASE_DIR, 'static', 'scripts')
    try: return [f[:-3] for f in os.listdir(script_folder) if f.endswith('.py') and not f.startswith('__')]
    except FileNotFoundError: logger.error(f"Carpeta de scripts no encontrada: {script_folder}"); return []

def execute_script(script_name, input_folder, output_folder):
    script_path = os.path.join(BASE_DIR, 'static', 'scripts', f"{script_name}.py")
    if not os.path.exists(script_path): raise FileNotFoundError(f"Script no encontrado: {script_name}.py")
    spec = importlib.util.spec_from_file_location(script_name, script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.INPUT_FOLDER, module.OUTPUT_FOLDER = input_folder, output_folder
    if hasattr(module, 'procesar_archivos'): module.procesar_archivos()
    else: raise AttributeError(f"Función 'procesar_archivos' no encontrada en {script_name}")
        
def after_this_request(f):
    if not hasattr(g, 'after_request_callbacks'): g.after_request_callbacks = []
    g.after_request_callbacks.append(f); return f

@app.teardown_request
def call_after_request_callbacks(response):
    for callback in getattr(g, 'after_request_callbacks', ()): response = callback(response)
    return response

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)