from flask import Flask, render_template, redirect, url_for, flash, request, session, get_flashed_messages, current_app, jsonify, send_file, abort, send_from_directory, abort, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from forms import RegistrationForm, LoginForm, ResetPasswordForm  
from models import db, User, Department, FileMetadata  
from dotenv import load_dotenv
from custom_filters import datetimeformat, filesizeformat, filename_without_extension, filetype
import json 
import uuid
from utils.zke import ZKEncryption
from datetime import datetime, time, timedelta
from io import BytesIO
from base64 import b64encode, b64decode
from utils.log import SecurityLogger
from werkzeug.serving import WSGIRequestHandler
from utils.SSHOperations import SSHOperations
from utils.secure_setup import set_secure_permissions, create_secure_directories
from utils.env_crypto import SecureEnv
from functools import wraps
import subprocess
import platform
from flask import render_template, request, redirect, url_for, flash
import time 
import logging
from models import Department, DepartmentAuditLog
import requests, os, logging, urllib.parse, base64
from flask_session import Session
import urllib3

# Disable InsecureRequestWarning for local TrueNAS connections
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Remove all previous session configurations
secure_env = SecureEnv()
env_vars = secure_env.decrypt_env()

# Create session directory if it doesn't exist
session_dir = os.path.join(app.root_path, 'flask_session')
os.makedirs(session_dir, exist_ok=True)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

security_logger = SecurityLogger(app)

load_dotenv()
# Use dynamic path based on application root
db_path = os.path.join(app.root_path, 'instance', 'users.db')
app.config['SESSION_COOKIE_SECURE'] = False  # Allow non-HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 300  # 5 minutes
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = env_vars.get('SECRET_KEY')
app.config['ADMIN_PASSWORD'] = env_vars.get('ADMIN_PASSWORD')

app.jinja_env.filters['datetimeformat'] = datetimeformat
app.jinja_env.filters['filesizeformat'] = filesizeformat
app.jinja_env.filters['filename_without_extension'] = filename_without_extension
app.jinja_env.filters['filetype'] = filetype


db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Get environment variables
env_vars = secure_env.decrypt_env()

# Get TrueNAS IP from environment
TRUENAS_IP = env_vars.get('TRUENAS_IP')
if TRUENAS_IP and not TRUENAS_IP.startswith('http://'):
    TRUENAS_IP = f"http://{TRUENAS_IP}"

TRUENAS_URL = f"{TRUENAS_IP}/api/v2.0/filesystem/put"
TRUENAS_API_KEY = env_vars.get('TRUENAS_API_KEY')
TRUENAS_MOVE_ENDPOINT = f"{TRUENAS_IP}/api/v2.0/filesystem/move"
TRUENAS_DATASET_ENDPOINT = f"{TRUENAS_IP}/api/v2.0/filesystem/dataset"
TRUENAS_DELETE_ENDPOINT = f"{TRUENAS_IP}/api/v2.0/filesystem/delete"
TRUENAS_STAT_ENDPOINT = f"{TRUENAS_IP}/api/v2.0/filesystem/stat"
TRUENAS_GET_ENDPOINT = f"{TRUENAS_IP}/api/v2.0/filesystem/get"
TRUENAS_ACL_GET_ENDPOINT = f"{TRUENAS_IP}/api/v2.0/filesystem/getacl"
TRUENAS_ACL_SET_ENDPOINT = f"{TRUENAS_IP}/api/v2.0/filesystem/setacl"
TRUENAS_SSH_HOST = env_vars.get('TRUENAS_SSH_HOST')
TRUENAS_SSH_USER = env_vars.get('TRUENAS_SSH_USER')
TRUENAS_SSH_KEY_PATH = env_vars.get('TRUENAS_SSH_KEY_PATH')
UNLOCK_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'unlock.flag')
UNLOCK_DURATION = 300  # 5 minutes

# Get department dataset path from environment
DEPARTMENT_DATASET = env_vars.get('DEPARTMENT_DATASET')
if not DEPARTMENT_DATASET:
    logger.error("DEPARTMENT_DATASET not configured. Please configure the system first.")
DEPARTMENTS_BASE_PATH = f"/mnt/{DEPARTMENT_DATASET}" if DEPARTMENT_DATASET else None

def check_configuration(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        secure_env = SecureEnv()
        is_configured = secure_env.is_configured()
        
        # Always allow configuration steps when system is not configured
        if not is_configured:
            return f(*args, **kwargs)
            
        # Check if unlocked
        if check_unlock_flag():
            return f(*args, **kwargs)
            
        # If configured but locked, show locked template
        return render_template('configure.html', 
                            is_configured=is_configured,
                            is_locked=True)
    return decorated_function

def verify_ownership(filename):
    """Helper function to verify file ownership"""
    file_metadata = FileMetadata.query.filter_by(filename=filename).first()
    if not file_metadata or file_metadata.owner != current_user.name:
        return False
    return True

@app.route('/test_config')
def test_config():
    secure_env = SecureEnv()
    
    # Test initialization
    init_success = secure_env.initialize_config()
    
    # Check configuration status
    is_configured = secure_env.is_configured()
    
    # Get current configuration with all values
    current_config = secure_env.decrypt_env()
    
    # Set TRUENAS_IP if empty
    if not current_config.get('TRUENAS_IP'):
        current_config['TRUENAS_IP'] = current_config.get('TRUENAS_SSH_HOST', '')
        secure_env.update_env(current_config)
    
    return jsonify({
        'init_success': init_success,
        'is_configured': is_configured,
        'current_config': current_config  # Show all variables including sensitive ones
    })

@app.before_request
def log_request():
    try:
        # Skip logging for static files
        if not request.path.startswith('/static/'):
            security_logger.log_access()
    except Exception as e:
        app.logger.error(f"Logging error: {str(e)}")
        # Continue with the request even if logging fails
        pass

@app.after_request
def log_response(response):
    if not request.path.startswith('/static/'):
        security_logger.log_access(response)
    return response

@app.before_request
def make_session_permanent():
    session.permanent = True

@login_manager.user_loader
def load_user(user_id):
    # New SQLAlchemy 2.0 syntax
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/check_file/<filename>')
@login_required
def check_file(filename):
    file_meta = FileMetadata.query.filter_by(filename=filename).first()
    if file_meta:
        return jsonify({
            'filename': file_meta.filename,
            'size': file_meta.size,
            'has_metadata': bool(file_meta.encryption_metadata)
        })
    return jsonify({'error': 'File not found'}), 404

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        is_admin = False

        # Check if admin registration checkbox is selected
        if form.is_admin_checkbox.data:
            if form.admin_password.data == current_app.config['ADMIN_PASSWORD']:
                is_admin = True
            else:
                return jsonify({"status": "error", "message": "Invalid admin password."}), 400

        # User registration logic (saving the user to database)
        new_user = User(
            username=form.username.data,
            name=form.name.data,
            security_question=form.security_question.data,
            security_answer=form.security_answer.data,
        )

        new_user.set_password(form.password.data)
        new_user.is_admin = is_admin
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"status": "success", "message": "Registration successful!"})

    # If the form is not valid or on GET request, render the form page
    return render_template('register.html', form=form)



@app.route('/access_department', methods=['GET', 'POST'])
def access_department():
    if request.method == 'POST':
        department_name = request.form['department_name']
        department_password = request.form['password']
        
        # Retrieve the department by name
        department = Department.query.filter_by(department_name=department_name).first()
        
        if department and department.check_password(department_password):
            # Access granted: Redirect to the department files page
            return redirect(url_for('department_files', department_id=department.id))
        else:
            flash('Incorrect department password or department does not exist.', 'error')
            return redirect(url_for('access_department'))
    
    return render_template('access_department.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()

    # Handle POST request
    if request.method == 'POST':
        # Handle the "Back to Login" scenario (Clear session and go to login page)
        if 'back_to_login' in request.form:
            session.clear()
            return redirect(url_for('login'))

        if session.get('stage') == 'username' and form.username.data:
            user = User.query.filter_by(username=form.username.data).first()
            if user:
                # If username is valid, transition to the security question stage
                session['stage'] = 'security_question'
                session['username'] = form.username.data
                session['security_question'] = user.security_question  # Save the security question ID to session
                flash('Username verified. Please answer the security question.', 'success')
            else:
                flash('Username not found. Please try again.', 'danger')
        
        elif session.get('stage') == 'security_question':
            user = User.query.filter_by(username=session['username']).first()
            if user and user.security_answer == form.security_answer.data:
                # If the answer is correct, go to reset password stage
                session['stage'] = 'reset_password'
                flash('Security answer verified. You can now reset your password.', 'success')
            else:
                flash('Incorrect security answer. Please try again.', 'danger')

        elif session.get('stage') == 'reset_password':
            user = User.query.filter_by(username=session['username']).first()
            if form.new_password.data == form.confirm_new_password.data:
                user.set_password(form.new_password.data)
                db.session.commit()
                session.clear()  # Clear the session after password reset
                flash('Your password has been reset successfully.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Passwords do not match. Please try again.', 'danger')

    # If session has no stage, set it to 'username'
    if 'stage' not in session:
        session['stage'] = 'username'

    # Retrieve full security question based on session data
    security_question = None
    if session.get('stage') == 'security_question':
        security_question_id = session.get('security_question')  # Get question identifier
        question_dict = {
            'mother_maiden': "What is your mother's maiden name?",
            'first_pet': "What was the name of your first pet?",
            'birth_city': "What city were you born in?"
        }
        # Get the actual question text based on the stored identifier
        security_question = question_dict.get(security_question_id, 'Unknown question')

    # Render the appropriate template based on the current session stage
    stage = session.get('stage', 'username')

    return render_template(
        'reset_password.html',
        form=form,
        stage=stage,
        security_question=security_question,  # Pass the full security question text to template
    )


@app.route('/reset_password_new_password', methods=['GET', 'POST'])
def reset_password_new_password():
    form = ResetPasswordForm()

    # Stage checks if the user is logged in and the session exists
    if 'username' not in session:
        flash('Session expired, please start over.', 'danger')
        return redirect(url_for('reset_password'))  # Redirect if session is missing

    # Handle password reset (Stage 3)
    if request.method == 'POST':
        user = User.query.filter_by(username=session['username']).first()
        if form.new_password.data == form.confirm_new_password.data:
            user.set_password(form.new_password.data)
            db.session.commit()
            session.clear()  # Clear the session when the password is successfully reset
            flash('Password reset successfully.', 'success')
            return redirect(url_for('login'))  # Redirect to login after password reset
        else:
            flash('Passwords do not match.', 'danger')

    return render_template('reset_password_new_password.html', form=form)


    # Fetch the current stage
    stage = session.get('stage', 'username')

    # Map security question identifier to the full question text
    security_questions = {
        'mother_maiden': "What is your mother's maiden name?",
        'first_pet': "What was the name of your first pet?",
        'birth_city': "What city were you born in?"
    }
    
    # Get the full question text to display on the template
    security_question = security_questions.get(session.get('security_question'), 'Unknown security question')

    # Render the template with necessary data
    return render_template(
        'reset_password.html',
        form=form,
        stage=stage,
        security_question=security_question,
        flash_messages=flash_messages  # Display relevant flash messages
    )



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    flash_messages = list(get_flashed_messages(with_categories=False))

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Log login attempt
        security_logger.log_security_event('login_attempt', {
            'username': username,
            'ip': request.remote_addr,
            'timestamp': datetime.now().isoformat()
        })

        user = User.query.filter_by(username=username).first()
        if not user:
            # Log failed login - invalid username
            security_logger.log_security_event('login_failed', {
                'username': username,
                'reason': 'Invalid username',
                'ip': request.remote_addr
            })
            flash('Invalid username. Please try again.', 'danger')
            return redirect(url_for('login'))

        if not user.check_password(password):
            # Log failed login - invalid password
            security_logger.log_security_event('login_failed', {
                'username': username,
                'reason': 'Invalid password',
                'ip': request.remote_addr
            })
            flash('Invalid password. Please try again.', 'danger')
            return redirect(url_for('login'))

        # Log successful login
        security_logger.log_security_event('login_success', {
            'username': username,
            'user_id': user.id,
            'name': user.name,
            'is_admin': user.is_admin
        })

        login_user(user)
        session.pop('department', None)  # Ensure the department session is cleared
        session['username'] = username  # Add username to session for logging
        flash('Logged in successfully. Please select a department.', 'success')
        return redirect(url_for('select_department'))

    return render_template('login.html', form=form, flash_messages=flash_messages)
    
@app.route('/select_department', methods=['GET', 'POST'])
@login_required
def select_department():
    # Get current dataset path from environment
    env_vars = secure_env.decrypt_env()
    department_base = env_vars.get('DEPARTMENT_DATASET')
    departments_base_path = f"/mnt/{department_base}"
    
    headers = {
        "Authorization": f"Bearer {TRUENAS_API_KEY}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            f"{TRUENAS_IP}/api/v2.0/filesystem/listdir",
            headers=headers,
            json={"path": departments_base_path}
        )
        
        if response.status_code == 200:
            departments_data = response.json()
            departments = []
            for item in departments_data:
                if item.get('type') == 'DIRECTORY':
                    department_name = item.get('name')
                    departments.append({'department_name': department_name})
        else:
            app.logger.error(f"Failed to list departments: {response.text}")
            departments = []
            flash("Failed to load departments. Please try again later.", "error")
    except Exception as e:
        app.logger.error(f"Error listing departments: {str(e)}")
        departments = []
        flash("Failed to load departments. Please try again later.", "error")

    # Handle POST requests for selecting a department
    if request.method == 'POST':
        # If a password is submitted (password verification step)
        if 'password' in request.form:
            department_name = request.form.get('department_name')
            entered_password = request.form.get('password')
            department = Department.query.filter_by(department_name=department_name).first()

            # Check if password is correct
            if department and department.check_password(entered_password):
                session['department'] = department_name  # Grant access to this department
                flash(f'Access granted to {department_name} department!', 'success')
                return redirect(url_for('dashboard'))

            flash('Incorrect password. Please try again.', 'error')
            # Return template with both departments list and the selected department name
            return render_template('select_department.html', 
                                departments=departments,
                                department_name=department_name,
                                show_password_form=True)

        # If a department is selected (department selection step)
        department_name = request.form.get('department')
        if department_name:
            session['selected_department'] = department_name
            # Return template with both departments list and the selected department
            return render_template('select_department.html', 
                                departments=departments,
                                department_name=department_name,
                                show_password_form=True)
        else:
            flash("Please select a valid department.", "danger")

    # Default GET request - show department selection
    return render_template('select_department.html', departments=departments)



@app.route('/verify_department_password', methods=['GET', 'POST'])
@login_required
def verify_department_password():
    selected_department = session.get('selected_department')
    if not selected_department:
        flash("Please select a department first.", "warning")
        return redirect(url_for('select_department'))

    if request.method == 'POST':
        entered_password = request.form.get('password')
        department = Department.query.filter_by(department_name=selected_department).first()

        if department and department.check_password(entered_password):  # Verify password
            session['department'] = selected_department  # Mark the department as accessed
            flash('Access granted to the department.', 'success')
            return redirect(url_for('dashboard'))

        flash('Incorrect password. Please try again.', 'danger')

    return render_template('verify_department_password.html', department=selected_department)

@app.route('/configure_yvex', methods=['GET', 'POST'])
def configure_yvex():
    # Initialize SecureEnv at the start
    secure_env = SecureEnv()
    
    if request.method == 'POST':
        # Verify all required fields are present
        required_fields = ['truenas_ip', 'api_key', 'dataset_path', 'admin_password', 'root_password']
        if not all(field in request.form for field in required_fields):
            return jsonify({
                'success': False,
                'message': 'Please complete all configuration steps'
            })

        # Process configuration
        config_data = {
            'TRUENAS_IP': request.form.get('truenas_ip'),
            'TRUENAS_SSH_HOST': request.form.get('truenas_ip'),
            'TRUENAS_API_KEY': request.form.get('api_key'),
            'DEPARTMENT_DATASET': request.form.get('dataset_path'),
            'ADMIN_PASSWORD': request.form.get('admin_password'),
            'ROOT_PASSWORD': request.form.get('root_password'),
            'CONFIGURED_FLAG': '1'
        }

        if secure_env.update_env(config_data):
            write_unlock_flag()  # Keep unlock flag until redirect
            return jsonify({
                'success': True,
                'message': 'Configuration completed successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to save configuration'
            })

    # For GET requests, render the configuration page
    return render_template('configure.html',
                         is_configured=secure_env.is_configured(),
                         unlocked=check_unlock_flag())


@app.route('/ping_truenas/<ip>')
def ping_truenas(ip):
    print("\n=== Starting TrueNAS Ping Check ===")
    print(f"Received request to ping: {ip}")
    
    try:
        # Send multiple pings (4 pings)
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        print(f"\n[SERVER] Executing ping command: ping {param} 4 {ip}")
        
        ping_result = subprocess.run(['ping', param, '4', ip], 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True)
        
        if ping_result.returncode == 0:
            flash('Successfully connected to TrueNAS server!', 'success')
            try:
                response = requests.get(f"http://{ip}/api/v2.0/system/info", 
                                     timeout=5,
                                     verify=False)
                
                if response.status_code in [200, 401]:
                    flash('✓ TrueNAS system detected! Ready for API key configuration.', 'success')
                    return jsonify({
                        'success': True,
                        'message': '✓ TrueNAS system detected!',
                        'flash_messages': get_flashed_messages(with_categories=True)
                    })
                else:
                    flash('Host is reachable but does not appear to be a TrueNAS system', 'error')
                    
            except requests.exceptions.RequestException as e:
                flash(f'Connection error: {str(e)}', 'error')
                
            return jsonify({
                'success': False,
                'message': 'Host is reachable but not a TrueNAS system',
                'flash_messages': get_flashed_messages(with_categories=True)
            })
        else:
            flash(f'Failed to ping {ip}. Please check if the IP is correct and the system is online.', 'error')
            return jsonify({
                'success': False,
                'message': f'Failed to ping {ip}',
                'flash_messages': get_flashed_messages(with_categories=True)
            })
            
    except Exception as e:
        flash(f'Error during ping: {str(e)}', 'error')
        return jsonify({
            'success': False,
            'message': f'Error during ping: {str(e)}',
            'flash_messages': get_flashed_messages(with_categories=True)
        })

@app.route('/verify_api_key', methods=['POST'])
def verify_api_key():
    data = request.json
    ip = data.get('ip')
    api_key = data.get('api_key')
    
    if not api_key:
        flash('API key is required', 'error')
        return jsonify({
            'success': False,
            'message': 'API key is required',
            'flash_messages': get_flashed_messages(with_categories=True)
        })
    
    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        response = requests.get(f"http://{ip}/api/v2.0/system/info", headers=headers)
        
        if response.status_code == 200:
            flash('API key validated successfully!', 'success')
            return jsonify({
                'success': True,
                'message': 'API key is valid',
                'flash_messages': get_flashed_messages(with_categories=True)
            })
        else:
            flash('Invalid API key. Please check and try again.', 'error')
            return jsonify({
                'success': False,
                'message': 'Invalid API key',
                'flash_messages': get_flashed_messages(with_categories=True)
            })
    except Exception as e:
        flash(f'Error validating API key: {str(e)}', 'error')
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}',
            'flash_messages': get_flashed_messages(with_categories=True)
        })

@app.route('/check_dataset_path', methods=['POST'])
def check_dataset_path():
    data = request.json
    ip = data.get('ip')
    api_key = data.get('api_key')
    path = data.get('path')
    
    if not path:
        flash('Dataset path is required', 'error')
        return jsonify({
            'success': False,
            'message': 'Dataset path is required',
            'flash_messages': get_flashed_messages(with_categories=True)
        })
    
    # Remove any leading /mnt/ if present
    dataset_name = path.replace('/mnt/', '', 1)
    dataset_name = dataset_name.replace('/', '%2F')
    
    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(
            f"http://{ip}/api/v2.0/pool/dataset/id/{dataset_name}",
            headers=headers
        )
        
        dataset_exists = response.status_code == 200
        
        if dataset_exists:
            flash('Dataset found and validated successfully!', 'success')
        else:
            flash('Dataset not found. Please check the path and try again.', 'error')
        
        return jsonify({
            'success': dataset_exists,
            'message': 'Dataset found!' if dataset_exists else 'Dataset not found',
            'flash_messages': get_flashed_messages(with_categories=True)
        })
            
    except Exception as e:
        flash(f'Error checking dataset: {str(e)}', 'error')
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}',
            'flash_messages': get_flashed_messages(with_categories=True)
        })
    
def write_unlock_flag():
    """Write the unlock file with expiration timestamp."""
    expire_time = time.time() + UNLOCK_DURATION
    with open(UNLOCK_FILE, 'w') as f:
        f.write(str(expire_time))

def check_unlock_flag():
    """Return True if the unlock file exists and is still valid."""
    secure_env = SecureEnv()
    env_vars = secure_env.decrypt_env()
    
    # If both ROOT_PASSWORD and TRUENAS_IP are null, system is in bootstrap mode
    if not env_vars.get('ROOT_PASSWORD') and not env_vars.get('TRUENAS_IP'):
        return True
        
    if os.path.exists(UNLOCK_FILE):
        try:
            with open(UNLOCK_FILE, 'r') as f:
                expire_time = float(f.read().strip())
            if time.time() < expire_time:
                return True
            else:
                os.remove(UNLOCK_FILE)
        except Exception as e:
            app.logger.error(f"Error reading unlock flag: {e}")
    return False

@app.route('/get_ssh_key')
def get_ssh_key():
    try:
        # Get key path from SSHOperations class
        ssh_key_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), 
            'config', 
            'truenas_service.key.pub'
        )
        
        # Read the public key
        with open(ssh_key_path, 'r') as f:
            public_key = f.read().strip()
            
        return jsonify({
            'success': True,
            'key': public_key
        })
        
    except Exception as e:
        app.logger.error(f"Error reading SSH key: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error reading SSH key: {str(e)}'
        })

@app.route('/verify_ssh_connection', methods=['POST'])
def verify_ssh_connection():
    try:
        if not check_unlock_flag():
            app.logger.error("Configuration is locked")
            return jsonify({
                'success': False,
                'message': 'Configuration is locked. Please unlock first.'
            }), 401

        data = request.json
        truenas_ip = data.get('truenas_ip')
        
        app.logger.debug(f"Attempting SSH connection to: {truenas_ip}")
        
        if not truenas_ip:
            app.logger.error("No TrueNAS IP provided")
            return jsonify({
                'success': False,
                'message': 'TrueNAS IP is required'
            }), 400

        # Initialize SSH connection
        ssh_ops = SSHOperations(
            host=truenas_ip,
            username='root'
        )
        
        app.logger.debug("Trying SSH connection...")
        # Test connection with simple command
        ssh = ssh_ops.connect()
        _, stdout, _ = ssh.exec_command('whoami')
        output = stdout.read().decode().strip()
        
        app.logger.debug(f"SSH command output: {output}")
        
        if output == 'root':
            app.logger.debug("SSH connection successful")
            return jsonify({
                'success': True,
                'message': 'SSH connection successful'
            })
        else:
            app.logger.error(f"SSH connection failed - not running as root: {output}")
            return jsonify({
                'success': False,
                'message': 'SSH connection failed - not running as root'
            })
            
    except Exception as e:
        app.logger.error(f"SSH verification error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'SSH connection failed: {str(e)}'
        }), 500

@app.route('/truenas-unlock', methods=['POST'])
def truenas_unlock():
    secure_env = SecureEnv()
    env_vars = secure_env.decrypt_env()
    
    # Get stored TrueNAS IP and root password from the env
    stored_ip = env_vars.get('TRUENAS_IP')
    root_password = env_vars.get('ROOT_PASSWORD')
    
    # If both are null, system is in bootstrap mode - no unlock needed
    if not stored_ip and not root_password:
        return jsonify({'success': True, 'message': 'System in bootstrap mode, no unlock needed'})
    
    # Get request IP and provided password from header
    request_ip = request.remote_addr
    provided_password = request.headers.get('X-TrueNAS-Key')
    
    app.logger.debug(f"Request IP: {request_ip}")
    app.logger.debug(f"Stored IP: {stored_ip}")
    
    if stored_ip and request_ip != stored_ip:
        return jsonify({'error': f'Unauthorized IP. Must originate from {stored_ip}'}), 403
    
    # If root password is set, verify it
    if root_password and provided_password != root_password:
        return jsonify({'error': 'Invalid password'}), 401
    
    try:
        # Write the unlock flag with expiration timestamp
        write_unlock_flag()
        app.logger.debug("Unlock flag written successfully.")
        return jsonify({'success': True, 'message': 'Configuration unlocked'})
    except Exception as e:
        app.logger.error(f"Error writing unlock flag: {e}")
        return jsonify({'error': f'Error writing unlock flag: {str(e)}'}), 500

@app.route('/check_unlock_status')
def check_unlock_status():
    unlocked = check_unlock_flag()
    app.logger.debug(f"Unlock flag status: {unlocked}")
    return jsonify({'unlocked': unlocked})

@app.route('/dashboard')
@login_required
def dashboard():
    department = session.get('department')
    if not department:
        flash("Please select and authenticate a department first.", "warning")
        return redirect(url_for('select_department'))

    headers = {
        "Authorization": f"Bearer {TRUENAS_API_KEY}",
        "Content-Type": "application/json",
    }
    department_path = f"{DEPARTMENTS_BASE_PATH}/{department}/"
    payload = {"path": department_path}

    try:
        # Fetch all files in the selected department from the NAS
        response = requests.post(f"{TRUENAS_IP}/api/v2.0/filesystem/listdir", 
                               headers=headers, json=payload)
        response.raise_for_status()
        truenas_files = {file['name']: file for file in response.json()}

        # Fetch all file metadata from the database
        db_files = FileMetadata.query.filter_by(department=department).all()
        files_metadata = []

        # Process each file found in TrueNAS
        for encrypted_filename, truenas_file in truenas_files.items():
            # Look up file in database
            db_file = FileMetadata.query.filter_by(
                department=department,
                filename=encrypted_filename
            ).first()

            if db_file:
                # File is in database, use its metadata
                file_metadata = {
                    "filename": encrypted_filename,
                    "original_filename": db_file.original_filename,
                    "size": truenas_file['size'],
                    "type": os.path.splitext(db_file.original_filename)[1][1:].upper() or "UNKNOWN",
                    "last_modified": db_file.last_modified.strftime('%Y-%m-%d %H:%M:%S'),
                    "owner": db_file.owner,
                    "is_public": db_file.is_public,  # Include public/private status
                    "id": db_file.id
                }
            else:
                # File exists in TrueNAS but not in database
                file_metadata = {
                    "filename": encrypted_filename,
                    "original_filename": encrypted_filename,
                    "size": truenas_file['size'],
                    "type": "UNKNOWN",
                    "last_modified": "Unknown",
                    "owner": "Unknown",
                    "is_public": False,  # Default to private if not in database
                    "id": None
                }
            
            files_metadata.append(file_metadata)

        # Sort files by modification date (newest first)
        files_metadata.sort(key=lambda x: x["last_modified"], reverse=True)
        
        return render_template('dashboard.html', 
                             files=files_metadata, 
                             department=department,
                             current_user=current_user)

    except requests.exceptions.RequestException as e:
        flash("Connection failed to TrueNAS. Please Check Connection to TrueNas PC.", "error")
        return render_template('dashboard.html', 
                             department=department, 
                             files=[],
                             current_user=current_user)

@app.route('/toggle_access/<filename>', methods=['POST'])
@login_required
def toggle_access(filename):
    try:
        # Start fresh session
        db.session.expire_all()
        
        file_metadata = FileMetadata.query.filter_by(filename=filename).first()
        
        if not file_metadata:
            app.logger.error(f"File not found: {filename}")
            return jsonify({'error': 'File not found'}), 404
            
        if file_metadata.owner != current_user.name:
            app.logger.error(f"Unauthorized access attempt by {current_user.name}")
            return jsonify({'error': 'Not authorized - you are not the owner'}), 403
        
        # Store old state for logging
        old_state = "public" if file_metadata.is_public else "private"
        
        # Toggle state
        file_metadata.is_public = not file_metadata.is_public
        new_state = "public" if file_metadata.is_public else "private"
        
        # Create audit log entry
        audit_log = DepartmentAuditLog(
            department=session.get('department'),
            action='ACCESS_CHANGE',
            details=f'Changed file "{file_metadata.original_filename}" access from {old_state} to {new_state}',
            user=current_user.name,
            timestamp=datetime.now()
        )
        db.session.add(audit_log)
        
        # Force flush and commit both changes
        try:
            db.session.flush()
            db.session.commit()
            
            # Verify change persisted
            db.session.refresh(file_metadata)
            app.logger.info(f"State after commit and refresh: {file_metadata.is_public}")
            
            # Double check with a fresh query
            verify = FileMetadata.query.filter_by(filename=filename).first()
            app.logger.info(f"State from fresh query: {verify.is_public}")
            
        except Exception as commit_error:
            app.logger.error(f"Commit error: {commit_error}")
            db.session.rollback()
            raise
        
        return jsonify({
            'success': True,
            'message': f'File is now {new_state}',
            'is_public': file_metadata.is_public,
            'verified_state': verify.is_public
        })
        
    except Exception as e:
        app.logger.error(f"Toggle access error: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/rename_file/<filename>', methods=['POST'])
@login_required
def rename_file(filename):
    if not verify_ownership(filename):
        return jsonify({'error': 'Not authorized - you are not the owner'}), 403

    try:
        new_name = request.form.get('new_name')
        department = session.get('department')
        
        if not new_name or not department:
            return jsonify({'error': 'Invalid request parameters'}), 400

        # Get file metadata
        file_metadata = FileMetadata.query.filter_by(
            filename=filename,
            department=department
        ).first()
        
        if not file_metadata:
            return jsonify({'error': 'File not found'}), 404

        # Store old name for logging
        old_name = file_metadata.original_filename

        # Update the original_filename in database
        file_metadata.original_filename = new_name
        
        # Create audit log entry
        audit_log = DepartmentAuditLog(
            department=department,
            action='FILE_RENAME',
            details=f'Renamed file from "{old_name}" to "{new_name}"',
            user=current_user.name,
            timestamp=datetime.now()
        )
        db.session.add(audit_log)
        
        # Commit both the rename and the log entry
        db.session.commit()
        
        app.logger.info(f"File renamed in database: {filename} -> {new_name}")
        
        return jsonify({
            'success': True,
            'message': 'File renamed successfully',
            'new_name': new_name
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Rename error: {str(e)}")
        return jsonify({'error': str(e)}), 500



@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    uploaded_file = request.files.get('file')
    department = session.get('department')
    encryption_password = request.form.get('encryption_password')

    if not department or not uploaded_file or not encryption_password:
        flash("Missing required information.", "danger")
        return redirect(url_for("dashboard"))

    try:
        # Read file data
        file_data = uploaded_file.read()
        original_size = len(file_data)

        # Generate encrypted filename
        encrypted_filename = str(uuid.uuid4()) + '.enc'

        # Encrypt the file
        encrypted_package = ZKEncryption.encrypt_file(file_data, encryption_password)

        # Prepare file path
        file_path = f"{DEPARTMENTS_BASE_PATH}/{department}/{encrypted_filename}"
        department_path = f"{DEPARTMENTS_BASE_PATH}/{department}"
        
        headers = {
            "Authorization": f"Bearer {TRUENAS_API_KEY}",
            "Content-Type": "application/json"
        }

        # Check/create department directory
        dir_check = requests.post(
            f"{TRUENAS_IP}/api/v2.0/filesystem/stat",
            headers=headers,
            json={"path": department_path}
        )

        if dir_check.status_code != 200:
            mkdir_payload = {"path": department_path, "options": {"create_parents": True}}
            requests.post(
                f"{TRUENAS_IP}/api/v2.0/filesystem/mkdir",
                headers=headers,
                json=mkdir_payload
            )

        # Check if path exists
        check_response = requests.post(
            f"{TRUENAS_IP}/api/v2.0/filesystem/stat",
            headers=headers,
            json={"path": file_path}
        )

        if check_response.status_code == 200 and check_response.json().get('type') == 'DIRECTORY':
            delete_payload = {"paths": [file_path]}
            requests.post(
                f"{TRUENAS_IP}/api/v2.0/filesystem/delete_files",
                headers=headers,
                json=delete_payload
            )

        # Upload encrypted file
        upload_payload = {"path": file_path}
        files = {
            "file": (
                encrypted_filename,
                encrypted_package['encrypted_data'],
                'application/octet-stream'
            )
        }

        response = requests.post(
            TRUENAS_URL,
            headers={"Authorization": f"Bearer {TRUENAS_API_KEY}"},
            data={"data": json.dumps(upload_payload)},
            files=files
        )
        response.raise_for_status()

        # Create file metadata
        file_metadata = FileMetadata(
            filename=encrypted_filename,
            original_filename=uploaded_file.filename,
            size=len(encrypted_package['encrypted_data']),
            last_modified=datetime.now(),
            department=department,
            owner=current_user.name,
            is_public=False,
            encryption_metadata=json.dumps({
                **encrypted_package['metadata'],
                'encrypted_filename': encrypted_filename
            })
        )
        db.session.add(file_metadata)

        # Create audit log entry
        audit_log = DepartmentAuditLog(
            department=department,
            action='FILE_UPLOAD',
            details=f'Uploaded file: {uploaded_file.filename} (Original Size: {filesizeformat(original_size)}, Encrypted Size: {filesizeformat(len(encrypted_package["encrypted_data"]))})',
            user=current_user.name,
            timestamp=datetime.now()
        )
        db.session.add(audit_log)

        # Commit both metadata and audit log
        db.session.commit()

        flash('File encrypted and uploaded successfully!', 'success')

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Upload error: {str(e)}")
        flash(f"Error during upload: {str(e)}", 'danger')
        
    return redirect(url_for('dashboard'))

@app.route('/download_file/<filename>', methods=['POST'])
@login_required
def download_file(filename):
    if not verify_ownership(filename):
        return jsonify({'error': 'Not authorized - you are not the owner'}), 403
    try:
        department = session.get('department')
        decryption_password = request.form.get('decryption_password')
        
        app.logger.info(f"Download request for {filename} from {department}")

        # Get file metadata from database
        file_metadata = FileMetadata.query.filter_by(
            filename=filename,
            department=department
        ).first()
        
        if not file_metadata:
            return jsonify({'error': 'File metadata not found'}), 404

        # Get encryption metadata
        encryption_metadata = json.loads(file_metadata.encryption_metadata)
        
        # Construct file path
        file_path = f"{DEPARTMENTS_BASE_PATH}/{department}/{filename}"
        
        # Get encrypted file from TrueNAS
        headers = {
            "Authorization": f"Bearer {TRUENAS_API_KEY}",
            "Content-Type": "application/json"
        }
        
        # Send path as raw string
        data = f'"{file_path}"'
        
        response = requests.post(
            f"{TRUENAS_IP}/api/v2.0/filesystem/get",
            headers=headers,
            data=data
        )
        
        if response.status_code != 200:
            app.logger.error(f"Failed to retrieve file: {response.text}")
            return jsonify({'error': 'Failed to retrieve file'}), 500

        encrypted_data = response.content
        if not encrypted_data:
            app.logger.error("Retrieved empty file")
            return jsonify({'error': 'File is empty'}), 400

        # Create audit log entry before decryption attempt
        audit_log = DepartmentAuditLog(
            department=department,
            action='FILE_DOWNLOAD',
            details=f'Downloaded file: {file_metadata.original_filename} (Encrypted Size: {filesizeformat(len(encrypted_data))})',
            user=current_user.name,
            timestamp=datetime.now()
        )
        db.session.add(audit_log)
        db.session.commit()

        # Prepare decryption package
        encrypted_package = {
            'metadata': {
                'salt': encryption_metadata['salt'],
                'nonce': encryption_metadata['nonce'],
                'tag': encryption_metadata['tag'],
                'key_tag': encryption_metadata['key_tag'],
                'encrypted_key': encryption_metadata['encrypted_key']
            },
            'encrypted_data': encrypted_data
        }

        try:
            # Decrypt the file
            decrypted_data = ZKEncryption.decrypt_file(encrypted_package, decryption_password)
            
            # Use the original filename from database
            original_filename = file_metadata.original_filename
            
            # Set Content-Disposition header with the original filename
            headers = {
                'Content-Disposition': f'attachment; filename="{original_filename}"',
                'Content-Type': 'application/octet-stream'
            }
            
            return send_file(
                BytesIO(decrypted_data),
                download_name=original_filename,
                as_attachment=True,
                mimetype='application/octet-stream'
            )

        except Exception as e:
            app.logger.error(f"Decryption failed: {str(e)}")
            return jsonify({'error': 'Invalid decryption password'}), 400

    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/delete_file/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    if not verify_ownership(filename):
        return jsonify({'error': 'Not authorized - you are not the owner'}), 403
    try:
        # Get environment variables using SecureEnv
        env_vars = secure_env.decrypt_env()
        ssh_host = env_vars.get('TRUENAS_SSH_HOST')
        ssh_user = env_vars.get('TRUENAS_SSH_USER')

        department = session.get('department')
        if not department:
            return jsonify({'error': 'Department not selected'}), 400

        # Get original filename from database first
        file_metadata = FileMetadata.query.filter_by(
            filename=filename,
            department=department
        ).first()
        
        original_filename = file_metadata.original_filename if file_metadata else filename

        # Construct file path
        file_path = f"{DEPARTMENTS_BASE_PATH}/{department}/{filename}"
        app.logger.info(f"Attempting to delete file: {original_filename}")

        # Initialize SSH operations with decrypted credentials
        ssh_ops = SSHOperations(
            host=ssh_host,
            username=ssh_user
        )

        # Attempt to delete the file
        success, message = ssh_ops.delete_file(file_path, secure=False)

        if not success:
            app.logger.error(f"Failed to delete file: {original_filename}")
            return jsonify({'error': f'Failed to delete file: {message}'}), 500

        if file_metadata:
            # Create audit log entry before deleting metadata
            audit_log = DepartmentAuditLog(
                department=department,
                action='FILE_DELETE',
                details=f'Deleted file: {original_filename} (Size: {filesizeformat(file_metadata.size)})',
                user=current_user.name,
                timestamp=datetime.now()
            )
            db.session.add(audit_log)
            
            # Delete metadata and commit both operations
            db.session.delete(file_metadata)
            db.session.commit()
            
            security_logger.log_security_event('file_deletion', {
                'filename': original_filename,
                'department': department,
                'user': current_user.username,
                'secure_wipe': False
            })
            
            return jsonify({'message': f'File {original_filename} deleted successfully'})
        else:
            return jsonify({'message': f'File {original_filename} deleted, no metadata found'})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Delete error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/erase_file/<filename>', methods=['POST'])
@login_required
def erase_file(filename):
    if not verify_ownership(filename):
        return jsonify({'error': 'Not authorized - you are not the owner'}), 403

    try:
        department = session.get('department')
        if not department:
            return jsonify({'error': 'Department not selected'}), 400

        # Get file metadata
        file_metadata = FileMetadata.query.filter_by(
            filename=filename,
            department=department
        ).first()
        
        if not file_metadata:
            return jsonify({'error': 'File not found'}), 404

        # Construct file path
        file_path = f"{DEPARTMENTS_BASE_PATH}/{department}/{filename}"
        app.logger.info(f"Attempting to securely erase: {file_metadata.original_filename}")

        # Initialize SSH with secure environment
        env_vars = secure_env.decrypt_env()
        ssh_ops = SSHOperations(
            host=env_vars.get('TRUENAS_SSH_HOST'),
            username=env_vars.get('TRUENAS_SSH_USER')
        )

        # Attempt secure deletion
        success, message = ssh_ops.delete_file(file_path, secure=True)

        if not success:
            app.logger.error(f"Failed to erase file: {message}")
            return jsonify({'error': f'Failed to erase file: {message}'}), 500

        # Create audit log entry before database operations
        audit_log = DepartmentAuditLog(
            department=department,
            action='FILE_SECURE_ERASE',
            details=f'Securely erased file: {file_metadata.original_filename} using Gutmann method (Size: {filesizeformat(file_metadata.size)})',
            user=current_user.name,
            timestamp=datetime.now()
        )
        db.session.add(audit_log)

        # Delete metadata from database
        db.session.delete(file_metadata)
        
        # Commit both operations
        db.session.commit()
        
        # Log the secure deletion in security log
        security_logger.log_security_event('file_secure_deletion', {
            'filename': file_metadata.original_filename,
            'department': department,
            'user': current_user.username,
            'method': 'Gutmann (35 passes)'
        })
        
        return jsonify({
            'message': f'File {file_metadata.original_filename} securely erased using Gutmann method'
        })

    except Exception as e:
        db.session.rollback()  # Rollback on error
        app.logger.error(f"Secure erase error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/list_files/<department>')
@login_required
def list_files(department):
    headers = {
        "Authorization": f"Bearer {TRUENAS_API_KEY}",
        "Content-Type": "application/json"
    }
    
    department_path = f"{DEPARTMENTS_BASE_PATH}/{department}"
    
    try:
        # List directory contents
        response = requests.post(
            f"{TRUENAS_IP}/api/v2.0/filesystem/listdir",
            headers=headers,
            json={"path": department_path}
        )
        
        if response.status_code == 200:
            files = response.json()
            
            # Create audit log entry
            audit_log = DepartmentAuditLog(
                department=department,
                action='LIST_FILES',
                details=f'Listed department files (Total files: {len(files)})',
                user=current_user.name,
                timestamp=datetime.now()
            )
            db.session.add(audit_log)
            db.session.commit()
            
            return jsonify({
                'path': department_path,
                'files': files
            })
        else:
            # Log failed attempt
            audit_log = DepartmentAuditLog(
                department=department,
                action='LIST_FILES_FAILED',
                details=f'Failed to list files: {response.text}',
                user=current_user.name,
                timestamp=datetime.now()
            )
            db.session.add(audit_log)
            db.session.commit()
            
            return jsonify({
                'error': f"Failed to list files: {response.text}",
                'status_code': response.status_code
            })
            
    except Exception as e:
        # Log error
        try:
            audit_log = DepartmentAuditLog(
                department=department,
                action='LIST_FILES_ERROR',
                details=f'Error listing files: {str(e)}',
                user=current_user.name,
                timestamp=datetime.now()
            )
            db.session.add(audit_log)
            db.session.commit()
        except:
            pass
            
        return jsonify({'error': str(e)})
    
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('department', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/check_admin')
@login_required
def check_admin():
    print("\n=== Check Admin Debug Logs ===")
    print(f"User: {current_user.username}")
    print(f"Is Admin: {current_user.is_admin}")
    return jsonify({'is_admin': current_user.is_admin})

@app.route('/department_logs')
@login_required
def department_logs():
    if not current_user.is_admin:
        return jsonify({
            'success': False,
            'message': 'Admin access required'
        }), 403

    department = session.get('department')
    if not department:
        return jsonify({
            'success': False,
            'message': 'No department selected'
        }), 400

    try:
        # Get ALL logs for the department, ordered by timestamp descending
        logs = DepartmentAuditLog.query.filter_by(department=department)\
            .order_by(DepartmentAuditLog.timestamp.desc())\
            .all()

        log_data = [{
            'action': log.action,
            'details': log.details,
            'user': log.user,
            'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        } for log in logs]

        app.logger.debug(f"Retrieved {len(log_data)} logs for department {department}")

        return jsonify({
            'success': True,
            'logs': log_data
        })

    except Exception as e:
        app.logger.error(f"Error fetching department logs: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error fetching logs: {str(e)}'
        }), 500

@app.route('/add_department', methods=['POST'])
@login_required
def add_department():
    if not current_user.is_admin:
        return jsonify({
            'success': False,
            'message': 'You must be an admin to add departments'
        }), 403

    department_name = request.form.get('department_name')
    password = request.form.get('password')
    
    # Get current dataset path from environment
    env_vars = secure_env.decrypt_env()
    department_base = env_vars.get('DEPARTMENT_DATASET')
    
    # Validate input
    if not department_name or not password:
        return jsonify({
            'success': False,
            'message': 'Department name and password are required'
        }), 400

    # Check if department already exists
    if Department.query.filter_by(department_name=department_name).first():
        return jsonify({
            'success': False,
            'message': 'Department already exists'
        }), 400

    try:
        headers = {
            "Authorization": f"Bearer {TRUENAS_API_KEY}",
            "Content-Type": "application/json"
        }
        
        # Create the department-specific dataset with current base path
        department_dataset_path = f"{department_base}/{department_name}"
        dataset_payload = {
            "name": department_dataset_path,
            "type": "FILESYSTEM",
            "share_type": "SMB"
        }
        
        app.logger.debug(f"Creating dataset with path: {department_dataset_path}")
        app.logger.debug(f"Dataset payload: {dataset_payload}")
        
        response = requests.post(
            f"{TRUENAS_IP}/api/v2.0/pool/dataset",
            headers=headers,
            json=dataset_payload
        )
        
        app.logger.debug(f"TrueNAS API Response: {response.status_code} - {response.text}")
        
        if response.status_code not in [200, 201]:
            raise Exception(f"Failed to create department dataset: {response.text}")

        # Create department in database
        new_department = Department(department_name=department_name)
        new_department.set_password(password)
        db.session.add(new_department)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Department {department_name} created successfully'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Department creation error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Failed to create department: {str(e)}'
        })

@app.route('/delete_department', methods=['POST'])
@login_required
def delete_department():
    if not current_user.is_admin:
        return jsonify({
            'success': False,
            'message': 'You must be an admin to delete departments'
        }), 403

    current_department_name = session.get('department')
    current_password = request.form.get('password')

    app.logger.debug("\n=== Department Delete Debug Logs ===")
    app.logger.debug(f"Attempting to delete department: {current_department_name}")

    # Get current department
    department = Department.query.filter_by(department_name=current_department_name).first()
    if not department:
        return jsonify({
            'success': False,
            'message': 'Department not found'
        }), 404

    # Verify password
    if not department.check_password(current_password):
        return jsonify({
            'success': False,
            'message': 'Current password is incorrect'
        }), 400

    try:
        headers = {
            "Authorization": f"Bearer {TRUENAS_API_KEY}",
            "Content-Type": "application/json"
        }

        # Encode dataset path for API request
        dataset_path = f"Basic/Departments/{current_department_name}"
        encoded_dataset_path = urllib.parse.quote(dataset_path, safe='')

        app.logger.debug(f"Encoded dataset path: {encoded_dataset_path}")

        # Check if dataset exists
        check_response = requests.get(
            f"{TRUENAS_IP}/api/v2.0/pool/dataset/id/{encoded_dataset_path}",
            headers=headers
        )

        app.logger.debug(f"Check dataset response: {check_response.status_code}")
        app.logger.debug(f"Check dataset response text: {check_response.text}")

        if check_response.status_code == 200:
            # Delete the dataset
            delete_response = requests.delete(
                f"{TRUENAS_IP}/api/v2.0/pool/dataset/id/{encoded_dataset_path}",
                headers=headers
            )

            app.logger.debug(f"Delete response status: {delete_response.status_code}")
            app.logger.debug(f"Delete response text: {delete_response.text}")

            if delete_response.status_code not in [200, 204]:
                raise Exception(f"Failed to delete department dataset: {delete_response.text}")

            # Remove from database only if deletion was successful
            db.session.delete(department)
            db.session.commit()

            # Clear session
            session.pop('department', None)

            return jsonify({
                'success': True,
                'message': 'Department deleted successfully',
                'redirect': url_for('select_department')
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Dataset not found on TrueNAS'
            }), 404

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Department deletion error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Failed to delete department: {str(e)}'
        })

@app.route('/update_department', methods=['POST'])
@login_required
def update_department():
    if not current_user.is_admin:
        return jsonify({
            'success': False, 
            'message': 'You must be an admin to modify department settings'
        }), 403

    # Get form data
    new_department_name = request.form.get('department_name')
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    current_department_name = session.get('department')

    app.logger.debug("\n=== Department Update Debug Logs ===")
    app.logger.debug(f"Current department: {current_department_name}")
    app.logger.debug(f"Requested new name: {new_department_name}")

    # Get current department
    current_department = Department.query.filter_by(department_name=current_department_name).first()
    if not current_department:
        return jsonify({
            'success': False, 
            'message': 'Department not found'
        }), 404

    # Verify current password
    if not current_department.check_password(current_password):
        return jsonify({
            'success': False, 
            'message': 'Current password is incorrect'
        }), 400

    try:
        headers = {
            "Authorization": f"Bearer {TRUENAS_API_KEY}",
            "Content-Type": "application/json"
        }

        # Only proceed with rename if name has changed
        if new_department_name != current_department_name:
            # Check if new name already exists
            if Department.query.filter_by(department_name=new_department_name).first():
                return jsonify({
                    'success': False,
                    'message': 'A department with this name already exists'
                }), 400

            # Update dataset paths to match TrueNAS API format
            old_dataset = f"Basic/Departments/{current_department_name}"
            new_dataset = f"Basic/Departments/{new_department_name}"

            app.logger.debug(f"Old dataset: {old_dataset}")
            app.logger.debug(f"New dataset: {new_dataset}")

            # Check if old dataset exists
            dataset_check_url = f"{TRUENAS_IP}/api/v2.0/pool/dataset/id/{urllib.parse.quote(old_dataset, safe='')}"
            app.logger.debug(f"Dataset check URL: {dataset_check_url}")
            
            check_response = requests.get(dataset_check_url, headers=headers)
            app.logger.debug(f"Dataset check response: {check_response.status_code} - {check_response.text}")

            if check_response.status_code != 200:
                raise Exception(f"Dataset '{old_dataset}' not found.")

            # Rename dataset
            rename_payload = {
                "name": new_dataset  # Only the new name is needed in the payload
            }

            # Log the rename payload
            app.logger.debug(f"Rename payload: {rename_payload}")

            # Use the correct endpoint for renaming
            rename_endpoint = f"{TRUENAS_IP}/api/v2.0/pool/dataset/id/{urllib.parse.quote(old_dataset, safe='')}/rename"
            
            response = requests.post(rename_endpoint, headers=headers, json=rename_payload)
            app.logger.debug(f"Rename response: {response.status_code} - {response.text}")

            if response.status_code not in [200, 201]:
                raise Exception(f"Failed to rename dataset: {response.text}")

            # Update database
            current_department.department_name = new_department_name
            session['department'] = new_department_name

        # Update password if provided
        if new_password:
            current_department.set_password(new_password)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Department settings updated successfully'
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Department update error: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Failed to update department: {str(e)}'
        })

if __name__ == "__main__":
    # Prevent duplicate execution caused by the reloader
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        # Print Custom Banner only once (on the main process)
        print("""
╦  ╦╦  ╦╔═╗═╗ ╦
╚╗╔╝╚╗╔╝║╣ ╔╩╦╝ 
 ╚╝  ╚╝ ╚═╝╩ ╚═
Secure File Management System Is Running 
--------------------------------""")

        host = "0.0.0.0"
        port = 5000

        print(f" * Running on all addresses ({host})")
        print(f" * Running on http://127.0.0.1:{port}")
        print(f" * Running on http://192.168.8.192:{port}")
        print("INFO:werkzeug:Press CTRL+C to quit\n")

    try:
        # Start Flask App (WITH Debug Reloader for Auto-Restart)
        app.run(
            host="0.0.0.0",    
            port=5000,      
            debug=True,     # Enables Debug Mode
            use_reloader=True  # Enables Auto-Restart on File Change
        )

    except KeyboardInterrupt:
        print("\nShutting down server...")
    except Exception as e:
        print(f"\nError starting server: {str(e)}")