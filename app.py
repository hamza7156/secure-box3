from flask import Flask, render_template, redirect, Response, request, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import os
from pyotp import TOTP, random_base32
from qrcode import make as make_qr
from io import BytesIO
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FileField, BooleanField
from wtforms.validators import DataRequired
import base64
import hashlib
from cryptography.fernet import Fernet
import logging
import zlib
from collections import defaultdict
from time import time

# In-memory store for login attempts (IP: {count, timestamp})
login_attempts = defaultdict(lambda: {'count': 0, 'timestamp': 0})
ATTEMPT_LIMIT = 10
TIME_WINDOW = 60  # 1 minute for testing

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with a strong key
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['WTF_CSRF_ENABLED'] = True
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# Initialize Flask-Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day"]
)

# Storage limit: 15MB in bytes
STORAGE_LIMIT = 15 * 1024 * 1024  # 15,728,640 bytes

@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Too many login attempts. Please wait a minute before trying again.")
    logger.warning(f"Rate limit exceeded for IP: {request.remote_addr}")
    return redirect(url_for('login'))

# Set up logging
logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Define allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_encryption_key(user_key):
    salt = b'some_salt_value'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(user_key.encode()))
    return key.decode()

# Database model for users
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    secret_key = db.Column(db.String(32), nullable=True)

# Form classes
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UploadForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])
    encryption_key = StringField('Encryption Key', validators=[DataRequired()])
    submit = SubmitField('Upload')

class DownloadForm(FlaskForm):
    encryption_key = StringField('Encryption Key', validators=[DataRequired()])
    submit = SubmitField('Download')

class DeleteForm(FlaskForm):
    submit = SubmitField('Delete')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    enable_2fa = BooleanField('Enable 2FA with Google Authenticator')
    submit = SubmitField('Register')

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        enable_2fa = form.enable_2fa.data

        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash('Username must contain only letters, numbers, or underscores.')
            return redirect(url_for('register'))
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$', password):
            flash('Password must be at least 8 characters and include one uppercase letter, one lowercase letter, one number, and one special character (!@#$%^&*).')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another one.')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        secret_key = random_base32() if enable_2fa else None
        new_user = User(username=username, password=hashed_password, secret_key=secret_key)
        db.session.add(new_user)
        db.session.commit()

        if enable_2fa:
            totp = TOTP(secret_key)
            qr_uri = totp.provisioning_uri(username, issuer_name="SecureBox")
            qr = make_qr(qr_uri)
            buffer = BytesIO()
            qr.save(buffer, format="PNG")
            qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')
            return render_template('show_qr.html', qr_code=qr_code, username=username)
        else:
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
    current_time = time()
    
    # Initialize or reset attempts on GET request if time window has elapsed
    if request.method == 'GET':
        if ip not in login_attempts or (current_time - login_attempts[ip]['timestamp'] > TIME_WINDOW):
            login_attempts[ip] = {'count': 0, 'timestamp': current_time}
    
    remaining_attempts = max(0, ATTEMPT_LIMIT - login_attempts[ip]['count'])
    form = LoginForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        if login_attempts[ip]['count'] >= ATTEMPT_LIMIT:
            flash("Too many login attempts. Please wait 1 minute before trying again.")
            logger.warning(f"Rate limit exceeded for IP: {ip}")
        else:
            username = form.username.data
            password = form.password.data
            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password, password):
                if user.secret_key:
                    session['temp_username'] = username
                    return redirect(url_for('verify_2fa'))
                else:
                    session['username'] = username
                    flash('Login successful!')
                    logger.info(f"User {username} logged in successfully")
                    login_attempts[ip] = {'count': 0, 'timestamp': 0}  # Reset on success
                    return redirect(url_for('dashboard'))
            else:
                login_attempts[ip]['count'] += 1
                login_attempts[ip]['timestamp'] = current_time
                flash('Invalid login. Please try again.')
                logger.warning(f"Failed login attempt for username: {username}")
    
    # Update remaining attempts after POST processing
    remaining_attempts = max(0, ATTEMPT_LIMIT - login_attempts[ip]['count'])
    return render_template('login.html', form=form, remaining_attempts=remaining_attempts, ATTEMPT_LIMIT=ATTEMPT_LIMIT)

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'temp_username' not in session:
        return redirect(url_for('login'))
    username = session['temp_username']
    user = User.query.filter_by(username=username).first()
    if request.method == 'POST':
        otp = request.form['otp']
        totp = TOTP(user.secret_key)
        if totp.verify(otp):
            session.pop('temp_username', None)
            session['username'] = username
            flash('Login successful!')
            logger.info(f"User {username} logged in successfully with 2FA")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP. Please try again.')
    return render_template('verify_2fa.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    
    # Calculate storage usage
    files = os.listdir(user_folder)
    total_size = sum(os.path.getsize(os.path.join(user_folder, f)) for f in files if os.path.isfile(os.path.join(user_folder, f)))
    usage_percentage = min((total_size / STORAGE_LIMIT) * 100, 100) if STORAGE_LIMIT > 0 else 0  # Cap at 100%
    storage_used_mb = total_size / (1024 * 1024)  # Convert bytes to MB
    storage_limit_mb = STORAGE_LIMIT / (1024 * 1024)  # Convert bytes to MB
    
    upload_form = UploadForm()
    download_form = DownloadForm()
    delete_form = DeleteForm()
    return render_template('dashboard.html', username=username, files=files, upload_form=upload_form, 
                           download_form=download_form, delete_form=delete_form, total_size=total_size, 
                           storage_limit=STORAGE_LIMIT, usage_percentage=usage_percentage, 
                           storage_used_mb=storage_used_mb, storage_limit_mb=storage_limit_mb)

@app.route('/upload', methods=['POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    form = UploadForm()
    
    if form.validate_on_submit():
        file = form.file.data
        encryption_key = form.encryption_key.data
        if file.filename == '':
            flash('No file selected')
            return redirect(url_for('dashboard'))
        if not allowed_file(file.filename):
            flash('File type not allowed. Only txt, pdf, png, jpg, jpeg, gif, doc, docx are permitted.')
            return redirect(url_for('dashboard'))
        
        # Check storage limit
        total_size = sum(os.path.getsize(os.path.join(user_folder, f)) for f in os.listdir(user_folder) if os.path.isfile(os.path.join(user_folder, f)))
        file_content = file.read()
        file_size = len(file_content)
        file.seek(0)  # Reset file pointer after reading
        
        if total_size + file_size > STORAGE_LIMIT:
            flash('Storage limit of 15MB exceeded. Upgrade your plan to add more files.')
            return redirect(url_for('dashboard'))
        
        try:
            combined = (username + encryption_key).encode()
            key = base64.urlsafe_b64encode(hashlib.sha256(combined).digest())
            # Selective compression based on file type
            filename = secure_filename(file.filename)
            extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            compressible_types = {'txt', 'doc', 'docx'}
            if extension in compressible_types:
                file_data = zlib.compress(file_content, level=9)  # Max compression level
                logger.info(f"Compressed {filename} from {file_size} to {len(file_data)} bytes")
            else:
                file_data = file_content  # No compression for already-compressed types
                logger.info(f"Skipped compression for {filename} (already compressed type)")
            
            encrypted_data = Fernet(key).encrypt(file_data)
            file_path = os.path.join(user_folder, filename)
            with open(file_path, "wb") as encrypted_file:
                encrypted_file.write(encrypted_data)
            flash('File processed and uploaded successfully!')
        except Exception as e:
            logger.error(f"Upload failed for {username}: {str(e)}")
            flash('An error occurred while uploading the file. Please try again.')
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>', methods=['POST'])
def download(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    form = DownloadForm()
    
    if form.validate_on_submit():
        encryption_key = form.encryption_key.data
        try:
            combined = (username + encryption_key).encode()
            key = base64.urlsafe_b64encode(hashlib.sha256(combined).digest())
            fernet = Fernet(key)
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
            file_path = os.path.join(user_folder, filename)
            with open(file_path, "rb") as encrypted_file:
                encrypted_data = encrypted_file.read()
                decrypted_data = fernet.decrypt(encrypted_data)
            
            # Conditional decompression based on file type
            extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            compressible_types = {'txt', 'doc', 'docx'}
            if extension in compressible_types:
                decompressed_data = zlib.decompress(decrypted_data)
                logger.info(f"Decompressed {filename} for download")
            else:
                decompressed_data = decrypted_data  # No decompression needed
                logger.info(f"Skipped decompression for {filename} (uncompressed type)")
            
            return Response(
                decompressed_data,
                mimetype="application/octet-stream",
                headers={"Content-Disposition": f'attachment; filename={filename}'}
            )
        except Exception as e:
            logger.error(f"Download failed for {username}, file {filename}: {str(e)}")
            flash('An error occurred while downloading the file. Please check your encryption key and try again.')
    return redirect(url_for('dashboard'))

@app.route('/delete/<filename>', methods=['POST'])
def delete(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    form = DeleteForm()
    
    if form.validate_on_submit():
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
        file_path = os.path.join(user_folder, filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            flash(f'{filename} has been deleted.')
        else:
            flash(f'Error: {filename} not found.')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/error_log')
def error_log():
    logger.debug(f"Session data: {session}")
    if 'username' not in session:
        logger.warning("No username in session, redirecting to login")
        return redirect(url_for('login'))
    
    username = session['username']
    logger.debug(f"Accessing error log for user: {username}")
    try:
        with open('app.log', 'r') as log_file:
            errors = [line.strip() for line in log_file if f"failed for {username}" in line][-5:]
            user_errors = []
            for error in errors:
                message = error.split(': ', 1)[1] if ': ' in error else error
                user_errors.append(f"Error: {message}")
    except FileNotFoundError:
        user_errors = ["No error logs found."]
    except Exception as e:
        logger.error(f"Error log retrieval failed for {username}: {str(e)}")
        user_errors = ["An error occurred while retrieving logs."]

    return render_template('error_log.html', errors=user_errors)
# Create the database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get('FLASK_DEBUG', 'False') == 'True')