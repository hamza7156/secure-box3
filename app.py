from flask import Flask, render_template, redirect, request, url_for, session, flash, send_from_directory
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.fernet import Fernet

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

def generate_encryption_key(user_key):
    """ Generate a secure encryption key from user input """
    salt = b'some_salt_value'  # You can generate a random salt for each user
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
    encryption_key = db.Column(db.String(200), nullable=False)  # New field for encryption key



# Create the database (run this once)
with app.app_context():
    db.create_all()

# User dashboard (requires login)
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)

    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    # List files in user's folder
    files = os.listdir(user_folder)
    return render_template('dashboard.html', username=username, files=files)

# File upload functionality
@app.route('/upload', methods=['POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)

    if not os.path.exists(user_folder):
        os.makedirs(user_folder)

    if 'file' not in request.files or 'encryption_key' not in request.form:
        flash('Missing file or encryption key')
        return redirect(url_for('dashboard'))

    file = request.files['file']
    encryption_key = request.form['encryption_key'].encode()  # User-provided key

    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard'))

    try:
        # Ensure encryption key is exactly 32 bytes long (Fernet requirement)
        key = base64.urlsafe_b64encode(encryption_key.ljust(32)[:32])

        # Encrypt the file
        fernet = Fernet(key)
        file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)

        # Save the encrypted file
        filename = secure_filename(file.filename)
        file_path = os.path.join(user_folder, filename)

        with open(file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        flash('File encrypted and uploaded successfully!')
    except Exception as e:
        flash(f'Encryption error: {str(e)}')

    return redirect(url_for('dashboard'))

# File deletion functionality
@app.route('/delete/<filename>', methods=['POST'])
def delete(filename):
    if 'username' not in session:
        return redirect(url_for('login'))

    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
    file_path = os.path.join(user_folder, filename)

    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'{filename} has been deleted.')
    else:
        flash(f'Error: {filename} not found.')

    return redirect(url_for('dashboard'))

# File download functionality
@app.route('/download/<filename>', methods=['POST'])
def download(filename):
    if 'username' not in session:
        return redirect(url_for('login'))

    encryption_key = request.form['encryption_key'].encode()  # User-provided key

    try:
        import base64
        from cryptography.fernet import Fernet

        # Ensure the key is correctly formatted
        key = base64.urlsafe_b64encode(encryption_key.ljust(32)[:32])
        fernet = Fernet(key)

        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['username'])
        file_path = os.path.join(user_folder, filename)

        # Read and decrypt the file
        with open(file_path, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()
            decrypted_data = fernet.decrypt(encrypted_data)

        # Serve the decrypted file as a response
        from flask import Response
        return Response(
            decrypted_data,
            mimetype="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename={filename}'}
        )

    except Exception as e:
        flash(f'Decryption failed: {str(e)}')
        return redirect(url_for('dashboard'))



# User login functionality
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if user exists in the database
        user = User.query.filter_by(username=username).first()
        print(f"User found: {user}")
        if user and bcrypt.check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid login. Please try again.')

    return render_template('login.html')

# User registration functionality
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']  # Get username from form
        password = request.form['password']  # Get password from form

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another one.')
            return redirect(url_for('register'))

        # Create a new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password, encryption_key='')  # Encryption key is not needed now

        # Save user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.')
        return redirect(url_for('login'))

    return render_template('register.html')



# Logout functionality
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))
if __name__ == '__main__':
    app.run(debug=True)