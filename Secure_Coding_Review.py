from flask import Flask, request, redirect, url_for, session, jsonify, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_talisman import Talisman
import sqlite3
import pyotp
import smtplib
import secrets
import logging
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')  # Use environment variable for secret key

# Initialize Flask-Limiter
limiter = Limiter(app, key_func=lambda: request.remote_addr)

# Initialize Flask-Talisman for security headers
Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
})

# Configure logging
logging.basicConfig(filename='user_activity.log', level=logging.INFO)

# Database connection
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# Send OTP via email
def send_otp(email, otp):
    with smtplib.SMTP('smtp.example.com') as server:  # Replace with your SMTP server
        server.login('your_email@example.com', 'password')  # Replace with your email and password
        server.sendmail('your_email@example.com', email, f'Subject: Your OTP\n\n{otp}')

# User registration
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']
    
    hashed_password = generate_password_hash(password)
    
    conn = get_db_connection()
    conn.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, hashed_password, email))
    conn.commit()
    conn.close()
    
    return redirect(url_for('login'))

# User login
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username = request.form['username']
    password = request.form['password']
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if user and check_password_hash(user['password'], password):
        # Generate OTP
        totp = pyotp.TOTP('base32secret3232')  # Use a secure method to store the secret
        otp = totp.now()
        send_otp(user['email'], otp)
        session['user_id'] = user['id']
        return redirect(url_for('verify_otp'))
    else:
        return 'Invalid credentials', 401

# Verify OTP
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    otp = request.form['otp']
    user_id = session.get('user_id')
    
    if user_id:
        totp = pyotp.TOTP('base32secret3232')  # Use the same secret as above
        if totp.verify(otp):
            return redirect(url_for('profile'))
        else:
            return 'Invalid OTP', 401
    return redirect(url_for('login'))

# User profile
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    logging.info(f'User  {session["user_id"]} accessed their profile.')
    return 'Welcome to your profile!'

# Password reset request
@app.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.form['email']
    token = secrets.token_urlsafe()
    # Store token in the database with an expiration time (not implemented here)
    send_reset_email(email, token)
    return 'Check your email for the password reset link.'

# Send password reset email
def send_reset_email(email, token):
    reset_link = url_for('reset_with_token', token=token, _external=True)
    # Send email logic...

# Secure file upload
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    
    # Validate file type (e.g., only allow images)
    # if not allowed_file(file.filename):