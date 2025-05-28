from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import hashlib, base64
from cryptography.fernet import Fernet
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'rahasia-super-aman'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'hasil_enkripsi'
DECRYPTED_FOLDER = 'hasil_dekripsi'
KEY_FILE = 'kunci_manual.key'
TEXT_KEY_FILE = 'kunci_manual_text.txt'

for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

def log_aktivitas(pesan):
    with open("log_aktivitas.txt", "a") as f:
        waktu = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{waktu}] {pesan}\n")

def buat_kunci_manual(teks_kunci):
    hash_kunci = hashlib.sha256(teks_kunci.encode()).digest()
    kunci = base64.urlsafe_b64encode(hash_kunci)
    with open(KEY_FILE, "wb") as f:
        f.write(kunci)
    with open(TEXT_KEY_FILE, "w") as f:
        f.write(teks_kunci)
    return kunci

def baca_kunci():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    return None

@app.route('/')
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])  # Ambil user dari database
        return render_template('index.html', user=user)
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(email=email).first():
            flash('Email sudah terdaftar.', 'danger')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password)
        new_user = User(email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash('Registrasi berhasil. Silakan login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login berhasil!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Email atau password salah.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logout berhasil.', 'info')
    return redirect(url_for('login'))

@app.route('/buat-kunci', methods=['POST'])
def buat_kunci():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    teks = request.form.get('teks_kunci')
    if teks and len(teks) >= 8:
        buat_kunci_manual(teks)
        flash('Kunci berhasil dibuat!', 'success')
    else:
        flash('Teks kunci minimal 8 karakter.', 'danger')
    return redirect(url_for('index'))

@app.route('/enkripsi', methods=['POST'])
def enkripsi():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = request.files['file']
    if file and file.filename:
        kunci = baca_kunci()
        if not kunci:
            flash('Kunci belum tersedia. Buat dulu!', 'danger')
            return redirect(url_for('index'))

        filename = file.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        with open(filepath, 'rb') as f:
            data = f.read()

        fernet = Fernet(kunci)
        encrypted = fernet.encrypt(data)

        encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename + '.encrypted')
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted)

        log_aktivitas(f"User {session['user_id']} mengenkripsi {filename}")
        return send_file(encrypted_path, as_attachment=True)

    flash('File tidak valid.', 'danger')
    return redirect(url_for('index'))

@app.route('/dekripsi', methods=['POST'])
def dekripsi():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file = request.files['file']
    output_name = request.form.get('output_name')
    if file and file.filename and output_name:
        kunci = baca_kunci()
        if not kunci:
            flash('Kunci belum tersedia. Buat dulu!', 'danger')
            return redirect(url_for('index'))

        filename = file.filename
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        with open(filepath, 'rb') as f:
            data = f.read()

        try:
            fernet = Fernet(kunci)
            decrypted = fernet.decrypt(data)
        except Exception as e:
            flash(f'Dekripsi gagal: {str(e)}', 'danger')
            return redirect(url_for('index'))

        decrypted_path = os.path.join(DECRYPTED_FOLDER, output_name)
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted)

        log_aktivitas(f"User {session['user_id']} mendekripsi {filename}")
        return send_file(decrypted_path, as_attachment=True)

    flash('Input tidak lengkap.', 'danger')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
