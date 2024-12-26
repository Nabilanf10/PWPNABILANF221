from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Konfigurasi database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inisialisasi database
db = SQLAlchemy(app)

# Inisialisasi Flask-Migrate
migrate = Migrate(app, db)

# Model User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    email = db.Column(db.String(200), nullable=False, unique=True)  # Kolom email
    password = db.Column(db.String(200), nullable=False)

# Halaman utama
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Halaman registrasi
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')

        # Validasi username dan email
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))

        # Tambahkan user ke database
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful, please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

# Halaman login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid username or password', 'danger')

    return render_template('login.html')

# Halaman dashboard
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('login'))

    users = User.query.all()
    return render_template('dashboard.html', users=users)

# Tambah user
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except:
            flash('Error adding user.', 'danger')
    return render_template('add_user.html')

# Edit user
@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    if 'user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('login'))

    user = User.query.get_or_404(id)

    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'], method='sha256')

        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_user.html', user=user)

# Hapus user
@app.route('/delete_user/<int:id>', methods=['POST'])
def delete_user(id):
    if 'user_id' not in session:
        flash('Please login first', 'warning')
        return redirect(url_for('login'))

    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('dashboard'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)