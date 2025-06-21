from flask import Flask, render_template, redirect, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Replace with a secure random string in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(100), nullable=False)
    app_username = db.Column(db.String(100), nullable=False)
    email_used = db.Column(db.String(100), nullable=False)
    password_used = db.Column(db.String, nullable=False)  # Store as hashed

class UserLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

with app.app_context():
    db.create_all()
    # Create a default admin account if not exists
    if not UserLogin.query.filter_by(username='admin').first():
        hashed = generate_password_hash('admin123')
        db.session.add(UserLogin(username='admin', password_hash=hashed))
        db.session.commit()

# 🔒 Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = UserLogin.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user'] = username
            return redirect('/')
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

# 🔐 Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

# 🔐 Protect routes
def login_required(route_function):
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            return redirect('/login')
        return route_function(*args, **kwargs)
    wrapper.__name__ = route_function.__name__
    return wrapper

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    users = []
    search_term = ''
    if request.method == 'POST':
        search_term = request.form['name']
        users = User.query.filter(User.app_name.like(f"%{search_term}%")).all()
    return render_template('index.html', users=users, search_term=search_term)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        new_user = User(
            app_name=request.form['app_name'],
            app_username=request.form['username'],
            email_used=request.form['email'],
            password_used=generate_password_hash(request.form['password'])  # Hashing
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect('/')
    return render_template('add.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.app_name = request.form['app_name']
        user.app_username = request.form['username']
        user.email_used = request.form['email']
        new_pass = request.form['password']
        if not check_password_hash(user.password_used, new_pass):
            user.password_used = generate_password_hash(new_pass)
        db.session.commit()
        return redirect('/')
    return render_template('edit.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
