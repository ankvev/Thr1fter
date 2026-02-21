from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from dotenv import load_dotenv
import bleach

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise ValueError("ERROR: SECRET_KEY environment variable not found.")


# Load API key from environment
API_KEY = os.getenv('API_KEY', '')


# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'


# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

# Sanitise user input
def sanitise_input(userInput : list):
    for key in userInput.keys():
        userInput[key] = bleach.clean(userInput[key])
    return userInput


# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('thr1fter.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1], user_data[2])
    return None


def init_db():
    conn = sqlite3.connect('thr1fter.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Thrift stores table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS thrift_stores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            city TEXT NOT NULL,
            state TEXT,
            post_code TEXT,
            latitude REAL,
            longitude REAL,
            phone TEXT,
            website TEXT,
            hours TEXT,
            description TEXT,
            added_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (added_by) REFERENCES users(id)
        )
    ''')
    
    # User favorites/saved stores
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS favorites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            store_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (store_id) REFERENCES thrift_stores(id),
            UNIQUE(user_id, store_id)
        )
    ''')
    
    # Reviews
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            store_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            rating INTEGER CHECK(rating >= 1 AND rating <= 5),
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (store_id) REFERENCES thrift_stores(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()

init_db()


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    # If user is already logged in, redirect to home
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == "POST":
        features = {
        "username" : request.form.get('username'),
        "password" : request.form.get('password')
        }

        features = sanitise_input(features)

        # Validate input
        if not features["username"] or not features["password"]:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        conn = sqlite3.connect('thr1fter.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (features["username"],))
        user_data = cursor.fetchone()
        conn.close()
        
        # Check if user exists and password is correct
        if user_data and check_password_hash(user_data[2], features["password"]):
            # Create User object and log them in
            user = User(user_data[0], user_data[1], user_data[3])
            login_user(user)
            flash('Login successful!', 'success')
            
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect username or password.', 'error')
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect('/')
    
    if request.method == 'POST':
        features = {
        "username" : request.form.get('username'),
        "password" : request.form.get('password'),
        "email" : request.form.get('email')
        }

        features = sanitise_input(features)
        
        # Server-side validation
        sym="!@#$%^&"
        if len(features["password"]) < 12 or not ((features["password"]).isalnum()) or not any(symbol in features["password"] for symbol in sym):
            flash('Invalid password input.', 'error')
            return render_template('register.html')
        
        if len(features["username"]) < 3 or any(symbol in features["password"] for symbol in sym):
            flash('Invalid username input', 'error')
            return render_template('register.html')
        
        # Hash Password
        hashed_password = generate_password_hash(features["password"], method='pbkdf2:sha256')
        
        conn = sqlite3.connect('thr1fter.db')
        cursor = conn.cursor()
        

        try:
            cursor.execute("SELECT * FROM users WHERE username = ?", (features["username"], ))
            result = cursor.fetchone()
            print(result)
            if features["email"]:
                cursor.execute(
                    'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                    (features["username"], hashed_password, features["email"])
                )
            else:
                cursor.execute(
                    'INSERT INTO users (username, password) VALUES (?, ?)',
                    (features["username"], hashed_password)
                )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            conn.close()
            return redirect('/login')
            
        except sqlite3.IntegrityError as e:
            print(e)
            conn.close()
            flash('Username or email already exists.', 'error')
            return render_template('register.html')
    
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))  


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/stores')
@login_required
def stores():
    conn = sqlite3.connect('thr1fter.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM thrift_stores ORDER BY name')
    stores_data = cursor.fetchall()
    conn.close()
    
    # Convert to list of dictionaries for easier use in template
    stores_list = []
    for store in stores_data:
        stores_list.append({
            'id': store[0],
            'name': store[1],
            'address': store[2],
            'phone': store[3],
            'website': store[4],
            'hours': store[5],
            'description': store[6],
            'added_by': store[7],
        })
    
    return render_template('stores.html', stores=stores_list, username=current_user.username)

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', username=current_user.username)

@app.route('/add_store', methods=['GET', 'POST'])
@login_required
def add_store():
    if request.method == 'POST':

        features = {
        "name" : request.form.get('name'),
        "address" : request.form.get('address'),
        "city" : request.form.get('city'),
        "state" : request.form.get('state'),
        "post_code" : request.form.get('post_code'),
        "latitude" : request.form.get('latitude'),
        "longitude" : request.form.get('longitude'),
        "phone" : request.form.get('phone'),
        "website" : request.form.get('website'),
        "hours" : request.form.get('hours'),
        "description" : request.form.get('description')
        }

        features = sanitise_input(features)

        # Validate required fields
        if not features["name"] or not features["address"] or not features["city"]:
            flash('Please fill in at least the store name, address, and city.', 'error')
            return render_template('add_store.html', maps_api_key=API_KEY)
        
        # Convert coordinates to float
        try:
            lat = float(features["latitude"]) if features["latitude"] else None
            lng = float(features["longitude"]) if features["longitude"] else None
        except (ValueError, TypeError):
            lat = None
            lng = None
        
        conn = sqlite3.connect('thr1fter.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO thrift_stores 
                (name, address, city, state, post_code, latitude, longitude, 
                 phone, website, hours, description, added_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (features["name"], features["address"], features["city"], features["state"], features["post_code"], lat, lng,
                  features["phone"], features["website"], features["hours"], features["description"], current_user.id))
            conn.commit()
            flash('Store added successfully!', 'success')
            conn.close()
            return redirect(url_for('stores'))
        except Exception as e:
            conn.close()
            flash(f'Error adding store: {str(e)}', 'error')
            return render_template('add_store.html', maps_api_key=API_KEY)
    
    # Pass API key to template
    return render_template('add_store.html', username=current_user.username, maps_api_key=API_KEY)


if __name__ == '__main__':
    app.run(debug=True)