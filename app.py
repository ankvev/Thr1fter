from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3
import os
from dotenv import load_dotenv
import nh3

# ── Environment & app setup ───────────────────────────────────────────────────

load_dotenv()  # reads .env file into environment variables

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise ValueError("ERROR: SECRET_KEY environment variable not found.")

API_KEY = os.getenv('API_KEY', '')  # Google Maps API key

# ── Flask-Login setup ─────────────────────────────────────────────────────────

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'


class User(UserMixin):
    """Minimal user object required by Flask-Login.
    
    Stores id, username, email and admin flag so we can check
    permissions anywhere current_user is available.
    """
    def __init__(self, id, username, email, admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.admin = bool(admin)


@login_manager.user_loader
def load_user(user_id):
    """Reload a user object from the DB for every request.
    
    Flask-Login calls this automatically using the ID stored in the session.
    Returns None if the user no longer exists (e.g. after account deletion).
    """
    conn = sqlite3.connect('thr1fter.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, admin FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return User(row['id'], row['username'], row['email'], row['admin'])
    return None


# ── Decorators ────────────────────────────────────────────────────────────────

def admin_required(f):
    """Route decorator that blocks non-admin users with a 403 flash redirect."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.admin:
            flash('You do not have permission to access that page.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ── Helpers ───────────────────────────────────────────────────────────────────

def sanitise_input(user_input: dict) -> dict:
    """Strip HTML/JS from every string value in the dict using nh3.
    
    Called on all form data before validation or DB writes.
    Numeric fields (latitude, longitude) are excluded from HTML
    sanitisation because nh3 treats decimal strings as invalid HTML and
    returns an empty string, destroying the coordinate values.
    """
    _numeric = {'latitude', 'longitude'}
    return {k: (v if k in _numeric else nh3.clean(v)) for k, v in user_input.items()}


def get_db():
    """Open a SQLite connection with row_factory set to sqlite3.Row.
    
    Remember to call conn.close() when done.
    Using Row lets you access columns by name: row['username'].
    """
    conn = sqlite3.connect('thr1fter.db')
    conn.row_factory = sqlite3.Row
    return conn


# ── Database initialisation ───────────────────────────────────────────────────

def init_db():
    """Create all tables if they don't already exist.
    
    Safe to run on every startup – CREATE TABLE IF NOT EXISTS is a no-op
    when the table already exists.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Users – stores credentials, email and the admin flag
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            admin      BOOL    DEFAULT 0,
            username   TEXT    UNIQUE NOT NULL,
            password   TEXT    NOT NULL,
            email      TEXT    UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Thrift stores – core store record including coordinates for the map
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS thrift_stores (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL,
            address     TEXT    NOT NULL,
            city        TEXT    NOT NULL,
            state       TEXT,
            post_code   TEXT,
            latitude    REAL,
            longitude   REAL,
            phone       TEXT,
            website     TEXT,
            hours       TEXT,
            description TEXT,
            added_by    INTEGER,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (added_by) REFERENCES users(id)
        )
    ''')

    # Categories – one row per store, a boolean column per category type
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            store_id                  INTEGER NOT NULL,
            general_clothing          BOOL DEFAULT 0,
            vintage_retro             BOOL DEFAULT 0,
            y2k                       BOOL DEFAULT 0,
            grunge                    BOOL DEFAULT 0,
            streetwear                BOOL DEFAULT 0,
            designer_luxury_resale    BOOL DEFAULT 0,
            formal_evening            BOOL DEFAULT 0,
            workwear                  BOOL DEFAULT 0,
            sportswear_activewear     BOOL DEFAULT 0,
            childrens_clothing        BOOL DEFAULT 0,
            shoes_footwear            BOOL DEFAULT 0,
            bags_purses               BOOL DEFAULT 0,
            jewellery                 BOOL DEFAULT 0,
            hats_caps                 BOOL DEFAULT 0,
            belts_scarves             BOOL DEFAULT 0,
            furniture                 BOOL DEFAULT 0,
            homewares_kitchenware     BOOL DEFAULT 0,
            antiques                  BOOL DEFAULT 0,
            art_prints                BOOL DEFAULT 0,
            linen_textiles            BOOL DEFAULT 0,
            lamps_lighting            BOOL DEFAULT 0,
            books                     BOOL DEFAULT 0,
            vinyl_music               BOOL DEFAULT 0,
            dvds_vhs_games            BOOL DEFAULT 0,
            collectibles_memorabilia  BOOL DEFAULT 0,
            toys_figurines            BOOL DEFAULT 0,
            op_charity_shop           BOOL DEFAULT 0,
            mixed_goods               BOOL DEFAULT 0,
            electrical_tech           BOOL DEFAULT 0,
            sports_equipment          BOOL DEFAULT 0,
            craft_fabric_sewing       BOOL DEFAULT 0,
            instruments               BOOL DEFAULT 0,
            FOREIGN KEY (store_id) REFERENCES thrift_stores(id)
        )
    ''')

    # Favourites – many-to-many between users and stores
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS favorites (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            store_id   INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id)  REFERENCES users(id),
            FOREIGN KEY (store_id) REFERENCES thrift_stores(id),
            UNIQUE(user_id, store_id)
        )
    ''')

    conn.commit()
    conn.close()


init_db()


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Already authenticated users go straight to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        features = sanitise_input({
            'username': request.form.get('username', ''),
            'password': request.form.get('password', '')
        })

        if not features['username'] or not features['password']:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (features['username'],))
        row = cursor.fetchone()
        conn.close()

        if row and check_password_hash(row['password'], features['password']):
            user = User(row['id'], row['username'], row['email'], row['admin'])
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect username or password.', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        features = sanitise_input({
            'username': request.form.get('username', ''),
            'password': request.form.get('password', ''),
            'email':    request.form.get('email', '')
        })

        # Server-side password policy – mirrors the client-side checks in register.js
        syms = "`~!@#$%^&*()_-+={[}]|\\:;'\"<,.>/?}"
        if (len(features['password']) < 12
                or not any(s in features['password'] for s in syms)
                or not any(c.isdigit() for c in features['password'])):
            flash('Password must be at least 12 characters with a number and a symbol.', 'error')
            return render_template('register.html')

        if len(features['username']) < 3 or any(s in features['username'] for s in syms):
            flash('Username must be at least 3 characters with no special characters.', 'error')
            return render_template('register.html')

        hashed = generate_password_hash(features['password'], method='pbkdf2:sha256')

        conn = get_db()
        cursor = conn.cursor()
        try:
            if features['email']:
                cursor.execute(
                    'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                    (features['username'], hashed, features['email'])
                )
            else:
                cursor.execute(
                    'INSERT INTO users (username, password) VALUES (?, ?)',
                    (features['username'], hashed)
                )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('That username or email is already taken.', 'error')
            return render_template('register.html')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))


# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    cursor = conn.cursor()

    # Fetch this user's favourited stores, newest first, for the right-hand panel
    cursor.execute('''
        SELECT ts.*
        FROM   thrift_stores ts
        JOIN   favorites f ON ts.id = f.store_id
        WHERE  f.user_id = ?
        ORDER  BY f.created_at DESC
    ''', (current_user.id,))
    favourite_stores = [dict(r) for r in cursor.fetchall()]

    # Fetch ALL stores with coordinates for the map markers,
    # flagging which ones this user has favourited
    cursor.execute('''
        SELECT ts.id, ts.name, ts.address, ts.city, ts.state,
               ts.latitude, ts.longitude, ts.phone, ts.website, ts.hours,
               CASE WHEN f.store_id IS NOT NULL THEN 1 ELSE 0 END AS is_favourite
        FROM   thrift_stores ts
        LEFT   JOIN favorites f ON ts.id = f.store_id AND f.user_id = ?
        WHERE  ts.latitude IS NOT NULL AND ts.longitude IS NOT NULL
    ''', (current_user.id,))
    map_stores = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return render_template(
        'dashboard.html',
        username=current_user.username,
        maps_api_key=API_KEY,
        favourite_stores=favourite_stores,
        map_stores=map_stores
    )


# ═══════════════════════════════════════════════════════════════════════════════
# STORES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/stores')
@login_required
def stores():
    conn = get_db()
    cursor = conn.cursor()

    # Pull stores with their category flags and whether the current user
    # has favourited them.  LEFT JOINs ensure stores with no categories row
    # or no favourite still appear.
    cursor.execute('''
        SELECT ts.*,
               c.general_clothing, c.vintage_retro, c.y2k, c.grunge, c.streetwear,
               c.designer_luxury_resale, c.formal_evening, c.workwear,
               c.sportswear_activewear, c.childrens_clothing, c.shoes_footwear,
               c.bags_purses, c.jewellery, c.hats_caps, c.belts_scarves,
               c.furniture, c.homewares_kitchenware, c.antiques, c.art_prints,
               c.linen_textiles, c.lamps_lighting, c.books, c.vinyl_music,
               c.dvds_vhs_games, c.collectibles_memorabilia, c.toys_figurines,
               c.op_charity_shop, c.mixed_goods, c.electrical_tech,
               c.sports_equipment, c.craft_fabric_sewing, c.instruments,
               CASE WHEN f.store_id IS NOT NULL THEN 1 ELSE 0 END AS is_favourite
        FROM   thrift_stores ts
        LEFT   JOIN categories c ON ts.id = c.store_id
        LEFT   JOIN favorites  f ON ts.id = f.store_id AND f.user_id = ?
        ORDER  BY ts.name ASC
    ''', (current_user.id,))

    stores_list = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return render_template('stores.html', stores=stores_list, username=current_user.username)


# ═══════════════════════════════════════════════════════════════════════════════
# FAVOURITES API  (JSON endpoint consumed by stores.js)
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/favourite/<int:store_id>', methods=['POST'])
@login_required
def toggle_favourite(store_id):
    """Toggle favourite status for a store. Returns JSON {is_favourite, store_id}."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        'SELECT id FROM favorites WHERE user_id = ? AND store_id = ?',
        (current_user.id, store_id)
    )
    existing = cursor.fetchone()

    if existing:
        # Already saved – remove it
        cursor.execute(
            'DELETE FROM favorites WHERE user_id = ? AND store_id = ?',
            (current_user.id, store_id)
        )
        is_favourite = False
    else:
        cursor.execute(
            'INSERT INTO favorites (user_id, store_id) VALUES (?, ?)',
            (current_user.id, store_id)
        )
        is_favourite = True

    conn.commit()
    conn.close()
    return jsonify({'is_favourite': is_favourite, 'store_id': store_id})


# ═══════════════════════════════════════════════════════════════════════════════
# SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/settings')
@login_required
def settings():
    return render_template(
        'settings.html',
        username=current_user.username,
        email=current_user.email
    )


@app.route('/settings/update_account', methods=['POST'])
@login_required
def update_account():
    """Update the logged-in user's username and/or email."""
    new_username = nh3.clean(request.form.get('username', '').strip())
    new_email    = nh3.clean(request.form.get('email', '').strip())

    syms = "`~!@#$%^&*()_-+={[}]|\\:;'\"<,.>/?}"
    if len(new_username) < 3 or any(s in new_username for s in syms):
        flash('Invalid username. Must be at least 3 characters, no special characters.', 'error')
        return redirect(url_for('settings'))

    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            'UPDATE users SET username = ?, email = ? WHERE id = ?',
            (new_username, new_email or None, current_user.id)
        )
        conn.commit()
        flash('Account details updated successfully.', 'success')
    except sqlite3.IntegrityError:
        flash('That username or email is already taken.', 'error')
    finally:
        conn.close()

    return redirect(url_for('settings'))


@app.route('/settings/change_password', methods=['POST'])
@login_required
def change_password():
    """Change password after verifying the current one."""
    current_pw = request.form.get('current_password', '')
    new_pw     = request.form.get('new_password', '')
    confirm_pw = request.form.get('confirm_password', '')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()
    conn.close()

    if not check_password_hash(row['password'], current_pw):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('settings'))

    if new_pw != confirm_pw:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('settings'))

    syms = "`~!@#$%^&*()_-+={[}]|\\:;'\"<,.>/?}"
    if (len(new_pw) < 12
            or not any(s in new_pw for s in syms)
            or not any(c.isdigit() for c in new_pw)):
        flash('Password must be 12+ characters with at least one number and one symbol.', 'error')
        return redirect(url_for('settings'))

    hashed = generate_password_hash(new_pw, method='pbkdf2:sha256')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed, current_user.id))
    conn.commit()
    conn.close()
    flash('Password changed successfully.', 'success')
    return redirect(url_for('settings'))


@app.route('/settings/delete_account', methods=['POST'])
@login_required
def delete_account():
    """Permanently delete the current user's account and all their data."""
    password = request.form.get('confirm_delete_password', '')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE id = ?', (current_user.id,))
    row = cursor.fetchone()

    if not check_password_hash(row['password'], password):
        conn.close()
        flash('Incorrect password. Account not deleted.', 'error')
        return redirect(url_for('settings'))

    uid = current_user.id
    # Delete related records before the user row to avoid FK constraint issues
    cursor.execute('DELETE FROM favorites WHERE user_id = ?', (uid,))
    cursor.execute('DELETE FROM users     WHERE id = ?',      (uid,))
    conn.commit()
    conn.close()

    logout_user()
    flash('Your account has been permanently deleted.', 'success')
    return redirect(url_for('home'))


# ═══════════════════════════════════════════════════════════════════════════════
# ADD STORE
# ═══════════════════════════════════════════════════════════════════════════════

# Full list of category column names – used for both INSERT and filter logic
CATEGORY_FIELDS = [
    'general_clothing', 'vintage_retro', 'y2k', 'grunge', 'streetwear',
    'designer_luxury_resale', 'formal_evening', 'workwear', 'sportswear_activewear',
    'childrens_clothing', 'shoes_footwear', 'bags_purses', 'jewellery',
    'hats_caps', 'belts_scarves', 'furniture', 'homewares_kitchenware',
    'antiques', 'art_prints', 'linen_textiles', 'lamps_lighting', 'books',
    'vinyl_music', 'dvds_vhs_games', 'collectibles_memorabilia', 'toys_figurines',
    'op_charity_shop', 'mixed_goods', 'electrical_tech', 'sports_equipment',
    'craft_fabric_sewing', 'instruments'
]


@app.route('/add_store', methods=['GET', 'POST'])
@login_required
def add_store():
    if request.method == 'POST':
        features = sanitise_input({
            'name':        request.form.get('name', ''),
            'address':     request.form.get('address', ''),
            'city':        request.form.get('city', ''),
            'state':       request.form.get('state', ''),
            'post_code':   request.form.get('post_code', ''),
            'latitude':    request.form.get('latitude', ''),
            'longitude':   request.form.get('longitude', ''),
            'phone':       request.form.get('phone', ''),
            'website':     request.form.get('website', ''),
            'hours':       request.form.get('hours', ''),
            'description': request.form.get('description', '')
        })

        if not features['name'] or not features['address'] or not features['city']:
            flash('Store name, address, and city are required.', 'error')
            return render_template('add_store.html', maps_api_key=API_KEY)

        # Parse coordinates – None if missing or not valid numbers
        try:
            lat = float(features['latitude'])  if features['latitude']  else None
            lng = float(features['longitude']) if features['longitude'] else None
        except ValueError:
            lat, lng = None, None

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO thrift_stores
                    (name, address, city, state, post_code, latitude, longitude,
                     phone, website, hours, description, added_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                features['name'], features['address'], features['city'],
                features['state'], features['post_code'], lat, lng,
                features['phone'], features['website'], features['hours'],
                features['description'], current_user.id
            ))
            store_id = cursor.lastrowid

            # Build the categories row – 1 for each selected checkbox, 0 otherwise
            selected = request.form.getlist('categories')
            cat_vals = [1 if f in selected else 0 for f in CATEGORY_FIELDS]
            cols = ', '.join(['store_id'] + CATEGORY_FIELDS)
            placeholders = ', '.join(['?'] * (1 + len(CATEGORY_FIELDS)))
            cursor.execute(
                f'INSERT INTO categories ({cols}) VALUES ({placeholders})',
                [store_id] + cat_vals
            )

            conn.commit()
            flash('Store added successfully!', 'success')
            return redirect(url_for('stores'))

        except Exception as e:
            flash(f'Error adding store: {e}', 'error')
            return render_template('add_store.html', maps_api_key=API_KEY)
        finally:
            conn.close()

    return render_template('add_store.html', username=current_user.username, maps_api_key=API_KEY)


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN PANEL
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/admin')
@login_required
@admin_required
def admin():
    """Main admin dashboard – lists all users and stores."""
    conn = get_db()
    cursor = conn.cursor()

    # All users with store count
    cursor.execute('''
        SELECT u.*,
               (SELECT COUNT(*) FROM thrift_stores WHERE added_by = u.id) AS store_count
        FROM   users u
        ORDER  BY u.created_at DESC
    ''')
    users = [dict(r) for r in cursor.fetchall()]

    # All stores with the username of whoever added them
    cursor.execute('''
        SELECT ts.*,
               u.username AS added_by_username
        FROM   thrift_stores ts
        LEFT   JOIN users u ON ts.added_by = u.id
        ORDER  BY ts.created_at DESC
    ''')
    all_stores = [dict(r) for r in cursor.fetchall()]

    conn.close()

    return render_template(
        'admin.html',
        users=users,
        all_stores=all_stores
    )


@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
@admin_required
def admin_toggle_admin(user_id):
    """Flip the admin flag for a user. Prevents an admin from removing their own flag."""
    if user_id == current_user.id:
        flash('You cannot change your own admin status.', 'error')
        return redirect(url_for('admin'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT admin, username FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        flash('User not found.', 'error')
        return redirect(url_for('admin'))

    new_status = 0 if row['admin'] else 1
    cursor.execute('UPDATE users SET admin = ? WHERE id = ?', (new_status, user_id))
    conn.commit()
    conn.close()

    action = 'granted admin to' if new_status else 'removed admin from'
    flash(f'Successfully {action} {row["username"]}.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    """Delete a user and all their associated data."""
    if user_id == current_user.id:
        flash('You cannot delete your own account from the admin panel.', 'error')
        return redirect(url_for('admin'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        flash('User not found.', 'error')
        return redirect(url_for('admin'))

    username = row['username']
    # Clean up all user data to avoid orphaned records
    cursor.execute('DELETE FROM favorites     WHERE user_id  = ?', (user_id,))
    cursor.execute('DELETE FROM thrift_stores WHERE added_by = ?', (user_id,))
    cursor.execute('DELETE FROM users         WHERE id       = ?', (user_id,))
    conn.commit()
    conn.close()

    flash(f'User "{username}" and all their data have been deleted.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/store/<int:store_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_store(store_id):
    """Delete a store along with its categories and favourites."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT name FROM thrift_stores WHERE id = ?', (store_id,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        flash('Store not found.', 'error')
        return redirect(url_for('admin'))

    name = row['name']
    # Remove dependent records before deleting the store
    cursor.execute('DELETE FROM favorites     WHERE store_id = ?', (store_id,))
    cursor.execute('DELETE FROM categories    WHERE store_id = ?', (store_id,))
    cursor.execute('DELETE FROM thrift_stores WHERE id       = ?', (store_id,))
    conn.commit()
    conn.close()

    flash(f'Store "{name}" has been deleted.', 'success')
    return redirect(url_for('admin'))


if __name__ == '__main__':
    app.run(debug=True)