from flask import Flask, redirect, render_template, request, jsonify, session
from functools import wraps
import sqlite3
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room
from datetime import timedelta

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

app.secret_key = "mic-cheque-1-2"

# Keep the session alive across page refreshes instead of losing login state
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=1)
# Don't let Flask re-read templates from disk on every single request
app.config["TEMPLATES_AUTO_RELOAD"] = False


# =====================================
# DECORATOR (defined first, before use)
# =====================================

def login_required(role=None, api=False):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                if api:
                    return jsonify({"success": False, "message": "Not logged in"}), 401
                return redirect("/login")
            if role and session.get("role") != role:
                if api:
                    return jsonify({"success": False, "message": "Not authorized"}), 403
                return redirect("/login")
            return f(*args, **kwargs)
        return wrapper
    return decorator


def get_db():
    conn = sqlite3.connect("laundry.db")
    conn.row_factory = sqlite3.Row
    return conn


# =====================================
# DATABASE INITIALIZATION
# =====================================

def init_db():
    conn = sqlite3.connect("laundry.db")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'CUSTOMER'
    )
    """)

    # orders now tracks which user placed it, so customers only see their own
    c.execute("""
    CREATE TABLE IF NOT EXISTS orders(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        customer TEXT,
        phone TEXT,
        service TEXT,
        status TEXT DEFAULT 'Pending',
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    c.execute(
        "INSERT OR IGNORE INTO users (fullname, username, password, role) VALUES (?, ?, ?, ?)",
        ('System Administrator', 'admin', generate_password_hash('admin123'), 'ADMIN')
    )

    conn.commit()
    conn.close()


# =====================================
# AUTH ROUTES
# =====================================

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        username = data.get('username', '')
        password = data.get('password', '')

        conn = sqlite3.connect("laundry.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session.permanent = True
            session['user_id'] = user[0]
            session['fullname'] = user[1]
            session['role'] = user[4]

            return jsonify({"success": True, "role": user[4]})

        return jsonify({"success": False, "message": "Invalid username or password"})

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json()

        fullname = data.get('fullname')
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'CUSTOMER')

        if not fullname or not username or not password:
            return jsonify({"success": False, "message": "Missing required fields"})

        try:
            conn = sqlite3.connect("laundry.db")
            c = conn.cursor()

            hashed_password = generate_password_hash(password)

            # This now correctly inserts into the users table (it was
            # previously inserting into `orders` with undefined variables)
            c.execute(
                """
                INSERT INTO users (fullname, username, password, role)
                VALUES (?, ?, ?, ?)
                """,
                (fullname, username, hashed_password, role)
            )
            conn.commit()
            conn.close()

            return jsonify({"success": True, "message": "Account created successfully"})

        except sqlite3.IntegrityError:
            return jsonify({"success": False, "message": "Username already exists"})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# =====================================
# CUSTOMER DASHBOARD
# =====================================

@app.route('/customer')
@login_required(role="CUSTOMER")
def customer_dashboard():
    conn = sqlite3.connect("laundry.db")
    c = conn.cursor()
    c.execute(
        "SELECT * FROM orders WHERE user_id=? ORDER BY id DESC",
        (session['user_id'],)
    )
    orders = c.fetchall()
    conn.close()
    return render_template("customer_dashboard.html", orders=orders, fullname=session.get('fullname'))


# =====================================
# ADMIN DASHBOARD
# =====================================

@app.route('/admin')
@login_required(role="ADMIN")
def admin_dashboard():
    conn = sqlite3.connect("laundry.db")
    c = conn.cursor()
    c.execute("SELECT * FROM orders")
    orders = c.fetchall()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()
    return render_template("admin_dashboard.html", orders=orders, users=users, fullname=session.get('fullname'))


# =====================================
# ORDER API
# =====================================

@app.route('/orders', methods=['GET'])
@login_required(api=True)
def get_orders():
    conn = sqlite3.connect("laundry.db")
    c = conn.cursor()
    c.execute("SELECT * FROM orders ORDER BY id DESC")
    orders = c.fetchall()
    conn.close()
    return jsonify(orders)


@app.route('/orders_data')
def orders_data():
    if 'user_id' not in session:
        return jsonify([])

    conn = sqlite3.connect("laundry.db")
    c = conn.cursor()
    c.execute("SELECT * FROM orders")
    orders = c.fetchall()
    conn.close()
    return jsonify(orders)


@app.route('/add_order', methods=['POST'])
@login_required(api=True)
def add_order():
    try:
        data = request.get_json()
        customer = data["customer"]
        phone = data["phone"]
        service = data["service"]

        conn = sqlite3.connect("laundry.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO orders(user_id, customer, phone, service, status) VALUES (?, ?, ?, ?, ?)",
            (session['user_id'], customer, phone, service, "Pending")
        )
        conn.commit()
        new_order_id = c.lastrowid  # actual id of the row just inserted
        conn.close()

        # Only notify the customer who placed this order, not every
        # connected client, so customers can't see each other's orders live.
        order_payload = {
            "id": new_order_id,
            "customer": customer,
            "phone": phone,
            "service": service,
            "status": "Pending"
        }
        socketio.emit("new_order", order_payload, room=str(session['user_id']))
        # Admins need to see every new order regardless of who placed it.
        socketio.emit("new_order", order_payload, room="admins")

        return jsonify({"success": True, "message": "Order added successfully"})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route('/complete/<int:order_id>')
@login_required(role="ADMIN", api=True)
def complete_order(order_id):
    conn = sqlite3.connect("laundry.db")
    c = conn.cursor()

    # Look up who owns this order BEFORE updating, so we notify the right customer
    c.execute("SELECT user_id FROM orders WHERE id=?", (order_id,))
    row = c.fetchone()
    owner_id = row[0] if row else None

    c.execute("UPDATE orders SET status='Completed' WHERE id=?", (order_id,))
    conn.commit()
    conn.close()

    if owner_id is not None:
        socketio.emit("order_completed", {"id": order_id}, room=str(owner_id))
    # Other admin sessions need to see the update too, not just the customer.
    socketio.emit("order_completed", {"id": order_id}, room="admins")

    return jsonify({"success": True})


@app.route('/delete/<int:order_id>', methods=['DELETE'])
@login_required(role="ADMIN", api=True)
def delete_order(order_id):
    try:
        conn = sqlite3.connect("laundry.db")
        c = conn.cursor()

        c.execute("SELECT user_id FROM orders WHERE id=?", (order_id,))
        row = c.fetchone()
        owner_id = row[0] if row else None

        c.execute("DELETE FROM orders WHERE id=?", (order_id,))
        conn.commit()
        conn.close()

        if owner_id is not None:
            socketio.emit("order_deleted", {"id": order_id}, room=str(owner_id))
        socketio.emit("order_deleted", {"id": order_id}, room="admins")

        return jsonify({"success": True, "message": "Order deleted"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route('/clear_orders', methods=['DELETE'])
@login_required(role="ADMIN", api=True)
def clear_orders():
    try:
        conn = sqlite3.connect("laundry.db")
        c = conn.cursor()
        c.execute("DELETE FROM orders")
        conn.commit()
        conn.close()
        # Broadcast to everyone (admins and customers alike) since this wipes
        # every order in the system, not just one person's.
        socketio.emit("orders_cleared", {})
        return jsonify({"success": True, "message": "All orders cleared"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
@login_required(role="ADMIN", api=True)
def delete_user(user_id):
    try:
        conn = sqlite3.connect("laundry.db")
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()

        socketio.emit("user_deleted", {"id": user_id})

        return jsonify({"success": True, "message": "User deleted successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@socketio.on('connect')
def connect():
    if 'user_id' in session:
        join_room(str(session['user_id']))
        if session.get('role') == 'ADMIN':
            join_room('admins')


# =====================================
# SERVER START
# =====================================

if __name__ == '__main__':
    init_db()
    print("Laundry Management System Started")

    socketio.run(
        app,
        host="0.0.0.0",
        port=5001,
        debug=True,
        use_reloader=False  # prevents the dev server from restarting/reloading on every file save
    )