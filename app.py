from flask import Flask, redirect, render_template, request, jsonify, session
from functools import wraps
import sqlite3
import base64
import os
from datetime import datetime, timedelta
import requests
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room

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
# M-PESA (DARAJA) CONFIG
# =====================================
# Set these as real environment variables before running the app.
# Sandbox docs / test credentials: https://developer.safaricom.co.ke/
#
#   export MPESA_CONSUMER_KEY=...
#   export MPESA_CONSUMER_SECRET=...
#   export MPESA_SHORTCODE=174379          # sandbox test paybill
#   export MPESA_PASSKEY=...               # given with the sandbox shortcode
#   export MPESA_CALLBACK_URL=https://<your-public-url>/mpesa/callback
#
# CALLBACK_URL must be a public HTTPS URL Safaricom's servers can reach —
# on localhost you need a tunnel (e.g. `ngrok http 5001`) while testing.

MPESA_BASE_URL = os.environ.get("MPESA_BASE_URL", "https://sandbox.safaricom.co.ke")
MPESA_CONSUMER_KEY = os.environ.get("MPESA_CONSUMER_KEY", "")
MPESA_CONSUMER_SECRET = os.environ.get("MPESA_CONSUMER_SECRET", "")
MPESA_SHORTCODE = os.environ.get("MPESA_SHORTCODE", "")
MPESA_PASSKEY = os.environ.get("MPESA_PASSKEY", "")
MPESA_CALLBACK_URL = os.environ.get("MPESA_CALLBACK_URL", "")


def normalize_phone(raw_phone):
    """M-Pesa wants 2547XXXXXXXX / 2541XXXXXXXX — no +, no leading 0."""
    digits = "".join(ch for ch in str(raw_phone) if ch.isdigit())
    if digits.startswith("0"):
        digits = "254" + digits[1:]
    elif digits.startswith("7") or digits.startswith("1"):
        digits = "254" + digits
    return digits


def mpesa_access_token():
    resp = requests.get(
        f"{MPESA_BASE_URL}/oauth/v1/generate?grant_type=client_credentials",
        auth=(MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET),
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def mpesa_password_and_timestamp():
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    raw = f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}"
    password = base64.b64encode(raw.encode()).decode()
    return password, timestamp


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

    # Payment columns, added via ALTER so an existing laundry.db upgrades in
    # place instead of needing to be deleted. sqlite3 has no
    # "ADD COLUMN IF NOT EXISTS", so we just swallow the error if the
    # column is already there from a previous run.
    for ddl in (
        "ALTER TABLE orders ADD COLUMN payment_status TEXT DEFAULT 'unpaid'",
        "ALTER TABLE orders ADD COLUMN payment_method TEXT",
        "ALTER TABLE orders ADD COLUMN checkout_request_id TEXT",
        "ALTER TABLE orders ADD COLUMN amount INTEGER",
    ):
        try:
            c.execute(ddl)
        except sqlite3.OperationalError:
            pass  # column already exists

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
    return render_template("frontpage.html")


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
# NOTE: SELECT lists columns by name (not "SELECT *") and get_db()'s
# sqlite3.Row lets the template read o.id / o.customer / o.status / etc.
# by name. Doing this by position used to break as soon as `user_id`
# (or, now, the payment columns) shifted every later index by one.

@app.route('/customer')
@login_required(role="CUSTOMER")
def customer_dashboard():
    conn = get_db()
    orders = conn.execute(
        """
        SELECT id, customer, phone, service, status, payment_status
        FROM orders
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (session['user_id'],)
    ).fetchall()
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

    # Look up who owns this order BEFORE updating, so we notify the right
    # customer, and so we can send customer/phone along with the event —
    # the frontend's "Pay" button needs them without a second round trip.
    c.execute("SELECT user_id, customer, phone FROM orders WHERE id=?", (order_id,))
    row = c.fetchone()
    owner_id = row[0] if row else None
    customer = row[1] if row else ""
    phone = row[2] if row else ""

    c.execute("UPDATE orders SET status='Completed' WHERE id=?", (order_id,))
    conn.commit()
    conn.close()

    payload = {"id": order_id, "customer": customer, "phone": phone}

    if owner_id is not None:
        socketio.emit("order_completed", payload, room=str(owner_id))
    # Other admin sessions need to see the update too, not just the customer.
    socketio.emit("order_completed", payload, room="admins")

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


# =====================================
# PAYMENT API (M-PESA STK PUSH)
# =====================================

@app.route('/stk_push', methods=['POST'])
@login_required(api=True)
def stk_push():
    """Called from the 'Pay now' button on the orders page. Starts an
    M-Pesa STK push and returns immediately — the pass/fail result arrives
    later via the /mpesa/callback route -> 'payment_status' socket event."""
    if not all([MPESA_CONSUMER_KEY, MPESA_CONSUMER_SECRET, MPESA_SHORTCODE,
                MPESA_PASSKEY, MPESA_CALLBACK_URL]):
        return jsonify({"success": False, "message": "M-Pesa is not configured on the server"}), 500

    data = request.get_json() or {}
    order_id = data.get("order_id")
    phone = normalize_phone(data.get("phone", ""))
    try:
        amount = int(data.get("amount", 0))
    except (TypeError, ValueError):
        amount = 0

    if not order_id or not phone or amount <= 0:
        return jsonify({"success": False, "message": "Missing order_id, phone or amount"}), 400

    conn = get_db()
    order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        conn.close()
        return jsonify({"success": False, "message": "Order not found"}), 404

    # Customers may only pay for their own orders; admins can pay for any.
    if session.get('role') != 'ADMIN' and order['user_id'] != session['user_id']:
        conn.close()
        return jsonify({"success": False, "message": "Not authorized"}), 403

    try:
        token = mpesa_access_token()
    except requests.RequestException:
        conn.close()
        return jsonify({"success": False, "message": "Could not reach M-Pesa. Try again."}), 502

    password, timestamp = mpesa_password_and_timestamp()

    payload = {
        "BusinessShortCode": MPESA_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",  # use CustomerBuyGoodsOnline for a Till number
        "Amount": amount,
        "PartyA": phone,
        "PartyB": MPESA_SHORTCODE,
        "PhoneNumber": phone,
        "CallBackURL": MPESA_CALLBACK_URL,
        "AccountReference": f"Order{order_id}",
        "TransactionDesc": "Laundry order payment",
    }

    try:
        r = requests.post(
            f"{MPESA_BASE_URL}/mpesa/stkpush/v1/processrequest",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        result = r.json()
    except requests.RequestException:
        conn.close()
        return jsonify({"success": False, "message": "Could not reach M-Pesa. Try again."}), 502

    if result.get("ResponseCode") == "0":
        conn.execute(
            "UPDATE orders SET checkout_request_id=?, amount=?, payment_method='mpesa' WHERE id=?",
            (result["CheckoutRequestID"], amount, order_id)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Prompt sent"})

    conn.close()
    return jsonify({
        "success": False,
        "message": result.get("errorMessage", "Could not start the payment")
    }), 400


@app.route('/mpesa/callback', methods=['POST'])
def mpesa_callback():
    """Safaricom POSTs the final result here once the customer responds to
    the prompt (enters PIN, cancels, or it times out). This URL must be the
    same public HTTPS URL set as MPESA_CALLBACK_URL above — no login here,
    Safaricom's servers are the caller, not a browser with a session."""
    body = request.get_json(force=True, silent=True) or {}
    try:
        stk = body["Body"]["stkCallback"]
    except KeyError:
        return jsonify({"ResultCode": 1, "ResultDesc": "Invalid payload"}), 400

    checkout_id = stk.get("CheckoutRequestID")
    result_code = stk.get("ResultCode")

    conn = get_db()
    order = conn.execute(
        "SELECT * FROM orders WHERE checkout_request_id=?", (checkout_id,)
    ).fetchone()

    if order:
        order_id = order['id']
        owner_id = order['user_id']

        if result_code == 0:
            conn.execute("UPDATE orders SET payment_status='paid' WHERE id=?", (order_id,))
            conn.commit()
            payload = {"order_id": order_id, "status": "paid"}
        else:
            # e.g. ResultCode 1032 = user cancelled, 1037 = timeout
            conn.execute("UPDATE orders SET payment_status='failed' WHERE id=?", (order_id,))
            conn.commit()
            payload = {"order_id": order_id, "status": "failed", "reason": stk.get("ResultDesc")}

        if owner_id is not None:
            socketio.emit("payment_status", payload, room=str(owner_id))
        socketio.emit("payment_status", payload, room="admins")

    conn.close()
    # Safaricom just needs a 200 with this shape to consider it handled.
    return jsonify({"ResultCode": 0, "ResultDesc": "Accepted"})


@app.route('/payment_method', methods=['POST'])
@login_required(api=True)
def payment_method():
    """Called from the 'Pay after delivery' button."""
    data = request.get_json() or {}
    order_id = data.get("order_id")
    method = data.get("method")

    if not order_id or not method:
        return jsonify({"success": False, "message": "Missing order_id or method"}), 400

    conn = get_db()
    order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        conn.close()
        return jsonify({"success": False, "message": "Order not found"}), 404

    if session.get('role') != 'ADMIN' and order['user_id'] != session['user_id']:
        conn.close()
        return jsonify({"success": False, "message": "Not authorized"}), 403

    conn.execute("UPDATE orders SET payment_method=? WHERE id=?", (method, order_id))
    conn.commit()
    conn.close()

    return jsonify({"success": True})


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