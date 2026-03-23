from flask import Flask, render_template, request, redirect, session, Response
from flask_sqlalchemy import SQLAlchemy
import hashlib
import datetime
import pyotp
import qrcode
import io
import base64
import requests
import math
import os
from requests.auth import HTTPBasicAuth

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)

database_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db = SQLAlchemy(app)

RAZORPAY_KEY_ID     = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")


# ---------------- SECURITY HEADERS ----------------
@app.after_request
def set_security_headers(response: Response) -> Response:
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://checkout.razorpay.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' https://api.razorpay.com; "
        "frame-src https://api.razorpay.com;"
    )
    return response


# ---------------- HTTPS REDIRECT ----------------
@app.before_request
def enforce_https():
    if os.environ.get('RENDER') and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
        host = request.host
        path = request.full_path.rstrip('?')
        return redirect(f"https://{host}{path}", code=301)


# ---------------- RAZORPAY ----------------
def create_razorpay_order(amount: int) -> dict:
    response = requests.post(
        "https://api.razorpay.com/v1/orders",
        auth=HTTPBasicAuth(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET),
        json={"amount": amount, "currency": "INR", "payment_capture": 1},
        timeout=10
    )
    return response.json()


# ---------------- DATABASE MODELS ----------------
class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    txnpass  = db.Column(db.String(100))
    secret   = db.Column(db.String(200))
    attempts = db.Column(db.Integer, default=0)
    blocked  = db.Column(db.Boolean, default=False)
    balance  = db.Column(db.Float, default=10000.0)


class Transaction(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(100))
    amount        = db.Column(db.Float)
    previous_hash = db.Column(db.String(64))
    current_hash  = db.Column(db.String(64))
    timestamp     = db.Column(db.String(50))


# ---------------- BLOCKCHAIN HASH ----------------
def generate_block_hash(username: str, amount: float, previous_hash: str = "0" * 64) -> str:
    data = f"{username}{amount}{previous_hash}{datetime.datetime.now(datetime.timezone.utc)}"
    return hashlib.sha256(data.encode()).hexdigest()


# ---------------- LOGIN ----------------
@app.route('/', methods=['GET', 'POST'])
def login():
    error = ""

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if not user:
            error = "User not found"

        elif user.blocked:
            error = "Account blocked after 3 wrong attempts"

        elif password != user.password:
            user.attempts += 1
            if user.attempts >= 3:
                user.blocked = True
                error = "Account blocked after 3 wrong attempts"
            else:
                error = f"Invalid password ({3 - user.attempts} attempts left)"
            db.session.commit()

        else:
            user.attempts = 0
            db.session.commit()
            session['user'] = username
            return redirect('/dashboard')

    return render_template("app.html", page="login", error=error)


# ---------------- SIGNUP ----------------
@app.route('/signup_page')
def signup_page():
    return render_template("app.html", page="signup", error="")


@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    txnpass  = request.form['txnpass']

    if User.query.filter_by(username=username).first():
        return render_template("app.html", page="signup",
                               error="Username already exists. Please choose another.")

    secret = pyotp.random_base32()

    new_user = User(
        username=username,
        password=password,
        txnpass=txnpass,
        secret=secret
    )

    db.session.add(new_user)
    db.session.commit()

    totp = pyotp.TOTP(secret)
    uri  = totp.provisioning_uri(name=username, issuer_name="SecurePay")

    img = qrcode.make(uri)
    with io.BytesIO() as buffer:
        img.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode()

    return render_template("setup_totp.html", qr_code=img_str)


# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')

    user         = User.query.filter_by(username=session['user']).first()
    transactions = Transaction.query.filter_by(username=session['user'])\
                                    .order_by(Transaction.id.desc()).all()

    fraud_alert = any(t.amount > 5000 for t in transactions)

    return render_template("dashboard.html",
                           user=user,
                           transactions=transactions,
                           fraud_alert=fraud_alert)


# ---------------- PAYMENT ----------------
@app.route('/payment', methods=['GET', 'POST'])
def payment():
    error = ""

    if 'user' not in session:
        return redirect('/')

    if request.method == 'POST':
        txnpass = request.form['txnpass']
        amount  = request.form['amount']

        try:
            if not amount or amount.strip().lower() in ('nan', 'inf', '-inf', 'infinity'):
                raise ValueError
            amount_float = float(amount)
            if math.isnan(amount_float) or math.isinf(amount_float) or amount_float <= 0:
                raise ValueError
        except (ValueError, TypeError):
            error = "Invalid amount entered."
            return render_template("app.html", page="payment", error=error)

        user = User.query.filter_by(username=session['user']).first()

        if txnpass != user.txnpass:
            error = "Wrong Transaction Password"
        elif amount_float > user.balance:
            error = f"Insufficient balance. Available: ₹{user.balance}"
        else:
            session['amount'] = amount
            return redirect('/otp')

    return render_template("app.html", page="payment", error=error)


# ---------------- TOTP VERIFICATION ----------------
@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if 'user' not in session:
        return redirect('/')

    error = ""
    user  = User.query.filter_by(username=session.get('user')).first()

    if request.method == 'POST':
        entered = request.form['otp']
        totp    = pyotp.TOTP(user.secret)

        if totp.verify(entered):
            return redirect('/pay_api')
        else:
            error = "Invalid OTP. Please try again."

    return render_template("app.html", page="otp", error=error)


# ---------------- RAZORPAY ----------------
@app.route('/pay_api')
def pay_api():
    if 'user' not in session:
        return redirect('/')

    try:
        raw = session.get('amount', '1')
        amount_float = float(raw)
        if math.isnan(amount_float) or math.isinf(amount_float) or amount_float <= 0:
            raise ValueError
        amount = int(amount_float * 100)
    except (ValueError, TypeError):
        return redirect('/payment')

    order = create_razorpay_order(amount)

    return render_template(
        "app.html",
        page="pay_api",
        order_id=order['id'],
        key_id=RAZORPAY_KEY_ID,
        amount=session.get('amount')
    )


@app.route('/payment_failed')
def payment_failed():
    return render_template("app.html", page="failed")


# ---------------- SUCCESS + BLOCKCHAIN ----------------
@app.route('/success')
def success():
    if 'user' not in session:
        return redirect('/')

    username = session.get('user')
    amount   = float(session.get('amount', 0))

    last_txn      = Transaction.query.filter_by(username=username)\
                                     .order_by(Transaction.id.desc()).first()
    previous_hash = last_txn.current_hash if last_txn else "0" * 64

    block_hash = generate_block_hash(username, amount, previous_hash)

    txn = Transaction(
        username=username,
        amount=amount,
        previous_hash=previous_hash,
        current_hash=block_hash,
        timestamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    db.session.add(txn)

    user = User.query.filter_by(username=username).first()
    user.balance = round(user.balance - amount, 2)

    db.session.commit()

    return render_template("app.html", page="success", block_hash=block_hash)


# ---------------- ADMIN ----------------
ADMIN_ID        = os.environ.get("ADMIN_ID", "miniproject0511")
_admin_salt     = b"securepay_admin_salt_v1"
ADMIN_PASS_HASH = hashlib.pbkdf2_hmac(
    'sha256',
    os.environ.get("ADMIN_PASSWORD", "miniproject@123").encode(),
    _admin_salt,
    200_000
).hex()


@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    error = ""
    if request.method == 'POST':
        uid  = request.form.get('username', '')
        pwd  = request.form.get('password', '')
        entered_hash = hashlib.pbkdf2_hmac('sha256', pwd.encode(), _admin_salt, 200_000).hex()
        if uid == ADMIN_ID and entered_hash == ADMIN_PASS_HASH:
            session['admin'] = True
            return redirect('/admin_dashboard')
        error = "Invalid admin credentials."
    return render_template("admin.html", error=error)


@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin'):
        return redirect('/admin')
    users        = User.query.all()
    transactions = Transaction.query.order_by(Transaction.id.desc()).all()
    return render_template("admin_dashboard.html", users=users, transactions=transactions)


@app.route('/admin_logout')
def admin_logout():
    session.pop('admin', None)
    return redirect('/admin')


# ---------------- MAIN ----------------
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
