from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
import razorpay
import hashlib
import datetime
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = "secretkey123"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

client = razorpay.Client(auth=(
    "rzp_test_SGr3TtEdPGJPpf",
    "8j3b0VhFxCNkiTm7Azd7WHrC"
))

# ---------------- DATABASE MODEL ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    txnpass = db.Column(db.String(100))
    secret = db.Column(db.String(200))  # TOTP Secret
    attempts = db.Column(db.Integer, default=0)
    blocked = db.Column(db.Boolean, default=False)

# ---------------- BLOCKCHAIN HASH ----------------
def generate_block_hash(username, amount):
    data = f"{username}{amount}{datetime.datetime.now()}"
    return hashlib.sha256(data.encode()).hexdigest()

# ---------------- LOGIN ----------------
@app.route('/', methods=['GET','POST'])
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
                error = f"Invalid password ({3-user.attempts} attempts left)"
            db.session.commit()

        else:
            user.attempts = 0
            db.session.commit()
            session['user'] = username
            return redirect('/payment')

    return render_template("app.html", page="login", error=error)

# ---------------- SIGNUP ----------------
@app.route('/signup_page')
def signup_page():
    return render_template("app.html", page="signup", error="")

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    txnpass = request.form['txnpass']

    if User.query.filter_by(username=username).first():
        return "User already exists"

    secret = pyotp.random_base32()

    new_user = User(
        username=username,
        password=password,
        txnpass=txnpass,
        secret=secret
    )

    db.session.add(new_user)
    db.session.commit()

    # Generate QR Code for Google Authenticator
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="SecurePay")

    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    img_str = base64.b64encode(buffer.getvalue()).decode()

    return render_template("setup_totp.html", qr_code=img_str)

# ---------------- PAYMENT ----------------
@app.route('/payment', methods=['GET','POST'])
def payment():
    error = ""

    if 'user' not in session:
        return redirect('/')

    if request.method == 'POST':
        txnpass = request.form['txnpass']
        amount = request.form['amount']

        user = User.query.filter_by(username=session['user']).first()

        if txnpass != user.txnpass:
            error = "Wrong Transaction Password"
        else:
            session['amount'] = amount
            return redirect('/otp')

    return render_template("app.html", page="payment", error=error)

# ---------------- TOTP VERIFICATION ----------------
@app.route('/otp', methods=['GET','POST'])
def otp():
    error = ""
    user = User.query.filter_by(username=session.get('user')).first()

    if request.method == 'POST':
        entered = request.form['otp']
        totp = pyotp.TOTP(user.secret)

        if totp.verify(entered):
            return redirect('/pay_api')
        else:
            error = "Invalid OTP"

    return render_template("app.html", page="otp", error=error)

# ---------------- RAZORPAY ----------------
@app.route('/pay_api')
def pay_api():
    amount = int(float(session.get('amount', 1)) * 100)

    order = client.order.create({
        "amount": amount,
        "currency": "INR",
        "payment_capture": 1
    })

    return render_template(
        "app.html",
        page="pay_api",
        order_id=order['id'],
        key_id="rzp_test_SGr3TtEdPGJPpf",
        amount=session.get('amount')
    )

@app.route('/payment_failed')
def payment_failed():
    return render_template("app.html", page="failed")

# ---------------- SUCCESS + BLOCKCHAIN ----------------
@app.route('/success')
def success():
    username = session.get('user')
    amount = session.get('amount')

    block_hash = generate_block_hash(username, amount)

    return render_template(
        "app.html",
        page="success",
        block_hash=block_hash
    )

# ---------------- MAIN ----------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
