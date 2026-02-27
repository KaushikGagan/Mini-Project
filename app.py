from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
import random
import time
import razorpay
import hashlib
import datetime

app = Flask(__name__)
app.secret_key = "secretkey123"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

client = razorpay.Client(auth=(
    "rzp_test_SGr3TtEdPGJPpf",
    "8j3b0VhFxCNkiTm7Azd7WHrC"
))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    txnpass = db.Column(db.String(100))
    attempts = db.Column(db.Integer, default=0)
    blocked = db.Column(db.Boolean, default=False)

# Blockchain-style hash generator
def generate_block_hash(username, amount):
    data = f"{username}{amount}{datetime.datetime.now()}"
    return hashlib.sha256(data.encode()).hexdigest()


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

    new_user = User(username=username, password=password, txnpass=txnpass)
    db.session.add(new_user)
    db.session.commit()

    return redirect('/')


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
            session['otp'] = str(random.randint(100000,999999))
            session['otp_time'] = time.time()
            print("OTP:", session['otp'])
            return redirect('/otp')

    return render_template("app.html", page="payment", error=error)


@app.route('/otp', methods=['GET','POST'])
def otp():
    error = ""
    remaining = 0

    if 'otp_time' in session:
        remaining = int(180 - (time.time() - session['otp_time']))
        if remaining < 0:
            remaining = 0

    if request.method == 'POST':
        entered = request.form['otp']

        if time.time() - session.get('otp_time',0) > 180:
            error = "OTP expired"
        elif entered == session.get('otp'):
            return redirect('/pay_api')
        else:
            error = "Invalid OTP"

    return render_template("app.html", page="otp", error=error, remaining=remaining)


@app.route('/pay_api')
def pay_api():
    amount = int(float(session.get('amount',1)) * 100)

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


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
