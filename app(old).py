from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import random
import smtplib

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///todo.db"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///user.db"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "your_secret_key"

db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Todo Model
class Todo(db.Model):
    SNo = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.String, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self) -> str:
        return f"{self.SNo} - {self.title}"
    
# Global dictionary to store OTPs
otp_storage = {}

@app.route('/')
def default():
    if 'user_id' not in session:
        return redirect(url_for('todo_app'))
    return redirect(url_for('dashboard'))

# Landing Page
@app.route('/todo_app')
def todo_app():
    return render_template('landing.html')

from flask import make_response

# Home Page (ToDo List)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Session expired! please login again.','warning')
        return redirect(url_for('todo_app'))

    user_id = session['user_id']
    username = session.get('username')  # Use .get() to prevent KeyError
    allTodo = Todo.query.filter_by(user_id=user_id).all()

    response = make_response(render_template('index.html', allTodo=allTodo, username=username))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    return response

'''
# Home Page (ToDo List)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('todo_app'))
    user_id = session['user_id']
    username = session['username']
    allTodo = Todo.query.filter_by(user_id=user_id).all()
    return render_template('index.html', allTodo=allTodo, username=username)
'''
# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already exists!", "danger")
            return redirect(url_for('signup'))
        user = User(name=name, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.name
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        flash("Invalid credentials. Try again.", "danger")
    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully!.", "info")
    return redirect(url_for('todo_app'))

# Send OTP via Email
def send_otp(email):
    otp = random.randint(100000, 999999)
    sender_email = "kumarajay69206@gmail.com"
    sender_password = "wyxh swld mxzk ynxe"

    if not sender_email or not sender_password:
        print("Error: Email credentials not set")
        return False

    subject = "Password Reset OTP"
    body = f"Your OTP for password reset is: {otp}"
    message = f"Subject: {subject}\n\n{body}"

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, message)

            session['sent_otp'] = otp  # Store OTP in session
            session['email'] = email  # Store email in session
            session['otp_expiry'] = (datetime.datetime.now() + datetime.timedelta(minutes=5)).timestamp()  # Set expiry time

        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
    
# Verify OTP Route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        email = session.get('email')  # Retrieve email from session
        sent_otp = session.get('sent_otp')  # Retrieve OTP from session
        entered_otp = request.form['otp']  # User input

        if not email or not sent_otp:
            flash("Session expired! Please request OTP again.", "danger")
            return redirect(url_for('forgot_password'))

        if str(sent_otp) == entered_otp:  # Convert OTP to string before comparing
            session.pop('sent_otp')  # Remove OTP from session after verification
            session['verified_email'] = email  # Store verified email in session
            flash("OTP verified successfully! Please reset your password.", "success")
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid OTP. Please try again.", "danger")

    return render_template('verify_otp.html')

# Forgot Password Route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')  # Fetch email from form
        user = User.query.filter_by(email=email).first()

        if user:
            if send_otp(email):
                flash('OTP sent successfully!', 'success')
                return redirect(url_for('verify_otp'))
            else:
                flash("Failed to send OTP. Try again later.", "danger")
        else:
            flash("No account found with this email!", "danger")

    return render_template('forgot_password.html')

# Reset Password Route
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'verified_email' not in session:
        flash("Session expired! Please verify OTP again.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        email = session['verified_email']
        user = User.query.filter_by(email=email).first()

        if user:
            user.password = new_password  # Store hashed password in production
            db.session.commit()
            session.pop('verified_email')  # Remove email from session
            flash("Password reset successfully! Please login.", "success")
            return redirect(url_for('login'))

        flash("Something went wrong. Try again.", "danger")

    return render_template('reset_password.html')

# Retrieve Username via Email
@app.route('/get_username', methods=['GET', 'POST'])
def get_username():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            flash(f"Your username is: {user.username}", "success")
        else:
            flash("Email not found!", "danger")
    return render_template('get_username.html')

@app.route('/addTodo', methods=['POST'])
def addTodo():
    if 'user_id' not in session:  # ✅ Ensure user is logged in
        flash("Please log in to add a task!", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        user_id = session['user_id']  # ✅ Get user_id from session

        todo = Todo(title=title, desc=desc, user_id=user_id)  # ✅ Pass user_id
        db.session.add(todo)
        db.session.commit()

        flash("Task added successfully!", "success")
        return redirect(url_for('dashboard'))  # Redirect to home/dashboard

#Update Todo
@app.route('/update/<int:SNo>',methods=['GET','POST'])
def updateTodo(SNo):
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        todo = Todo.query.filter_by(SNo=SNo).first()
        todo.title = title
        todo.desc = desc
        db.session.add(todo)
        db.session.commit()
        
        flash("Todo details updated successfully!", "success")
        return redirect("/")
    
    todo = Todo.query.filter_by(SNo=SNo).first()
    return render_template('update.html', todo=todo)

#Delete Record
@app.route('/delete/<int:SNo>')
def deleteRecord(SNo):
    todo = Todo.query.filter_by(SNo=SNo).first()
    db.session.delete(todo)
    db.session.commit()
    # Redirect to the homepage to follow the PRG pattern
    flash("Task deleted successfully!","success")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
