from flask import Flask, make_response, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import random
import smtplib
import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///user.db"  # Default DB
app.config['SQLALCHEMY_BINDS'] = {
    'todo': "sqlite:///todo.db"  # Additional DB
}

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')  # Load the secret key securely
app.config['SESSION_PERMANENT'] = False  # Prevent session expiration issues
#app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=2)  # Extend session life

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions on the server

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

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

@app.route('/')
def default():
    if 'user_id' not in session:
        return redirect(url_for('todo_app'))
    return redirect(url_for('dashboard'))

# Landing Page
@app.route('/todo_app')
def todo_app():
    return render_template('landing.html')

# Dashbord route
@app.route('/todo_app/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Session expired! Please log in again.', 'warning')
        return redirect(url_for('todo_app'))

    user_id = session['user_id']
    username = session.get('username')

    # Calculate remaining session time
    expiry_time = session.get('session_expiry', 0)
    current_time = datetime.now().timestamp()
    remaining_time = max(0, int(expiry_time - current_time))  # Avoid negative values

    allTodo = Todo.query.filter_by(user_id=user_id).all()

    response = make_response(render_template('index.html', allTodo=allTodo, username=username, remaining_time=remaining_time))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response

# Signup
@app.route('/todo_app/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        user = User(name=name, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/todo_app/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.name
            session.permanent = True  # Enable session expiration
            
            expiry_time = datetime.now() + timedelta(minutes=15)  # Set session expiry time
            session['session_expiry'] = expiry_time.timestamp()  # Store expiry time as timestamp
            
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))

        flash("Invalid credentials. Try again.", "danger")

    return render_template('login.html')



# Logout
@app.route('/todo_app/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully!.", "info")
    return redirect(url_for('todo_app'))

# Forgot password
@app.route('/todo_app/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email').strip()  # Ensure no extra spaces
        user = User.query.filter_by(email=email).first()

        if user:
            if send_otp(email):  
                session['email'] = email  # Store email in session
                flash("OTP sent successfully!", "success")
                return redirect(url_for('verify_otp'))
            else:
                flash("Failed to send OTP. Try again later.", "danger")
        else:
            flash("No account found with this email!", "danger")
    #session.pop('email', None)
    return render_template('forgot_password.html')

# Send OTP via Email
def send_otp(email):
    otp = random.randint(100000, 999999)
    sender_email = os.getenv('EMAIL_USER')
    sender_password = os.getenv('EMAIL_PASS')

    if not sender_email or not sender_password:
        print("Error: Email credentials not set")
        return False

    subject = "Password Reset OTP"
    body = f"Your OTP for password reset is: {otp}"
    message = f"Subject: {subject}\n\n{body}"

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message)
        
        session['sent_otp'] = otp
        session['otp_expiry'] = (datetime.now() + timedelta(minutes=3)).timestamp()
        session.modified = True  # ✅ Force session update
        return True
    return False

# Verify OTP Route
@app.route('/todo_app/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    # Prevent direct access if OTP was not sent
    email = session.get('email')  # Retrieve email from session
    sent_otp = session.get('sent_otp')  # Retrieve stored OTP
    otp_expiry = session.get('otp_expiry') # Retrieve OTP expiry time

    if not email:
        flash("Session expired! Please request for new otp.", "danger")
        return redirect(url_for('forgot_password'))

    if not sent_otp:
        flash("OTP expired! Please request for new otp.", "danger")
        return redirect(url_for('forgot_password'))

    if not otp_expiry:
        flash("OTP expiry not found! Please request for new otp.", "danger")
        return redirect(url_for('forgot_password'))
        
    email = session.get('email')  # Retrieve email from session
    sent_otp = session.get('sent_otp')  # Retrieve stored OTP
    otp_expiry = session.get('otp_expiry')  # Retrieve OTP expiry time

    # Check if OTP has expired
    if datetime.now().timestamp() > otp_expiry:
        session.pop('sent_otp', None)  # Remove expired OTP
        session.pop('otp_expiry', None)
        session.pop('email', None)
        flash("OTP has expired! Please request a new one.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()  # Ensure OTP is stripped of spaces

        # Validate OTP
        if str(sent_otp) == entered_otp:
            # OTP is valid; clean up session
            session.pop('sent_otp', None)
            session.pop('otp_expiry', None)
            session.pop('email', None)
            session['verified_email'] = email  # Store verified email

            flash("OTP verified successfully! Please reset your password.", "success")
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid OTP! Please try again.", "danger")
            return redirect(url_for('verify_otp'))

    return render_template('verify_otp.html')

# Reset Password using OTP
@app.route('/todo_app/reset_password', methods=['GET', 'POST'])
def reset_password():
    email = session.get('verified_email')  # Retrieve verified email
    # Prevent unauthorized access
    if not email:
        flash('Session expired! Please verify OTP again.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        cpassword = request.form.get('cpassword', '').strip()

        # Validate passwords
        if not password or not cpassword:
            flash('Password fields cannot be empty!', 'danger')
            return redirect(url_for('reset_password'))

        if password != cpassword:
            flash('Passwords do not match! Please try again.', 'danger')
            return redirect(url_for('reset_password'))

        # Update user password
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password)  # Hash password
            db.session.commit()

            # Clean up session after successful reset
            session.pop('verified_email', None)
            flash("Password reset successful! Please log in.", "success")
            return redirect(url_for('login'))
        else:
            flash("User not found! Please try again.", "danger")

    return render_template('reset_password.html')

# Retrieve Username via Email
@app.route('/todo_app/get_username', methods=['GET', 'POST'])
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
        if not todo:
            flash("Task not found!", "danger")
            return redirect(url_for("dashboard"))

        db.session.add(todo)
        db.session.commit()

        flash("Task added successfully!", "success")
        return redirect(url_for('dashboard'))  # Redirect to home/dashboard

#Update Todo
@app.route('/update/<int:SNo>', methods=['GET','POST'])
def updateTodo(SNo):
    if 'user_id' not in session:  # ✅ Ensure user is logged in
        flash("Please log in to do this task!", "warning")
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        todo = Todo.query.filter_by(SNo=SNo).first()
        
        todo.title = title
        todo.desc = desc
        db.session.commit()
        
        flash("Todo details updated successfully!", "success")
        return redirect(url_for(("dashboard")))
    
    todo = Todo.query.filter_by(SNo=SNo).first()
    return render_template('update.html', todo=todo)

#Delete Record
@app.route('/delete_todo/<int:SNo>')
def deleteRecord(SNo):
    if 'user_id' not in session:  # ✅ Ensure user is logged in
        flash("Please log in to do this task!", "warning")
        return redirect(url_for('login'))
    
    todo = Todo.query.filter_by(SNo=SNo).first()
    db.session.delete(todo)
    db.session.commit()
    # Redirect to the homepage to follow the PRG pattern
    flash("Task deleted successfully!","success")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables for the default DB
    app.run(debug=True)
