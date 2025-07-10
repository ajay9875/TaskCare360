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

from datetime import datetime
from flask import current_app, jsonify
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import os
import smtplib
from datetime import datetime
from flask import current_app, jsonify
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_daily_task_reminders():
    sender_email = os.getenv('EMAIL_USER')
    sender_password = os.getenv('EMAIL_PASS')
    login_url = "https://taskcare360.onrender.com"

    if not sender_email or not sender_password:
        return jsonify({"error": "Email credentials are not set."}), 500

    try:
        users = User.query.all()
        if not users:
            return False
        else:
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(sender_email, sender_password)

                for user in users:
                    tasks = Todo.query.filter_by(user_id=user.id).order_by(Todo.date_created.desc()).all()

                    if not tasks:
                        html_body = f"""
                        <p>Hi {user.name},</p>
                        <p>Great job staying on top of your tasks! 🎉<br>
                        You currently have no pending tasks. Keep up the great work!</p>
                        <p>👉 <a href="{login_url}">Login to add or manage your tasks</a></p>
                        <br><p>— <strong>TaskCare360 Team</strong></p>
                        """
                    else:
                        task_rows = ""
                        for task in tasks:
                            task_rows += f"""
                                <tr>
                                    <td style="border:1px solid #ddd;padding:8px;">{task.title}</td>
                                    <td style="border:1px solid #ddd;padding:8px;">{task.desc or 'No description'}</td>
                                    <td style="border:1px solid #ddd;padding:8px;">{task.date_created.strftime('%Y-%m-%d')}</td>
                                </tr>
                            """

                        html_body = f"""
                        <p>Hi {user.name},</p>
                        <p>You're performing well. Continue with the same dedication to achieve your goals today.</p>
                        <p>Here’s a summary of your pending tasks (most recent first):</p>

                        <table style="border-collapse: collapse; width: 100%; font-family: Arial, sans-serif;">
                            <thead>
                                <tr style="background-color: #f2f2f2;">
                                    <th style="border:1px solid #ddd;padding:8px;text-align:left;">Title</th>
                                    <th style="border:1px solid #ddd;padding:8px;text-align:left;">Description</th>
                                    <th style="border:1px solid #ddd;padding:8px;text-align:left;">Date</th>
                                </tr>
                            </thead>
                            <tbody>
                                {task_rows}
                            </tbody>
                        </table>

                        <p><strong>Total pending tasks:</strong> {len(tasks)}</p>
                        <p>Take small steps consistently — your productivity matters! 🚀</p>
                        <p>👉 <a href="{login_url}">Login to manage your tasks</a></p>
                        <br><p>— <strong>TaskCare360 Team</strong></p>
                        """

                    subject = f"📋 Daily Task Reminder - {datetime.now().strftime('%b %d')}"

                    # Create MIME message with HTML content
                    msg = MIMEMultipart("alternative")
                    msg['From'] = sender_email
                    msg['To'] = user.email
                    msg['Subject'] = subject
                    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

                    try:
                        server.send_message(msg)
                    except Exception as e:
                        current_app.logger.error(f"Failed to send to {user.email}: {e}")

                return True

    except Exception as e:
        current_app.logger.error(f"Unexpected error: {e}")
        return jsonify({"error": "An error occurred while sending reminders."}), 500

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import time
import threading

def notification_scheduler():
    target_hour = 7
    target_minute = 0

    ist = ZoneInfo("Asia/Kolkata")  # Timezone for India
    last_run_date = None  # Track last run date in IST

    while True:
        now = datetime.now(ist)
        today_target = now.replace(hour=target_hour, minute=target_minute, second=0, microsecond=0)

        # Determine next target time
        if now >= today_target:
            next_target = today_target + timedelta(days=1)
        else:
            next_target = today_target

        seconds_until_next = (next_target - now).total_seconds() - 30
         
        if seconds_until_next <= 0:
            print(f"Executing message schedular immediately.")
        else:
            print(f"[Scheduler] Sleeping for {int(seconds_until_next)} seconds until {next_target}")

        if seconds_until_next > 1:
            time.sleep(seconds_until_next)

        # Wait until exact target time
        while datetime.now(ist) < next_target:
            time.sleep(1)

        # Avoid duplicate runs
        if last_run_date == datetime.now(ist).date():
            print("⏳ Already ran today — skipping.")
            continue

        try:
            with app.app_context():
                sent_msg = send_daily_task_reminders()
                if sent_msg:
                    print("✅ Reminders sent successfully.")
                else:
                    print("❌ No users found to send reminders.")

                last_run_date = datetime.now(ist).date()
                
        except Exception as e:
            print(f"❌ Failed to send notifications: {e}")

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
        return redirect(url_for('TaskCare360'))
    return redirect(url_for('dashboard'))

# Landing Page
@app.route('/TaskCare360')
def TaskCare360():
    return render_template('landing.html')

# Dashbord route
@app.route('/TaskCare360/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Session expired! Please log in again.', 'warning')
        return redirect(url_for('TaskCare360'))

    user_id = session.get('user_id')
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
@app.route('/TaskCare360/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            # Validate form data exists
            if not all(field in request.form for field in ['name', 'email', 'password']):
                flash("All fields are required!", "danger")
                return redirect(url_for('signup'))

            # Get and sanitize inputs
            name = request.form['name'].strip()
            email = request.form['email'].strip().lower()
            raw_password = request.form['password'].strip()

            # Validate name
            if not name or len(name) > 100:
                flash("Name must be 1-100 characters", "danger")
                return redirect(url_for('signup'))

            # Validate password strength
            if len(raw_password) < 8:
                flash("Password must be at least 8 characters", "danger")
                return redirect(url_for('signup'))

            # Check if email exists
            if User.query.filter_by(email=email).first():
                flash("Email already registered. Please login instead.", "warning")
                return redirect(url_for('login'))

            # Create user
            try:
                hashed_password = generate_password_hash(raw_password)
                user_data = {
                    'name': name,
                    'email': email,
                    'password': hashed_password
                }
                new_user = User(**user_data)
                db.session.add(new_user)
                db.session.commit()
                flash("Signup successful! Please log in.", "success")
                return redirect(url_for('login'))
            except Exception as db_error:
                db.session.rollback()
                current_app.logger.error(f"Database error: {str(db_error)}")
                flash("Registration failed. Please try again.", "danger")
                return redirect(url_for('signup'))

        except Exception as e:
            current_app.logger.error(f"Signup error: {str(e)}")
            flash("An error occurred during registration", "danger")
            return redirect(url_for('signup'))

    # GET request
    return render_template('signup.html')

@app.route('/TaskCare360/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
  
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.name
            session.permanent = True  # Enable session expiration
            
            expiry_time = datetime.now() + timedelta(minutes=10)  # Set session expiry time
            session['session_expiry'] = expiry_time.timestamp()  # Store expiry time as timestamp
            
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))

        flash("Invalid credentials. Try again.", "danger")

    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully!.", "info")
    return redirect(url_for('TaskCare360'))

# Forgot password
@app.route('/TaskCare360/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', "").strip()  # Ensure no extra spaces
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

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, message)

        # Store OTP and expiry in Flask session
        session['sent_otp'] = str(otp)  # Store as string to avoid type issues
        session['otp_expiry'] = (datetime.now() + timedelta(minutes=3)).timestamp()
        session.modified = True
        return True

    except smtplib.SMTPAuthenticationError:
        print("SMTP Authentication failed. Check app password.")
    except Exception as e:
        print(f"Failed to send OTP email: {e}")
    
    return False

# Verify OTP Route
@app.route('/TaskCare360/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    try:
        # Retrieve all session data at once
        email = session.get('email')
        sent_otp = session.get('sent_otp')
        otp_expiry = session.get('otp_expiry')

        # Validate all required session data exists
        if not email or not sent_otp or not otp_expiry:
            session.pop('sent_otp', None)
            session.pop('otp_expiry', None)
            session.pop('email', None)
            flash("OTP session invalid. Please request a new OTP.", "danger")
            return redirect(url_for('forgot_password'))

        # Safe OTP expiry check
        try:
            if datetime.now().timestamp() > float(otp_expiry):
                session.pop('sent_otp', None)
                session.pop('otp_expiry', None)
                session.pop('email', None)
                flash("OTP has expired! Please request a new one.", "danger")
                return redirect(url_for('forgot_password'))
        except (TypeError, ValueError):
            session.pop('sent_otp', None)
            session.pop('otp_expiry', None)
            session.pop('email', None)
            flash("OTP validation error. Please request a new one.", "danger")
            return redirect(url_for('forgot_password'))

        if request.method == 'POST':
            entered_otp = request.form.get('otp', '').strip()
            
            # Basic OTP format validation
            if not entered_otp or not entered_otp.isdigit() or len(entered_otp) != 6:
                flash("Invalid OTP format. Please enter 6 digits.", "danger")
                return redirect(url_for('verify_otp'))

            # Simple comparison (for learning - in production use constant-time compare)
            if str(sent_otp) != entered_otp:
                flash("Invalid OTP! Please try again.", "danger")
                return redirect(url_for('verify_otp'))
                
            # Successful verification
            session.pop('sent_otp', None)
            session.pop('otp_expiry', None)
            session['verified_email'] = email  # Store verified email
            session.pop('email', None)

            flash("OTP verified successfully! Please reset your password.", "success")
            return redirect(url_for('reset_password'))

        return render_template('verify_otp.html')

    except Exception as e:
        # Log unexpected errors (make sure to configure logging in your app)
        current_app.logger.error(f"OTP verification error: {str(e)}")
        session.pop('sent_otp', None)
        session.pop('otp_expiry', None)
        session.pop('email', None)
        flash("An unexpected error occurred. Please try again.", "danger")
        return redirect(url_for('forgot_password'))
    
# Reset Password using OTP
@app.route('/TaskCare360/reset_password', methods=['GET', 'POST'])
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
@app.route('/TaskCare360/get_username', methods=['GET', 'POST'])
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
    try:
        # ✅ Check user is logged in
        if 'user_id' not in session:
            flash("Please log in to add a task!", "warning")
            return redirect(url_for('login'))

        # ✅ Validate form inputs
        title = request.form.get('title', '').strip()
        desc = request.form.get('desc', '').strip()

        if not title or not desc:
            flash("Both title and description are required.", "danger")
            return redirect(url_for('dashboard'))

        if len(title) > 200:
            flash("Title must be 1–200 characters.", "danger")
            return redirect(url_for('dashboard'))

        user_id = session['user_id']

        # ✅ Create and save the new todo
        new_todo = Todo(
            title=title,
            desc=desc,
            user_id=user_id,
            date_created=datetime.utcnow()  # ✅ CORRECT FIELD NAME
        )

        db.session.add(new_todo)
        db.session.commit()

        # Optional: Log IP and device for tracking/debugging
        user_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent')
        app.logger.info(f"Task added by user {user_id} from IP: {user_ip}, Device: {user_agent}")

        flash("Task added successfully!", "success")
        return redirect(url_for('dashboard'))

    except KeyError as ke:
        app.logger.error(f"Session error: {ke}")
        flash("Session error. Please log in again.", "danger")
        return redirect(url_for('login'))

    except Exception as e:
        db.session.rollback()
        app.logger.exception(f"Error adding task: {e}")  # ✅ Full traceback logging
        flash("An unexpected error occurred while saving your task.", "danger")
        return redirect(url_for('dashboard'))
    
#Update Todo
@app.route('/update/<int:SNo>', methods=['GET', 'POST'])
def updateTodo(SNo):
    try:
        # Authentication check
        if 'user_id' not in session:
            flash("Please log in to update tasks!", "warning")
            return redirect(url_for('login'))

        # Get the todo item with ownership check
        todo = Todo.query.filter_by(SNo=SNo, user_id=session['user_id']).first()
        if not todo:
            flash("Task not found or unauthorized access", "danger")
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            try:
                # Input validation
                title = request.form.get('title', '').strip()
                desc = request.form.get('desc', '').strip()

                if not title:
                    flash("Title cannot be empty!", "danger")
                    return render_template('update.html', todo=todo)

                if len(title) > 200:  # Adjust max length as needed
                    flash("Title too long (max 200 characters)", "danger")
                    return render_template('update.html', todo=todo)

                # Update todo
                todo.title = title
                todo.desc = desc
                todo.updated_at = datetime.utcnow()  # Optional timestamp update
                
                db.session.commit()
                flash("Task updated successfully!", "success")
                return redirect(url_for('dashboard'))

            except KeyError:
                flash("Invalid form submission", "danger")
                return render_template('update.html', todo=todo)
                
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Error updating todo: {str(e)}")
                flash("Failed to update task", "danger")
                return render_template('update.html', todo=todo)

        # GET request - show form
        return render_template('update.html', todo=todo)

    except Exception as e:
        current_app.logger.error(f"Unexpected error in updateTodo: {str(e)}")
        flash("An unexpected error occurred", "danger")
        return redirect(url_for('dashboard'))

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

# ✅ Start scheduler only once in production (and local dev)
def start_scheduler():
    if os.environ.get("RUN_MAIN") != "true":  # Avoid running twice in development
        scheduler_thread = threading.Thread(target=notification_scheduler, daemon=True)
        scheduler_thread.start()

# ✅ Always create the database on startup
with app.app_context():
    db.create_all()
    start_scheduler()  # 🔥 Always start scheduler

# ✅ Run app only if in local dev
if __name__ == '__main__':
    app.run(debug=False)
