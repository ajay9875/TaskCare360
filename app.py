from flask import Flask, make_response, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import random
import smtplib
import os
from dotenv import load_dotenv
load_dotenv()

from datetime import datetime, UTC
from flask import current_app, jsonify
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import os
import smtplib
from datetime import datetime
from flask import current_app, jsonify
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'

# PostgreSQL Configuration - Single Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')  # postgresql://user:pass@host/dbname
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,
    'max_overflow': 20,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
    'pool_timeout': 30
}

db = SQLAlchemy(app)

# ======================
# MODELS (100% Attribute Preservation)
# ======================
from zoneinfo import ZoneInfo
ist = ZoneInfo("Asia/Kolkata")  # Timezone for India
import pytz

# Global variable (no need for self/this)
IST = pytz.timezone('Asia/Kolkata')
print(datetime.now(ist).date())
class User(db.Model):
    __tablename__ = 'user'  # Original table name
    __table_args__ = {'schema': 'taskcare_schema'}

    # Original Attributes (Exactly as in SQLite)
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    
    # Original Relationship (if used)
    todos = db.relationship('Todo', backref='user', lazy=True)

class Todo(db.Model):
    __tablename__ = 'todo'  # Original table name
    __table_args__ = {'schema': 'taskcare_schema'}

    # Original Attributes (Exactly as in SQLite)
    SNo = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.String, nullable=False)
    date_created = db.Column(db.Date, nullable=False)  # No default
    date_updated = db.Column(db.Date, nullable=True)  # No default

    user_id = db.Column(db.Integer, db.ForeignKey('taskcare_schema.user.id'), nullable=False)  # Original FK

    def __repr__(self) -> str:
        return f"{self.SNo} - {self.title}"  # Original
    
@app.route('/addTodo', methods=['POST'])
def addTodo():
    try:
        if 'user_id' not in session:
            flash("Please login first", "warning")
            return redirect(url_for('login'))

        # Get and validate form data
        title = request.form.get('title', '').strip()
        desc = request.form.get('desc', '').strip()
        
        if not title or not desc:
            flash("Both fields required", "danger")
            return redirect(url_for('dashboard'))

        # Get current IST date (timezone-aware)
        global ist
        current_ist_date = datetime.now(ist).date()

        # Create new todo
        new_todo = Todo(
            title=title,
            desc=desc,
            user_id=session['user_id'],
            date_created=current_ist_date  # Explicit IST date
        )

        db.session.add(new_todo)
        db.session.commit()
        flash("Task added!", "success")
        return redirect(url_for('dashboard'))

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Add task failed: {str(e)}", exc_info=True)
        flash("Task addition failed", "danger")
        return redirect(url_for('dashboard'))

# Create schemas if they don't exist
def initialize_database():
    with app.app_context():
        # Create schema if not exists
        db.session.execute(db.text('CREATE SCHEMA IF NOT EXISTS taskcare_schema'))
        db.session.commit()
        db.create_all()
        print("Database schema and tables initialized!")

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import time
import threading

"""# Route/Function to define time for sending email
def notification_scheduler():
    target_hour = 7
    target_minute = 30

    global ist # Timezone for India
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
            print(f"❌ Failed to send notifications: {e}")"""

from datetime import datetime, timedelta
import time
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")

def notification_scheduler():
    target_times = [
        (7, 30),   # 7:30 AM
        (15, 30)    # 5:30 PM
    ]
    
    last_run_times = {}  # Track last run for each target

    while True:
        now = datetime.now(IST)
        
        # Find the next target time
        next_target = None
        for hour, minute in target_times:
            target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            
            # If target is in the past today, schedule for next day
            if now >= target:
                target += timedelta(days=1)
                
            # Find the earliest upcoming target
            if next_target is None or target < next_target:
                next_target = target

        sleep_seconds = (next_target - now).total_seconds()
        
        if sleep_seconds > 1:
            print(f"⏳ Next run at {next_target.strftime('%I:%M %p')} IST (in {int(sleep_seconds)}s)")
            time.sleep(sleep_seconds)

        # Verify we're at the exact target time
        while datetime.now(IST) < next_target:
            time.sleep(0.1)

        # Check if we already ran for this specific time today
        current_target = next_target.replace(tzinfo=None)
        if last_run_times.get(current_target.date()) == current_target.time():
            print(f"⏭ Already ran at {current_target.strftime('%I:%M %p')} today")
            continue

        try:
            with app.app_context():
                print(f"⏰ Executing scheduler for {current_target.strftime('%I:%M %p')} IST")
                sent_msg = send_daily_task_reminders()
                
                if sent_msg:
                    print("✅ Reminders sent successfully")
                    last_run_times[current_target.date()] = current_target.time()
                else:
                    print("ℹ️ No users needed reminders")

        except Exception as e:
            print(f"❌ Error sending notifications: {str(e)}")

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
                        <p>👉 <a href="{login_url}">Login</a> to manage your tasks</p>
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

@app.route('/')
def default():
    if 'user_id' not in session:
        return redirect(url_for('TaskCare360'))
    return redirect(url_for('dashboard'))

# Landing Page
@app.route('/TaskCare360')
def TaskCare360():
    return render_template('landing.html')

#Dashboard Page
@app.route('/TaskCare360/dashboard')
def dashboard():
    if 'user_id' not in session:
        #flash('Session expired! Please log in again.', 'warning')
        session.clear()
        return redirect(url_for('TaskCare360'))

    # Enforce session expiry on server side
    expiry_timestamp = session.get('session_expiry', 0)
    #current_timestamp = datetime.utcnow().timestamp()
    current_timestamp = datetime.now(UTC).timestamp()  # ✅ Modern replacement for utcnow()

    if current_timestamp > expiry_timestamp:
        session.clear()
        flash('Session expired. Please login again.', 'danger')
        return redirect(url_for('logout'))

    # Get current UTC time

    """ 
    utc_now = datetime.now(UTC)
    ist_now = utc_now.astimezone(ist)
    print("IST Time:", ist_now) 
    """

    user_id = session['user_id']
    username = session['username']

    remaining_time = max(0, int(expiry_timestamp - current_timestamp))  # Seconds

    allTodo = Todo.query.filter_by(user_id=user_id).all()

    # Prevent caching of this page
    response = make_response(render_template('index.html',
                                             allTodo=allTodo,
                                             username=username,
                                             remaining_time=remaining_time))
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response

# Signup
@app.route('/TaskCare360/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            # Validate all required fields exist
            required_fields = ['name', 'email', 'Cemail', 'password', 'Cpassword']
            if not all(field in request.form for field in required_fields):
                flash("All fields are required!", "danger")
                return redirect(url_for('signup'))

            # Get and sanitize inputs
            name = request.form['name'].strip()
            email = request.form['email'].strip().lower()
            Cemail = request.form['Cemail'].strip().lower()
            password = request.form['password'].strip()
            Cpassword = request.form['Cpassword'].strip()

            # Validate email match
            if email != Cemail:
                flash("Email addresses do not match!", "danger")
                return redirect(url_for('signup'))

            # Validate password match
            if password != Cpassword:
                flash("Passwords do not match!", "danger")
                return redirect(url_for('signup'))

            # Validate name
            if not name or len(name) > 100:
                flash("Name must be 1-100 characters", "danger")
                return redirect(url_for('signup'))

            # Validate password strength
            if len(password) < 8:
                flash("Password must be at least 8 characters", "danger")
                return redirect(url_for('signup'))

            # Check if email exists
            if User.query.filter_by(email=email).first():
                flash("Email already registered. Please login instead.", "warning")
                return redirect(url_for('login'))

            # Create user
            try:
                hashed_password = generate_password_hash(password)
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

# Login Page Route
@app.route('/TaskCare360/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.name
            session.permanent = True  # Required if using app.permanent_session_lifetime

            # Use UTC for deployment-safe session expiry
            expiry_time = datetime.now(UTC) + timedelta(minutes=15)  # 15 minutes
            session['session_expiry'] = expiry_time.timestamp()

            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))

        flash("Invalid credentials. Try again.", "danger")

    return render_template('login.html')

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)

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
from flask import flash, redirect, render_template, request
from sqlalchemy.exc import SQLAlchemyError

@app.route('/TaskCare360/get_username', methods=['GET', 'POST'])
def get_username():
    if request.method == 'POST':
        try:
            # Validate email input
            email = request.form.get('email', '').strip()
            if not email or '@' not in email:
                flash("Please enter a valid email address", "danger")
                return redirect('get_username')

            # Database query with error handling
            user = User.query.filter_by(email=email).first()
            
            if user:
                flash(f"Your username is: {user.email}", "success")
            else:
                flash("Email not registered. Check spelling or try another.", "danger")                
            return redirect('get_username')

        except SQLAlchemyError as e:
            # Log the error for debugging
            app.logger.error(f"Database error in get_username: {str(e)}")
            flash("A database error occurred. Please try again.", "danger")
            return redirect('get_username')

        except Exception as e:
            # Catch-all for other exceptions
            app.logger.error(f"Unexpected error in get_username: {str(e)}")
            flash("An unexpected error occurred. Please try again.", "danger")
            return redirect('get_username')

    return render_template('forgot_username.html')
    
#Update Todo
@app.route('/TaskCare360/update/<int:SNo>', methods=['GET', 'POST'])
def updateTodo(SNo):
    try:
        # Authentication check
        if 'user_id' not in session or 'username' not in session:
            flash("Please log in to update tasks!", "warning")
            return redirect(url_for('login'))

        # Get the todo item with ownership check
        todo = Todo.query.filter_by(SNo=SNo, user_id=session['user_id']).first()
        if not todo:
            flash("Task not found, please add new task first.", "danger")
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

                global ist
                current_ist_date = datetime.now(ist).date()

                # Update todo
                todo.title = title
                todo.desc = desc
                todo.date_updated = current_ist_date # Optional timestamp update
                
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
    #db.create_all()
    start_scheduler()  # 🔥 Always start scheduler

# ✅ Run app only if in local dev
if __name__ == '__main__':
    initialize_database()
    app.run(debug=False)
