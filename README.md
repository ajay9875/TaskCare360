# Flask To-Do App

## Overview
This is a Flask-based To-Do web application that allows users to create, update, and delete tasks. It includes user authentication, session management, and password recovery via email.

## Features
- User Registration & Login with password hashing
- Session-based authentication
- Add, update, and delete tasks
- Password reset via OTP (sent to email)
- Secure session management with expiration handling
- SQLite database management using SQLAlchemy
- API Endpoints for task management
- Responsive UI with Bootstrap

## Technologies Used
- Flask
- SQLAlchemy
- SQLite
- smtplib (for email functionality)
- Python-dotenv (for managing environment variables)
- Bootstrap (for frontend styling)

## Installation

### Prerequisites
Ensure you have Python installed (preferably version 3.8 or higher).

### Steps
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/todo-flask-app.git
   cd todo-flask-app
   ```

2. Create and activate a virtual environment:
   ```sh
   python -m venv env
   # On Windows
   env\Scripts\activate
   # On macOS/Linux
   source env/bin/activate
   ```

3. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

4. Create a `.env` file and add the following:
   ```sh
   SECRET_KEY=your_secret_key_here
   EMAIL_USER=your_email@example.com
   EMAIL_PASS=your_email_password
   ```

5. Initialize the database:
   ```sh
   python -c "from app import db; db.create_all()"
   ```

6. Run the application:
   ```sh
   python app.py
   ```

## API Endpoints

| Method | Endpoint                | Description                         |
|--------|-------------------------|-------------------------------------|
| GET    | `/`                     | Landing page                        |
| GET    | `/dashboard`            | User dashboard                      |
| POST   | `/signup`               | Register new user                   |
| POST   | `/login`                | Login user                          |
| GET    | `/logout`               | Logout user                         |
| POST   | `/forgot_password`      | Send OTP to reset password          |
| POST   | `/verify_otp`           | Verify OTP for password reset       |
| POST   | `/reset_password`       | Reset password using OTP            |
| POST   | `/add_todo`             | Add a new task                      |
| POST   | `/update_todo/<int:SNo>`| Update an existing task             |
| GET    | `/delete_todo/<int:SNo>`| Delete a task                       |

## File Structure
```
.
├── templates/          # HTML templates
├── static/             # Static files (CSS, JS, Images)
├── instance/           # Database storage (ignored in .gitignore)
├── app.py              # Main application file
├── models.py           # Database models
├── routes.py           # Application routes
├── forms.py            # Form handling with WTForms
├── utils.py            # Helper functions (email sending, validation)
├── requirements.txt    # List of dependencies
├── .env                # Environment variables (ignored in .gitignore)
├── .gitignore          # Ignored files for Git
└── README.md           # Project documentation
```

## Deployment
To deploy the application:
1. Push the code to GitHub:
   ```sh
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/yourusername/todo-flask-app.git
   git push -u origin main
   ```

2. Deploy on a hosting service like Heroku or Render.

## Environment Variables
Ensure the `.env` file contains:
```sh
SECRET_KEY=your_secret_key_here
EMAIL_USER=your_email@example.com
EMAIL_PASS=your_email_password
```

## Contribution
Feel free to submit pull requests or report issues!

## License
This project is open-source and available under the MIT License.

