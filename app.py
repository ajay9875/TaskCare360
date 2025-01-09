from flask import Flask, render_template, request, redirect, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

# sqlite://<nohostname>/<path>
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///todo.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Model definition
class Todo(db.Model):
    SNo = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    desc = db.Column(db.String, nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"{self.SNo} - {self.title}"


# Add a Todo
@app.route('/addTodo', methods=['POST'])
def addTodo():
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        
        todo = Todo(title=title, desc=desc)
        db.session.add(todo)
        db.session.commit()
        
        return redirect('/')

#Update Todo
@app.route('/update/<int:SNo>',methods=['POST'])
def updateTodo(SNo):
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        todo = Todo.query.filter_by(SNo=SNo).first()
        todo.title = title
        todo.desc = desc
        db.session.add(todo)
        db.session.commit()
        
        return redirect("/")
    todo = Todo.query.filter_by(SNo=SNo).first()
    return render_template('update.html',todo=todo)

#Delete Record
@app.route('/delete/<int:SNo>')
def deleteRecord(SNo):
    todo = Todo.query.filter_by(SNo=SNo).first()
    db.session.delete(todo)
    db.session.commit()
    # Redirect to the homepage to follow the PRG pattern
    return redirect(url_for('home'))


# Route definition
@app.route('/')
def home():
    allTodo = Todo.query.all()  # Fetch all todos
    return render_template('index.html', allTodo=allTodo)


# Entry point
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Initialize database
    app.run(debug=True)
