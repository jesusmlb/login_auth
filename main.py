from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CREATE DATABASE


class Base(DeclarativeBase):
    pass
# Connect to Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE TABLE IN DB


class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    # Let's get the data from the form to update the database
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        if User.query.filter_by(email=email).first():
            error = 'You already signed up with that email, log in instead!'
            return render_template("login.html", error=error)
        else:
            password = request.form.get('password')
            # Let's hash the password
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            name = request.form.get('name')
            session['my_var'] = name.capitalize()
            # Let's save the user data to the database
            db.session.add(User(email=email, password=hashed_password, name=name))
            db.session.commit()
            return redirect(url_for('secrets'))
    else:
        return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        # Let's check if the user exists in the database
        user = User.query.filter_by(email=email).first()
        if user:
            # Let's check if the password is correct
            if check_password_hash(user.password, password):
                session['my_var'] = user.name.capitalize()
                login_user(user)
                return redirect(url_for('secrets'))
            else:
                error = 'Password is incorrect'
        else:
            error = 'User not found'
    return render_template("login.html", error=error, logged_in=current_user.is_authenticated)


# Let's pass the loggin status to the template
@app.context_processor
def inject_logged_in():
    return {'logged_in': current_user.is_authenticated}


@app.route('/secrets')
@login_required
def secrets():
    name = session.get('my_var')
    return render_template("secrets.html", name=name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download', methods=['POST', 'GET'])
@login_required
def download():
    # Let's get the file from directory
    if request.method == 'GET':
        return send_from_directory(directory='static/files', path="cheat_sheet.pdf")

if __name__ == "__main__":
    app.run(debug=True)
