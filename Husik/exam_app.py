from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, LoginManager, UserMixin, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length, EqualTo, Email
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:qwerty@localhost:5432/students_db'
app.config['SECRET_KEY'] = 'Chamberofsecrets'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class Students(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    surname = db.Column(db.String(30))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(50))

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

@login_manager.user_loader
def load_user(user_id):
    return Students.query.get(int(user_id))

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Email()])
    password = PasswordField('Password', validators=[InputRequired(message='Password is required'),
                                            Length(min=6, message='Password must be at least 6 characters')])
class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired(message='Name is required.'),
                                           Length(min=2, max=50, message='Name must be between 2 and 50 characters.')])
    surname = StringField('Surname', validators=[InputRequired(message='Surname is required.'),
                                                 Length(min=2, max=50,
                                                        message='Surname must be between 2 and 50 characters.')])
    email = StringField('Email', validators=[Email()])
    password = PasswordField('Password', validators=[
        InputRequired(message='Password is required'),
        Length(min=6, message='Password must be at least 6 characters')])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[InputRequired(message='Confirm Password is required.'),
                                                 EqualTo('password', message='Passwords do not match.')])

@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        pass
    return render_template('home.html')

@app.route('/signUp', methods=['GET', 'POST'])
def signUp():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = Students.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('An account with this email already exists. Please log in.', 'danger')
            return redirect(url_for('signUp'))

        new_user = Students(name=form.name.data, surname=form.surname.data, email=form.email.data, password=form.password.data)

        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for('userPage'))

    return render_template('signUp.html', form=form)

@app.route('/signIn', methods=['GET', 'POST'])
def signIn():
    form = LoginForm()

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = Students.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')

            next_page = session.get('next')
            if next_page:
                return redirect(next_page)

            return redirect(url_for('userPage'))
        else:
            flash('Login failed. Please check your email and password.', 'danger')

    session['next'] = request.args.get('next')

    return render_template('signIn.html', form=form)

@app.route('/userPage', methods=['GET', 'POST'])
@login_required
def userPage():
    return render_template('userPage.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('home'))

@app.route('/adminPage', methods=['GET','POST'])
def adminPage():
    return render_template('adminPage.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)



# from flask import Flask, render_template
# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate, MigrateCommand
# from flask_script import Manager
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField
# from wtforms.validators import InputRequired, Length
#
# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:qwerty@localhost:5432/students_db'
# app.config['DEBUG'] = True
#
# db = SQLAlchemy(app)
# migrate = Migrate(app, db)
#
# manager = Manager(app)
# manager.add_command('db', MigrateCommand)
#
# class Students(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.Column(db.String(100)))
#     surname = db.Column(db.String(30))
#     email = db.Column(db.String(100))
#     password = db.Column(db.String(50))
#
# class RegisterForm(FlaskForm):
#     name = StringField('Name', validators=[InputRequired('Full name is requires'), Length(max=100, message='Your name can\'t be more than 100 characters.')])
#     surname = StringField('Surname', validators=[InputRequired('Surname is required.'), Length(max=35, message='Your surname can\'t be more than 35 characters.')])
#     email = StringField('Email', validators=[InputRequired('Email is required.'), Length(max=40, message='Your email can\'t be more than 40 characters.')])
#     password = PasswordField('Password', validators=[InputRequired('Password is required.')])
#
# @app.route('/')
# def home():
#     return render_template('home.html')

# from flask_wtf import FlaskForm
# from flask_wtf.file import FileField, FileAllowed
# from wtforms import StringField, PasswordField, SubmitField
# from wtforms.validators import InputRequired, Length, Email, EqualTo
#
# class RegisterForm(FlaskForm):
#     name = StringField('Name', validators=[InputRequired(message='Name is required.'),
#                                            Length(min=2, max=50, message='Name must be between 2 and 50 characters.')])
#     surname = StringField('Surname', validators=[InputRequired(message='Surname is required.'),
#                                                  Length(min=2, max=50,
#                                                         message='Surname must be between 2 and 50 characters.')])
#     email = StringField('Email', validators=[Email()])
#
#     password = PasswordField('Password', validators=[
#         InputRequired(message='Password is required'),
#         Length(min=6, message='Password must be at least 6 characters')])
#     confirm_password = PasswordField('Confirm Password',
#                                      validators=[InputRequired(message='Confirm Password is required.'),
#                                                  EqualTo('password', message='Passwords do not match.')])
#
# class LoginForm(FlaskForm):
#     email = StringField('Email', validators=[Email()])
#     password = PasswordField('Password', validators=[
#         InputRequired(message='Password is required.'),
#         Length(min=8, message='Password must be at least 8 characters long.')
#     ])

# class UpdateProfileImageForm(FlaskForm):
    # profile_image = FileField('Update Profile Image', validators=[FileAllowed(['jpg', 'jpeg', 'png'])])
    # submit = SubmitField('Upload')


# from flask import Flask, render_template, request, g, flash, abort, url_for, redirect
# from flask_sqlalchemy import SQLAlchemy
# import os
# from werkzeug.security import generate_password_hash, check_password_hash
# from flask_login import LoginManager, login_user, login_required, logout_user, current_user

# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:qwerty@localhost:5432/students_db'
#
# db = SQLAlchemy(app)

# login_manager = LoginManager(app)
# login_manager.login_view = 'login'
# login_manager.login_message = 'Authorize yourself to access restricted pages.'
# login_manager.login_message_category = 'success'

# class Students(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(80), nullable=False)
#     surname = db.Column(db.String(80), nullable=False)
#     email = db.Column(db.String(80), nullable=False, unique=True)
#     password = db.Column(db.String(120), nullable=False)
#
# @app.route('/')
# @app.route('/home', methods=['GET', 'POST'])
# def home():
#     return render_template('home.html')
#
# # def get_db():
# #     pass
#
# @app.route('/signUp', methods=['GET', 'POST'])
# def signUp():
#     if request.method == 'POST':
        # db = get_db()
        # hashed_password = generate_password_hash(request.form['password'], method='sha256')
        # db.execute('insert into users (name, surname, email, password) values (?)', [request.form['name'], hashed_password, 0, 0])
        # db.commit()
        # name = request.form['username']
        # surname = request.form['surname']
        # email = request.form['email']
        # password = request.form['password']
#         return '<h1>User created</h1>'
#
#     return render_template('signUp.html')
#
# @app.route('/signIn')
# def signIn():
#     return render_template('signIn.html')
#
# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True)

# from socket import create_connection
# from flask import Flask, render_template, redirect, request, url_for, session, flash
# from flask_login import login_user
# from flask_sqlalchemy import SQLAlchemy
# from werkzeug.security import generate_password_hash, check_password_hash
#
# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:qwerty@localhost:5432/students_db'
# app.config['SECRET_KEY'] = 'Txdfcghvjxdgbh'
#
# db = SQLAlchemy(app)
#
# class Students(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(80), nullable=False)
#     surname = db.Column(db.String(80), nullable=False)
#     email = db.Column(db.String(80), nullable=False, unique=True)
#     password = db.Column(db.String(120), nullable=False)
#
# @app.route('/', methods=['GET', 'POST'])
# @app.route('/home', methods=['GET', 'POST'])
# def home():
#     return render_template('home.html')
# def create_user(conn, user):
#     pass
#
# @app.route('/signUp', methods=['GET', 'POST'])
# def signUp():
#     if request.method == 'POST':
#         username = request.form['username']
#         email = request.form['email']
#         password = request.form['password']
#
#         conn = create_connection()
#
#         user = (username, email, password)
#         create_user(conn, user)
#
#         conn.close()
#
#         return redirect(url_for('signIn'))
#
#     return render_template('signUp.html')
#
# @app.route('/signIn', methods=['GET', 'POST'])
# def signIn():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']
#
#         user = Students.query.filter_by(email=email).first()
#
#         if user and check_password_hash(user.password, password):
#             session['user_id'] = user.id
#             login_user(user)
#             flash('Login successful!', 'success')
#
#             return redirect(url_for('home'))
#         else:
#             flash('Invalid email or password. Please try again.', 'error')
#
#         return redirect(url_for('userPage'))
#
#     return render_template('signIn.html')
#
# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True)

# @app.route('/signUp', methods=['GET', 'POST'])
# def signUp():
#     if request.method == 'POST':
#        if len(request.form['name']) > 4 and len(request.form['email']) > 4 \
#            and len(request.form['psw']) > 4 and request.form['psw'] == request.form['psw2']:
#            hash = generate_password_hash(request.form['psw'])
#            res = db.addStudents(request.form['name'], request.form['email'], hash)
#            if res:
#                flash('You signUp successfully',  'success')
#                return redirect(url_for('signIn'))
#            else:
#                flash('Wrong data have been added', 'error')
#        else:
#            flash('Fields are filled in uncorrect', 'error')
#     return render_template('signUp.html')

# from flask import Flask, render_template, request, redirect, flash, url_for
# from sqlalchemy.testing import db
# from werkzeug.security import generate_password_hash, check_password_hash
#
# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:qwerty@localhost:5432/students_db'
# app.secret_key = 'your_secret_key_here'
#
# class Students(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(80), nullable=False)
#     surname = db.Column(db.String(80), nullable=False)
#     email = db.Column(db.String(80), nullable=False, unique=True)
#     password = db.Column(db.String(120), nullable=False)
#
# @app.route('/home', method=['GET', 'POST'])
# def home():
#     return render_template(url_for('home.html'))
#
# @app.route('/signUp', methods=['GET', 'POST'])
# def signUp():
#     if request.method == 'POST':
#         name = request.form['name']
#         surname = request.form['surname']
#         email = request.form['email']
#         password = request.form['password']
#         confirm_password = request.form['confirm_password']
#
#         if password != confirm_password:
#             flash('Passwords do not match. Please try again.', 'error')
#             return redirect(url_for('signUp'))
#
#         hashed_password = generate_password_hash(password, method='sha256')
#
#         new_user = Students(name=name, surname=surname, email=email, password=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()
#
#         flash('Registration successful. You can now log in.', 'success')
#         return redirect(url_for('signIn'))  # Replace with the appropriate route
#
#     return render_template('signUp.html')

# if __name__ == '__main__':
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True)

# from flask import Flask, render_template, request, flash, redirect, url_for
# from flask_sqlalchemy import SQLAlchemy
# from werkzeug.security import generate_password_hash, check_password_hash
#
# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:qwerty@localhost:5432/students_db'
# db = SQLAlchemy(app)
#
# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(50), nullable=False)
#     email = db.Column(db.String(120), unique=True, nullable=False)
#     password = db.Column(db.String(100), nullable=False)
#
# @app.route('/home', methods=['GET', 'POST'])
# @app.route('/')
# def home():
#     users = User.query.all()
#     return render_template('home.html', users=users)
#
# @app.route('/signUp', methods=['GET', 'POST'])
# def signUp():
#     if request.method == 'POST':
#         name = request.form['name']
#         email = request.form['email']
#         password = request.form['password']
#
#         hashed_password = generate_password_hash(password, method='sha256')
#
#         new_user = User(name=name, email=email, password=hashed_password)
#         db.session.add(new_user)
#         db.session.commit()
#
#         flash('Registration successful. You can now log in.', 'success')
#         return redirect(url_for('signUp'))
#
#     return render_template('signUp.html')
#
# @app.route('/signIn', methods=['GET', 'POST'])
# def signIn():
#     if request.method == 'POST':
#         email = request.form['email']
#         password = request.form['password']
#
#         user = User.query.filter_by(email=email).first()
#
#         if user and check_password_hash(user.password, password):
#             flash('Login successful!', 'success')
#             return redirect(url_for('home'))
#         else:
#             flash('Login failed. Please check your credentials.', 'danger')
#
#     return render_template('signIn.html')
#
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
