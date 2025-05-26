from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo, Regexp
import bcrypt
from flask_mysqldb import MySQL
import os
from dotenv import load_dotenv
from wtforms.validators import Length
from wtforms.validators import URL
from datetime import timedelta


load_dotenv()  # Load environment variables from .env

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'app_user'         # Changed from root
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')  # Read from .env
app.config['MYSQL_DB'] = 'mydatabase'
app.secret_key = os.getenv('SECRET_KEY')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

mysql = MySQL(app)

class SignUp(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])

    email = StringField("Email", validators=[DataRequired(), Email()])
    
    mobile = StringField("Mobile", validators=[
        DataRequired(),
        Regexp(r'^[0-9]{10}$', message="Invalid mobile number (must be 10 digits)")
    ])
    
    gender = SelectField("Gender", choices=[
        ('male', 'Male'), 
        ('female', 'Female'), 
        ('other', 'Other')
    ], validators=[DataRequired()])

    github = StringField("Github Profile", validators=[
    DataRequired(),
    URL(message="Invalid GitHub profile URL"),
    Regexp(r'github\.com/', message="Must be a GitHub profile URL")
])

    password = PasswordField("Password", validators=[
    DataRequired(),
    Length(min=12, message="Password must be at least 12 characters"),
    Regexp(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_])',
           message="Must include: 1 uppercase, 1 lowercase, 1 number, 1 special character")
])

    confirm_password = PasswordField("Confirm Password", validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])

    submit = SubmitField("Sign Up")

    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email Already Taken')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

@app.route('/')
def home():
    return render_template('app.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUp()
    if form.validate_on_submit():
        try:
            # Get form data
            name = form.name.data
            email = form.email.data
            mobile = form.mobile.data
            gender = form.gender.data
            password = form.password.data

            # Hash the password (during signup)
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Database operation
            cursor = mysql.connection.cursor()
            cursor.execute(
    "INSERT INTO users (name, email, mobile, gender, password, github) VALUES (%s,%s,%s,%s,%s,%s)",  # Added github
    (name, email, mobile, gender, hashed_password, form.github.data)  # Added GitHub data
)
            mysql.connection.commit()
            
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash('Registration failed. Please try again.')
            mysql.connection.rollback()
        finally:
            cursor.close()

    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        cursor = None  # Initialize cursor for finally block

        try:
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()
            
            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                session.permanent = True  # Enable session expiration
                session['user_id'] = user['id']  # Use dictionary access
                session['user_name'] = user['name']  # Store name in session
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
            
            flash("Invalid email or password", "danger")
            return redirect(url_for('login'))

        except Exception as e:
            app.logger.error(f"Login error for {email}: {str(e)}")
            flash("An error occurred during login. Please try again.", "danger")
            return redirect(url_for('login'))
        
        finally:
            if cursor:
                cursor.close()

    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    
    if not user:
        flash("User not found. Please log in again.")
        session.pop('user_id', None)  # Clear invalid session
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', 
        user_name=user['name'],     # Access by column name
        user_email=user['email'],
        user_mobile=user['mobile'],
        user_gender=user['gender'],
        user_github=user['github']
    )

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)