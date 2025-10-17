import pathlib

import google
from firebase_admin.firestore import client
from flask import Flask, render_template, request, flash, redirect, url_for,session
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms.validators import DataRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Float
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import os
from google_auth_oauthlib.flow import Flow

class Base(DeclarativeBase):
    pass

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")  # None if not set

scopes = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid"
]


GOOGLE_CLIENT_ID=os.environ.get('CLIENT')
client_secret_file = os.path.join(pathlib.Path(__file__).parent, 'client_secret.json')

flow = Flow.from_client_secrets_file(
    'client_secret.json',
    scopes=[
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
        'openid'
    ],
    redirect_uri='http://127.0.0.1:5000/callback'
)



app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///mydatabase.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Register')



# Routes

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user:
            if check_password_hash(user.password, form.password.data):
                flash("Logged in successfully!", "success")
                return redirect(url_for('home'))
            else:
                flash("Invalid password. Try again.", "danger")
        else:
            flash("Email not found. Please register first.", "warning")
            return redirect(url_for('register'))

    # Generate Google login URL
    authorization_url, state = flow.authorization_url()
    session['state'] = state

    return render_template('login.html', form=form, google_login_url=authorization_url)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    # Handle normal form registration
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered. Please login.", "danger")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Account created! You can now login.", "success")
        return redirect(url_for('login'))

    # Handle Google OAuth link
    # Make sure 'flow' is initialized before using it
    authorization_url, state = flow.authorization_url()
    session['state'] = state

    return render_template('register.html', form=form, google_login_url=authorization_url)


# Callback route to handle Google login
@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    # Get user info
    request_session = google.auth.transport.requests.Request()
    id_info = google.oauth2.id_token.verify_oauth2_token(
        credentials.id_token, request_session, audience=None
    )

    email = id_info.get("email")

    # Check if user exists
    user = User.query.filter_by(email=email).first()
    if not user:
        # Optionally, create user automatically
        flash("Please register first to use this email.", "warning")
        return redirect(url_for('register'))

    flash(f"Logged in as {email} via Google!", "success")
    return redirect(url_for('home'))


entries = []  # simple in-memory storage for now

@app.route('/save-entry', methods=['POST'])
def save_entry():
    entry = request.form.get('entry')
    if entry:
        entries.append(entry)
    return redirect(url_for('home'))


@app.route('/ai-support')
def ai_support():
    return render_template('ai-support.html', current_page='ai_support')

@app.route('/')
def home():
    return render_template('home.html', entries=entries, current_page='home')


@app.route('/goals')
def goals():
    return render_template('goals.html')

@app.route('/insights')
def insights():
    return render_template('insights.html')

@app.route('/mind-space')
def mind_space():
    return render_template('mind_space.html', current_page='mind_space')



with app.app_context():
    db.create_all()

if __name__=="__main__":
    app.run(debug=True)



