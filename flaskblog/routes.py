from flask import render_template, url_for, flash, redirect
from flaskblog import app, db, bcrypt
from flaskblog.forms import RegistrationForm, LoginForm
from flaskblog.models import User
from flask_bcrypt import Bcrypt
from flask_login import login_user


doctors = [
    {
        "name": "Ankit Sahasrabudhe",
        "education": "MBBS",
        "specialist": "Anasthesialogist",
        "experience": 3,
        "patients_examined": 10,
        "fees": 499,
        "contact": '+91 89852 43789'
    },
    {
        "name": "Pankaj Joshi",
        "education": "MD",
        "specialist": "Cardiologist",
        "experience": 8,
        "patients_examined": 12,
        "fees": 325,
        "contact": '+91 73789 89852'
    },
    {
        "name": "Arunesh Dutt",
        "education": "BDMS",
        "specialist": "General Physician",
        "experience": 12,
        "patients_examined": 15,
        "fees": 600,
        "contact": '+91 43898 52789'
    }

]
@app.route('/')
@app.route('/home')
def home():
    return render_template("home.html", doctors=doctors)


@app.route('/about')
def about():
    return render_template("about-us.html", title="About")


@app.route('/contact')
def contact():
    return render_template("contact-us.html", title="Contact")


@app.route('/help')
def help():
    return render_template("help.html", title="Help")

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created successfully for {form.username.data}!', 'success')
        return redirect(url_for('login'))
    return render_template("register.html", title="Register", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)  
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful', 'danger')
    return render_template("login.html", title="Login", form=form)