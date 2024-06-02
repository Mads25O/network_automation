from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy import func

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method != 'POST':
        return render_template('login.html', user=current_user)

    username = request.form.get('username')
    password = request.form.get('password')
    
    user = User.query.filter_by(username=username).first()
    
    if user:
        if check_password_hash(user.password, password):
            flash('Logget ind!', category='success')
            login_user(user, remember=True)
            return redirect(url_for('views.home'))
        else:
            flash('Forkert adgangskode', category='error')
    else:
        flash('Bruger eksisterer ikke', category='error')

    return render_template('login.html', user=current_user)

    

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.')
    return redirect(url_for('auth.login'))

@auth.route('/register', methods=['GET', 'POST'])
def register():

    if request.method != 'POST':
        return render_template('register.html', user=current_user)
    
    username = request.form.get('username')
    password1 = request.form.get('password1')
    password2 = request.form.get('password2')
    
    user = User.query.filter_by(username=username).first()


    if user:
        flash('Brugernavn findes allerede.', category='error')
    elif len(username) < 4:
        flash('Username must be greater than 3 characters. Brugernavn er for kort', category='error')
    elif password1 != password2:
        flash('Adgangskoderne matcher ikke', category='error')
    elif len(password1) < 7:
        flash('Adgangskode er for kort', category='error')
    else:
        new_user = User(username=username, password=generate_password_hash(password1, method='pbkdf2'))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user, remember=True)

        flash('Account created!', category='success')
        return redirect(url_for('views.home'))
    
    return render_template('register.html', user=current_user)

    