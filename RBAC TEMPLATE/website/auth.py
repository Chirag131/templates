from flask import Blueprint,request , redirect , url_for , render_template , abort
from flask_login import login_user , logout_user , login_required , current_user
from .models import User, db
from . import bcrypt
from functools import wraps

auth = Blueprint('auth',__name__)

@auth.route('/signup', methods = ['GET','POST'])
def signup():
    if request.method == "POST" :
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role = request.form['role']
        new_user = User(username=username,password=password,role=role)
        db.session.add(new_user)
        db.session.commit()

        user = User.query.filter_by(username=request.form['username']).first()
        login_user(user)
        if user.role == 'admin':
            return redirect(url_for('routes.admin_dashboard'))
        elif user.role == 'viewer':
            return redirect(url_for('routes.viewer_dashboard'))
        else : 
            return redirect(url_for('auth.login'))
    return render_template('signup.html')


@auth.route('/login', methods = ['GET','POST'])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password,request.form['password']):
            login_user(user)

            if user.role == 'admin':
             return redirect(url_for('routes.admin_dashboard'))
            elif user.role == 'viewer':
                return redirect(url_for('routes.viewer_dashboard'))
            else : 
                return redirect(url_for('auth.login'))
        
    return render_template('login.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


def role_required(*roles):
    def wrapper(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if current_user.role not in roles :
                return abort(403)
            return func(*args ,**kwargs)
        return decorated_view
    return wrapper

