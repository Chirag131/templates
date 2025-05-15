from flask import Blueprint, render_template
from flask_login import login_required
from .auth import role_required

routes = Blueprint('routes' , __name__)

@routes.route('/')
def home():
    return render_template('home.html')

@routes.route('/admin')
@login_required
@role_required('admin')
def admin_dashboard():
    return render_template('admin.html')

@routes.route('/viewer')
@login_required
@role_required('viewer')
def viewer_dashboard():
    return render_template('viewer.html')

