from flask import Flask, render_template, request, redirect, url_for, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from functools import wraps
from api_key import *  # contains CLIENT_ID and CLIENT_SECRET

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# OAuth config
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    token_url="https://oauth2.googleapis.com/token",
    userinfo_endpoint="https://www.googleapis.com/oauth2/v3/userinfo",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid profile email'}
)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=True)
    role = db.Column(db.String(50), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Decorators
def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            username = session.get('username')
            if not username:
                return redirect(url_for('home'))
            user = User.query.filter_by(username=username).first()
            if user and user.role in roles:
                return fn(*args, **kwargs)
            return abort(403)
        return decorated_view
    return wrapper

# Routes
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['username'] = username
        return redirect(url_for('dashboard'))
    else:
        return render_template('index.html', error='Invalid username or password.')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    if User.query.filter_by(username=username).first():
        return render_template('index.html', error='Username already exists.')
    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    session['username'] = username
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            session.pop('username', None)
            return redirect(url_for('home'))
        if user.role:
            return redirect(url_for(f"{user.role}_dashboard"))
        return redirect(url_for('select_role'))
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/login/google')
def login_google():
    try:
        redirect_uri = url_for('authorize_google', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        app.logger.error(f'Error during login: {str(e)}')
        return "ERROR", 500

@app.route('/authorize/google')
def authorize_google():
    token = google.authorize_access_token()
    resp = google.get(google.server_metadata['userinfo_endpoint'])
    user_info = resp.json()
    username = user_info['email']

    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, role=None)
        db.session.add(user)
        db.session.commit()

    session['username'] = username
    session['oauth_token'] = token

    if not user.role:
        return redirect(url_for('select_role'))
    return redirect(url_for(f"{user.role}_dashboard"))

@app.route('/select-role', methods=['GET', 'POST'])
def select_role():
    if 'username' not in session:
        return redirect(url_for('home'))

    user = User.query.filter_by(username=session['username']).first()
    if not user:
        session.pop('username', None)
        return redirect(url_for('home'))

    if request.method == 'POST':
        selected_role = request.form.get('role')
        if selected_role in ['admin', 'editor', 'viewer']:
            user.role = selected_role
            db.session.commit()
            return redirect(url_for(f"{selected_role}_dashboard"))
        else:
            return "Invalid role selected", 400

    return render_template('select_role.html')

# Dashboards
@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/editor/dashboard')
@role_required('editor')
def editor_dashboard():
    return render_template('editor_dashboard.html')

@app.route('/viewer/dashboard')
@role_required('viewer')
def viewer_dashboard():
    return render_template('viewer_dashboard.html')

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
