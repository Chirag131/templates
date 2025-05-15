from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from . import db, login_manager

@login_manager.user_loader
def load_user(user_id):
    if user_id.isdigit():
        return User.query.get(int(user_id))
    return None
    


class User(db.Model, UserMixin):
    id = db.Column(db.Integer , primary_key = True)
    username = db.Column(db.String(150), unique = True, nullable = False)
    password = db.Column(db.String(60) , nullable = False)
    role = db.Column(db.String(20), nullable = False, default = 'viewer')

    def __repr__ (self):
        return f"<User {self.username} - Role : {self.role}>"
    


