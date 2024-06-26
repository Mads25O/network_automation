from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class Networks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    network_id = db.Column(db.Integer)
    network_name = db.Column(db.String(100))
    host = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    networks = db.relationship('Networks')
    
