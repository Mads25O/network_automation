from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(10000))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Networks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    network_id = db.Column(db.Integer)
    network_name = db.Column(db.String(100))
    host = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    routers = db.relationship('Routers')

class Routers(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    router_id = db.Column(db.Integer)
    router_name = db.Column(db.String(100))
    host = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    networks = db.Column(db.Integer, db.ForeignKey('networks.id'))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    notes = db.relationship('Note')
    networks = db.relationship('Networks')
