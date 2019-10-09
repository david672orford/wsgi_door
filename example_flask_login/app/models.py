from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from . import app

db = SQLAlchemy(app)

class User(UserMixin, db.Model):
	__tablename__ = "users"
	id = db.Column(db.String(), primary_key=True)
	username = db.Column(db.String())
	name = db.Column(db.String())
	email = db.Column(db.String())

db.create_all()
