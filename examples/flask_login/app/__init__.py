from flask import Flask

app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(
	SQLALCHEMY_DATABASE_URI = 'sqlite:///%s/app.db' % app.instance_path,
	SQLALCHEMY_TRACK_MODIFICATIONS = False,
	)
app.config.from_pyfile('config.py')

from .login import login_manager
login_manager.init_app(app)

from . import models
from . import views
from . import admin

