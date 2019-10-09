from flask import abort
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import current_user

from . import app
from .login import login_manager
from .models import db, User

class ProtectedView(ModelView):
	def inaccessible_callback(self, name, **kwargs):
		if not current_user.is_authenticated:
			return login_manager.unauthorized()
		abort(403)
	def is_accessible(self):
		return current_user.is_authenticated

class UserView(ProtectedView):
	pass

admin = Admin(app, name='Example')
admin.add_view(UserView(User, db.session))


