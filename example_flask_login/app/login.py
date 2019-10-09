from flask import redirect
from flask_login import LoginManager
from .models import db, User

login_manager = LoginManager()

@login_manager.unauthorized_handler
def unauthorized():
	request.environ['wsgi_door']['next'] = request.url
	return redirect("/auth/login/")

@login_manager.request_loader
def load_user_from_request(request):
	wsgi_door = request.environ['wsgi_door']
	if 'provider' in wsgi_door:
		key = '%s:%s' % (wsgi_door['provider'], wsgi_door['id'])
		user = User.query.filter_by(id=key).first()
		if user is None:
			user = User(id=key, username=wsgi_door['username'], name=wsgi_door['name'], email=wsgi_door['email'])
			db.session.add(user)
			db.session.commit()
		return user	
	return None	
