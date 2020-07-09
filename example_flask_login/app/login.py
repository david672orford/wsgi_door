from flask import redirect, request
from flask_login import LoginManager
from .models import db, User

login_manager = LoginManager()

# Start of request hook. If the user has a wsgi_door session, load his user record.
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

# User has hit a protected view while not logged in. Save the requested URL
# and send him to the login page.
@login_manager.unauthorized_handler
def unauthorized():
	response = redirect("/auth/login/")
	request.environ['wsgi_door'].set_next_url(response, request.url)
	return response

