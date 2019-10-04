import os
from werkzeug.wrappers import BaseRequest as Request, BaseResponse as Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import NotFound
from werkzeug.utils import redirect
from werkzeug.contrib.securecookie import SecureCookie
from jinja2 import Environment, FileSystemLoader
import json
from urllib.parse import urlencode
from .providers import available_auth_providers

class JSONSecureCookie(SecureCookie):
	serialization_method = json

class WsgiDoorAuth(object):
	cookie_name = "wsgi_door"
	def __init__(self, app, client_keys, secret, templates=None):
		self.app = app					# The WSGI app which we are wrapping
		self.secret = secret			# for signing the cookie

		# Initialize those authentication providers for which client keys have been provided.
		self.auth_providers = {}
		for provider_name, provider_keys in client_keys.items():
			self.auth_providers[provider_name] = available_auth_providers[provider_name](provider_keys)

		self.url_map = Map([
			Rule('/auth/login/', endpoint='on_login_index'),
			Rule('/auth/login/<provider_name>', endpoint='on_login'),
			Rule('/auth/authorized/<provider_name>', endpoint='on_authorized'),
			Rule('/auth/error/<provider_name>', endpoint='on_error'),
			Rule('/auth/status', endpoint='on_status'),
			Rule('/auth/logout', endpoint='on_logout'),
			])

		template_path = os.path.join(os.path.dirname(__file__), 'templates')
		if templates:
			template_path.insert(0, templates)
		self.jinja_env = Environment(loader=FileSystemLoader(template_path), autoescape=True)

	# Prepare a response from a Jinja2 template.
	def render_template(self, template_name, **context):
		t = self.jinja_env.get_template(template_name)
		return Response(t.render(context), mimetype='text/html')

	# Generate the URL at which we wish to receive the OAuth2 response
	def callback_url(self, request, provider_name):
		return "{scheme}://{host}/auth/authorized/{provider_name}".format(
			scheme = request.scheme,
			host = request.host,
			provider_name = provider_name,
			)

	# Generate a URL for the error page
	def error_url(self, request, provider_name, **kwargs):
		return "{scheme}://{host}/auth/error/{provider_name}?{query}".format(
			scheme = request.scheme,
			host = request.host,
			provider_name = provider_name,
			query = urlencode(kwargs),
			)

	# Handle an WSGI request
	# We peel off requests to authentication pages and pass other requests
	# through to the wrapped WSGI application.
	def __call__(self, environ, start_response):
		request = Request(environ)
		session = JSONSecureCookie.load_cookie(request, self.cookie_name, self.secret)

		# Try to dispatch to one of our handler functions
		adapter = self.url_map.bind_to_environ(request.environ)
		response = None
		try:
			endpoint, values = adapter.match()
			response = getattr(self, endpoint)(request, session, **values)
			session.save_cookie(response, key=self.cookie_name, httponly=True, secure=True)
			return response(environ, start_response)
		except NotFound:
			pass

		# If we reach this point, we pass thru to the wrapped WSGI application.
		if 'remote_user' in session:
			environ['AUTH_TYPE'] = session['provider']
			environ['REMOTE_USER'] = session['remote_user']
		environ['wsgi_door_session'] = session
		return self.app(environ, start_response)

	# The user has asked for a list of the available login providers.
	# Render from an Jinja2 template.
	def on_login_index(self, request, session):
		return self.render_template("login.html", providers=self.auth_providers.keys())

	# User has asked to log in using one of the authentication providers offered.
	# Redirect the user's browser to the provider's login page.
	def on_login(self, request, session, provider_name):
		provider = self.auth_providers.get(provider_name)
		if provider is not None:
			callback_url = self.callback_url(request, provider_name)
			authorize_url = provider.make_authorize_url(session, callback_url)
			if authorize_url is None:
				authorize_url = self.error_url(request, provider_name, error='no_authorize_url', error_description='Failed to make the authorization URL.')
			return redirect(authorize_url)
		raise NotFound()

	# Browser has returned from the provider's login page.
	def on_authorized(self, request, session, provider_name):
		provider = self.auth_providers.get(provider_name)
		if provider is not None:
			callback_url = self.callback_url(request, provider_name)
			access_token = provider.get_access_token(request, session, callback_url)
			print("access_token:", json.dumps(access_token, indent=4, ensure_ascii=False))
			if 'error' in access_token:
				return redirect(self.error_url(request, provider_name, error=access_token.get('error'), error_description=access_token.get('error_description')))
			next_url = session.pop('next', '/auth/status')
			session.clear()
			session['provider'] = provider_name
			session.update(provider.get_normalized_profile(access_token))
			return redirect(next_url)
		raise NotFound()

	# Page which displays the status of the user's login session.
	def on_status(self, request, session):
		return self.render_template(
			"status.html",
			session=json.dumps(session, sort_keys=True, indent=4, ensure_ascii=False)
			)

	# When login fails we redirect to this page.
	def on_error(self, request, session, provider_name):
		return self.render_template(
			"error.html",
			provider=provider_name,
			error=request.args.get('error'),
			error_description=request.args.get('error_description')
			)

	# User has hit the logout button. Destory the session cookie.
	def on_logout(self, request, session):
		session.clear()
		return redirect("/")

class WsgiDoorFilter(object):
	def __init__(self, app, protected_paths=[], redirect_to="/auth/login/"):
		self.app = app
		self.protected_paths = protected_paths
		self.redirect_to = redirect_to
	def __call__(self, environ, start_response):
		if not 'REMOTE_USER' in environ:
			request = Request(environ)
			for protected_path in self.protected_paths:
				if request.path.startswith(protected_path):
					environ['wsgi_door_session']['next'] = request.path
					return redirect(self.redirect_to)(environ, start_response)
		return self.app(environ, start_response)

