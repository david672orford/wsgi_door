import os
from werkzeug.wrappers import BaseRequest as Request, BaseResponse as Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import NotFound
from werkzeug.utils import redirect
from werkzeug.contrib.securecookie import SecureCookie
from jinja2 import Environment, FileSystemLoader
import json
from urllib.parse import urlencode

class JSONSecureCookie(SecureCookie):
	serialization_method = json

class WsgiDoorAuth(object):
	cookie_name = "wsgi_door"
	def __init__(self, app, auth_providers, secret, templates=None):
		self.app = app					# The WSGI app which we are wrapping
		self.secret = secret			# for signing the cookie
		self.auth_providers = auth_providers

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
		environ['wsgi_door'] = session
		return self.app(environ, start_response)

	# The user has asked for a list of the available login providers.
	# Render from an Jinja2 template.
	def on_login_index(self, request, session):
		# If there is only one provider configured, don't bother with the provider selection page.
		if len(self.auth_providers) == 1:
			return self.on_login(request, session, list(self.auth_providers.keys())[0])
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
		provider_name = session.get('provider')
		session.clear()
		if provider_name is not None:
			provider = self.auth_providers.get(provider_name)
			if provider is not None and provider.logout_url is not None:
				logged_out_url = "{scheme}://{host}".format(scheme = request.scheme, host = request.host)
				return redirect(provider.logged_url.format(client_id=self.client_id, logged_out_url=logged_out_url))
		return redirect("/")

class WsgiDoorFilter(object):
	def __init__(self, app, login_path="/auth/login/", deny_path="/auth/deny", protected_paths=[], allowed_groups=None):
		self.app = app
		self.login_path = login_path
		self.deny_path = deny_path
		self.protected_paths = protected_paths
		self.allowed_groups = set(allowed_groups) if allowed_groups else None

	def __call__(self, environ, start_response):
		session = environ['wsgi_door']
		request = Request(environ)
		if self.path_is_protected(request.path):
			if not 'provider' in session:
				session['next'] = request.path
				return redirect(self.login_path)(environ, start_response)
			if not self.user_is_allowed(session):
				return redirect(self.deny_path)
		if 'provider' in session:
			environ['AUTH_TYPE'] = session['provider']
			environ['REMOTE_USER'] = self.build_remote_user(session)
		return self.app(environ, start_response)

	# Override to provide new kinds of protected path tests
	def path_is_protected(self, path):
		for protected_path in self.protected_paths:
			if path.startswith(protected_path):
				return True
		return False

	# Override to provide new kinds of user authorization tests
	def user_is_allowed(self, session):
		if self.allowed_groups is not None:
			return self.allowed_groups.intersection(set(session.get('groups',[])))
		return True

	# Override to change the format of REMOTE_USER.
	def build_remote_user(self, session):
		if session['username']:
			return session['username']
		else:
			return "{provider}:{id}".format_map(session)

