import os
#from werkzeug.wrappers import BaseRequest as Request, BaseResponse as Response
from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule, RequestRedirect
from werkzeug.exceptions import NotFound
from werkzeug.utils import redirect
try:
	from werkzeug.contrib.securecookie import SecureCookie
except ImportError:
	from secure_cookie.cookie import SecureCookie
from jinja2 import Environment, FileSystemLoader
import json
from urllib.parse import urlencode, urlparse
import logging

# Name of our session cookie
cookie_name = "wsgi_door"

logger = logging.getLogger(__name__)

class JSONSecureCookie(SecureCookie):
	"""Object representing the login session cookie"""
	serialization_method = json
	def set_next_url(self, response, next_url, secure=True):
		"""Add the URL to redirect to after login to the session and set the session
		cookie in the response object provided"""
		self['next'] = next_url
		self.save_cookie(response, cookie_name, httponly=True, secure=secure)

class WsgiDoorAuth(object):
	"""WSGI middleware which inserts authentication using the specified providers"""

	def __init__(self, app, auth_providers, secret, templates=None, stylesheet_url=None):
		self.wsgi_app = app				# The WSGI app which we are wrapping
		self.secret = secret			# for signing the cookie
		self.auth_providers = auth_providers
		self.stylesheet_url = stylesheet_url

		self.url_map = Map([
			Rule('/auth/login/', endpoint='on_login_index'),
			Rule('/auth/login/<provider_name>', endpoint='on_login'),
			Rule('/auth/authorized/<provider_name>', endpoint='on_authorized'),
			Rule('/auth/error/<provider_name>', endpoint='on_error'),
			Rule('/auth/denied', endpoint='on_denied'),
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

	# Handle an HTTP requests
	# We peel off requests to authentication pages and pass other requests
	# through to the wrapped WSGI application.
	def __call__(self, environ, start_response):
		request = Request(environ)
		session = JSONSecureCookie.load_cookie(request, cookie_name, self.secret)

		# Try to dispatch to one of our handler functions
		adapter = self.url_map.bind_to_environ(request.environ)
		response = None
		try:
			try:
				endpoint, values = adapter.match()
				response = getattr(self, endpoint)(request, session, **values)
			except RequestRedirect as e:
				response = e
			localhost = request.host.split(":")[0] == "localhost"
			session.save_cookie(response, key=cookie_name, httponly=True, secure=(not localhost))
			return response(environ, start_response)
		except NotFound:
			pass

		# If we reach this point, the requested URL is not one of ours.
		# Pass it thru to the wrapped WSGI application.
		environ['wsgi_door'] = session
		return self.wsgi_app(environ, start_response)

	# The user has asked for a list of the available login providers.
	# Render from an Jinja2 template.
	def on_login_index(self, request, session):

		if 'next' in request.args:
			session['next'] = urlparse(request.args['next']).path

		# If there is only one provider configured, don't bother with the provider selection page.
		if len(self.auth_providers) == 1:
			return self.on_login(request, session, list(self.auth_providers.keys())[0])
		return self.render_template("login.html", providers=self.auth_providers.keys(), stylesheet_url=self.stylesheet_url)

	# User has asked to log in using one of the authentication providers offered.
	# Redirect the user's browser to the provider's login page.
	def on_login(self, request, session, provider_name):
		provider = self.auth_providers.get(provider_name)
		if provider is not None:
			callback_url = self.callback_url(request, provider_name)
			authorize_url = provider.make_authorize_url(session, callback_url, request.args)
			if authorize_url is None:
				authorize_url = self.error_url(request, provider_name, error='no_authorize_url', error_description='Failed to make the authorization URL.')
			return redirect(authorize_url)
		raise NotFound()

	# Browser has returned from the provider's login page. The query string
	# should now contain an authorization code which we will exchange for an
	# access token. We use this to fetch the user's profile and store it in
	# the session cookie.
	def on_authorized(self, request, session, provider_name):
		provider = self.auth_providers.get(provider_name)
		if provider is not None:

			# There is no reason for the browser to hit this URL without our cookie.
			# If it is missing, say so now so as not to produce a confusing error
			# message in provider.get_access_token() when it can't find the state.
			if not cookie_name in request.cookies:
				return redirect(self.error_url(request, provider_name, error="no_cookie", error_description="Your web browser failed to save the login cookie."))

			# Get the access token
			callback_url = self.callback_url(request, provider_name)
			access_token = provider.get_access_token(request, session, callback_url)

			if 'error' in access_token:
				return redirect(self.error_url(request, provider_name, error=access_token.get('error'), error_description=access_token.get('error_description')))

			# Get the user's profile in a provider-specific manner
			# (likely by calling its graph API).
			try:
				raw_profile = provider.get_profile(access_token)
			except Exception as e:
				logger.error("Profile fetch failed: %s" % str(e))
				return redirect(self.error_url(request, provider_name, error='profile_fetch_failed', error_description=str(e)))

			logger.debug("raw profile: %s" % json.dumps(raw_profile, indent=4, sort_keys=True))

			# Every provider has its own format for the user profile. Call a provider-
			# specific function to extract what we need to create a normalized profile
			# which will go into the session cookie.
			try:
				profile = provider.normalize_profile(access_token, raw_profile)
			except Exception as e:
				logger.error("Normalization failed: %s" % str(e))
				return redirect(self.error_url(request, provider_name, error='profile_fetch_failed', error_description="normalization failed"))

			# The page which the user originally tried to access should be in the
			# signed session cookie. Get it out, then clear the cookie and store
			# the profile in it.
			next_url = session.pop('next', '/auth/status')
			session.clear()
			session['provider'] = provider_name
			session.update(profile)

			# Piggyback various things onto the session cookie object and
			# call the login hook. Ignore the result code.
			session.provider = provider
			session.access_token = access_token
			session.raw_profile = raw_profile
			request.environ['wsgi_door'] = session
			self.wsgi_app(request.environ, lambda status, headers: None)

			# Now that the user is logged in, redirect back to the original page.
			return redirect(next_url)

		# URL does not match a configured provider
		raise NotFound()

	# Page which displays the status of the user's login session.
	def on_status(self, request, session):
		return self.render_template(
			"status.html",
			session=json.dumps(session, sort_keys=True, indent=4, ensure_ascii=False),
			stylesheet_url=self.stylesheet_url,
			)

	# When login fails we redirect to this page.
	def on_error(self, request, session, provider_name):
		return self.render_template(
			"error.html",
			provider=provider_name,
			error=request.args.get('error'),
			error_description=request.args.get('error_description'),
			stylesheet_url=self.stylesheet_url,
			)

	# Access denied.
	def on_denied(self, request, session):
		return self.render_template(
			"denied.html",
			stylesheet_url=self.stylesheet_url,
			session=session,
			)

	# User has hit the logout button. Destory the session cookie.
	def on_logout(self, request, session):

		# Save the name of the IDP and then clear the login session cookie.
		provider_name = session.get('provider')
		session.clear()

		# To what URL should the browser be redirected when logout is complete?
		if 'next' in request.args:
			next_url = urlparse(request.args['next']).path
		else:
			next_url = "/"
		
		# If the user is logged in and the identity provider has a logout URL,
		# redirect it first so that the provider can destroy its session.
		# We will ask the provider to redirect to the next_url.
		response = None
		if provider_name is not None:
			provider = self.auth_providers.get(provider_name)
			if provider is not None and provider.logout_url is not None:
				response = redirect(provider.logout_url.format(
					client_id=provider.client_id,
					logged_out_url="{scheme}://{host}{next_url}".format(scheme=request.scheme, host=request.host, next_url=next_url)
					))

		# Otherwise redirect directly the the next URL.
		if response is None:
			response = redirect(next_url)

		# Forward the request to the underlying WSGI app so it can clean
		# up its session, if it has one. Discard everything except the
		# cookies it sets.
		request.environ['wsgi_door'] = session
		def start_response(status, headers):
			for name, value in headers:
				if name == 'Set-Cookie':
					response.headers.add(name, value)
		self.wsgi_app(request.environ, start_response)

		return response

class WsgiDoorFilter(object):
	"""This WSGI middleware requires the user to be authenticated whenever he
	tries to load one of the listed protect paths. It also sets
	AUTH_TYPE and REMOTE_USER in the WSGI environment. Note that since
	this reads the WSGI Door session cookie to figure out whether
	the user is logged in yet, it needs to go 'underneath' WsgiDoorAuth."""

	def __init__(self, app, login_path="/auth/login/", denied_path="/auth/denied", protected_paths=[], protected_path_exceptions=[], allowed_groups=None):
		self.wsgi_app = app
		self.login_path = login_path
		self.denied_path = denied_path
		self.protected_paths = protected_paths
		self.protected_path_exceptions = protected_path_exceptions
		self.allowed_groups = set(allowed_groups) if allowed_groups else None

	# Handle HTTP requests
	def __call__(self, environ, start_response):
		session = environ[cookie_name]
		request = Request(environ)
		if self.path_is_protected(request.path):
			localhost = request.host.split(":")[0] == "localhost"
			# Protected paths may only be accessed over HTTPS
			if request.scheme != "https" and not localhost:
				response = redirect("https://{host}{path}".format(host=request.host, path=request.path))
				return response(environ, start_response)
			# If user is not logged in,
			if not 'provider' in session:
				response = redirect(self.login_path)
				session.set_next_url(response, request.path, secure=(not localhost))
				return response(environ, start_response)
			# If user is logged in but not authorized,
			if not self.user_is_allowed(session):
				response = redirect(self.denied_path)
				return response(environ, start_response)
		if 'provider' in session:
			environ['AUTH_TYPE'] = session['provider']
			environ['REMOTE_USER'] = self.build_remote_user(session)
		return self.wsgi_app(environ, start_response)

	# Override this method to provide new kinds of protected path tests
	def path_is_protected(self, path):
		for protected_path in self.protected_paths:
			if path.startswith(protected_path):
				for protected_path_exception in self.protected_path_exceptions:
					if path.startswith(protected_path_exception):
						return False
				return True
		return False

	# Override this method to provide new kinds of user authorization tests
	def user_is_allowed(self, session):
		if self.allowed_groups is not None:
			return self.allowed_groups.intersection(set(session.get('groups',[])))
		return True

	# Override this method to change the format of REMOTE_USER.
	def build_remote_user(self, session):
		if session.get('username'):
			return session['username']
		else:
			return "{provider}:{id}".format_map(session)

