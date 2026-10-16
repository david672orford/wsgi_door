from collections import UserDict
import json
import logging
import os
from urllib.parse import urlencode, urlparse

from jinja2 import Environment, FileSystemLoader
from itsdangerous.url_safe import URLSafeTimedSerializer
from itsdangerous.exc import BadData
from werkzeug.wrappers import Request, Response
from werkzeug.routing import Map, Rule, RequestRedirect
from werkzeug.exceptions import NotFound
from werkzeug.utils import redirect

logger = logging.getLogger(__name__)

class WsgiDoorSession(dict):
	"""Object representing the login session cookie"""
	cookie_name = "wsgi_door"
	session_lifetime = 86400

	def __init__(self, request, secret_key):
		super().__init__()
		cookie = request.cookies.get(self.cookie_name)
		self.serializer = URLSafeTimedSerializer(secret_key)
		if cookie is not None:
			try:
				data = self.serializer.loads(cookie, max_age=self.session_lifetime)
				self.update(data)
			except BadData:
				pass

	def save_cookie(self, response, secure=False):
		cookie = self.serializer.dumps(dict(self))
		response.set_cookie(
			self.cookie_name,
			cookie,
			httponly = True,
			secure = secure,
			max_age = self.session_lifetime,
			samesite = "Lax",
			)

	def set_next_url(self, response, next_url, secure=True):
		"""Save the URL to redirect to after login in the session cookie"""
		self["next"] = next_url
		self.save_cookie(response, secure=secure)

class WsgiAuthProviderNotFound(NotFound):
	pass

class WsgiDoorAuth:
	"""WSGI middleware which inserts authentication using the specified providers"""

	def __init__(self, app, auth_providers, secret, templates=None, stylesheet_url=None):
		self.wsgi_app = app				# The WSGI app which we are wrapping
		self.secret = secret			# for signing the cookie
		self.auth_providers = auth_providers
		self.stylesheet_url = stylesheet_url

		self.url_map = Map([
			Rule("/auth/login/", endpoint="on_login_index"),
			Rule("/auth/login/<provider_name>", endpoint="on_login"),
			Rule("/auth/authorized/<provider_name>", endpoint="on_authorized"),
			Rule("/auth/error/<provider_name>", endpoint="on_error"),
			Rule("/auth/denied", endpoint="on_denied"),
			Rule("/auth/status", endpoint="on_status"),
			Rule("/auth/logout", endpoint="on_logout"),
			])

		template_path = [os.path.join(os.path.dirname(__file__), "templates")]
		if templates:
			template_path.insert(0, templates)
		self.jinja_env = Environment(loader=FileSystemLoader(template_path), autoescape=True)

	# Prepare a response from a Jinja2 template.
	def render_template(self, template_name, **context):
		t = self.jinja_env.get_template(template_name)
		return Response(t.render(context), mimetype="text/html")

	# Generate the URL at which we wish to receive the OAuth2 response
	def callback_url(self, request, provider_name):
		return f"{request.scheme}://{request.host}/auth/authorized/{provider_name}"

	# Generate a URL for the error page
	def error_url(self, request, provider_name, **kwargs):
		return f"{request.scheme}://{request.host}/auth/error/{provider_name}?{urlencode(kwargs)}"

	# Throw away the response from the wrapped app's login and logout hooks
	def consume_response(self, app_iter):
		for data in app_iter:
			pass
		if hasattr(app_iter, "close"):
			app_iter.close()

	# Handle an HTTP requests
	# We peel off requests to authentication pages and pass other requests
	# through to the wrapped WSGI application.
	def __call__(self, environ, start_response):
		request = Request(environ)
		session = WsgiDoorSession(request, self.secret)

		# Try to dispatch to one of our handler functions
		adapter = self.url_map.bind_to_environ(request.environ)
		try:
			try:
				endpoint, values = adapter.match()
				response = getattr(self, endpoint)(request, session, **values)
			except (RequestRedirect, WsgiAuthProviderNotFound) as e:
				response = e.get_response()
			localhost = request.host.split(":")[0] == "localhost"
			session.save_cookie(response, secure=(not localhost))
			return response(environ, start_response)
		except NotFound:
			pass

		# If we reach this point, the requested URL is not one of ours.
		# Pass it thru to the wrapped WSGI application.
		environ["wsgi_door"] = session
		return self.wsgi_app(environ, start_response)

	# The user has asked for a list of the available login providers.
	# Render from an Jinja2 template.
	def on_login_index(self, request, session):

		if "next" in request.args:
			session["next"] = urlparse(request.args["next"]).path

		# If there is only one provider configured, don't bother with the provider selection page.
		if len(self.auth_providers) == 1:
			return self.on_login(request, session, next(iter(self.auth_providers.keys())))
		return self.render_template("login.html", providers=self.auth_providers.keys(), stylesheet_url=self.stylesheet_url)

	# User has asked to log in using one of the authentication providers offered.
	# Redirect the user's browser to the provider's login page.
	def on_login(self, request, session, provider_name):
		provider = self.auth_providers.get(provider_name)
		if provider is not None:
			callback_url = self.callback_url(request, provider_name)
			authorize_url = provider.make_authorize_url(session, callback_url, request.args)
			if authorize_url is None:
				authorize_url = self.error_url(request, provider_name, error="no_authorize_url", error_description="Failed to make the authorization URL.")
			return redirect(authorize_url)
		raise WsgiAuthProviderNotFound()

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
			if not WsgiDoorSession.cookie_name in request.cookies:
				return redirect(self.error_url(request, provider_name, error="no_cookie", error_description="Your web browser failed to save the login cookie."))

			# Get the access token
			callback_url = self.callback_url(request, provider_name)
			access_token = provider.get_access_token(request, session, callback_url)

			if "error" in access_token:
				return redirect(self.error_url(request, provider_name, error=access_token.get("error"), error_description=access_token.get("error_description")))

			# Get the user's profile in a provider-specific manner
			# (likely by calling its graph API).
			try:
				raw_profile = provider.get_profile(access_token)
			except Exception as e:
				logger.error("Profile fetch failed: %s", e)
				return redirect(self.error_url(request, provider_name, error="profile_fetch_failed", error_description=str(e)))

			logger.debug("raw profile: %s", json.dumps(raw_profile, indent=4, sort_keys=True))

			# Every provider has its own format for the user profile. Call a provider-
			# specific function to extract what we need to create a normalized profile
			# which will go into the session cookie.
			try:
				profile = provider.normalize_profile(access_token, raw_profile)
			except Exception as e:
				logger.error("Normalization failed: %s", e)
				return redirect(self.error_url(request, provider_name, error="profile_fetch_failed", error_description="normalization failed"))

			# The page which the user originally tried to access should be in the
			# signed session cookie. Get it out, then clear the cookie and store
			# the user's profile in it.
			next_url = session.pop("next", "/auth/status")
			session.clear()
			session["provider"] = provider_name
			session.update(profile)

			# Piggyback various things onto the session cookie object and call through
			# to the wrapped WSGI app. That way it can handle the same path as a login
			# hook. We throw away the result, so it it does not handle the path, that
			# is fine too.
			session.provider = provider
			session.access_token = access_token
			session.raw_profile = raw_profile
			request.environ["wsgi_door"] = session
			self.consume_response(self.wsgi_app(request.environ, lambda status, headers: None))

			# Now that the user is logged in, redirect back to the original page.
			return redirect(next_url)

		# URL does not match a configured provider
		raise WsgiAuthProviderNotFound()

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
			error=request.args.get("error"),
			error_description=request.args.get("error_description"),
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
		provider_name = session.get("provider")
		session.clear()

		# To what URL should the browser be redirected when logout is complete?
		if "next" in request.args:
			next_url = urlparse(request.args["next"]).path
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
					logged_out_url=f"{request.scheme}://{request.host}{next_url}"
					))

		# Otherwise redirect directly to the next URL.
		if response is None:
			response = redirect(next_url)

		# Forward the request to the underlying WSGI app so it can clean up its
		# session, if it has one. Discard everything except the cookies it sets.
		request.environ["wsgi_door"] = session
		def start_response(status, headers):
			for name, value in headers:
				if name == "Set-Cookie":
					response.headers.add(name, value)
		self.consume_response(self.wsgi_app(request.environ, start_response))

		return response

class WsgiDoorFilter:
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
		self.allowed_groups = set(allowed_groups) if allowed_groups is not None else None

	# Handle HTTP requests
	def __call__(self, environ, start_response):
		session = environ["wsgi_door"]
		request = Request(environ)
		if self.path_is_protected(request.path):
			localhost = request.host.split(":")[0] == "localhost"
			# Protected paths may only be accessed over HTTPS
			if request.scheme != "https" and not localhost:
				response = redirect(f"https://{request.host}{request.path}")
				return response(environ, start_response)
			# If user is not logged in,
			if not "provider" in session:
				response = redirect(self.login_path)
				session.set_next_url(response, request.path, secure=(not localhost))
				return response(environ, start_response)
			# If user is logged in but not authorized,
			if not self.user_is_allowed(session):
				response = redirect(self.denied_path)
				return response(environ, start_response)
		if "provider" in session:
			environ["AUTH_TYPE"] = session["provider"]
			environ["REMOTE_USER"] = self.build_remote_user(session)
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
			return self.allowed_groups.intersection(set(session.get("groups",[])))
		return True

	# Override this method to change the format of REMOTE_USER.
	def build_remote_user(self, session):
		if session.get("username"):
			return session["username"]
		else:
			return "{provider}:{id}".format_map(session)

class WsgiLocalGroups:
	"""Local groups for testing purposes"""
	def __init__(self, app, groups):
		self.wsgi_app = app
		self.groups = groups
	def __call__(self, environ, start_response):
		session = environ["wsgi_door"]
		if "provider" in session and "username" in session:
			key = "{provider}:{username}".format_map(session)
			if "groups" not in session:
				session["groups"] = []
			for name, values in self.groups.items():
				if key in values:
					session["groups"].append(name)
		return self.wsgi_app(environ, start_response)
