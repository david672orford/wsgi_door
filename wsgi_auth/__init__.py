# wsgi_auth.py

import os
from werkzeug.wrappers import BaseRequest as Request, BaseResponse as Response
from werkzeug.routing import Map, Rule
from werkzeug.exceptions import NotFound
from werkzeug.utils import redirect
from werkzeug.contrib.securecookie import SecureCookie
from jinja2 import Environment, FileSystemLoader
import urllib.request
from urllib.parse import urlencode
import urllib.error
import json
import jwt
from secrets import token_hex

class AuthProviderOAuth1Base(object):
	def __init__(self, keys):
		self.client_id = keys['client_key']
		self.client_secret = keys['client_secret']

class AuthProviderOAuth2Base(object):
	authorize_url = None
	request_token_url = None
	request_token_params = {}
	profile_url = None

	def __init__(self, keys):
		self.client_id = keys['client_key']
		self.client_secret = keys['client_secret']

	# Build the URL to which the user's browser should be redirected to reach
	# the authentication provider's login page.
	def make_authorize_url(self, session, redirect_uri):
		state = session['state'] = token_hex(8)
		query = dict(
			client_id = self.client_id,
			redirect_uri = redirect_uri,
			response_type = 'code',
			state = state,
			)
		query.update(self.request_token_params)
		return '{authorize_url}?{query}'.format(authorize_url=self.authorize_url, query=urlencode(query))

	# Called when the browser gets redirected back to our site. Contact the
	# authentication provider directly and ask for an access_token.
	# Along with the access token we may receive other information such as
	# an OpenID Connect assertion (id_token) encoded in JWT format.
	# If we know the proper URL for this provider, ask for the user's
	# profile information too.
	def request_access_token(self, request, session, redirect_uri):
		if not 'state' in session:
			return dict(error="spurious_response", error_description="Browser was not expected to visit the redirect_uri.")
		if request.args.get('state') != session['state']:
			return dict(error="incorrect_state", error_description="The state value is not correct.")
		del session['state']

		form = dict(
			code = request.args.get('code'),
			client_id = self.client_id,
			client_secret = self.client_secret,
			redirect_uri = redirect_uri,
			grant_type = 'authorization_code',
			)
		try:
			response = urllib.request.urlopen(
				urllib.request.Request(self.access_token_url, headers={'Accept':'application/json'}),
				data=urlencode(form).encode('utf-8')
				)	
		except urllib.error.HTTPError as e:
			return dict(error="bad_response", error_description="HTTP request failed: %s %s" % (e.code, e.reason))
			
		content_type = response.info().get_content_type()
		if content_type != 'application/json':
			return dict(error="bad_response", error_description="Content-Type (%s) not supported." % content_type)
		access_token = json.load(response)

		if 'id_token' in access_token:
			access_token['id_token'] = jwt.decode(access_token['id_token'], verify=False)

		if 'access_token' in access_token and self.profile_url is not None:
			response = urllib.request.urlopen(
				urllib.request.Request(self.profile_url,
	            headers={'Authorization': 'Bearer ' + access_token['access_token']}
				))
			access_token['profile'] = json.load(response)

		return access_token

class AuthProviderGoogle(AuthProviderOAuth2Base):
	authorize_url = 'https://accounts.google.com/o/oauth2/auth'
	access_token_url = 'https://accounts.google.com/o/oauth2/token'
	request_token_params = { 'scope': 'openid profile email' }
	profile_url = 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json'

class AuthProviderFacebook(AuthProviderOAuth2Base):
	authorize_url = 'https://www.facebook.com/dialog/oauth'
	access_token_url = 'https://graph.facebook.com/oauth/access_token'
	request_token_params = { 'scope': 'email' }
	profile_url = 'https://graph.facebook.com/v1.0/me'

class AuthProviderTwitter(AuthProviderOAuth1Base):
	authorize_url = 'https://api.twitter.com/oauth/authenticate'
	access_token_url = 'https://api.twitter.com/oauth/access_token'

class AuthProviderGitHub(AuthProviderOAuth2Base):
	authorize_url = 'https://github.com/login/oauth/authorize'
	access_token_url = 'https://github.com/login/oauth/access_token'
	request_token_params = { 'scope': 'openid email' }
	profile_url = 'https://api.github.com/user'

class AuthProviderAzure(AuthProviderOAuth2Base):
	authorize_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
	access_token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
	request_token_params = { 'scope': 'openid email' }

available_auth_providers = {
	'google': AuthProviderGoogle,
	'facebook': AuthProviderFacebook,
	'twitter': AuthProviderTwitter,
	'github': AuthProviderGitHub,
	'azure': AuthProviderAzure,
	}	

class JSONSecureCookie(SecureCookie):
	serialization_method = json

class WSGIAuthMiddleware(object):
	def __init__(self, app, client_keys, secret, cookie_name="wsgi_auth", protected_paths=[]):

		# The WSGI app which we are wrapping
		self.app = app

		self.cookie_name = cookie_name
		self.secret = secret

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

		template_path = os.path.join(os.path.dirname(__file__), 'templates', 'auth')
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

	# Generate a URL to describe an error
	def error_url(self, request, provider_name, error, error_description):
		return "{scheme}://{host}/auth/failure/{provider_name}?{query}".format(
			scheme = request.scheme,
			host = request.host,
			provider_name = provider_name,
			query = urlencode(dict(error=error, error_description=error_description))
			)

	# Handle an WSGI request
	# We peel off requests to authentication pages and pass other requests
	# through to the wrapped WSGI application.
	def __call__(self, environ, start_response):
		request = Request(environ)
		session = JSONSecureCookie.load_cookie(request, self.cookie_name, self.secret)
		adapter = self.url_map.bind_to_environ(request.environ)
		try:
			endpoint, values = adapter.match()
			response = getattr(self, endpoint)(request, session, **values)
			session.save_cookie(response, key=self.cookie_name, httponly=True, secure=True)
			return response(environ, start_response)
		except NotFound:
			pass

		if 'REMOTE_USER' in session:
			environ['REMOTE_USER'] = session['REMOTE_USER']
		else:
			for protected_path in self.protected_paths:
				if request.path.startswtih(protected_path):
					session.clear()
					session['next'] = request.path
					return redirect('/auth/login')(environ, start_response)
					
		return self.app(environ, start_response)

	# The user has asked for a list of the available login providers
	def on_login_index(self, request, session):
		return self.render_template("login.html", providers=self.auth_providers.keys())

	# User has asked to log in using one of the authentication providers offered.
	# Redirect the user's browser to the provider's login page.
	def on_login(self, request, session, provider_name):
		provider = self.auth_providers.get(provider_name)
		if provider is not None:
			callback_url = self.callback_url(request, provider_name)
			return redirect(provider.make_authorize_url(session, callback_url))

	# Browser has returned from the provider's login page.
	def on_authorized(self, request, session, provider_name):
		provider = self.auth_providers.get(provider_name)
		if provider is not None:
			callback_url = self.callback_url(request, provider_name)
			access_token = provider.request_access_token(request, session, callback_url)
			if 'error' in access_token:
				return redirect(self.error_url(provider_name, error, error_description))
			print(json.dumps(access_token, indent=4, ensure_ascii=False))
			session['provider'] = provider_name
			session.update(access_token)
		next_url = session.pop('next', '/auth/status')
		return redirect(next_url)

	# Display the status of the user's login session
	def on_status(self, request, session):
		return self.render_template(
			"status.html",
			session=json.dumps(session, sort_keys=True, indent=4, ensure_ascii=False)
			)

	# Display an error message
	def on_error(self, request, session, provider_name):
		return self.render_template(
			"error.html",
			provider=provider_name,
			error=request.args.get('error'),
			error_description=request.args.get('error_description')
			)

	# Destroy the session cookie
	def on_logout(self, request, session):
		session.clear()
		return redirect("/")

