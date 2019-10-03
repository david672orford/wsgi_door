# wsgi_auth.py

from urllib.request import urlopen, Request
from urllib.parse import parse_qsl, urlencode
from urllib.error import HTTPError
import json
import sys
import jwt

class AuthProviderOAuth1Base(object):
	def __init__(self, keys):
		self.client_id = keys['client_key']
		self.client_secret = keys['client_secret']

class AuthProviderOAuth2Base(object):
	authorize_url = None
	request_token_url = None
	request_token_params = {}

	def __init__(self, keys):
		self.client_id = keys['client_key']
		self.client_secret = keys['client_secret']

	def make_authorize_url(self, redirect_uri):
		query = dict(
			client_id = self.client_id,
			redirect_uri = redirect_uri,
			response_type = 'code',
			state = '12345',
			)
		query.update(self.request_token_params)
		return '{authorize_url}?{query}'.format(authorize_url=self.authorize_url, query=urlencode(query))

	def request_access_token(self, environ, redirect_uri):
		query_dict = dict(parse_qsl(environ.get('QUERY_STRING','')))
		form = dict(
			code = query_dict.get('code'),
			client_id = self.client_id,
			client_secret = self.client_secret,
			redirect_uri = redirect_uri,
			grant_type = 'authorization_code',
			)
		try:
			response = urlopen(Request(self.access_token_url,
					headers={'Accept':'application/json'}
					),
				data=urlencode(form).encode('utf-8')
				)	
		except HTTPError as e:
			return (None, "bad_response", "HTTP request failed: %s %s" % (e.code, e.reason))
			
		content_type = response.info().get_content_type()
		if content_type == 'application/json':
			data = json.load(response)
		#elif content_type == 'application/x-www-form-urlencoded':
		#	data = dict(parse_qsl(response.read().decode('utf-8')))
		else:
			return (None, "bad_response", "Response content type (%s) not supported." % content_type)
		sys.stderr.write("%s\n" % json.dumps(data, indent=4))
		return (data, None, None)

	def get_profile(self, environ, redirect_uri):
		access_token, error, error_description = self.request_access_token(environ, redirect_uri)
		if access_token is None:
			return (None, error, error_description)
		elif 'id_token' in access_token:
			return (jwt.decode(access_token['id_token'], verify=False), None, None)
		elif 'access_token' in access_token:
			response = urlopen(
				Request(self.profile_url,
	            headers={'Authorization': 'Bearer ' + access_token['access_token']}
				))
			return (json.load(response), None, None)
		return (None, "bad_response", "Response does not include an access token.")

class AuthProviderGoogle(AuthProviderOAuth2Base):
	authorize_url = 'https://accounts.google.com/o/oauth2/auth'
	access_token_url = 'https://accounts.google.com/o/oauth2/token'
	request_token_params = { 'scope': 'openid profile email' }

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

class WSGIAuthMiddleware(object):
	def __init__(self, app, client_keys):

		# The WSGI app which we are wrapping
		self.app = app

		# Initialize those authentication providers for which client keys have been provided.
		self.auth_providers = {}
		for provider_name, provider_keys in client_keys.items():
			self.auth_providers[provider_name] = available_auth_providers[provider_name](provider_keys)

	# Generate the URL at which we wish to receive the OAuth2 response
	def callback_url(self, environ, provider_name):
		return "{scheme}://{host}/oauth-authorized/{provider_name}".format(
			scheme = environ.get('wsgi.url_scheme',''),
			host = environ.get('HTTP_HOST',''),
			provider_name = provider_name,
			)

	# Generate a URL to describe an error
	def error_url(self, environ, provider_name, error, error_description):
		return "{scheme}://{host}/auth/failure/{provider_name}?{query}".format(
			scheme = environ.get('wsgi.url_scheme',''),
			host = environ.get('HTTP_HOST',''),
			provider_name = provider_name,
			query = urlencode(dict(error=error, error_description=error_description))
			)

	# Throw an HTTP redirect
	def redirect(self, redirect_url, start_response):
		print("Redirect:", redirect_url)
		headers = {
			'Content-Type': 'text/plain;charset=utf-8',
			'Location': redirect_url,
			}
		start_response('307 Temporary Redirect', list(headers.items()))
		return [("Redirecting to %s..." % redirect_url).encode("utf-8")]

	# Handle an WSGI request
	def __call__(self, environ, start_response):
		path = environ['PATH_INFO']

		if path.startswith("/login/"):
			provider_name = path[7:]
			provider = self.auth_providers.get(provider_name)
			if provider is not None:
				callback_url = self.callback_url(environ, provider_name)
				return self.redirect(provider.make_authorize_url(callback_url), start_response)

		elif path.startswith("/oauth-authorized/"):
			provider_name = path[18:]
			provider = self.auth_providers.get(provider_name)
			if provider is not None:
				callback_url = self.callback_url(environ, provider_name)
				profile, error, error_description = provider.get_profile(environ, callback_url)
				if profile is None:
					return self.redirect(self.error_url(provider_name, error, error_description))
				print(json.dumps(profile, indent=4))

		return self.app(environ, start_response)

