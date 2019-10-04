from urllib.request import urlopen, Request
from urllib.parse import urlencode, parse_qsl
import urllib.error
import json
import jwt
from secrets import token_hex

# Base class for providers which still use OAuth version 1
# We use Oauthlib to sign the requests.
# https://oauth.net/core/1.0a/
class AuthProviderOAuth1Base(object):
	request_token_url = None
	authorize_url = None
	access_token_url = None

	def __init__(self, keys):
		self.client_id = keys['client_id']
		self.client_secret = keys['client_secret']

	def make_authorize_url(self, session, redirect_uri):
		import oauthlib.oauth1
		client = oauthlib.oauth1.Client(
			self.client_id,
			client_secret = self.client_secret,
			callback_uri = redirect_uri,
			)
		uri, headers, body = client.sign(self.request_token_url, http_method="POST")
		print(headers)
		try:
			response = urlopen(Request(uri, headers=headers), data=b"")
		except urllib.error.HTTPError as e:
			return None
		response_dict = dict(parse_qsl(response.read().decode("utf-8")))
		session['oauth_token'] = response_dict.get('oauth_token')
		session['oauth_token_secret'] = response_dict.get('oauth_token_secret')
		return "%s?%s" % (self.authorize_url, urlencode(dict(oauth_token=response_dict.get('oauth_token'))))

	def get_access_token(self, request, session, redirect_uri):
		import oauthlib.oauth1
		if not 'oauth_token' in session:
			return dict(error="spurious_response", error_description="Browser was not expected to visit the redirect_uri.")
		if request.args.get('oauth_token') != session['oauth_token']:
			return dict(error="incorrect_state", error_description="The oauth_token value is not correct.")
		client = oauthlib.oauth1.Client(
			self.client_id,
			client_secret = self.client_secret,
			resource_owner_key = session.pop('oauth_token'),
			resource_owner_secret = session.pop('oauth_token_secret'),
			verifier = request.args.get('oauth_verifier'),
			)
		uri, headers, body = client.sign(self.access_token_url, http_method="POST")
		try:
			response = urlopen(Request(uri, headers=headers), data=b"")
		except urllib.error.HTTPError as e:
			return dict(error="bad_response", error_description="HTTP request failed: %s %s" % (e.code, e.reason))
		return dict(parse_qsl(response.read().decode("utf-8")))

	def get_profile(self, access_token):
		import oauthlib.oauth1
		if self.profile_url is not None:
			client = oauthlib.oauth1.Client(
				self.client_id,
				client_secret = self.client_secret,
				resource_owner_key = access_token['oauth_token'],
				resource_owner_secret = access_token['oauth_token_secret'],
				)
			# FIXME: this is unsafe
			uri = self.profile_url.format(**access_token)
			uri, headers, body = client.sign(uri, http_method="GET")
			response = urlopen(Request(uri, headers=headers))
			return json.load(response)
		return None

# Base class for providers which use OAuth version 2
# https://oauth.net/2/
class AuthProviderOAuth2Base(object):
	authorize_url = None
	access_token_url = None
	profile_url = None
	scope = None

	def __init__(self, keys):
		self.client_id = keys['client_id']
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
			scope = self.scope,
			prompt = 'select_account',
			)
		return '{authorize_url}?{query}'.format(authorize_url=self.authorize_url, query=urlencode(query))

	# Called when the browser gets redirected back to our site. Contact the
	# authentication provider directly and ask for an access_token.
	# Along with the access token we may receive other information such as
	# an OpenID Connect assertion (id_token) encoded in JWT format.
	# If we know the proper URL for this provider, ask for the user's
	# profile information too.
	def get_access_token(self, request, session, redirect_uri):
		if 'error' in request.args:
			return dict(error=request.args.get('error'), error_description=request.args.get('error_description'))
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
			response = urlopen(
				Request(self.access_token_url, headers={'Accept':'application/json'}),
				data=urlencode(form).encode('utf-8')
				)	
		except urllib.error.HTTPError as e:
			return dict(error="bad_response", error_description="HTTP request failed: %s %s" % (e.code, e.reason))
			
		content_type = response.info().get_content_type()
		if content_type != 'application/json':
			return dict(error="bad_response", error_description="Content-Type (%s) not supported." % content_type)
		access_token = json.load(response)

		if 'id_token' in access_token:
			# FIXME: verify token
			id_token = jwt.decode(access_token['id_token'], verify=False)
			access_token['id_token'] = id_token

		return access_token

	# Send a request to the provider's url for retrieving the user's profile.
	def get_profile(self, access_token):
		if self.profile_url is not None:
			response = urlopen(
				Request(self.profile_url,
	            headers={'Authorization': 'Bearer ' + access_token['access_token']}
				))
			return json.load(response)
		return None

	# Extract standard user profile information from the information included
	# with the access token. If it is not enough, call .get_profile().
	# This is a stub which should be overriden in derived classes.
	def get_normalized_profile(self, access_token):
		return dict()

# https://console.developers.google.com/
class AuthProviderGoogle(AuthProviderOAuth2Base):
	authorize_url = 'https://accounts.google.com/o/oauth2/auth'
	access_token_url = 'https://accounts.google.com/o/oauth2/token'
	scope = 'openid profile email'
	profile_url = 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json'
	def get_normalized_profile(self, access_token):
		id_token = access_token.get('id_token',{})
		if id_token.get('email_verified') is True:
			return dict(remote_user=id_token['email'])
		return dict()

# https:/developers.facebook.com
class AuthProviderFacebook(AuthProviderOAuth2Base):
	authorize_url = 'https://www.facebook.com/dialog/oauth'
	access_token_url = 'https://graph.facebook.com/oauth/access_token'
	scope = 'email'
	profile_url = 'https://graph.facebook.com/v1.0/me'
	def get_normalized_profile(self, access_token):
		profile = self.get_profile(access_token)
		if 'name' in profile:
			return dict(remote_user="%s@facebook" % profile['name'])
		return dict()

# https://developer.twitter.com/en/apps
class AuthProviderTwitter(AuthProviderOAuth1Base):
	request_token_url = 'https://api.twitter.com/oauth/request_token'
	authorize_url = 'https://api.twitter.com/oauth/authenticate'
	access_token_url = 'https://api.twitter.com/oauth/access_token'
	#profile_url = 'https://api.twitter.com/1.1/account/settings.json'
	profile_url = 'https://api.twitter.com/1.1/users/show.json?user_id={user_id}'
	def get_normalized_profile(self, access_token):
		profile = self.get_profile(access_token)
		print("profile:", profile)
		return dict(remote_user="%s@twitter" % access_token['screen_name'])

# https://github.com/settings/apps
class AuthProviderGitHub(AuthProviderOAuth2Base):
	authorize_url = 'https://github.com/login/oauth/authorize'
	access_token_url = 'https://github.com/login/oauth/access_token'
	scope = 'openid email'
	profile_url = 'https://api.github.com/user'
	def get_normalized_profile(self, access_token):
		profile = self.get_profile(access_token)
		if 'login' in profile:
			return dict(remote_user="%s@github.com" % profile['login'])
		return dict()

# https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade
class AuthProviderAzure(AuthProviderOAuth2Base):
	authorize_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
	access_token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
	scope = 'openid email'
	profile_url = 'https://graph.microsoft.com/v1.0/me'
	def get_normalized_profile(self, access_token):
		id_token = access_token.get('id_token',{})
		if 'email' in id_token:
			return dict(remote_user=id_token.get('email'))
		return dict()

# https://www.linkedin.com/developers/apps/
class AuthProviderLinkedin(AuthProviderOAuth2Base):
	authorize_url = None
	access_token_url = None
	scope = None

# https://developers.pinterest.com/apps/
class AuthProviderPinterest(AuthProviderOAuth2Base):
	authorize_url = 'https://api.pinterest.com/oauth/'
	access_token_url = 'https://api.pinterest.com/v1/oauth/token'
	profile_url = 'https://api.pinterest.com/v1/me/'
	scope = 'read_public'
	def get_normalized_profile(self, access_token):
		profile = self.get_profile(access_token)
		print("profile:", profile)
		return dict()

# https://developer.wordpress.com/apps/
class AuthProviderWordpress(AuthProviderOAuth2Base):
	authorize_url = 'https://public-api.wordpress.com/oauth2/authorize'
	access_token_url = 'https://public-api.wordpress.com/oauth2/token'
	profile_url = 'https://public-api.wordpress.com/rest/v1/me'
	scope = 'auth'
	def get_normalized_profile(self, access_token):
		profile = self.get_profile(access_token)
		print("profile:", profile)
		return dict()

available_auth_providers = {
	'google': AuthProviderGoogle,
	'facebook': AuthProviderFacebook,
	'twitter': AuthProviderTwitter,
	'github': AuthProviderGitHub,
	'azure': AuthProviderAzure,
	#'linkedin': AuthProviderLinkedin,
	'pinterest': AuthProviderPinterest,
	'wordpress': AuthProviderWordpress,
	}

