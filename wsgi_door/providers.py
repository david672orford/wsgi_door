from urllib.request import urlopen, Request
from urllib.parse import urlencode, parse_qsl
from urllib.error import HTTPError
import json
import jwt
from secrets import token_hex
import gzip
from base64 import b64encode
import logging

# References
# https://oauth.net/articles/authentication/
# https://stackoverflow.com/questions/2138656/signing-requests-in-python-for-oauth

# Uncomment to enable debugging of communication with the authentication provider.
#import urllib.request
#urllib.request.install_opener(urllib.request.build_opener(urllib.request.HTTPSHandler(debuglevel=1)))

logger = logging.getLogger(__name__)

# Base class for providers which still use OAuth version 1
# We use Oauthlib to sign the requests.
# https://oauth.net/core/1.0a/
class AuthProviderOAuth1Base(object):
	request_token_url = None
	authorize_url = None
	access_token_url = None
	logout_url = None

	def __init__(self, keys):
		self.client_id = keys['client_id']
		self.client_secret = keys['client_secret']

	def make_authorize_url(self, session, redirect_uri, extra_args):
		import oauthlib.oauth1
		client = oauthlib.oauth1.Client(
			self.client_id,
			client_secret = self.client_secret,
			callback_uri = redirect_uri,
			)
		uri, headers, body = client.sign(self.request_token_url, http_method="POST")
		try:
			response = urlopen(Request(uri, headers=headers), data=b"")
		except HTTPError as e:
			return None
		response_dict = dict(parse_qsl(response.read().decode("utf-8")))
		session['oauth_token'] = response_dict.get('oauth_token')
		session['oauth_token_secret'] = response_dict.get('oauth_token_secret')
		# FIXME: extra_args ignored
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
		except HTTPError as e:
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
	authorize_args = {}
	access_token_url = None
	access_token_args = {}
	profile_url = None
	logout_url = None
	user_agent = 'wsgi_door:v0.1'

	def __init__(self, keys):
		self.keys = keys
		self.client_id = keys['client_id']
		self.client_secret = keys['client_secret']
		self.config = keys

	# Build the URL to which the user's browser should be redirected to reach
	# the authentication provider's login page.
	def make_authorize_url(self, session, redirect_uri, extra_args):
		state = session['state'] = token_hex(8)
		query = dict(
			client_id = self.client_id,
			redirect_uri = redirect_uri,
			response_type = 'code',
			state = state,
			)
		query.update(self.authorize_args)
		query.update(extra_args)			# from /auth/login query string
		return '{authorize_url}?{query}'.format(
			authorize_url=self.authorize_url.format_map(self.config),
			query=urlencode(query)
			)

	# Called when the browser gets redirected back to our site. Contact the
	# authentication provider directly and ask for an access_token.
	# Along with the access token we may receive other information such as
	# an OpenID Connect assertion (id_token) encoded in JWT format.
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
		form.update(self.access_token_args)
		try:
			response = urlopen(
				Request(self.access_token_url.format_map(self.config),
					headers={
						'Content-Type':'application/x-www-form-urlencoded',
						'Accept':'application/json',
						'User-Agent':self.user_agent,
						# For Reddit
						'Authorization':'Basic ' + b64encode(("%s:%s" % (self.client_id, self.client_secret)).encode("ascii")).decode("ascii")
						}
					),
				# Some providers do not support JSON requests, so we have to use form encoding.
				data=urlencode(form).encode('utf-8')
				)	
		except HTTPError as e:
			#print(e.read())
			return dict(error="bad_response", error_description="HTTP request failed: %s %s" % (e.code, e.reason))
			
		content_type = response.info().get_content_type()
		if content_type == 'application/json':
			access_token = json.load(response)
		elif content_type == 'text/plain':		# Stackexchange bug
			access_token = dict(parse_qsl(response.read().decode('utf-8')))
		else:
			return dict(error="bad_response", error_description="Content-Type (%s) not supported." % content_type)

		# If there is an id_token (OpenID Connect) included, decode it.
		if 'id_token' in access_token:
			# FIXME: verify token
			id_token = jwt.decode(access_token['id_token'], verify=False)
			if id_token.get('aud') != self.client_id:
				return dict(error="bad_id_token", error_description="The token was not intended for this service.")
			access_token['id_token'] = id_token

		return access_token

	# Send an HTTP query (using the access_token) and parse the result as JSON.
	def get_json(self, url, access_token_dict, **kwargs):
		if len(kwargs.keys()):
			url = url + "?" + urlencode(kwargs)
		response = urlopen(
			Request(url,
	           	headers={
					'Authorization': 'Bearer ' + access_token_dict['access_token'],
					'Accept':'application/json',
					'User-Agent':self.user_agent,
					}
				)
			)
		content_type = response.info().get_content_type()
		assert content_type == "application/json", content_type

		# Another Stackexchange bug (IDP uses gzip without permission)
		if response.getheader('Content-Encoding','') == 'gzip':
			response = gzip.GzipFile(fileobj=response)

		response = json.load(response)
		return response

	# Send a request to the provider's url for retrieving the user's profile.
	def get_profile(self, access_token):
		if self.profile_url is None:
			return None
		return self.get_json(self.profile_url, access_token)

	# Extract standard user profile information from the information included
	# with the access token. If it is not enough, call .get_profile().
	# This is a stub which should be overriden in derived classes.
	def normalize_profile(self, access_token, profile):
		print("No profile normalizer defined for this provider")
		print("access_token:", json.dumps(access_token, indent=4, sort_keys=True))
		print("profile:", json.dumps(profile, indent=4, sort_keys=True))
		return dict(
			id = None,
			username = None,
			name = None,
			email = None,
			picture = None,
			)

# https://console.developers.google.com/
class AuthProviderGoogle(AuthProviderOAuth2Base):
	authorize_url = 'https://accounts.google.com/o/oauth2/auth'
	access_token_url = 'https://accounts.google.com/o/oauth2/token'
	authorize_args = {'scope': 'openid profile email'}
	profile_url = 'https://www.googleapis.com/oauth2/v1/userinfo?alt=json'
	def normalize_profile(self, access_token, profile):
		id_token = access_token['id_token']
		return dict(
			id = id_token['sub'],
			username = id_token['email'],
			name = profile['name'],
			email = id_token['email'],
			picture = profile['picture'],
			)

# https://developers.facebook.com
class AuthProviderFacebook(AuthProviderOAuth2Base):
	authorize_url = 'https://www.facebook.com/dialog/oauth'
	access_token_url = 'https://graph.facebook.com/oauth/access_token'
	authorize_args = {'scope': 'email'}
	profile_url = 'https://graph.facebook.com/v1.0/me'
	def normalize_profile(self, access_token, profile):
		return dict(
			id = profile['id'],
			username = None,
			name = profile['name'],
			email = None,
			picture = None,
			groups = None,
			)

# https://developer.twitter.com/en/apps
class AuthProviderTwitter(AuthProviderOAuth1Base):
	request_token_url = 'https://api.twitter.com/oauth/request_token'
	authorize_url = 'https://api.twitter.com/oauth/authenticate'
	access_token_url = 'https://api.twitter.com/oauth/access_token'
	profile_url = 'https://api.twitter.com/1.1/users/show.json?user_id={user_id}'
	def get_normalize_profile(self, access_token, profile):
		return dict(
			id = access_token['user_id'],
			username = access_token['screen_name'],
			name = None,
			email = None,
			picture = profile['profile_image_url_https'],
			groups = None,
			)

# https://github.com/settings/apps
class AuthProviderGithub(AuthProviderOAuth2Base):
	authorize_url = 'https://github.com/login/oauth/authorize'
	access_token_url = 'https://github.com/login/oauth/access_token'
	authorize_args = {'scope': 'openid email'}
	profile_url = 'https://api.github.com/user'
	def normalize_profile(self, access_token, profile):
		return dict(
			id = profile['login'],
			username = profile['login'],
			name = profile['name'],
			email = profile['email'],		# may be None
			picture = profile['avatar_url'],
			groups = None,
			)

# Microsoft Identity Platform v2.0
# (Not to be confused with Azure Active Directory v1.0 which is Microsoft's
# prior OAUTH2 implementation.)
#
# To register your application, go the Azure Portal:
#  https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade
#  Redirect URL:
#    https://example.com/auth/authorized/azure
#  Logout URL:
#    https://example.com/auth/logout
class AuthProviderAzure(AuthProviderOAuth2Base):
	authorize_url = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize'
	authorize_args = {'scope': 'openid user.read Directory.Read.All'}
	access_token_url = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'
	profile_url = 'https://graph.microsoft.com/v1.0/me'
	logout_url = "https://login.microsoftonline.com/{client_id}/oauth2/logout?post_logout_redirect_uri={logged_out_url}"

	def normalize_profile(self, access_token, profile):
		return dict(
			id = profile['userPrincipalName'],
			username = profile['userPrincipalName'],
			name = profile['displayName'],
			email = profile['mail'],
			picture = None,
			groups = self.get_groups(access_token)
			)
		# Most of the above is available from the ID token
		#id_token = access_token.get('id_token',{})
		#return dict(
		#	id = id_token['upd'],
		#	username = id_token['upn'],
		#	name = id_token['name'],
		#	email = None,
		#	picture = None,
		#	groups = self.get_groups(access_token)
		#	)

	def get_groups(self, access_token):
		response = self.get_json('https://graph.microsoft.com/v1.0/me/memberOf', access_token)
		logger.debug("raw groups: %s" % json.dumps(response, indent=4, sort_keys=True))
		groups = []
		for group in response['value']:
			groups.append(group['displayName'])
		return groups

	def get_profile_picture(self, access_token):
		request = Request("https://graph.microsoft.com/v1.0/me/photo/$value",
	           	headers={
					'Authorization': 'Bearer ' + access_token['access_token'],
					'Accept':'image/jpeg',
					'User-Agent':self.user_agent,
					}
			)
		try:
			response = urlopen(request)
		except HTTPError as e:
			logger.debug("Failed to get profile picture: %s" % e.code)
			if e.code != 404:		# no profile picture
				raise
			return None
			
		content_type = response.info().get_content_type()
		assert content_type == "image/jpeg" or content_type == "image/pjpeg", content_type
		return response.read()

# https://www.linkedin.com/developers/apps/
# https://docs.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow
class AuthProviderLinkedin(AuthProviderOAuth2Base):
	authorize_url =    'https://www.linkedin.com/oauth/v2/authorization'
	access_token_url = 'https://www.linkedin.com/oauth/v2/accessToken'
	profile_url = 'https://api.linkedin.com/v2/me'
	authorize_args = {'scope': 'r_liteprofile r_basicprofile r_emailaddress'}
	def normalize_profile(self, access_token, profile):
		print("profile:", profile)
		return dict(
			id = profile['id'],
			username = None,
			name = "%s %s" % (profile['localizedFirstName'], profile['localizedLastName']),
			email = None,
			picture = None,
			)

# https://developers.pinterest.com/apps/
class AuthProviderPinterest(AuthProviderOAuth2Base):
	authorize_url = 'https://api.pinterest.com/oauth/'
	access_token_url = 'https://api.pinterest.com/v1/oauth/token'
	profile_url = 'https://api.pinterest.com/v1/me/'
	authorize_args = {'scope': 'read_public'}
	def normalize_profile(self, access_token, profile):
		profile = profile['data']
		return dict(
			id = profile['id'],
			username = None,
			name = '%s %s' % (profile['first_name'], profile['last_name']),
			email = None,
			picture = None,
			groups = None,
			)

# https://developer.wordpress.com/apps/
class AuthProviderWordpress(AuthProviderOAuth2Base):
	authorize_url = 'https://public-api.wordpress.com/oauth2/authorize'
	access_token_url = 'https://public-api.wordpress.com/oauth2/token'
	profile_url = 'https://public-api.wordpress.com/rest/v1/me'
	authorize_args = {'scope': 'auth'}
	def normalize_profile(self, access_token, profile):
		return dict(
			id = str(profile['ID']),
			username = profile['display_name'],
			name = None,
			email = profile['email'],
			picture = profile['avatar_URL'],
			groups = None,
			)

# https://stackapps.com/apps/oauth/
class AuthProviderStackexchange(AuthProviderOAuth2Base):
	authorize_url = 'https://stackoverflow.com/oauth'
	access_token_url = 'https://stackoverflow.com/oauth/access_token'
	profile_url = 'https://api.stackexchange.com/2.2/me'
	def get_profile(self, access_token):
		return self.get_json(self.profile_url, access_token, site='stackoverflow', key=self.keys['request_key'], access_token=access_token['access_token'])
	def normalize_profile(self, access_token, profile):
		profile = profile['items'][0]
		return dict(
			id = str(profile['user_id']),
			username = profile['display_name'],
			name = None,
			picture = profile['profile_image'],
			groups = None,
			)

# https://www.reddit.com/prefs/apps
# https://github.com/reddit-archive/reddit/wiki/oauth2
class AuthProviderReddit(AuthProviderOAuth2Base):
	#authorize_url = 'https://www.reddit.com/api/v1/authorize'
	authorize_url = 'https://www.reddit.com/api/v1/authorize.compact'
	access_token_url = 'https://www.reddit.com/api/v1/access_token'
	profile_url = 'https://oauth.reddit.com/api/v1/me'
	authorize_args = {'scope': 'identity'}
	def normalize_profile(self, access_token, profile):
		return dict(
			id = profile['id'],
			username = profile['name'],
			name = None,
			email = None,
			picture = profile['icon_img'],
			groups = None,
			)

default_auth_providers = {
	'google': AuthProviderGoogle,
	'facebook': AuthProviderFacebook,
	'twitter': AuthProviderTwitter,
	'github': AuthProviderGithub,
	'azure': AuthProviderAzure,
	'linkedin': AuthProviderLinkedin,
	'pinterest': AuthProviderPinterest,
	'wordpress': AuthProviderWordpress,
	'stackexchange': AuthProviderStackexchange,
	'reddit': AuthProviderReddit,
	}

def init_providers(config, additional_providers={}):
	"""Initialize those authentication providers for which client keys
	are provided in the supplied configuration."""
	auth_providers = {}
	auth_providers.update(default_auth_providers)
	auth_providers.update(additional_providers)
	result = {}
	for provider_name, provider_config in config.items():
		result[provider_name] = auth_providers[provider_name](provider_config)
	return result

