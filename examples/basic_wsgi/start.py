#! /usr/bin/python3 -B

from werkzeug.serving import run_simple
from werkzeug.middleware.proxy_fix import ProxyFix

from wsgi_door.providers import init_providers
from wsgi_door.middleware import WsgiDoorAuth, WsgiDoorFilter

from app import app
from config import config

# Enable and configure authentication providers using the
# configuration provided.
auth_providers = init_providers(config['AUTH_CLIENT_KEYS'])

# This determines when the user needs to be logged in. It needs to go
# 'underneath' WsgiDoorAuth so it can tell whether the user is logged
# in. If the user is not logged in and needs to be, it redirects to
# /auth/login/.
app = WsgiDoorFilter(app,
	# Make the user log in before accessing any paths which begin with these strings.
	protected_paths=["/admin/", "/private/"],
	# Reject users who are no a member of one of these groups.
	#allowed_groups=config['ALLOWED_GROUPS'],
	)

# Set REMOTE_USER and wsgi_door in the WSGI environment.
# Graft on the /auth/ directory.
app = WsgiDoorAuth(app, auth_providers, secret=config['SECRET_KEY'])

app = ProxyFix(app, x_proto=1)
run_simple('0.0.0.0', 5000, app)
