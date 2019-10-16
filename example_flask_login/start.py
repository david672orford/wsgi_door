#! /usr/bin/python3 -B
import sys
sys.path.append("..")

from werkzeug.serving import run_simple
from werkzeug.middleware.proxy_fix import ProxyFix

from wsgi_door.providers import init_providers
from wsgi_door.middleware import WsgiDoorAuth

from app import app

auth_providers = init_providers(app.config.AUTH_CLIENT_KEYS)
app.wsgi_app = WsgiDoorAuth(app.wsgi_app, auth_providers, app.config.SECRET_KEY)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_for=1)
run_simple('0.0.0.0', 5000, app)
