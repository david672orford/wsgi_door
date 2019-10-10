#! /usr/bin/python3 -B
import sys
sys.path.append("..")
from werkzeug.serving import run_simple
from werkzeug.middleware.proxy_fix import ProxyFix
from app import app
from wsgi_door.providers import init_providers
from wsgi_door.middleware import WsgiDoorAuth
auth_providers = init_providers(app.config['AUTH_CLIENT_KEYS'])
app = WsgiDoorAuth(app, auth_providers, app.config['SECRET'])
app = ProxyFix(app, x_proto=1)
run_simple('0.0.0.0', 5000, app)
