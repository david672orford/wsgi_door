#! /usr/bin/python3 -B
import sys
sys.path.append("..")
from werkzeug.serving import run_simple
from werkzeug.middleware.proxy_fix import ProxyFix
from app import app
from wsgi_door.providers import init_providers
from wsgi_door.middleware import WsgiDoorAuth, WsgiDoorFilter
from config import auth_client_keys
auth_providers = init_providers(auth_client_keys)
app = WsgiDoorFilter(app, protected_paths=["/admin/", "/private/"])
app = WsgiDoorAuth(app, auth_providers, secret="j+Qs/fLkj3lkj;ljX2ljW23ljk32l4")
app = ProxyFix(app, x_proto=1)
run_simple('0.0.0.0', 5000, app)
