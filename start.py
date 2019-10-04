#! /usr/bin/python3
from werkzeug.serving import run_simple
from werkzeug.middleware.proxy_fix import ProxyFix
from app import app
from wsgi_auth import WSGIAuthMiddleware
from config import auth_client_keys
app = WSGIAuthMiddleware(app, auth_client_keys, "j+Qs/fLkj3lkj;ljX2ljW23ljk32l4", protected_paths=["/admin/", "/private/"])
app = ProxyFix(app, x_proto=1)
run_simple('0.0.0.0', 5000, app)
