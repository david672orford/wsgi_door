This is an implementation of web authentication using services such as
Google, Facebook, and Azure. Authentication is performed using OAuth
and OAuth2.

This authenticaton library takes the form of WSGI middleware. If you wrap your
WSGI app (which includes Flask apps) in WsgiAuthDoor middleware, it will
overlay a /auth/ directory. Within this directory are views for logging in
using the configured providers and for logging out. For example:

## /auth/login/
Display a list of the configured providers and let the user choose

## /auth/login/google
Log in using a Google account

## /auth/login/azure
Log in using Microsoft Azure

## /auth/logout
Destroy the session cookie

# Redirect URL

    http://*hostname*/auth/authorized/*provider*

# Protecting Directories

The WsgiAuthFilter middleware provides a simple way to specify which
directories in your app should be protected. You should wrap your app
with WsgiAuthFilter first and then WsgiAuthDoor. If WsgiAuthFilter
finds that the user has attempted to access a protected page but is not
logged in, it will redirect his browser to a login page in /auth/login/.
There is an example in the example directory.

# Integration with Flask

If you app uses Flask, you can use Flask-Login instead of WsgiAuthFilter.
There is an example in the example\_flask\_login directory.

# Todo

Retrieving /auth/login rather than the correct /auth/login/ results in
a werkzeug.routing.RequestRedirect being throw. We don't seem to 
handle this properly.


