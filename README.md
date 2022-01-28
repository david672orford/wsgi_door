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

# Redirect URL Format

    https://*hostname*/auth/authorized/*provider*

# Protecting Directories

The WsgiAuthFilter middleware provides a simple way to specify which
directories in your app should be protected. You should wrap your app with
WsgiAuthFilter first and then WsgiAuthDoor. If WsgiAuthFilter finds that the
user has attempted to access a protected page but is not logged in, it will
redirect his browser to a login page in /auth/login/. There is an example
in the example directory.

# User Profile

Profile information about the logged-in user is available in the WSGI environment.
For basic applications the name of the user is set as **REMOTE\_USER**.

If more information is required, a standardized profile is available as a
dictionary in **wsgi\_door**. This dictionary can be conveniently viewed
by going to:

	https://*hostname*/auth/status

The fields include:

* id: a unique and unchanging ID assigned to the user by the identity provider. Most often a username or a number.
* provider: the name of the identity provider which authenticated this user
* username: the user's login name or handle
* name: the user's actual name
* picture: the URL of the user's profile picture
* email: the e-mail address of this user
* groups: a list of groups to which this user belongs

# Login Hook

If you need even more information, you should create a login hook. The login
hook takes the form of a URL in your application with the same path as the
redirect URL. When the user logs in, **wsgi\_door** will pass the request
through to your handler. It will do this after the **wsgi\_door** session
cookie object has been created.

Beyond the information normally set in the cookie, the object will have three
attributes set. These are not part of the cookie and will be present only
this one time. They are:

* .provider -- The authentication provider object instance. Useful for the
API URLs or additional methods such as .get\_profile\_picture() which
some providers have.
* .access\_token -- The access token needed to access the provider's graph API.
If you call a method in the provider object instance which access the graph API,
you will have to provide this token as a parameter.
* .raw\_profile -- A dictionary containing information about the user as returned by
the authentication provider's graph API. If .raw\_profile['groups'] is defined,
it will include the descriptions of the groups.

# Integration with Flask

If you app uses Flask, you can use Flask-Login instead of WsgiAuthFilter.
There is an example in the examples/flask\_login directory.

# Changes

* In version 0.1 the value of **id** set by the Azure provider is *username*@*domain*.
  In version 0.2 it is the Azure user ID which is a string of random characters.
* Starting in version 0.2 the version can be read from wsgi\_door.__version__.
  Prior to version 0.2 their is no programatic way to determine the version.
* Starting in version 0.2 you can include the desired scopes in the configuration
  dict for a provider.


