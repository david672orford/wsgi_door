The WSGI middleware supplied in this project can add authentication in
front of your app.

The authentication is provided by the WsgiAuthDoor middleware. It overlays
a /auth/ directory on your project. Within this directory are views for
logging in using the configured providers and for logging out. For example:

 /auth/login/
  Display a list of the configured providers and let the user choose
 /auth/login/google
  Log in using a Google account
 /auth/logout
  Destroy the session cookie

The WsgiAuthFilter middleware provides a simple way to specify which
directories in your app should be protected. You should wrap your app
with WsgiAuthFilter first and then WsgiAuthDoor. If WsgiAuthFilter
finds that the user has attempted to access a protected page but is not
logged in, it will redirect his browser to a login page in /auth/login/.
There is an example in the example directory.

If you app uses Flask, you can use Flask-Login instead of WsgiAuthFilter.
There is an example in the example\_flask\_login directory.

