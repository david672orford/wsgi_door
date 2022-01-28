This is an example of a Flask app using wsgi\_door for authentication
and Flask-Login to connect wsgi\_door and Flask together. In this
example views provided by Flask-Admin are protected.

If you do not require the per-view control which Flask-Login provides, you 
may find it simpler to use the basic\_wsgi example instead since it
requires much less integration into the app.

To run this example:

    cp instance/sample-config.py instance/config.py
    vim instance/config.py
    PYTHONPATH=../.. ./start.py

