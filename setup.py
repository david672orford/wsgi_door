# https://packaging.python.org/tutorials/packaging-projects/

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="wsgi_door",
    version="0.1",
    author="David Chappell",
    author_email="David.Chappell@trincoll.edu",
    description="WSGI Middleware which provides OAuth2 authentication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/david672orford/wsgi_door",
    packages=['wsgi_door'],
    package_data={"wsgi_door":["templates/*.html"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
	install_requires=[
		'PyJWT',
		'Werkzeug',
	],
)

