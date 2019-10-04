import json
def app(environ, start_response):
	start_response("200 OK", [("Content-Type", "text/plain;charset=utf-8")])
	greeting = "Hello, %s!\n\n" % environ.get('REMOTE_USER')
	data = json.dumps(environ, indent=4, sort_keys=True, ensure_ascii=False, default=str)
	return map(lambda s: s.encode("utf-8"), [greeting, data])
