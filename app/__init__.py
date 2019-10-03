import json
def app(environ, start_response):
	start_response("200 OK", [("Content-Type", "text/plain;charset=utf-8")])
	data = json.dumps(environ, indent=4, sort_keys=True, ensure_ascii=False, default=str)
	return [("Hello, World!\n%s" % data).encode("utf-8")]
