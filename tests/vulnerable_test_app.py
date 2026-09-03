"""
A tiny, deliberately vulnerable app used ONLY to demo/test the scanner
locally. Do not deploy this anywhere real. Runs on http.server, no
external deps needed.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

GIT_HEAD_BODY = "ref: refs/heads/main\n"


class VulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # quiet

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/.git/HEAD":
            self._send(200, GIT_HEAD_BODY, extra_headers={})
            return

        if path == "/search":
            q = qs.get("q", [""])[0]
            # VULNERABLE: reflects user input unescaped -> reflected XSS
            body = f"<html><body>You searched for: {q}</body></html>"
            self._send(200, body, extra_headers={})
            return

        # default page: no security headers, discloses server version
        body = (
            "<html><body><h1>Demo Vulnerable App</h1>"
            "<a href=\"/search?q=test\">Search</a></body></html>"
        )
        self._send(200, body, extra_headers={"Server": "Apache/2.2.15 (CentOS)"})

    def _send(self, status: int, body: str, extra_headers: dict):
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(encoded)))
        for k, v in extra_headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(encoded)


def run(port=8899):
    server = HTTPServer(("127.0.0.1", port), VulnerableHandler)
    print(f"Vulnerable test app running on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
