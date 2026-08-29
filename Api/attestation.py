from http.server import BaseHTTPRequestHandler
import secrets
import json
import urllib.request
import urllib.parse
import os

class handler(BaseHTTPRequestHandler):

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        # Return a fresh cryptographically secure nonce
        nonce = secrets.token_urlsafe(32)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps({"nonce": nonce}).encode())

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            data = json.loads(body)
        except Exception:
            self._json_response(400, {"success": False, "error": "invalid json"})
            return

        token = data.get("token")
        nonce = data.get("nonce")

        if not token or not nonce:
            self._json_response(400, {"success": False, "error": "missing token or nonce"})
            return

        access_token = os.environ.get("META_ACCESS_TOKEN")
        if not access_token:
            self._json_response(500, {"success": False, "error": "server misconfigured"})
            return

        # Call Meta verification endpoint
        params = urllib.parse.urlencode({
            "token": token,
            "access_token": access_token
        })
        url = f"https://graph.oculus.com/platform_integrity/verify?{params}"

        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                result = json.loads(resp.read().decode())
        except Exception as e:
            self._json_response(502, {
                "success": False,
                "error": f"Meta request failed: {str(e)}"
            })
            return

        success = (
            isinstance(result, dict)
            and "data" in result
            and len(result["data"]) > 0
            and result["data"][0].get("message") == "success"
        )

        if success:
            self._json_response(200, {
                "success": True,
                "claims": result["data"][0].get("claims")
            })
        else:
            self._json_response(403, {
                "success": False,
                "error": "attestation verification failed",
                "details": result
            })

    def _json_response(self, status, payload):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())
