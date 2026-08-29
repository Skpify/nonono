from flask import Flask, request, jsonify
import secrets
import urllib.request
import urllib.parse
import os
import json

app = Flask(__name__)

@app.route("/api/attestation", methods=["GET", "POST", "OPTIONS"])
def attestation():
    # Handle CORS preflight
    if request.method == "OPTIONS":
        response = jsonify({})
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return response

    if request.method == "GET":
        nonce = secrets.token_urlsafe(32)
        response = jsonify({"nonce": nonce})
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    # POST - verify
    data = request.get_json(silent=True) or {}
    token = data.get("token")
    nonce = data.get("nonce")

    if not token or not nonce:
        return jsonify({"success": False, "error": "missing token or nonce"}), 400

    access_token = os.environ.get("META_ACCESS_TOKEN")
    if not access_token:
        return jsonify({"success": False, "error": "server misconfigured"}), 500

    params = urllib.parse.urlencode({
        "token": token,
        "access_token": access_token
    })
    url = f"https://graph.oculus.com/platform_integrity/verify?{params}"

    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            result = json.loads(resp.read().decode())
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Meta request failed: {str(e)}"
        }), 502

    success = (
        isinstance(result, dict)
        and "data" in result
        and len(result["data"]) > 0
        and result["data"][0].get("message") == "success"
    )

    response = jsonify({
        "success": success,
        "claims": result["data"][0].get("claims") if success else None,
        "error": None if success else "attestation verification failed",
        "details": None if success else result
    })
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response, 200 if success else 403


# This is required by Vercel
app = app
