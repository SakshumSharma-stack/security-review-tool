# ============================================================
# INTENTIONALLY VULNERABLE CODE — FOR TESTING PURPOSES ONLY
# These snippets are designed to trigger the security scanner.
# Do NOT use any of this code in a real application.
# ============================================================

from flask import Flask, request, jsonify
import sqlite3
import jwt
import hashlib

app = Flask(__name__)

# ----------------------------------------------------------------
# A01: Broken Access Control
# Vulnerability: The endpoint fetches a user record using an ID
# supplied directly by the caller. There is no check that the
# authenticated user is allowed to view *that* ID — any logged-in
# user (or an unauthenticated one if the route had no auth at all)
# can enumerate every account by changing the ?user_id= parameter.
# This is a classic Insecure Direct Object Reference (IDOR).
# ----------------------------------------------------------------
@app.route("/api/user/profile", methods=["GET"])
def get_user_profile():
    user_id = request.args.get("user_id")          # attacker-controlled
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # No ownership check: any caller can read any user's profile
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return jsonify({"user": user})


# ----------------------------------------------------------------
# A02: Hardcoded Credentials
# Vulnerability: The database password and a third-party API key
# are embedded as string literals. Anyone with read access to this
# file (or git history) can extract them immediately.
# Rotating these credentials requires a code change and redeployment.
# ----------------------------------------------------------------
DB_PASSWORD = "SuperSecret123!"          # hardcoded database password
STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"   # hardcoded API key

def connect_to_database():
    # Credential is visible in plaintext — should come from os.environ
    connection_string = f"postgresql://admin:{DB_PASSWORD}@prod-db:5432/appdb"
    return connection_string


# ----------------------------------------------------------------
# A03: SQL Injection
# Vulnerability: The username value from the login form is
# interpolated directly into the SQL query string using an f-string.
# An attacker can supply:  ' OR '1'='1  to bypass authentication,
# or more destructive payloads to dump or drop tables.
# ----------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # UNSAFE: user input concatenated into query — use ? placeholders instead
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()

    if user:
        return jsonify({"status": "login successful"})
    return jsonify({"status": "invalid credentials"}), 401


# ----------------------------------------------------------------
# A05: Security Misconfiguration — Debug Mode Enabled
# Vulnerability: Running Flask with debug=True in production exposes
# the Werkzeug interactive debugger. Any visitor who triggers an
# unhandled exception gets a full stack trace AND an in-browser
# Python REPL that can execute arbitrary code on the server.
# ----------------------------------------------------------------
if __name__ == "__main__":
    # debug=True must never be set in a production environment
    app.run(host="0.0.0.0", port=5000, debug=True)


# ----------------------------------------------------------------
# A07: Identification and Authentication Failures — Weak JWT Secret
# Vulnerability: The JWT signing secret is a short, hardcoded
# dictionary word. An attacker who obtains a valid token can
# brute-force the secret offline in seconds and then forge tokens
# for any user, including admins. The 'none' algorithm is also
# accepted because no explicit algorithm list is enforced on decode.
# ----------------------------------------------------------------
JWT_SECRET = "secret"   # trivially guessable — must be a long random value

def create_token(user_id: int, role: str) -> str:
    payload = {"user_id": user_id, "role": role}
    # Signed with a weak secret; any HS256 brute-forcer will crack this
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(token: str) -> dict:
    # No algorithm allowlist: accepts whatever 'alg' the token header claims,
    # including 'none', meaning a tampered unsigned token passes verification
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256", "none"])
