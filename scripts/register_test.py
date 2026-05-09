import json
import urllib.request
import traceback

url = 'http://127.0.0.1:5000/api/auth/register'
body = {"username": "testuser1", "password": "pass1234", "email": "testuser1@example.com"}
req = urllib.request.Request(url, data=json.dumps(body).encode('utf-8'), headers={'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(req, timeout=10) as r:
        print('STATUS', r.status)
        print(r.read().decode())
except Exception:
    traceback.print_exc()
