import requests

BASE_URL = "http://127.0.0.1:5000"
PASSWORD = "testpassword123"

passed = 0
total = 0

def test(name, method, path, *, params=None, json=None, headers=None, expected_status=200, expected_keys=None):
    global passed, total
    total += 1
    url = BASE_URL + path
    try:
        r = getattr(requests, method)(url, params=params, json=json, headers=headers)
    except Exception as e:
        print(f"[X] {name} - request failed: {e}")
        return

    if r.status_code != expected_status:
        print(f"[X] {name} - expected status {expected_status}, got {r.status_code}")
        return

    if expected_keys is not None:
        try:
            data = r.json()
        except Exception:
            print(f"[X] {name} - response not JSON")
            return
        for key in expected_keys:
            if key not in data:
                print(f"[X] {name} - key '{key}' missing in response")
                return
    passed += 1
    print(f"[✔️] {name} - passed")

test("Register valid", "post", "/auth/register", json={"password": PASSWORD, "publicView": True}, expected_status=201, expected_keys=["publicKey", "token"])
r = requests.post(BASE_URL + "/auth/register", json={"password": PASSWORD, "publicView": True})
if r.status_code == 201:
    token = r.json()["token"]
    publicKey = r.json()["publicKey"]
else:
    print("Setup failed: Could not register")
    exit(1)

headers_auth = {"LogIt-Authorization": f"Bearer {token}"}

test("Register missing password", "post", "/auth/register", json={"publicView": True}, expected_status=400)
test("Login valid", "post", "/auth/login", json={"publicKey": publicKey, "password": PASSWORD}, expected_status=200, expected_keys=["token"])
test("Login wrong password", "post", "/auth/login", json={"publicKey": publicKey, "password": "wrongpass"}, expected_status=403)
test("Login missing key", "post", "/auth/login", json={"password": PASSWORD}, expected_status=400)
test("Log message valid", "get", "/api/log", params={"key": publicKey, "message": "hello", "channel": "test"}, expected_status=200, expected_keys=["status"])
test("Log message missing key", "get", "/api/log", params={"message": "hi", "channel": "test"}, expected_status=403)
test("Log message missing message", "get", "/api/log", params={"key": publicKey, "channel": "test"}, expected_status=400)
test("Bulk log valid", "post", "/api/log/bulk", params={"key": publicKey}, json=[{"message": "bulk1", "channel": "test"}], expected_status=200, expected_keys=["status", "insertedCount"])
test("Bulk log empty array", "post", "/api/log/bulk", params={"key": publicKey}, json=[], expected_status=400)
test("Bulk log missing key", "post", "/api/log/bulk", json=[{"message": "bulk1", "channel": "test"}], expected_status=403)
test("Pull logs public", "get", "/api/pull", params={"key": publicKey}, expected_status=200, expected_keys=["logs", "publicKey"])
test("Pull logs missing key", "get", "/api/pull", expected_status=403)
test("Pull logs auth valid", "get", "/api/pull", headers=headers_auth, expected_status=200, expected_keys=["logs", "publicKey"])
test("Pull logs invalid token", "get", "/api/pull", headers={"LogIt-Authorization": "Bearer invalidtoken"}, expected_status=401)
test("Search logs valid", "get", "/api/logs/search", headers=headers_auth, params={"channel": "test"}, expected_status=200, expected_keys=["logs", "publicKey"])
test("Search logs missing auth", "get", "/api/logs/search", expected_status=401)

r = requests.get(BASE_URL + "/api/log", params={"key": publicKey, "message": "to be edited", "channel": "edit-test"})
if r.status_code == 200:
    r2 = requests.get(BASE_URL + "/api/pull", params={"key": publicKey, "channel": "edit-test"}, headers=headers_auth)
    if r2.status_code == 200 and r2.json().get("logs"):
        logId = r2.json()["logs"][0]["logId"]
    else:
        logId = None
else:
    logId = None

if logId:
    test("Edit log valid", "put", "/api/edit", json={"logId": logId, "newMessage": "editedsd message"}, headers=headers_auth, expected_status=200)
    test("Edit log missing logId", "put", "/api/edit", json={"newMessage": "fail"}, headers=headers_auth, expected_status=400)
    test("Edit log missing newMessage", "put", "/api/edit", json={"logId": logId}, headers=headers_auth, expected_status=400)
else:
    print("[⚠] Skipped edit log tests - no log found")

if logId:
    test("Delete log valid", "delete", "/api/delete", json={"logId": logId}, headers=headers_auth, expected_status=200)
    test("Delete log missing logId", "delete", "/api/delete", json={}, headers=headers_auth, expected_status=400)
else:
    print("[⚠] Skipped delete log tests - no log found")

test("Clear logs", "delete", "/api/clear", headers=headers_auth, expected_status=200)

r = requests.get(BASE_URL + "/api/log", params={"key": publicKey, "message": "to be edited", "channel": "edit-test"})

test("Export logs JSON", "get", "/api/export", headers=headers_auth, params={"format": "json"}, expected_status=200)
test("Export logs CSV", "get", "/api/export", headers=headers_auth, params={"format": "csv"}, expected_status=200)
test("Add IP blacklist missing IP", "post", "/api/blacklist/add", headers=headers_auth, json={}, expected_status=400)
test("Add IP blacklist valid", "post", "/api/blacklist/add", headers=headers_auth, json={"ip": "1.2.3.4"}, expected_status=200)
test("Add IP blacklist duplicate", "post", "/api/blacklist/add", headers=headers_auth, json={"ip": "1.2.3.4"}, expected_status=400)
test("List IP blacklist", "get", "/api/blacklist/list", headers=headers_auth, expected_status=200, expected_keys=["blacklist"])
test("Remove IP blacklist missing IP", "post", "/api/blacklist/remove", headers=headers_auth, json={}, expected_status=400)
test("Remove IP blacklist valid", "post", "/api/blacklist/remove", headers=headers_auth, json={"ip": "1.2.3.4"}, expected_status=200)
test("Remove IP blacklist not found", "post", "/api/blacklist/remove", headers=headers_auth, json={"ip": "1.2.3.4"}, expected_status=400)
test("Add origin missing origin", "post", "/api/origin/add", headers=headers_auth, json={}, expected_status=400)
test("Add origin invalid format", "post", "/api/origin/add", headers=headers_auth, json={"origin": "invalid"}, expected_status=400)
test("Add origin valid", "post", "/api/origin/add", headers=headers_auth, json={"origin": "https://example.com"}, expected_status=200)
test("Add origin duplicate", "post", "/api/origin/add", headers=headers_auth, json={"origin": "https://example.com"}, expected_status=400)
test("List origins", "get", "/api/origin/list", headers=headers_auth, expected_status=200, expected_keys=["allowedOrigins"])
test("Remove origin missing origin", "post", "/api/origin/remove", headers=headers_auth, json={}, expected_status=400)
test("Remove origin invalid format", "post", "/api/origin/remove", headers=headers_auth, json={"origin": "badorigin"}, expected_status=400)
test("Remove origin valid", "post", "/api/origin/remove", headers=headers_auth, json={"origin": "https://example.com"}, expected_status=200)
test("Remove origin not found", "post", "/api/origin/remove", headers=headers_auth, json={"origin": "https://example.com"}, expected_status=400)
test("Webhook setup missing URL", "post", "/webhook_setup", headers=headers_auth, json={}, expected_status=400)
test("Webhook setup invalid URL format", "post", "/webhook_setup", headers=headers_auth, json={"webhookUrl": "ftp://bad.url"}, expected_status=400)
test("Webhook setup unsupported URL", "post", "/webhook_setup", headers=headers_auth, json={"webhookUrl": "https://google.com"}, expected_status=400)
test("Webhook setup valid discord", "post", "/webhook_setup", headers=headers_auth, json={"webhookUrl": "https://discord.com/api/webhooks/test"}, expected_status=200)
test("Stats endpoint", "get", "/stats", expected_status=200, expected_keys=["totalLogs", "totalDevKeys"])
test("404 error", "get", "/nonexistent", expected_status=404, expected_keys=["error"])
test("405 error (method not allowed)", "post", "/api/log", params={"key": publicKey}, json={}, expected_status=405)
test("401 error (unauthorized) - missing auth on protected", "get", "/api/logs/search", expected_status=401)
test("403 error (forbidden) - invalid public key", "get", "/api/log", params={"key": "invalidkey", "message": "test", "channel": "test"}, expected_status=403)

print(f"\nTested {passed}/{total} tests passed ({(passed / total) * 100:.2f}%)")
