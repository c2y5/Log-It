import requests

BASE_URL = "http://127.0.0.1:5000"
PASSWORD = "testpassword123"
TOKEN = None
PUBLIC_KEY = None
BLACKLIST_IP = "1.1.1.1"
TEST_ORIGIN = "http://example.com"

passed = 0
total = 0

def test(name, method, path, *, params=None, json=None, headers=None,
         expected_status=200, expected_keys=None, expected_values=None):
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
    if expected_keys or expected_values:
        try:
            data = r.json()
        except Exception:
            print(f"[X] {name} - response not JSON")
            return
        if expected_keys:
            for key in expected_keys:
                if key not in data:
                    print(f"[X] {name} - missing key '{key}'")
                    return
        if expected_values:
            for k, v in expected_values.items():
                if data.get(k) != v:
                    print(f"[X] {name} - expected {k}={v}, got {data.get(k)}")
                    return
    passed += 1
    print(f"[✔️] {name} tested working as expected")

resp = requests.post(BASE_URL + "/auth/register", json={"password": PASSWORD, "publicView": True})
if resp.status_code == 201:
    data = resp.json()
    PUBLIC_KEY = data.get("publicKey")
    TOKEN = data.get("token")
else:
    print("[X] Registration failed, cannot proceed")
    exit(1)

headers_auth = {"LogIt-Authorization": f"Bearer {TOKEN}"}

test("Register with missing fields", "post", "/auth/register", json={}, expected_status=400)
test("Login with invalid data", "post", "/auth/login", json={"publicKey": PUBLIC_KEY}, expected_status=400)
test("Login with wrong password", "post", "/auth/login", json={"publicKey": PUBLIC_KEY, "password": "wrong"}, expected_status=403)
test("Login success", "post", "/auth/login", json={"publicKey": PUBLIC_KEY, "password": PASSWORD}, expected_status=200, expected_keys=["token"])

test("Log without key", "get", "/api/log", expected_status=403)
test("Log with invalid key", "get", "/api/log", params={"key": "invalid"}, expected_status=403)
test("Log without message or channel", "get", "/api/log", params={"key": PUBLIC_KEY}, expected_status=400)

params_log = {"key": PUBLIC_KEY, "message": "Hello", "channel": "main"}
test("Log valid message", "get", "/api/log", params=params_log, expected_status=200, expected_values={"status": "success"})

bulk_logs = [
    {"message": "bulk1", "channel": "bulk", "logLevel": "info", "tags": ["tag1"]},
    {"message": "bulk2", "channel": "bulk", "logLevel": "warn", "tags": ["tag2"]}
]
test("Bulk log with empty", "post", "/api/log/bulk", params={"key": PUBLIC_KEY}, json=[], expected_status=400)
test("Bulk log valid", "post", "/api/log/bulk", params={"key": PUBLIC_KEY}, json=bulk_logs, expected_status=200, expected_values={"status": "success"})

test("Pull without key", "get", "/api/pull", expected_status=403)
test("Pull with invalid key", "get", "/api/pull", params={"key": "invalid"}, expected_status=403)

test("Search logs no auth", "get", "/api/logs/search", expected_status=401)
test("Search logs with auth", "get", "/api/logs/search", headers=headers_auth, expected_status=200, expected_keys=["logs"])

logId = None
search_resp = requests.get(BASE_URL + "/api/logs/search", headers=headers_auth).json()
if search_resp.get("logs"):
    logId = search_resp["logs"][0].get("logId")

test("Edit log missing fields", "put", "/api/edit", headers=headers_auth, json={}, expected_status=400)
if logId:
    test("Edit log success", "put", "/api/edit", headers=headers_auth, json={"logId": logId, "newMessage": "edited message"}, expected_status=200, expected_values={"status": "success"})

test("Delete log missing", "delete", "/api/delete", headers=headers_auth, json={}, expected_status=400)
if logId:
    test("Delete log success", "delete", "/api/delete", headers=headers_auth, json={"logId": logId}, expected_status=200, expected_values={"status": "success"})

test("Clear logs", "delete", "/api/clear", headers=headers_auth, expected_status=200)

test("Export logs json", "get", "/api/export", headers=headers_auth, expected_status=404)

test("Add IP blacklist missing", "post", "/api/blacklist/add", headers=headers_auth, json={}, expected_status=400)
test("Add IP blacklist success", "post", "/api/blacklist/add", headers=headers_auth, json={"ip": BLACKLIST_IP}, expected_status=200)
test("Add IP blacklist duplicate", "post", "/api/blacklist/add", headers=headers_auth, json={"ip": BLACKLIST_IP}, expected_status=400)

test("List IP blacklist", "get", "/api/blacklist/list", headers=headers_auth, expected_status=200, expected_keys=["blacklist"])

test("Remove IP blacklist missing", "post", "/api/blacklist/remove", headers=headers_auth, json={}, expected_status=400)
test("Remove IP blacklist success", "post", "/api/blacklist/remove", headers=headers_auth, json={"ip": BLACKLIST_IP}, expected_status=200)
test("Remove IP blacklist not found", "post", "/api/blacklist/remove", headers=headers_auth, json={"ip": BLACKLIST_IP}, expected_status=400)

test("Add origin missing", "post", "/api/origin/add", headers=headers_auth, json={}, expected_status=400)
test("Add origin invalid", "post", "/api/origin/add", headers=headers_auth, json={"origin": "ftp://bad"}, expected_status=400)
test("Add origin success", "post", "/api/origin/add", headers=headers_auth, json={"origin": TEST_ORIGIN}, expected_status=200)
test("Add origin duplicate", "post", "/api/origin/add", headers=headers_auth, json={"origin": TEST_ORIGIN}, expected_status=400)

test("List origins", "get", "/api/origin/list", headers=headers_auth, expected_status=200, expected_keys=["allowedOrigins"])

test("Remove origin missing", "post", "/api/origin/remove", headers=headers_auth, json={}, expected_status=400)
test("Remove origin invalid", "post", "/api/origin/remove", headers=headers_auth, json={"origin": "ftp://bad"}, expected_status=400)
test("Remove origin success", "post", "/api/origin/remove", headers=headers_auth, json={"origin": TEST_ORIGIN}, expected_status=200)
test("Remove origin not found", "post", "/api/origin/remove", headers=headers_auth, json={"origin": TEST_ORIGIN}, expected_status=400)

test("Webhook setup missing", "post", "/webhook_setup", headers=headers_auth, json={}, expected_status=400)
test("Webhook setup invalid url", "post", "/webhook_setup", headers=headers_auth, json={"webhookUrl": "http://bad"}, expected_status=400)
test("Webhook setup wrong service", "post", "/webhook_setup", headers=headers_auth, json={"webhookUrl": "https://google.com"}, expected_status=400)
test("Webhook setup valid", "post", "/webhook_setup", headers=headers_auth, json={"webhookUrl": "https://discord.com/api/webhooks/test"}, expected_status=200)

test("Stats endpoint", "get", "/stats", expected_status=200, expected_keys=["totalLogs", "totalDevKeys"])

test("404 handler", "get", "/nonexistent", expected_status=404, expected_values={"error": "Not found"})
test("400 handler by missing param", "post", "/api/origin/add", headers=headers_auth, json={}, expected_status=400, expected_values={"error": "Origin is required"})

def test_pull_filter(filter_name, filter_value, expected_status=200):
    params = {"key": PUBLIC_KEY, filter_name: filter_value, "page": 1}
    test(f"/api/pull filter {filter_name}={filter_value}", "get", "/api/pull", params=params,
         expected_status=expected_status, expected_keys=["logs"])

def test_search_filter(filter_name, filter_value, expected_status=200):
    params = {filter_name: filter_value, "page": 1, "limit": 10}
    test(f"/api/logs/search filter {filter_name}={filter_value}", "get", "/api/logs/search",
         params=params, headers=headers_auth, expected_status=expected_status, expected_keys=["logs"])

for i in range(3):
    requests.get(BASE_URL + "/api/log", params={
        "key": PUBLIC_KEY,
        "channel": f"channel{i}",
        "message": f"test message {i}",
        "logLevel": ["info", "warn", "error"][i],
        "tags": ["tagA", "tagB"][i % 2]
    })

test_pull_filter("channel", "channel1")
test_pull_filter("logId", "") 
test_pull_filter("ip", "127.0.0.1")
test_pull_filter("logLevel", "warn")
test_pull_filter("messageContains", "message")
test_pull_filter("messageContains", "nomatch")

test_search_filter("channel", "channel1")
test_search_filter("logLevel", "warn")
test_search_filter("ip", "127.0.0.1")
test_search_filter("tags", "tagA")
test_search_filter("tags", "tagA,tagB")
test_search_filter("messageContains", "test")
test_search_filter("messageRegex", "^test message 0$")
test_search_filter("messageRegex", "[", expected_status=400)

test_search_filter("startDate", "2025-01-01T00:00:00Z")
test_search_filter("endDate", "2030-01-01T00:00:00Z")
test_search_filter("startDate", "bad-date", expected_status=400)
test_search_filter("endDate", "bad-date", expected_status=400)

test_search_filter("sortField", "timestamp")
test_search_filter("sortOrder", "desc")
test_search_filter("limit", "5")
test_search_filter("fields", "message,channel,logLevel")

print(f"\nWorking correctly: {passed}/{total} tests passed.")
