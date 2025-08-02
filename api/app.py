from flask import Flask, request, jsonify, send_from_directory, Response
from pymongo import MongoClient
from dotenv import load_dotenv
import os
from datetime import datetime, timezone, timedelta
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
import yaml
import csv
import io
from flask_cors import CORS
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests
from dateutil import parser as date_parser
import re

app = Flask(__name__)
CORS(app, supports_credentials=True, expose_headers=["LogIt-Authorization"], allow_headers=["LogIt-Authorization", "Content-Type"])
load_dotenv()

with open(os.path.join(os.path.dirname(__file__), "api.yml"), "r") as f:
    swaggerTemplate = yaml.safe_load(f)

mongoClient = MongoClient(os.getenv("MONGO_URI"))
mongodb = mongoClient["logit-dev-19382"]
devKeys = mongodb["devKeys"]
logDb = mongodb["logs"]

jwtSecret = os.getenv("JWT_SECRET")
jwtAlgo = "HS256"
jwtExp = 60 * 60

def getIp(r):
    if r.headers.getlist("X-Forwarded-For"):
        ip = r.headers.getlist("X-Forwarded-For")[0].split(",")[0]
    else:
        ip = r.remote_addr

    return ip

def authRequire(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        authHeader = request.headers.get("LogIt-Authorization")
        if not authHeader:
            return jsonify({"error": "Authorization header is required"}), 401
        
        if authHeader.startswith("Bearer "):
            token = authHeader.split(" ")[1]
        else:
            token = authHeader

        try:
            decoded = jwt.decode(token, jwtSecret, algorithms=[jwtAlgo])
            savedHashedPwd = devKeys.find_one({"publicKey": decoded.get("publicKey")}, {"hashedPwd": 1})
            if not savedHashedPwd:
                return jsonify({"error": "Invalid public dev key"}), 403

            try:
                decodedPwd = decrypt(base64.b64decode(decoded.get("pwd")), jwtSecret).decode()
            except Exception as e:
                return jsonify({"error": "Failed to decrypt password"}), 403

            if not check_password_hash(savedHashedPwd.get("hashedPwd"), decodedPwd):
                return jsonify({"error": "Invalid password"}), 403
            
            request.publicDevKey = decoded.get("publicKey")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    return decorated

def isIpBlacklisted(ip, publicDevKey):
    dev = devKeys.find_one({"publicKey": publicDevKey}, {"blacklistedIps": 1})
    if dev and "blacklistedIps" in dev:
        return ip in dev["blacklistedIps"]

    return False

def isOriginAllowed(publicDevKey, request):
    origin = request.headers.get("Origin")
    if not origin:
        return True
    
    dev = devKeys.find_one({"publicKey": publicDevKey}, {"allowedOrigins": 1})
    if not dev:
        return False
    
    allowed = dev.get("allowedOrigins", [])
    return "*" in allowed or origin in allowed

def encrypt(input_bytes, key):
    if isinstance(key, str):
        key = key.encode()
    key = key.ljust(32, b'\0')[:32]
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted = encryptor.update(input_bytes) + encryptor.finalize()
    return iv + encrypted

def decrypt(encrypted_bytes, key):
    if isinstance(key, str):
        key = key.encode()
    key = key.ljust(32, b'\0')[:32]

    iv = encrypted_bytes[:16]
    actual_encrypted = encrypted_bytes[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    return decryptor.update(actual_encrypted) + decryptor.finalize()

### AUTH ENDPOINTS ###

@app.route("/auth/register", methods=["POST"])
def registerAuth():
    data = request.get_json()
    pwd = data.get("password")
    pubView = data.get("publicView")
    if not pwd or not isinstance(pubView, bool) or pubView is None:
        return jsonify({"error": "Password & public view is required"}), 400
    
    pubDevKey = secrets.token_urlsafe(16)
    hashedPwd = generate_password_hash(pwd)

    result = devKeys.insert_one({"publicKey": pubDevKey, "hashedPwd": hashedPwd, "publicView": pubView, "allowedOrigins": [], "blacklistedIps": [], "webhookUrl": None})

    if not result.inserted_id:
        return jsonify({"error": "Failed to register for a dev key"}), 500
    
    payload = {
        "publicKey": pubDevKey,
        "pwd": base64.b64encode(encrypt(pwd.encode(), jwtSecret)).decode(),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=jwtExp)
    }

    token = jwt.encode(payload, jwtSecret, algorithm=jwtAlgo)

    return jsonify({
        "publicKey": pubDevKey,
        "token": token
    }), 201

@app.route("/auth/login", methods=["POST"])
def loginAuth():
    data = request.get_json()
    pubDevKey = data.get("publicKey")
    pwd = data.get("password")
    if not pubDevKey or not pwd:
        return jsonify({"error": "Public key and password are required"}), 400
    
    dev = devKeys.find_one({"publicKey": pubDevKey})
    if not dev:
        return jsonify({"error": "Invalid public key"}), 403
    
    hashed = dev.get("hashedPwd")
    if not hashed or not check_password_hash(hashed, pwd):
        return jsonify({"error": "Invalid password"}), 403

    payload = {
        "publicKey": pubDevKey,
        "pwd": base64.b64encode(encrypt(pwd.encode(), jwtSecret)).decode(),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=jwtExp)
    }

    token = jwt.encode(payload, jwtSecret, algorithm=jwtAlgo)

    return jsonify({"token": token}), 200

### LOG ENDPOINTS ###

@app.route("/api/log", methods=["GET"])
def logMessage():
    pubDevKey = request.args.get("key")
    if not pubDevKey:
        return jsonify({"error": "Missing public dev key"}), 403

    if not devKeys.find_one({"publicKey": pubDevKey}):
        return jsonify({"error": "Invalid public dev key"}), 403
    
    if isIpBlacklisted(getIp(request), pubDevKey):
        return jsonify({"error": "Your IP is blacklisted"}), 403
    
    if not isOriginAllowed(pubDevKey, request):
        return jsonify({"error": "Origin not allowed"}), 403

    message = request.args.get("message")
    channel = request.args.get("channel")
    logLevel = request.args.get("logLevel", "info")
    tags = request.args.getlist("tags")
    environment = request.args.get("environment", "prod")

    if not message or not channel:
        return jsonify({"error": "Message and channel are required"}), 400

    log_entry = {
        "message": message,
        "ip": getIp(request),
        "logLevel": logLevel,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channel": channel,
        "logId": secrets.token_urlsafe(12)[:16],
        "publicDevKey": pubDevKey,
        "tags": tags if tags else [],
        "environment": environment
    }

    webhookUrl = devKeys.find_one({"publicKey": pubDevKey}, {"webhookUrl": 1}).get("webhookUrl")
    if webhookUrl:
        try:
            discord_payload = {
                "embeds": [
                    {
                        "title": f"📜 Log from {channel}",
                        "color": 0x3498db,
                        "fields": [
                            {"name": "Message", "value": message, "inline": False},
                            {"name": "Log Level", "value": logLevel, "inline": True},
                            {"name": "IP", "value": log_entry["ip"], "inline": True},
                            {"name": "Log ID", "value": log_entry["logId"], "inline": False}
                        ],
                        "footer": {"text": f"Public Key: {pubDevKey}"},
                        "timestamp": log_entry["timestamp"]
                    }
                ]
            }

            requests.post(webhookUrl, json=discord_payload)
        except requests.RequestException as e:
            print(f"Failed to send webhook: {e}")

    result = logDb.insert_one(log_entry)
    if result.inserted_id:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"error": "Failed to log message"}), 500    

@app.route("/api/log/bulk", methods=["POST"])
def bulkLogMessages():
    pubDevKey = request.args.get("key")
    if not pubDevKey:
        return jsonify({"error": "Missing public dev key"}), 403

    if not devKeys.find_one({"publicKey": pubDevKey}):
        return jsonify({"error": "Invalid public dev key"}), 403
    
    if isIpBlacklisted(getIp(request), pubDevKey):
        return jsonify({"error": "Your IP is blacklisted"}), 403
    
    if not isOriginAllowed(pubDevKey, request):
        return jsonify({"error": "Origin not allowed"}), 403

    data = request.get_json()
    if not isinstance(data, list) or not data:
        return jsonify({"error": "Data must be a JSON array and not empty"}), 400
    
    logsInsert = []

    for entry in data:
        message = entry.get("message")
        channel = entry.get("channel")
        logLevel = entry.get("logLevel", "info")
        tags = entry.get("tags", [])
        environment = entry.get("environment", "prod")

        if not message or not channel:
            return jsonify({"error": "Each entry must have a message and channel"}), 400
        
        log_entry = {
            "message": message,
            "ip": getIp(request),
            "logLevel": logLevel,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "channel": channel,
            "logId": secrets.token_urlsafe(12)[:16],
            "publicDevKey": pubDevKey,
            "tags": tags if tags else [],
            "environment": environment
        }

        logsInsert.append(log_entry)

    result = logDb.insert_many(logsInsert)
    if result.inserted_ids:
        return jsonify({"status": "success", "insertedCount": len(result.inserted_ids)}), 200
    
    return jsonify({"error": "Failed to log messages"}), 500

@app.route("/api/pull", methods=["GET"])
def pullLogs():
    hasAuth = False

    authHeader = request.headers.get("LogIt-Authorization")
    if authHeader:
        hasAuth = True
        if authHeader.startswith("Bearer "):
            token = authHeader.split(" ")[1]
        else:
            token = authHeader
        
        try:
            decoded = jwt.decode(token, jwtSecret, algorithms=[jwtAlgo])
            savedHashedPwd = devKeys.find_one({"publicKey": decoded.get("publicKey")}, {"hashedPwd": 1})
            if not savedHashedPwd:
                return jsonify({"error": "Invalid public dev key"}), 403
            try:
                decodedPwd = decrypt(base64.b64decode(decoded.get("pwd")), jwtSecret).decode()
            except Exception as e:
                return jsonify({"error": "Failed to decrypt password"}), 403
            if not check_password_hash(savedHashedPwd.get("hashedPwd"), decodedPwd):
                return jsonify({"error": "Invalid password"}), 403
            request.publicDevKey = decoded.get("publicKey")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

    if not hasAuth:
        pubKey = request.args.get("key")
        if not pubKey:
            return jsonify({"error": "Missing public dev key"}), 403
        
        if not devKeys.find_one({"publicKey": pubKey}):
            return jsonify({"error": "Invalid public dev key"}), 403
        request.publicDevKey = pubKey

    if isIpBlacklisted(getIp(request), request.publicDevKey) and not hasAuth:
        return jsonify({"error": "Your IP is blacklisted"}), 403

    result = devKeys.find_one({"publicKey": request.publicDevKey}, {"publicView": 1})
    publicView = result.get("publicView", False)

    if not publicView and not hasAuth:
        return jsonify({"error": "Public view is disabled for this key"}), 403

    page = request.args.get("page", 1, type=int)

    query = {"publicDevKey": request.publicDevKey}

    if hasAuth:
        channel = request.args.get("channel")
        logId = request.args.get("logId")
        ip = request.args.get("ip")
        logLevel = request.args.get("logLevel")
        messageContains = request.args.get("messageContains", "")

        if channel:
            query["channel"] = channel

        if logId:
            query["logId"] = logId

        if ip:
            query["ip"] = ip

        if logLevel:
            query["logLevel"] = logLevel

        if messageContains:
            query["message"] = {"$regex": messageContains, "$options": "i"}

        projection = {
            "_id": 0,
            "message": 1,
            "ip": 1,
            "logLevel": 1,
            "timestamp": 1,
            "channel": 1,
            "logId": 1,
            "environment": 1
        }

        logs = list(logDb.find(query, projection).sort("timestamp", -1).skip((page - 1) * 100).limit(100))

        return jsonify({
            "publicKey": request.publicDevKey,
            "page": page,
            "logs": logs
        }), 200

    else:
        projection = {
            "_id": 0,
            "message": 1,
            "ip": 1,
            "logLevel": 1,
            "timestamp": 1,
            "channel": 1,
            "logId": 1,
            "environment": 1
        }
        logs = list(logDb.find(query, projection).sort("timestamp", -1).skip((page - 1) * 100).limit(100))

        for log in logs:
            log["ip"] = "***"
            log["logId"] = "***"
            log["channel"] = "***"

        return jsonify({
            "publicKey": request.publicDevKey,
            "page": page,
            "logs": logs
        }), 200
    
@app.route("/api/logs/search", methods=["GET"])
@authRequire
def searchLogs():
    query = {"publicDevKey": request.publicDevKey}

    def multValueFilter(param_name):
        values = request.args.get(param_name)
        if values:
            values_list = [v.strip() for v in values.split(",") if v.strip()]
            if len(values_list) == 1:
                query[param_name] = values_list[0]
            else:
                query[param_name] = {"$in": values_list}

    multValueFilter("channel")
    multValueFilter("logLevel")
    multValueFilter("ip")

    environment = request.args.get("environment")
    if environment:
        query["environment"] = environment

    tags = request.args.get("tags")
    if tags:
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
        query["tags"] = {"$all": tag_list}

    messageContains = request.args.get("messageContains")
    if messageContains:
        query["message"] = {"$regex": messageContains, "$options": "i"}

    messageRegex = request.args.get("messageRegex")
    caseSensitive = request.args.get("caseSensitive", "false").lower() == "true"
    if messageRegex:
        try:
            flags = 0 if caseSensitive else re.IGNORECASE
            re.compile(messageRegex, flags)
            query["message"] = {"$regex": messageRegex, "$options": "" if caseSensitive else "i"}
        except re.error:
            projection = {
                "_id": 0,
                "message": 1,
                "ip": 1,
                "logLevel": 1,
                "timestamp": 1,
                "channel": 1,
                "logId": 1,
                "environment": 1
            }
            return jsonify({
                "publicKey": request.publicDevKey,
                "page": 1,
                "limit": 0,
                "filtersApplied": query,
                "returnedFields": list(projection.keys()),
                "logs": [],
            }), 400

    startDate = request.args.get("startDate")
    endDate = request.args.get("endDate")
    if startDate or endDate:
        time_filter = {}
        try:
            if startDate:
                time_filter["$gte"] = date_parser.parse(startDate).isoformat()
            if endDate:
                time_filter["$lte"] = date_parser.parse(endDate).isoformat()
            query["timestamp"] = time_filter
        except Exception:
            projection = {
                "_id": 0,
                "message": 1,
                "ip": 1,
                "logLevel": 1,
                "timestamp": 1,
                "channel": 1,
                "logId": 1,
                "environment": 1
            }
            return jsonify({
                "publicKey": request.publicDevKey,
                "page": 1,
                "limit": 0,
                "filtersApplied": query,
                "returnedFields": list(projection.keys()),
                "logs": []
            }), 400

    page = max(1, request.args.get("page", 1, type=int))
    limit = min(500, request.args.get("limit", 100, type=int))

    sortField = request.args.get("sortField", "timestamp")
    sortOrder = request.args.get("sortOrder", "desc").lower()
    sortDir = -1 if sortOrder == "desc" else 1

    fields = request.args.get("fields")
    if fields:
        projection = {f.strip(): 1 for f in fields.split(",") if f.strip()}
        projection["_id"] = 0
    else:
        projection = {
            "_id": 0,
            "message": 1,
            "ip": 1,
            "logLevel": 1,
            "timestamp": 1,
            "channel": 1,
            "logId": 1,
            "environment": 1
        }

    logs = list(
        logDb.find(query, projection).sort(sortField, sortDir).skip((page - 1) * limit).limit(limit)
    )

    return jsonify({
        "publicKey": request.publicDevKey,
        "page": page,
        "limit": limit,
        "sortField": sortField,
        "sortOrder": sortOrder,
        "filtersApplied": query,
        "returnedFields": list(projection.keys()),
        "logs": logs if logs else []
    }), 200

@app.route("/api/edit", methods=["PUT"])
@authRequire
def editLog():
    data = request.get_json()
    logId = data.get("logId")
    newMessage = data.get("newMessage")
    if not logId or not newMessage:
        return jsonify({"error": "Log ID and new message are required"}), 400

    result = logDb.update_one(
        {"logId": logId, "publicDevKey": request.publicDevKey},
        {"$set": {"message": newMessage}}
    )

    if result.modified_count > 0:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"error": "Failed to update log or log not found"}), 404

@app.route("/api/delete", methods=["DELETE"])
@authRequire
def deleteLog():
    data = request.get_json()
    logId = data.get("logId")
    if not logId:
        return jsonify({"error": "Log ID is required"}), 400
    
    result = logDb.delete_one({"logId": logId, "publicDevKey": request.publicDevKey})
    if result.deleted_count > 0:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"error": "Failed to delete log or log not found"}), 404
    
@app.route("/api/clear", methods=["DELETE"])
@authRequire
def clearLogs():
    result = logDb.delete_many({"publicDevKey": request.publicDevKey})
    if result.deleted_count > 0:
        return jsonify({"status": "success", "deletedCount": result.deleted_count}), 200
    else:
        return jsonify({"error": "No logs found to delete"}), 404

@app.route("/api/export", methods=["GET"])
@authRequire
def exportLogs():
    format = request.args.get("format", "json").lower()
    query = {"publicDevKey": request.publicDevKey}

    lg = {
        "_id": 0,
        "message": 1,
        "ip": 1,
        "logLevel": 1,
        "timestamp": 1,
        "channel": 1,
        "logId": 1
    }

    _logs = list(logDb.find(query, lg))

    if len(_logs) == 0:
        return jsonify({"error": "No logs found"}), 404

    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=_logs[0].keys())
        writer.writeheader()
        writer.writerows(_logs)
        return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=logs-{request.publicDevKey}.csv"})

    return jsonify(_logs)

### IP STUFF ###
@app.route("/api/blacklist/add", methods=["POST"])
@authRequire
def addIpBlacklist():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP address is required"}), 400
    
    result = devKeys.update_one({"publicKey": request.publicDevKey}, {"$addToSet": {"blacklist": ip}})

    if result.modified_count > 0:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"error": "Failed to add IP to blacklist or IP already exists"}), 400

@app.route("/api/blacklist/remove", methods=["POST"])
@authRequire
def removeIpBlacklist():
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "IP address is required"}), 400
    
    result = devKeys.update_one({"publicKey": request.publicDevKey}, {"$pull": {"blacklist": ip}})
    if result.modified_count > 0:
        return jsonify({"status": "IP removed from blacklist"}), 200
    else:
        return jsonify({"error": "Failed to remove IP from blacklist or IP not found"}), 400
    
@app.route("/api/blacklist/list", methods=["GET"])
@authRequire
def listIpBlacklist():
    result = devKeys.find_one({"publicKey": request.publicDevKey}, {"blacklist": 1})
    if result and "blacklist" in result:
        return jsonify({"blacklist": result["blacklist"]}), 200
    else:
        return jsonify({"blacklist": []}), 200

### ORIGIN ALLOW LIST ###

@app.route("/api/origin/add", methods=["POST"])
@authRequire
def addOriginAllowList():
    data = request.get_json()
    origin = data.get("origin")

    if not origin:
        return jsonify({"error": "Origin is required"}), 400
    
    if not origin.startswith("http://") and not origin.startswith("https://"):
        return jsonify({"error": "Origin must start with http:// or https://"}), 400
    
    result = devKeys.update_one({"publicKey": request.publicDevKey}, {"$addToSet": {"allowedOrigins": origin}})

    if result.modified_count > 0:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"error": "Failed to add origin or origin already exists"}), 400
    
@app.route("/api/origin/remove", methods=["POST"])
@authRequire
def removeOriginAllowList():
    data = request.get_json()
    origin = data.get("origin")

    if not origin:
        return jsonify({"error": "Origin is required"}), 400
    
    if not origin.startswith("http://") and not origin.startswith("https://"):
        return jsonify({"error": "Origin must start with http:// or https://"}), 400
    
    result = devKeys.update_one({"publicKey": request.publicDevKey}, {"$pull": {"allowedOrigins": origin}})
    
    if result.modified_count > 0:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"error": "Failed to remove origin or origin not found"}), 400
    
@app.route("/api/origin/list", methods=["GET"])
@authRequire
def listOriginAllowList():
    result = devKeys.find_one({"publicKey": request.publicDevKey}, {"allowedOrigins": 1})
    if result and "allowedOrigins" in result:
        return jsonify({"allowedOrigins": result["allowedOrigins"]}), 200
    else:
        return jsonify({"allowedOrigins": []}), 200

### SOME OTHER STUFF ###

@app.route("/openapi.json")
def openapiJson():
    return jsonify(swaggerTemplate)

@app.route("/")
def swaggerUI():
    swagger_dir = os.path.join(app.root_path, "../static/swagger")
    return send_from_directory(swagger_dir, "index.html")

@app.route("/<path:path>")
def swagger_static(path):
    swagger_dir = os.path.join(app.root_path, "../static/swagger")
    return send_from_directory(swagger_dir, path)

@app.route("/stats", methods=["GET"])
def stats():
    total_logs = logDb.count_documents({})
    total_devs = devKeys.count_documents({})
    return jsonify({
        "totalLogs": total_logs,
        "totalDevKeys": total_devs
    }), 200

@app.route("/webhook_setup", methods=["POST"])
@authRequire
def webhookSetup():
    data = request.get_json()
    if "webhookUrl" not in data:
        return jsonify({"error": "Webhook URL is required"}), 400
    
    webhookUrl = data["webhookUrl"]
    if not webhookUrl.startswith("http://") and not webhookUrl.startswith("https://"):
        return jsonify({"error": "URL must start with http:// or https://"}), 400
    
    if not webhookUrl.startswith("https://discord.com/api/webhooks/"):
        return jsonify({"error": "Only discord webhook is currently supported"}), 400
    
    devKeys.update_one({"publicKey": request.publicDevKey}, {"$set": {"webhookUrl": webhookUrl}})

    return jsonify({"status": "Webhook URL set successfully"}), 200

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Forbidden"}), 403

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "Unauthorized"}), 401

if __name__ == "__main__":
    app.run(debug=True, port=5000)