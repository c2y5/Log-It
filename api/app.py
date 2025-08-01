from flask import Flask, request, jsonify
from pymongo import MongoClient
from dotenv import load_dotenv
import os
from datetime import datetime, timezone, timedelta
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

app = Flask(__name__)
load_dotenv()

mongoClient = MongoClient(os.getenv("MONGO_URI"))
db = mongoClient["logit-dev-19382"]
devKeys = db["devKeys"]
logDb = db["logs"]

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
        authHeader = request.headers.get("Authorization")
        if not authHeader or not authHeader.startswith("Bearer "):
            return jsonify({"error": "Authorization header is required"}), 401
        
        token = authHeader.split(" ")[1]

        try:
            decoded = jwt.decode(token, jwtSecret, algorithms=[jwtAlgo])
            request.publicDevKey = decoded.get("publicKey")
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    return decorated

### AUTH ENDPOINTS ###

@app.route("/auth/register", methods=["POST"])
def registerAuth():
    data = request.get_json()
    pwd = data.get("password")
    if not pwd:
        return jsonify({"error": "Password is required"}), 400
    
    pubDevKey = secrets.token_urlsafe(16)
    hashedPwd = generate_password_hash(pwd)

    result = devKeys.insert_one({"publicKey": pubDevKey, "hashedPwd": hashedPwd})

    if not result.inserted_id:
        return jsonify({"error": "Failed to register for a dev key"}), 500
    
    payload = {
        "publicKey": pubDevKey,
        "hashedPwd": hashedPwd,
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
        "publicDevKey": pubDevKey,
        "hashedPwd": generate_password_hash(pwd),
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

    message = request.args.get("message")
    channel = request.args.get("channel")
    logLevel = request.args.get("logLevel", "info")
    if not message or not channel:
        return jsonify({"error": "Message and channel are required"}), 400

    log_entry = {
        "message": message,
        "ip": getIp(request),
        "logLevel": logLevel,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "channel": channel,
        "logId": secrets.token_urlsafe(12)[:16],
        "publicDevKey": pubDevKey
    }

    result = logDb.insert_one(log_entry)
    if result.inserted_id:
        return jsonify({"status": "success"}), 200
    else:
        return jsonify({"error": "Failed to log message"}), 500    

# TODO: make endpoint able to be accessed public but with limited info
# exclude ip, log id, channel
# remove filter ability for public
@app.route("/api/pull", methods=["GET"])
@authRequire
def pullLogs():
    if not devKeys.find_one({"publicKey": request.publicDevKey}):
        return jsonify({"error": "Invalid public dev key"}), 403

    channel = request.args.get("channel")
    logId = request.args.get("logId")
    ip = request.args.get("ip")
    logLevel = request.args.get("logLevel")
    page = request.args.get("page", 1, type=int)
    messageContains = request.args.get("messageContains", "")

    query = {"publicDevKey": request.publicDevKey}
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

    lg = {
        "_id": 0,
        "message": 1,
        "ip": 1,
        "logLevel": 1,
        "timestamp": 1,
        "channel": 1,
        "logId": 1
    }

    result_logs = list(logDb.find(query, lg).sort("timestamp", -1).skip((page - 1) * 100).limit(100))

    return jsonify({"publicKey": request.publicDevKey, "page": page, "logs": result_logs}), 200

@app.route("/api/edit", methods=["PUT"])
@authRequire
def editLog():
    if not devKeys.find_one({"publicKey": request.publicDevKey}):
        return jsonify({"error": "Invalid public dev key"}), 403

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
    if not devKeys.find_one({"publicKey": request.publicDevKey}):
        return jsonify({"error": "Invalid public dev key"}), 403
    
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
    if not devKeys.find_one({"publicKey": request.publicDevKey}):
        return jsonify({"error": "Invalid public dev key"}), 403
    
    result = logDb.delete_many({"publicDevKey": request.publicDevKey})
    if result.deleted_count > 0:
        return jsonify({"status": "success", "deletedCount": result.deleted_count}), 200
    else:
        return jsonify({"error": "No logs found to delete"}), 404

### SOME OTHER STUFF ###

@app.route("/stats", methods=["GET"])
def stats():
    total_logs = logDb.count_documents({})
    total_devs = devKeys.count_documents({})
    return jsonify({
        "totalLogs": total_logs,
        "totalDevs": total_devs
    }), 200

@app.route("/subscribe", methods=["POST"])
def subscribeLog():
    # live update log?
    data = request.get_json()
    raise NotImplementedError

if __name__ == "__main__":
    app.run(debug=True, port=5000)