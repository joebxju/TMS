import os
import json
import datetime
import pytz
import re
from functools import wraps
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from supabase import create_client, Client
from supabase.lib.client_options import ClientOptions
import jwt
import smtplib
from email.message import EmailMessage
from gotrue.errors import AuthApiError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from flask_cors import CORS
from celery import Celery

# Load environment variables
load_dotenv()

# Initialize Flask
app = Flask(__name__)
CORS(app, resources={r"/": {"origins": ""}}, supports_credentials=True)

# ================== CELERY SETUP ==================
celery = Celery(
    app.name,
    broker=os.getenv("REDIS_URL"),
    backend=os.getenv("REDIS_URL")
)
celery.conf.update(task_track_started=True)

# ================== HEALTH CHECK ENDPOINT ==================
@app.route("/health")
def health_check():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.datetime.now(pytz.timezone("Asia/Kolkata")).isoformat(),
        "service": "Security Monitoring System",
        "version": "1.0.0"
    })

# ================== CONFIGURATION VALUES ==================
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE")
JWT_SECRET = os.getenv("JWT_SECRET")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
LOCAL_TZ = pytz.timezone("Asia/Kolkata")
LOGIN_ATTEMPT_THRESHOLD = 3
BLOCK_DURATION_MINUTES = 1

# ================== SUPABASE INITIALIZATION ==================
try:
    supabase_client: Client = create_client(
        SUPABASE_URL,
        SUPABASE_KEY,
        options=ClientOptions(postgrest_client_timeout=10))
    print("✅ Supabase client initialized successfully")
except Exception as e:
    print(f"❌ Supabase initialization failed: {str(e)}")
    exit(1)

# ================== RATE LIMITER ==================
limiter = Limiter(
    app=app,
    key_func=lambda: request.headers.get("X-Forwarded-For", request.remote_addr),
    default_limits=["200 per day", "50 per hour"]
)

# ================== SECURITY PATTERNS ==================
attack_signatures = {
    "SQL Injection": [
        re.compile(pattern, re.IGNORECASE) for pattern in [
            r"select.*from", r"union.*select", r"drop\s+table", r"' OR 1=1 --"
        ]
    ],
    "XSS Attack": [
        re.compile(pattern, re.IGNORECASE) for pattern in [
            r"<script>.*</script>", r"onerror=", r"javascript:", r"eval\("
        ]
    ],
    "Command Injection": [
        re.compile(pattern, re.IGNORECASE) for pattern in [
            r";\s*(rm|ls|cat)", r"&\s*(ls|pwd)", r"\|\s*(whoami|id)", r"(wget|curl)\s"
        ]
    ],
    "Path Traversal": [
        re.compile(pattern, re.IGNORECASE) for pattern in [r"\.\./"]
    ],
    "Remote File Inclusion": [
        re.compile(pattern, re.IGNORECASE) for pattern in [r"https?://.*"]
    ],
    "Local File Inclusion": [
        re.compile(pattern, re.IGNORECASE) for pattern in [r"file://", r"php://"]
    ],
    "NoSQL Injection": [
        re.compile(pattern, re.IGNORECASE) for pattern in [r"\$ne", r"\$gt", r"\$lt"]
    ]
}

def detect_intrusion(input_str):
    if not input_str:
        return None
    input_str = str(input_str)
    for attack_type, patterns in attack_signatures.items():
        for pattern in patterns:
            if pattern.search(input_str):
                return attack_type
    return None

# ================== JWT VALIDATION ==================
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "Authorization token missing"}), 401
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user = decoded
            return f(*args, **kwargs)
        except Exception as e:
            print(f"JWT Validation Error: {e}")
            return jsonify({"error": "Invalid token"}), 401
    return decorated

# ================== ASYNC EMAIL TASK ==================
@celery.task
def send_async_email(subject, body):
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = ADMIN_EMAIL
        msg["To"] = ADMIN_EMAIL
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(ADMIN_EMAIL, EMAIL_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email Error: {e}")
        return False

# ================== API LOGGING MIDDLEWARE ==================
@app.before_request
def log_api_request():
    try:
        if request.method == "OPTIONS":
            return jsonify({"status": "ok"}), 200
            
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        data = {
            "ip_address": ip_address.split(",")[0].strip() if "," in ip_address else ip_address,
            "endpoint": request.path,
            "method": request.method,
            "timestamp": datetime.datetime.now(LOCAL_TZ).isoformat(),
            "request_data": dict(request.args) if request.method == "GET" else "*"
        }
        supabase_client.table("api_calls").insert(data).execute()
    except Exception as e:
        print(f"API Logging Error: {e}")

# ================== BLOCKING SYSTEM ==================
def unblock_expired_users():
    try:
        now = datetime.datetime.now(LOCAL_TZ)
        result = supabase_client.table("blocked_users").select("*").execute()
        for entry in result.data:
            unblock_at = datetime.datetime.fromisoformat(entry["unblock_at"])
            if unblock_at < now:
                supabase_client.table("blocked_users").delete().eq("id", entry["id"]).execute()
        print(f"Unblocking check completed at {now.isoformat()}")
    except Exception as e:
        print(f"Unblock Error: {e}")

scheduler = BackgroundScheduler()
scheduler.add_job(unblock_expired_users, 'interval', minutes=1)
scheduler.start()

def block_user(email, ip_address, reason="Brute-force detected"):
    try:
        block_until = datetime.datetime.now(LOCAL_TZ) + datetime.timedelta(minutes=BLOCK_DURATION_MINUTES)
        user_id = None
        
        email_body = f"""🚨 Security Alert: {reason}
        Email: {email}
        IP Address: {ip_address}
        Blocked Until: {block_until.strftime('%Y-%m-%d %H:%M:%S')}"""
        send_async_email.delay(f"🚨 {reason} Detected", email_body)

        try:
            user = supabase_client.auth.admin.get_user_by_email(email)
            user_id = user.user.id if user and hasattr(user, 'user') else None
        except Exception as e:
            print(f"User lookup error: {e}")

        supabase_client.table("blocked_users").insert([{
            "user_id": user_id,
            "email": email,
            "ip_address": ip_address,
            "blocked_at": datetime.datetime.now(LOCAL_TZ).isoformat(),
            "unblock_at": block_until.isoformat(),
            "reason": reason
        }]).execute()

        supabase_client.table("intrusion_alerts").insert([{
            "user_id": user_id,
            "ip_address": ip_address,
            "attack_type": reason,
            "timestamp": datetime.datetime.now(LOCAL_TZ).isoformat(),
            "status": "New",
            "extra_info": {"email": email, "block_until": block_until.isoformat()}
        }]).execute()

    except Exception as e:
        print(f"Block User Error: {e}")

# ================== STATIC FILES ==================
@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/<path:path>")
def static_files(path):
    return app.send_static_file(path)

# ================== MAIN ENDPOINTS ==================
@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"error": "Invalid request format"}), 400

        email = data['email'].strip().lower()
        password = data['password'].strip()
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        timestamp = datetime.datetime.now(LOCAL_TZ).isoformat()
        user_id = None
        role = "user"

        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
            return jsonify({"error": "Invalid email format"}), 400

        try:
            blocked_check = supabase_client.table("blocked_users").select("*").or_(
                "email.eq.{},ip_address.eq.{}".format(f"'{email}'", f"'{ip_address}'")
            ).execute()
            if blocked_check.data:
                block_info = blocked_check.data[0]
                unblock_time = datetime.datetime.fromisoformat(block_info["unblock_at"])
                time_remaining = (unblock_time - datetime.datetime.now(LOCAL_TZ)).total_seconds() / 60
                return jsonify({
                    "error": "You are blocked", 
                    "message": f"Your account or IP has been temporarily blocked due to security concerns. Please try again in {int(time_remaining) + 1} minutes."
                }), 403
        except Exception as e:
            print(f"Blocked users check failed: {str(e)}")
            return jsonify({"error": "Service unavailable"}), 500

        attack_type = detect_intrusion(email) or detect_intrusion(password)
        if attack_type:
            try:
                supabase_client.table("login_attempts").insert([{
                    "user_id": None,
                    "email": email,
                    "ip_address": ip_address,
                    "timestamp": timestamp,
                    "status": "failed"
                }]).execute()
            except Exception as e:
                print(f"Login attempt logging failed: {str(e)}")
            
            block_user(email, ip_address, f"{attack_type} detected")
            return jsonify({"error": "Suspicious activity detected"}), 403

        try:
            time_threshold = (datetime.datetime.now(LOCAL_TZ) - datetime.timedelta(minutes=10)).isoformat()
            failed_attempts = supabase_client.table("login_attempts").select(
                "id", count="exact"
            ).eq("email", email).eq("status", "failed").gte("timestamp", time_threshold).execute()
            
            if failed_attempts.count >= LOGIN_ATTEMPT_THRESHOLD:
                block_user(email, ip_address, "Brute-force detected")
                return jsonify({"error": "Too many failed attempts"}), 403
        except Exception as e:
            print(f"Failed attempts query error: {e}")
            return jsonify({"error": "Service unavailable"}), 500

        try:
            response = supabase_client.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            user_id = response.user.id
            
            role_data = supabase_client.table("user_roles").select("role").eq("user_id", user_id).execute()
            if not role_data.data:
                role = "user"
            else:
                role = role_data.data[0]["role"].strip().capitalize()
            
            token = jwt.encode({
                "user_id": user_id,
                "email": email,
                "role": role,
                "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            }, JWT_SECRET, algorithm="HS256")
            
            status = "success"
            message = "Login successful"
            code = 200
            
        except AuthApiError:
            status = "failed"
            message = "Invalid credentials"
            code = 401
        except Exception as e:
            return jsonify({"error": "Authentication service unavailable"}), 500

        try:
            supabase_client.table("login_attempts").insert([{
                "user_id": user_id,
                "email": email,
                "ip_address": ip_address,
                "timestamp": timestamp,
                "status": status
            }]).execute()
        except Exception as e:
            print(f"Login attempt logging failed: {str(e)}")

        return jsonify({
            "message": message,
            "user_id": user_id,
            "token": token if status == "success" else None
        }), code
    except Exception as e:
        print(f"💥 Critical login error: {str(e)}") 
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Internal server error"}), 500

# ================== USER ENDPOINTS ==================
@app.route("/user/login_attempts")
@jwt_required
def get_user_login_attempts():
    try:
        user_email = request.user.get("email")
        result = supabase_client.table("login_attempts").select("*").eq("email", user_email).execute()
        return jsonify(result.data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ================== ADMIN ENDPOINTS ==================
@app.route("/admin/logs")
@jwt_required
def get_security_logs():
    try:
        if request.user.get("role") != "Admin":
            return jsonify({"error": "Unauthorized access"}), 403
            
        logs = supabase_client.table("intrusion_alerts").select("*").execute()
        return jsonify(logs.data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/login_attempts")
@jwt_required
def get_login_attempts():
    try:
        if request.user.get("role") != "Admin":
            return jsonify({"error": "Unauthorized access"}), 403
            
        attempts = supabase_client.table("login_attempts").select("*").execute()
        return jsonify(attempts.data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/blocked_users")
@jwt_required
def get_blocked_users():
    try:
        if request.user.get("role") != "Admin":
            return jsonify({"error": "Unauthorized access"}), 403
            
        blocked = supabase_client.table("blocked_users").select("*").execute()
        return jsonify(blocked.data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/api_calls")
@jwt_required
def get_api_calls():
    try:
        if request.user.get("role") != "Admin":
            return jsonify({"error": "Unauthorized access"}), 403
            
        api_calls = supabase_client.table("api_calls").select("*").execute()
        return jsonify(api_calls.data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/test-attacks")
def test_attack_detection():
    tests = {
        "SQL Injection": "' OR 1=1 --",
        "XSS": "<script>alert(1)</script>",
        "Command Injection": "; rm -rf /",
        "NoSQL Injection": '{"$gt": ""}'
    }
    results = {test: bool(detect_intrusion(payload)) for test, payload in tests.items()}
    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)