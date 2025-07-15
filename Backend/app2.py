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

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/": {"origins": ""}}, supports_credentials=True)

# Update Celery configuration
celery = Celery(
    'app1',  # Change this to match your module name
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)
celery.conf.update(
    task_track_started=True,
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Asia/Kolkata',
    enable_utc=True,
    broker_connection_retry_on_startup=True
)

# Make sure Flask app knows about Celery
app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

# Configuration constants
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE")
JWT_SECRET = os.getenv("JWT_SECRET")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
LOCAL_TZ = pytz.timezone("Asia/Kolkata")
LOGIN_ATTEMPT_THRESHOLD = 3
BLOCK_DURATION_MINUTES = 1

# Initialize Supabase client
try:
    supabase_client: Client = create_client(
        SUPABASE_URL,
        SUPABASE_KEY,
        options=ClientOptions(
            postgrest_client_timeout=10,
            schema="public"
        )
    )
    print("✅ Supabase client initialized successfully")
except Exception as e:
    print(f"❌ Supabase initialization failed: {str(e)}")
    exit(1)

# Rate limiter configuration
limiter = Limiter(
    app=app,
    key_func=lambda: request.headers.get("X-Forwarded-For", request.remote_addr),
    default_limits=["200 per day", "50 per hour"]
)

# Attack signature patterns
attack_signatures = {
    "SQL Injection": [
        re.compile(pattern, re.IGNORECASE) for pattern in [
            # Existing patterns
            r"select.*from",
            r"union.*select", 
            r"drop\s+table", 
            r"' OR 1=1 --",
            r"insert\s+into",
            r"delete\s+from",
            r"update\s+.*\s+set",
            r"exec\s*\(",
            r"xp_cmdshell",
            r"--\s*$",
            r"/\*.*\*/",
            r"benchmark\s*\(",
            r"sleep\s*\(",
            # New patterns
            r"alter\s+table",
            r"create\s+table",
            r"information_schema",
            r"sysobjects",
            r"substring\(",
            r"convert\(",
            r"concat\(",
            r"group\s+by",
            r"having\s+\d+=\d+",
            r"waitfor\s+delay",
            r"' OR '1'='1",
            r"1\s*=\s*1",
            r"LOAD_FILE\(",
            r"INTO\s+OUTFILE"
        ]
    ],
    "XSS Attack": [
        re.compile(pattern, re.IGNORECASE) for pattern in [
            # Existing patterns
            r"<script>.*</script>",
            r"onerror=",
            r"javascript:", 
            r"eval\(",
            r"<img[^>]*script",
            r"onload\s*=",
            r"onclick\s*=",
            r"onmouseover\s*=",
            r"document\.cookie",
            r"document\.write",
            r"<iframe[^>]*>",
            r"data:text/html",
            r"vbscript:",
            r"expression\s*\(",
            # New patterns
            r"<svg[^>]*>",
            r"<meta[^>]*>",
            r"<link[^>]*>",
            r"<style[^>]*>",
            r"<body[^>]*>",
            r"<form[^>]*>",
            r"<input[^>]*>",
            r"alert\(",
            r"prompt\(",
            r"confirm\(",
            r"onmouseenter\s*=",
            r"onfocus\s*=",
            r"onblur\s*=",
            r"base64,",
            r"&#x[0-9A-Fa-f]+",
            r"\\x[0-9A-Fa-f]{2}"
        ]
    ],
    "Command Injection": [
        re.compile(pattern, re.IGNORECASE) for pattern in [
            r";\s*(rm|ls|cat)",
            r"&\s*(ls|pwd)",
            r"\|\s*(whoami|id)",
            r"(wget|curl)\s",
            # Additional Command Injection patterns
            r"ping\s+-[tc]",
            r"nc\s+-[el]",
            r"netcat",
            r"telnet\s+",
            r"python\s+-c",
            r"bash\s+-[ci]",
            r"chmod\s+[0-7]{3,4}",
            r"chown\s+[a-zA-Z0-9]+:",
            r"nmap\s+-"
        ]
    ],
    "Path Traversal": [
        re.compile(pattern, re.IGNORECASE) for pattern in [
            r"\.\./",
            # Additional Path Traversal patterns
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e/",
            r"\.\.%2f",
            r"\\\.\.\\",
            r"/etc/passwd",
            r"c:\\windows\\",
            r"\.\.%5c"
        ]
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

# Update the celery task decorator (remove the duplicate decorator)
@celery.task(name='app1.send_async_email', bind=True, max_retries=3)
def send_async_email(self, subject, body, recipient_email=None):
    try:
        msg = EmailMessage()
        msg.set_content(body)
        msg["Subject"] = subject
        msg["From"] = ADMIN_EMAIL
        msg["To"] = recipient_email if recipient_email else ADMIN_EMAIL
        
        # Update SMTP configuration for better Gmail compatibility
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.ehlo()  # Add explicit EHLO
            server.login(ADMIN_EMAIL, EMAIL_PASSWORD)
            server.send_message(msg)
            print(f"✅ Email sent successfully to {msg['To']}")
        return True
    except Exception as e:
        print(f"❌ Email Error: {str(e)}")
        try:
            self.retry(countdown=60, exc=e)
        except self.MaxRetriesExceededError:
            print(f"❌ Max retries exceeded for email to {recipient_email}")
        return False

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
        result = supabase_client.table("api_calls").insert(data).execute()
        if hasattr(result, 'error') and result.error:
            print(f"API Logging Error: {result.error.message}")
    except Exception as e:
        print(f"API Logging Exception: {str(e)}")

def unblock_expired_users():
    try:
        # Change to use LOCAL_TZ for consistency
        now = datetime.datetime.now(LOCAL_TZ)
        result = supabase_client.table("blocked_users").select("*").execute()
        
        if not result.data:
            return
            
        for entry in result.data:
            try:
                unblock_at_str = entry["unblock_at"].replace('Z', '+00:00')
                # Convert to LOCAL_TZ for comparison
                unblock_at = datetime.datetime.fromisoformat(unblock_at_str).astimezone(LOCAL_TZ)
                if unblock_at < now:
                    delete_result = supabase_client.table("blocked_users").delete().eq("id", entry["id"]).execute()
                    if not delete_result.data:
                        print(f"Failed to unblock entry {entry['id']}")
                    else:
                        print(f"Unblocked {entry['email'] or entry['ip_address']} at {datetime.datetime.now(LOCAL_TZ).strftime('%I:%M %p IST, %d %b %Y')}")
            except Exception as e:
                print(f"Error processing block entry {entry['id']}: {str(e)}")
                
    except Exception as e:
        print(f"Unblock Error: {str(e)}")

scheduler = BackgroundScheduler()
scheduler.add_job(unblock_expired_users, 'interval', minutes=1)
scheduler.start()

def block_user(email, ip_address, reason="Brute-force detected"):
    try:
        block_until = datetime.datetime.now(LOCAL_TZ) + datetime.timedelta(minutes=BLOCK_DURATION_MINUTES)
        user_id = None
        
        # Admin email content
        admin_email_body = f"""🚨 Security Alert: {reason}
        
        Details:
        - Email: {email}
        - IP Address: {ip_address}
        - Blocked Until: {block_until.strftime('%Y-%m-%d %H:%M:%S')}
        - Timestamp: {datetime.datetime.now(LOCAL_TZ).strftime('%Y-%m-%d %H:%M:%S')}
        
        Action Required: Review this activity in the admin dashboard."""
        
        # User email content
        user_email_body = f"""⚠️ Your Account Security Alert
        
        We detected suspicious activity on your account:
        
        - Reason: {reason}
        - IP Address: {ip_address}
        - Blocked Until: {block_until.strftime('%Y-%m-%d %H:%M:%S')}
        - Timestamp: {datetime.datetime.now(LOCAL_TZ).strftime('%Y-%m-%d %H:%M:%S')}
        
        If you didn't perform this action:
        - Change your password immediately
        - Contact administrator at: {ADMIN_EMAIL}
        - Review your account security settings
        
        If this was you, please wait until the block expires.
        For immediate assistance, contact: {ADMIN_EMAIL}"""
        
        # Send to admin
        send_async_email.delay(subject=f"🚨 {reason} Detected", body=admin_email_body)
        
        # Try to send to user if email is valid
        if re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
            send_async_email.delay(subject="⚠️ Suspicious Activity Detected", body=user_email_body, recipient_email=email)

        # Get user by email
        try:
            # Change from auth.users to auth API
            response = supabase_client.auth.admin.list_users()
            user = next((u for u in response if u.email == email), None)
            if user:
                user_id = user.id
        except Exception as e:
            print(f"User lookup error: {str(e)}")

        # Block user data
        block_data = {
            "user_id": user_id,
            "email": email,
            "ip_address": ip_address,
            "blocked_at": datetime.datetime.now(LOCAL_TZ).isoformat(),
            "unblock_at": block_until.isoformat(),
            "reason": reason
        }

        # Intrusion alert data
        # Update alert_data structure
        alert_data = {
            "user_id": user_id,
            "ip_address": ip_address,
            "attack_type": reason,
            "timestamp": datetime.datetime.now(LOCAL_TZ).isoformat(),
            "status": "pending",
            "extra_info": {
                "email": email,
                "block_until": block_until.isoformat(),
                "admin_contact": ADMIN_EMAIL
            }
        }

        try:
            # Insert into blocked_users
            block_result = supabase_client.table("blocked_users").insert(block_data).execute()
            if hasattr(block_result, 'error'):
                print(f"Block insert error: {block_result.error}")

            # Insert into intrusion_alerts
            alert_result = supabase_client.table("intrusion_alerts").insert(alert_data).execute()
            if hasattr(alert_result, 'error'):
                print(f"Alert insert error: {alert_result.error}")

        except Exception as e:
            print(f"Database operation failed: {str(e)}")

    except Exception as e:
        print(f"Block User Exception: {e}")

@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/<path:path>")
def static_files(path):
    return app.send_static_file(path)

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
            
            if hasattr(blocked_check, 'error'):
                print(f"Blocked users check error: {blocked_check.error.message}")
                return jsonify({"error": "Service unavailable"}), 500
                
            if blocked_check.data:
                block_info = blocked_check.data[0]
                unblock_at_str = block_info["unblock_at"].replace('Z', '+00:00')
                unblock_at = datetime.datetime.fromisoformat(unblock_at_str)
                unblock_at_ist = unblock_at.astimezone(LOCAL_TZ)
                current_time = datetime.datetime.now(LOCAL_TZ)
                
                if unblock_at_ist > current_time:
                    time_remaining = (unblock_at_ist - current_time).total_seconds() / 60
                    return jsonify({
                        "error": "Account Blocked",
                        "message": f"Your account is temporarily blocked. Please try again in {int(time_remaining)+1} minutes."
                    }), 403
        except Exception as e:
            print(f"Blocked users check failed: {str(e)}")
            return jsonify({"error": "Service unavailable"}), 500

        attack_type = detect_intrusion(email) or detect_intrusion(password)
        if attack_type:
            try:
                login_attempt_result = supabase_client.table("login_attempts").insert([{
                    "user_id": None,
                    "email": email,
                    "ip_address": ip_address,
                    "timestamp": timestamp,
                    "status": "failed"
                }]).execute()
                if hasattr(login_attempt_result, 'error'):
                    print(f"Login Attempt Insert Error: {login_attempt_result.error.message}")
            except Exception as e:
                print(f"Login attempt logging failed: {str(e)}")
            
            block_user(email, ip_address, f"{attack_type} detected")
            return jsonify({"error": "Suspicious activity detected"}), 403

        try:
            time_threshold = (datetime.datetime.now(LOCAL_TZ) - datetime.timedelta(minutes=10)).isoformat()
            failed_attempts = supabase_client.table("login_attempts").select(
                "id", count="exact"
            ).eq("email", email).eq("status", "failed").gte("timestamp", time_threshold).execute()
            
            if hasattr(failed_attempts, 'error'):
                print(f"Failed attempts query error: {failed_attempts.error.message}")
                return jsonify({"error": "Service unavailable"}), 500
                
            if failed_attempts.count >= LOGIN_ATTEMPT_THRESHOLD:
                block_until = datetime.datetime.now(LOCAL_TZ) + datetime.timedelta(minutes=BLOCK_DURATION_MINUTES)
                block_user(email, ip_address, "Brute-force detected")
                return jsonify({
                    "error": "Account Locked",
                    "message": f"Your account has been temporarily locked until {block_until.strftime('%Y-%m-%d %H:%M')}. " +
                               f"Contact {ADMIN_EMAIL} for immediate assistance."
                }), 403
        except Exception as e:
            print(f"Failed attempts query error: {e}")
            return jsonify({"error": "Service unavailable"}), 500

        try:
            response = supabase_client.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
            
            if hasattr(response, 'error'):
                print(f"Auth Error: {response.error.message}")
                raise AuthApiError(response.error.message)
                
            user_id = response.user.id
            
            # Update in login function
            role_data = supabase_client.table("user_roles").select("role", "name").eq("user_id", user_id).execute()
            if hasattr(role_data, 'error'):
                print(f"Role Query Error: {role_data.error.message}")
                role = "user"
            else:
                role = role_data.data[0]["role"].strip().capitalize() if role_data.data else "user"
            
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
            # Update login attempt data structure
            login_attempt_data = {
                "user_id": user_id,
                "email": email,
                "ip_address": ip_address,
                "timestamp": timestamp,
                "status": status  # Required field
            }
            login_result = supabase_client.table("login_attempts").insert([login_attempt_data]).execute()
            if hasattr(login_result, 'error'):
                print(f"Login Attempt Insert Error: {login_result.error.message}")
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

# Add after Supabase client initialization
def check_database_schema():
    required_tables = {
        'blocked_users': ['id', 'email', 'ip_address', 'blocked_at', 'unblock_at', 'reason'],
        'login_attempts': ['id', 'user_id', 'email', 'ip_address', 'timestamp', 'status'],
        'intrusion_alerts': ['id', 'user_id', 'ip_address', 'attack_type', 'timestamp', 'status', 'extra_info'],
        'api_calls': ['id', 'ip_address', 'endpoint', 'method', 'timestamp', 'request_data'],
        'user_roles': ['user_id', 'role', 'name']
    }
    try:
        for table, columns in required_tables.items():
            result = supabase_client.table(table).select(",".join(columns)).limit(1).execute()
            print(f"✅ Table '{table}' exists and is accessible")
    except Exception as e:
        print(f"❌ Database schema check failed for table {table}: {str(e)}")
        exit(1)

# Call this after client initialization
check_database_schema()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)