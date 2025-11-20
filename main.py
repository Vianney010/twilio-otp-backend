# main.py
import os
import time
import hashlib
import secrets
import requests
from flask import Flask, request, jsonify
from cachetools import TTLCache

app = Flask(__name__)

# Config from environment (set these in Render / host environment)
FAST2SMS_API_KEY = os.getenv("FAST2SMS_API_KEY")  # required
SENDER_ID = os.getenv("FAST2SMS_SENDER_ID", "FSTSMS")  # optional; defaults to FSTSMS or TXTIND etc.

if not FAST2SMS_API_KEY:
    raise RuntimeError("FAST2SMS_API_KEY environment variable is required")

# OTP stores (in-memory). TTLCache will auto-expire entries.
# otp_cache: phone -> dict { hash:..., ts:... }
otp_cache = TTLCache(maxsize=10000, ttl=300)  # 5 minutes expiry
# rate_limit_cache: phone -> [timestamps]
rate_cache = TTLCache(maxsize=10000, ttl=3600)  # 1 hour for rate limiting

# Helper: generate 6-digit OTP
def generate_otp():
    return f"{secrets.randbelow(10**6):06d}"

def hash_code(code: str) -> str:
    return hashlib.sha256(code.encode('utf-8')).hexdigest()

# Fast2SMS send function
def send_sms_via_fast2sms(phone: str, message: str):
    url = "https://www.fast2sms.com/dev/bulkV2"
    payload = {
        "route": "v3",
        "sender_id": SENDER_ID,
        "message": message,
        "language": "english",
        "flash": 0,
        "numbers": phone.replace("+", "")  # Fast2SMS expects numbers without plus in many cases
    }
    headers = {
        "authorization": FAST2SMS_API_KEY,
        "Content-Type": "application/json"
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json()

# Simple rate limiter: max 5 OTPs per phone per hour, and 1 per 30s
def can_send_otp(phone: str):
    now = int(time.time())
    entry = rate_cache.get(phone)
    if not entry:
        rate_cache[phone] = [now]
        return True, None
    # entry is list of timestamps
    # prune older than 1 hour (cache ttl does this, but keep safe)
    entry = [t for t in entry if now - t <= 3600]
    # check last send gap
    if entry and now - entry[-1] < 30:
        return False, "Please wait 30 seconds before requesting another OTP."
    if len(entry) >= 5:
        return False, "Exceeded OTP request limit. Try again later."
    entry.append(now)
    rate_cache[phone] = entry
    return True, None

@app.route("/send-otp", methods=["POST"])
def send_otp():
    data = request.get_json() or {}
    phone = data.get("phone")
    if not phone:
        return jsonify({"error": "Missing 'phone' in request"}), 400

    # Basic phone sanitization
    phone_sanitized = phone.strip()
    if phone_sanitized.startswith("+"):
        # keep plus for display but fast2sms payload removes it
        pass
    else:
        # if client sent 10-digit indian number, add +91
        if len(phone_sanitized) == 10 and phone_sanitized.isdigit():
            phone_sanitized = "+91" + phone_sanitized

    ok, msg = can_send_otp(phone_sanitized)
    if not ok:
        return jsonify({"error": msg}), 429

    otp = generate_otp()
    hashed = hash_code(otp)
    # store hashed OTP; TTLCache auto expires in 300s
    otp_cache[phone_sanitized] = {"hash": hashed, "ts": int(time.time())}

    # Prepare message (customize as you want)
    message = f"Your FoodApp OTP is {otp}. It will expire in 5 minutes."

    try:
        resp = send_sms_via_fast2sms(phone_sanitized, message)
        return jsonify({"status": "sent", "provider_response": resp}), 200
    except requests.HTTPError as e:
        # On failure, remove stored OTP
        otp_cache.pop(phone_sanitized, None)
        return jsonify({"error": "SMS provider error", "details": str(e), "resp_text": getattr(e.response, "text", "")}), 502
    except Exception as e:
        otp_cache.pop(phone_sanitized, None)
        return jsonify({"error": "Internal error sending SMS", "details": str(e)}), 500

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json() or {}
    phone = data.get("phone")
    code = data.get("code")

    if not phone or not code:
        return jsonify({"error": "Missing 'phone' or 'code'"}), 400

    # normalize phone (same logic as send)
    phone_sanitized = phone.strip()
    if not phone_sanitized.startswith("+") and len(phone_sanitized) == 10 and phone_sanitized.isdigit():
        phone_sanitized = "+91" + phone_sanitized

    entry = otp_cache.get(phone_sanitized)
    if not entry:
        return jsonify({"valid": False, "reason": "No OTP requested or OTP expired"}), 400

    hashed_input = hash_code(code)
    if hashed_input == entry["hash"]:
        # success: delete OTP to prevent reuse
        otp_cache.pop(phone_sanitized, None)
        return jsonify({"valid": True}), 200
    else:
        return jsonify({"valid": False, "reason": "Invalid OTP"}), 400

@app.route("/", methods=["GET"])
def home():
    return "Fast2SMS OTP backend running"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8080)))
