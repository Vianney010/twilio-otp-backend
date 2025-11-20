from flask import Flask, request, jsonify
from twilio.rest import Client
import os

app = Flask(__name__)

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILLO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_VERIFY_SID = os.getenv("TWILIO_VERIFY_SID")

client = Client(TWILIO_ACCOUNT_SID, TWILLO_AUTH_TOKEN)

@app.route("/send-otp", methods=["POST"])
def send_otp():
    data = request.get_json()
    phone = data["phone"]
    try:
        verification = client.verify.v2.services(TWILIO_VERIFY_SID).verifications.create(
            to=phone, channel="sms"
        )
        return jsonify({"status": verification.status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    phone = data["phone"]
    code = data["code"]

    try:
        check = client.verify.v2.services(TWILIO_VERIFY_SID).verification_checks.create(
            to=phone, code=code
        )
        return jsonify({"valid": check.valid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/")
def home():
    return "Twilio OTP Backend Running"
