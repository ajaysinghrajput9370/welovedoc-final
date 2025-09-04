# app.py — Part 1
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash, abort
import os
import uuid
import razorpay
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from dotenv import load_dotenv
import hmac
import hashlib
import json

# Import functions from file_manager.py (make sure file_manager.py is the fixed version)
from file_manager import (
    ensure_schema, init_db as fm_init_db,
    signup_user, login_user, check_subscription,
    activate_subscription, get_user_by_email,
    get_subscription_details, list_users
)

# ---------------- App Config ----------------
load_dotenv()
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['UPLOAD_FOLDER'] = os.getenv("UPLOAD_FOLDER", "uploads")
app.config['RESULT_FOLDER'] = os.getenv("RESULT_FOLDER", "results")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")
app.permanent_session_lifetime = timedelta(days=30)

# Ensure folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# ---------------- Razorpay / Env ----------------
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET")
ADMIN_VIEW_SECRET = os.getenv("ADMIN_VIEW_SECRET", "changeme_admin_secret")

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
    print("⚠️  Missing Razorpay keys in environment. Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET.")

razorpay_client = None
try:
    if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
except Exception as e:
    print("⚠️ Razorpay client init failed:", e)

# ---------------- Ensure DB schema ----------------
ensure_schema()
fm_init_db()

# ---------------- Helper: check active subscription ----------------
def has_active_subscription(email: str) -> bool:
    """Authoritative check from DB (do not rely solely on session)."""
    try:
        return check_subscription(email)
    except Exception as e:
        print("Error checking subscription:", e)
        return False

# ---------------- AUTH ROUTES ----------------
@app.route("/profile")
def profile():
    # Use session["email"] consistently
    if "email" not in session:
        flash("Login required", "warning")
        return redirect(url_for("login"))
    user = get_user_by_email(session["email"])
    sub_details = get_subscription_details(session["email"]) or {}
    return render_template("profile.html", user=user, subscription=sub_details)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please fill all fields", "warning")
            return redirect(url_for("signup"))

        ok = signup_user(name, email, password, subscription="free")
        if ok:
            session.permanent = True
            session["user_name"] = name
            session["email"] = email
            # set session subscription info from DB (fresh)
            details = get_subscription_details(email)
            if details:
                session["subscription"] = details.get("subscription")
                expiry = details.get("subscription_expiry")
                session["subscription_expiry"] = expiry.isoformat() if expiry else None
            flash("Signup successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Email already registered!", "danger")
            return redirect(url_for("signup"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        device_id = request.headers.get("X-Device-Id") or request.remote_addr

        result = login_user(email, password, device_id)
        if result is True:
            user = get_user_by_email(email)
            if not user:
                flash("Login error: user not found after auth", "danger")
                return redirect(url_for("login"))

            session.permanent = True
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["email"] = email

            # IMPORTANT: populate subscription info from DB into session
            sub_details = get_subscription_details(email)
            if sub_details:
                session["subscription"] = sub_details.get("subscription")
                expiry = sub_details.get("subscription_expiry")
                session["subscription_expiry"] = expiry.isoformat() if expiry else None
            else:
                session["subscription"] = "free"
                session["subscription_expiry"] = None

            flash("Login successful!", "success")
            return redirect(url_for("home"))

        elif result == "device_limit":
            flash("❌ Device limit exceeded for this subscription", "danger")
            return redirect(url_for("login"))
        else:
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session_keys = list(session.keys())
    for k in session_keys:
        session.pop(k, None)
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))
# app.py — Part 2 (continue)
# ---------------- PAYMENT ROUTES ----------------
@app.route("/create_order", methods=["POST"])
def create_order():
    if "email" not in session:
        return jsonify({"error": "Login required"}), 403

    if not razorpay_client:
        return jsonify({"error": "Razorpay not configured"}), 500

    data = request.get_json(silent=True) or {}
    plan = (data.get("plan") or "").lower().strip()

    PLAN_MAP = {
        "basic":     {"amount": 3000, "duration_months": 1},
        "standard":  {"amount": 3500, "duration_months": 1},
        "premium":   {"amount": 1,    "duration_months": 2},   # test ₹1
    }

    if plan not in PLAN_MAP:
        return jsonify({"error": "Invalid plan"}), 400

    amount = PLAN_MAP[plan]["amount"]
    duration = PLAN_MAP[plan]["duration_months"]

    session["selected_plan"] = plan
    session["selected_duration"] = duration
    session.modified = True

    receipt = f"wld_{plan}_{uuid.uuid4().hex[:16]}"

    try:
        order = razorpay_client.order.create({
            "amount": amount * 100,
            "currency": "INR",
            "receipt": receipt,
            "payment_capture": 1
        })
    except Exception as e:
        print("Razorpay order create error:", e)
        return jsonify({"error": "payment gateway error"}), 500

    session["razorpay_order_id"] = order.get("id")
    session.modified = True

    return jsonify(order)


def _apply_session_subscription_from_db(email):
    """Helper: refresh subscription info from DB into session."""
    try:
        details = get_subscription_details(email)
        if not details:
            session["subscription"] = "free"
            session["subscription_expiry"] = None
            return
        session["subscription"] = details.get("subscription")
        expiry = details.get("subscription_expiry")
        session["subscription_expiry"] = expiry.isoformat() if expiry else None
        session.modified = True
    except Exception as e:
        print("Error refreshing session subscription:", e)


@app.route("/payment_success", methods=["POST"])
def payment_success():
    try:
        print("Payment success endpoint called!")
        print("Form data received:", request.form)

        if "email" not in session:
            flash("Please login first", "danger")
            return redirect(url_for("login"))

        if "selected_plan" not in session or "razorpay_order_id" not in session:
            flash("Invalid or expired payment session. Please try again.", "danger")
            return redirect(url_for("pricing"))

        if not razorpay_client:
            flash("Payment gateway not configured", "danger")
            return redirect(url_for("pricing"))

        payment_id = request.form.get("razorpay_payment_id")
        order_id = request.form.get("razorpay_order_id")
        signature = request.form.get("razorpay_signature")

        try:
            razorpay_client.utility.verify_payment_signature({
                "razorpay_order_id": order_id,
                "razorpay_payment_id": payment_id,
                "razorpay_signature": signature
            })
        except Exception as verr:
            print("❌ Signature verification failed:", verr)
            flash("Payment verification failed. Please contact support.", "danger")
            return redirect(url_for("pricing"))

        plan = session["selected_plan"]
        duration = session.get("selected_duration", 1)
        email = session["email"]

        print(f"Activating {plan} plan for {email} with {duration} months duration")
        ok = activate_subscription(email, plan, duration)
        if ok:
            # IMPORTANT: refresh session subscription from DB so protected routes see it
            _apply_session_subscription_from_db(email)
            flash("✅ Subscription Activated Successfully!", "success")
            print("Subscription activated in database and session refreshed")
        else:
            flash("❌ Database error activating subscription", "danger")
            print("Failed to activate subscription in database")

        session.pop("selected_plan", None)
        session.pop("selected_duration", None)
        session.pop("razorpay_order_id", None)

        # Refresh session display name
        user = get_user_by_email(email)
        if user:
            session["user_name"] = user.get("name")

        return redirect(url_for("home"))

    except Exception as e:
        print("Error in payment_success:", str(e))
        flash("Payment processing error occurred", "danger")
        return redirect(url_for("pricing"))


@app.route("/razorpay_webhook", methods=["POST"])
def razorpay_webhook():
    payload = request.data
    signature = request.headers.get('X-Razorpay-Signature')

    try:
        if not RAZORPAY_WEBHOOK_SECRET:
            print("⚠️  No RAZORPAY_WEBHOOK_SECRET set; skipping verification (not recommended)")
            data = json.loads(payload or "{}")
            print("📦 Webhook received (UNVERIFIED):", data)
            return "", 200

        expected_signature = hmac.new(RAZORPAY_WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, signature or ""):
            print("❌ Invalid webhook signature")
            return "Invalid signature", 400

        data = json.loads(payload or "{}")
        print("📦 Webhook received:", data)

        # Optional: automatically activate subscription on payment.captured webhook
        try:
            event = data.get("event")
            if event == "payment.captured":
                payment = data.get("payload", {}).get("payment", {}).get("entity", {})
                email = payment.get("email")
                description = payment.get("description", "") or ""
                plan = None
                if "premium" in description.lower():
                    plan = "premium"
                elif "standard" in description.lower():
                    plan = "standard"
                elif "basic" in description.lower():
                    plan = "basic"

                if email and plan:
                    duration_map = {"basic": 1, "standard": 1, "premium": 2}
                    duration = duration_map.get(plan, 1)
                    ok = activate_subscription(email, plan, duration)
                    if ok:
                        print(f"Webhook: activated {plan} for {email}")
        except Exception as e:
            print("Webhook auto-activate error:", e)

        return "", 200

    except Exception as e:
        print("Webhook error:", str(e))
        return "Error processing webhook", 400


@app.route("/test_payment/<plan>")
def test_payment(plan):
    if "email" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    plan = plan.lower().strip()
    if plan == "basic":
        duration = 1
    elif plan == "standard":
        duration = 1
    elif plan == "premium":
        duration = 2
    else:
        flash("Invalid plan", "danger")
        return redirect(url_for("pricing"))

    if activate_subscription(session["email"], plan, duration):
        # mirror DB into session immediately
        _apply_session_subscription_from_db(session["email"])
        flash(f"✅ {plan.capitalize()} Subscription Activated for Testing!", "success")
    else:
        flash("❌ Failed to activate test subscription", "danger")

    return redirect(url_for("home"))


# ---------------- BASIC PAGES ----------------
@app.route("/")
def home():
    return render_template("welovedoc.html")


@app.route("/pricing")
def pricing():
    return render_template("pricing.html", razorpay_key_id=RAZORPAY_KEY_ID)


# ---------------- PROTECTED TOOL ROUTES ----------------
def _require_login():
    if "email" not in session:
        flash("Login required", "warning")
        return False
    return True


@app.route("/esic-highlight")
def esic_highlight_page():
    if not _require_login():
        return redirect(url_for("login"))

    # AUTHORITATIVE DB check (ensures we use DB state)
    if not has_active_subscription(session["email"]):
        flash("This feature is for paid users only", "danger")
        return redirect(url_for("pricing"))

    return render_template("esic-highlight.html")


@app.route("/pf-highlight")
def pf_highlight_page():
    if not _require_login():
        return redirect(url_for("login"))

    if not has_active_subscription(session["email"]):
        flash("This feature is for paid users only", "danger")
        return redirect(url_for("pricing"))

    return render_template("pf-highlight.html")


# ---------------- PROCESS API ----------------
from pf_highlight import highlight_pf
from esic_highlight import highlight_esic

@app.route("/process", methods=["POST"])
def process():
    if "email" not in session or not has_active_subscription(session["email"]):
        return jsonify({"error": "Subscription required"}), 403

    try:
        pdf_file = request.files.get('pdf_file')
        excel_file = request.files.get('excel_file')
        mode = (request.form.get("mode", "pf") or "pf").lower().strip()

        if not pdf_file or not excel_file or pdf_file.filename == '' or excel_file.filename == '':
            return jsonify({"error": "Please select both PDF and Excel files"}), 400

        pdf_filename = f"{uuid.uuid4()}_{secure_filename(pdf_file.filename)}"
        excel_filename = f"{uuid.uuid4()}_{secure_filename(excel_file.filename)}"

        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
        excel_path = os.path.join(app.config['UPLOAD_FOLDER'], excel_filename)

        pdf_file.save(pdf_path)
        excel_file.save(excel_path)

        if mode == "pf":
            output_pdf, not_found_excel = highlight_pf(pdf_path, excel_path, output_folder=app.config['RESULT_FOLDER'])
        else:
            output_pdf, not_found_excel = highlight_esic(pdf_path, excel_path, output_folder=app.config['RESULT_FOLDER'])

        response = {}
        if output_pdf:
            response["pdf_url"] = f"/download/{os.path.basename(output_pdf)}"
        if not_found_excel:
            response["excel_url"] = f"/download/{os.path.basename(not_found_excel)}"

        return jsonify(response), 200

    except Exception as e:
        print("Process error:", e)
        return jsonify({"error": str(e)}), 500


@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory(app.config['RESULT_FOLDER'], filename, as_attachment=True)


# ---------------- Admin / Debug ----------------
@app.route("/admin/users")
def admin_users():
    token = request.args.get("token")
    if not token or token != ADMIN_VIEW_SECRET:
        abort(403)
    users = list_users(200)
    return render_template("admin_users.html", users=users)


# ---------------- MAIN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # default 5000 rakho
    app.run(host="0.0.0.0", port=port)

