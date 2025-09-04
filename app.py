from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash, abort
import os
import uuid
import razorpay
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime, timezone
from dotenv import load_dotenv
import hmac
import hashlib
import json

# Import from file_manager.py
from file_manager import (
    ensure_schema, init_db as fm_init_db,
    signup_user, login_user, check_subscription,
    activate_subscription, get_user_by_email,
    get_subscription_details, list_users
)

# ---------------- Config ----------------
load_dotenv()
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config['UPLOAD_FOLDER'] = os.getenv("UPLOAD_FOLDER", "uploads")
app.config['RESULT_FOLDER'] = os.getenv("RESULT_FOLDER", "results")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")
app.permanent_session_lifetime = timedelta(days=30)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# ---------------- Razorpay ----------------
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET")
ADMIN_VIEW_SECRET = os.getenv("ADMIN_VIEW_SECRET", "changeme_admin_secret")

razorpay_client = None
try:
    if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
        razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
except Exception as e:
    print("⚠️ Razorpay init failed:", e)

# ---------------- Ensure DB ----------------
ensure_schema()
fm_init_db()

# ---------------- Helpers ----------------
def has_active_subscription(email: str) -> bool:
    """Check if user has an active paid subscription"""
    try:
        details = get_subscription_details(email)
        if details:
            sub = (details.get("subscription") or "").lower()
            expiry = details.get("subscription_expiry")
            if sub and sub != "free":
                if isinstance(expiry, datetime):
                    return datetime.now(timezone.utc) <= expiry.astimezone(timezone.utc)
                elif isinstance(expiry, str):
                    try:
                        expiry_dt = datetime.fromisoformat(expiry)
                        return datetime.now(timezone.utc) <= expiry_dt
                    except Exception:
                        return True
                else:
                    return True
    except Exception as e:
        print("has_active_subscription error:", e)
    try:
        return bool(check_subscription(email))
    except Exception:
        return False

def _apply_session_subscription_from_db(email):
    """Sync subscription info from DB to session"""
    try:
        details = get_subscription_details(email)
    except Exception as e:
        print("Warning: get_subscription_details failed:", e)
        details = None

    if not details:
        session["subscription"] = session.get("subscription", "free")
        session["subscription_expiry"] = session.get("subscription_expiry", None)
    else:
        session["subscription"] = details.get("subscription") or "free"
        expiry = details.get("subscription_expiry")
        if isinstance(expiry, datetime):
            session["subscription_expiry"] = expiry.isoformat()
        elif expiry:
            try:
                session["subscription_expiry"] = expiry if isinstance(expiry, str) else str(expiry)
            except Exception:
                session["subscription_expiry"] = None
        else:
            session["subscription_expiry"] = None
    session.modified = True

# ---------------- Auth Routes ----------------
@app.route("/profile")
def profile():
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
            _apply_session_subscription_from_db(email)
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
                flash("Login error", "danger")
                return redirect(url_for("login"))
            session.permanent = True
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["email"] = email
            _apply_session_subscription_from_db(email)
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        elif result == "device_limit":
            flash("❌ Device limit exceeded", "danger")
            return redirect(url_for("login"))
        else:
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("home"))

# ---------------- PAYMENT: CREATE ORDER ----------------
@app.route("/create_order", methods=["POST"])
def create_order():
    if "email" not in session:
        return jsonify({"error": "Login required"}), 403
    if not razorpay_client:
        return jsonify({"error": "Razorpay not configured"}), 500

    data = request.get_json(silent=True) or {}
    plan = (data.get("plan") or "").lower().strip()

    PLAN_MAP = {
        "basic":     {"amount": 1, "duration_months": 1},
        "standard":  {"amount": 3500, "duration_months": 1},
        "premium":   {"amount": 6000, "duration_months": 2},
    }

    if plan not in PLAN_MAP:
        return jsonify({"error": "Invalid plan"}), 400

    amount_inr = PLAN_MAP[plan]["amount"]
    duration = PLAN_MAP[plan]["duration_months"]

    amount_paise = amount_inr * 100

    session["selected_plan"] = plan
    session["selected_duration"] = duration
    session.modified = True

    receipt = f"wld_{plan}_{uuid.uuid4().hex[:16]}"

    try:
        order = razorpay_client.order.create({
            "amount": amount_paise,
            "currency": "INR",
            "receipt": receipt,
            "payment_capture": 1,
            "notes": {"plan": plan}
        })
    except Exception as e:
        print("Razorpay order create error:", e)
        return jsonify({"error": "Payment gateway error"}), 500

    session["razorpay_order_id"] = order.get("id")
    session.modified = True
    return jsonify(order)

# ---------------- PAYMENT SUCCESS ----------------
@app.route("/payment_success", methods=["POST"])
def payment_success():
    try:
        if "email" not in session:
            flash("Please login first", "danger")
            return redirect(url_for("login"))
        if "selected_plan" not in session or "razorpay_order_id" not in session:
            flash("Invalid or expired payment session", "danger")
            return redirect(url_for("pricing"))
        if not razorpay_client:
            flash("Payment gateway not configured", "danger")
            return redirect(url_for("pricing"))

        payment_id = request.form.get("razorpay_payment_id")
        order_id = request.form.get("razorpay_order_id")
        signature = request.form.get("razorpay_signature")

        # Verify signature
        try:
            razorpay_client.utility.verify_payment_signature({
                "razorpay_order_id": order_id,
                "razorpay_payment_id": payment_id,
                "razorpay_signature": signature
            })
        except Exception as verr:
            print("Signature verification failed:", verr)
            flash("Payment verification failed", "danger")
            return redirect(url_for("pricing"))

        plan = session.get("selected_plan", "premium")
        duration = session.get("selected_duration", 1)
        email = session["email"]

        ok = False
        try:
            ok = activate_subscription(email, plan, duration)
        except Exception as e:
            print("activate_subscription error:", e)

        if ok:
            _apply_session_subscription_from_db(email)
            flash("✅ Subscription Activated Successfully!", "success")
        else:
            session["subscription"] = plan
            session["subscription_expiry"] = (datetime.utcnow() + timedelta(days=30*duration)).isoformat()
            session.modified = True
            flash("✅ Subscription set in session (DB update may have failed)", "warning")

        session.pop("selected_plan", None)
        session.pop("selected_duration", None)
        session.pop("razorpay_order_id", None)

        return redirect(url_for("home"))

    except Exception as e:
        print("Error in payment_success:", e)
        flash("Payment processing error occurred", "danger")
        return redirect(url_for("pricing"))
# ---------------- RAZORPAY WEBHOOK ----------------
@app.route("/razorpay_webhook", methods=["POST"])
def razorpay_webhook():
    payload = request.data
    signature = request.headers.get('X-Razorpay-Signature')

    try:
        if RAZORPAY_WEBHOOK_SECRET:
            expected_signature = hmac.new(RAZORPAY_WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_signature, signature or ""):
                print("❌ Invalid webhook signature")
                return "Invalid signature", 400

        data = json.loads(payload or "{}")
        event = data.get("event")
        if event == "payment.captured":
            payment = data.get("payload", {}).get("payment", {}).get("entity", {})
            email = payment.get("email")
            notes = payment.get("notes") or {}
            plan = notes.get("plan")
            if email and plan:
                duration_map = {"basic": 1, "standard": 1, "premium": 2}
                duration = duration_map.get(plan, 1)
                try:
                    activate_subscription(email, plan, duration)
                    print(f"Webhook: activated {plan} for {email}")
                except Exception as e:
                    print("Webhook activation error:", e)
        return "", 200
    except Exception as e:
        print("Webhook error:", e)
        return "Error processing webhook", 400

# ---------------- TEST PAYMENT (FOR DEBUG) ----------------
@app.route("/test_payment/<plan>")
def test_payment(plan):
    if "email" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))

    plan = plan.lower().strip()
    duration = 2 if plan == "premium" else 1
    ok = False
    try:
        ok = activate_subscription(session["email"], plan, duration)
    except Exception as e:
        print("test_payment activate_subscription error:", e)

    if ok:
        _apply_session_subscription_from_db(session["email"])
        flash(f"✅ {plan.capitalize()} Subscription Activated for Testing!", "success")
    else:
        session["subscription"] = plan
        session["subscription_expiry"] = (datetime.utcnow() + timedelta(days=30*duration)).isoformat()
        session.modified = True
        flash(f"✅ {plan.capitalize()} Subscription Activated in session (DB update failed).", "warning")

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

# ---------------- DOWNLOAD ----------------
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
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
