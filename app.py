from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash
import os
import uuid
import sqlite3
import razorpay
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from pf_highlight import highlight_pf
from esic_highlight import highlight_esic
from dotenv import load_dotenv
from file_manager import check_subscription, activate_subscription, login_user  # keep using your existing functions
import hmac
import hashlib
import json

# ---------------- App Config ----------------
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULT_FOLDER'] = 'results'
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")  # use env if available
app.permanent_session_lifetime = timedelta(days=30)

# Ensure folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# ---------------- Load ENV ----------------
load_dotenv()

RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET")  # must be set in Render env

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
    print("⚠️  Missing Razorpay keys in environment. Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET.")

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)) if (RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET) else None

# ---------------- DB Setup ----------------
DB_PATH = "users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            subscription TEXT DEFAULT 'free',
            subscription_expiry TEXT,
            devices TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- DB Helpers ----------------
def get_user_by_email(email: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, password, subscription, subscription_expiry, devices FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "name": row[1],
        "email": row[2],
        "password": row[3],
        "subscription": row[4],
        "subscription_expiry": row[5],
        "devices": row[6]
    }

def has_active_subscription(email: str) -> bool:
    """Authoritative check from DB (avoid relying on session)."""
    user = get_user_by_email(email)
    if not user:
        return False
    sub = (user.get("subscription") or "free").lower()
    expiry_str = user.get("subscription_expiry")
    if sub == "premium" or sub == "standard" or sub == "basic" or sub == "paid":
        # Check expiry if present
        if expiry_str:
            try:
                expiry_dt = datetime.fromisoformat(expiry_str)
                return datetime.utcnow() <= expiry_dt
            except Exception:
                # If malformed expiry, treat as active for now (or change to False if you prefer strict)
                return True
        # No expiry set → treat as active
        return True
    return False

# ---------------- AUTH ROUTES ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please fill all fields", "warning")
            return redirect(url_for("signup"))

        hashed_pw = generate_password_hash(password)
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_pw))
            conn.commit()
            conn.close()

            session.permanent = True
            session["user_name"] = name
            session["email"] = email
            flash("Signup successful!", "success")
            return redirect(url_for("home"))
        except sqlite3.IntegrityError:
            flash("Email already registered!", "danger")
            return redirect(url_for("signup"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        device_id = request.headers.get("X-Device-Id") or request.remote_addr  # prefer a stable device id if you add one

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
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))
# ---------------- PAYMENT ROUTES ----------------
@app.route("/create_order", methods=["POST"])
def create_order():
    if "email" not in session:
        return jsonify({"error": "Login required"}), 403

    if not razorpay_client:
        return jsonify({"error": "Razorpay not configured"}), 500

    data = request.get_json(silent=True) or {}
    plan = (data.get("plan") or "").lower().strip()

    # Define your plan pricing (INR)
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

    # Razorpay receipt must be <= 40 chars
    receipt = f"wld_{plan}_{uuid.uuid4().hex[:16]}"

    order = razorpay_client.order.create({
        "amount": amount * 100,
        "currency": "INR",
        "receipt": receipt,
        "payment_capture": 1
    })

    # Save order_id for signature verification during payment_success
    session["razorpay_order_id"] = order.get("id")
    session.modified = True

    return jsonify(order)


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

        # ——— Verify Razorpay signature (very important) ———
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

        # ——— Activate subscription ———
        plan = session["selected_plan"]
        duration = session.get("selected_duration", 1)
        email = session["email"]

        print(f"Activating {plan} plan for {email} with {duration} months duration")

        # Use your existing file_manager implementation
        ok = activate_subscription(email, plan, duration)
        if ok:
            flash("✅ Subscription Activated Successfully!", "success")
            print("Subscription activated in database")
        else:
            flash("❌ Database error activating subscription", "danger")
            print("Failed to activate subscription in database")

        # Clear ephemeral payment session data
        session.pop("selected_plan", None)
        session.pop("selected_duration", None)
        session.pop("razorpay_order_id", None)

        # Optional: refresh user info in session (not used for access control, we check DB)
        user = get_user_by_email(email)
        if user:
            session["user_name"] = user["name"]

        return redirect(url_for("home"))

    except Exception as e:
        print("Error in payment_success:", str(e))
        flash("Payment processing error occurred", "danger")
        return redirect(url_for("pricing"))


@app.route("/razorpay_webhook", methods=["POST"])
def razorpay_webhook():
    # Verify webhook signature
    payload = request.data
    signature = request.headers.get('X-Razorpay-Signature')

    try:
        if not RAZORPAY_WEBHOOK_SECRET:
            print("⚠️  No RAZORPAY_WEBHOOK_SECRET set; skipping verification (not recommended)")
            # Still parse payload to log
            data = json.loads(payload or "{}")
            print("📦 Webhook received (UNVERIFIED):", data)
            return "", 200

        expected_signature = hmac.new(RAZORPAY_WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_signature, signature or ""):
            print("❌ Invalid webhook signature")
            return "Invalid signature", 400

        data = json.loads(payload or "{}")
        print("📦 Webhook received:", data)
        # (Optional) You can reconcile payment status here if needed
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

    # Use your existing activation logic
    if activate_subscription(session["email"], plan, duration):
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

    # Authoritative DB check (fixes your redirect loop)
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
@app.route("/process", methods=["POST"])
def process():
    # Block unauth users or inactive subs
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
        return jsonify({"error": str(e)}), 500


@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory(app.config['RESULT_FOLDER'], filename, as_attachment=True)

# ---------------- MAIN ----------------
if __name__ == "__main__":
    # Use Render's PORT if present
    port = int(os.getenv("PORT", "10000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, host="0.0.0.0", port=port)
