from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash, abort
import os
import uuid
import razorpay
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash 
from datetime import timedelta, datetime
from dotenv import load_dotenv
import json
import psycopg2

# Import from file_manager.py
from file_manager import (
    ensure_schema,
    signup_user, login_user,
    activate_subscription, get_user_by_email,
    get_subscription_details, list_users, update_device_login,
    is_subscription_active, set_user_disabled  # NEW
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

# ---------------- Admin Config ----------------
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

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
try:
    ensure_schema()
except Exception as e:
    print("Warning: ensure_schema() failed on import:", e)

# ---------------- Helpers ----------------
def _apply_session_subscription_from_db(email):
    """Refresh session subscription info from DB."""
    try:
        details = get_subscription_details(email)
    except Exception as e:
        print("Warning: get_subscription_details failed:", e)
        details = None

    if not details:
        session["subscription"] = "free"
        session["subscription_expiry"] = None
    else:
        session["subscription"] = details.get("subscription") or "free"
        expiry = details.get("subscription_expiry")
        if isinstance(expiry, datetime):
            session["subscription_expiry"] = expiry.isoformat()
        elif expiry:
            try:
                session["subscription_expiry"] = str(expiry)
            except Exception:
                session["subscription_expiry"] = None
        else:
            session["subscription_expiry"] = None
    session.modified = True

# ---------------- Template Utility ----------------
@app.context_processor
def utility_processor():
    from datetime import datetime
    return dict(now=datetime.utcnow)

# ---------------- Admin Routes ----------------
@app.route("/admin", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session["admin"] = True
            flash("Admin login successful!", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid admin credentials", "danger")
            return redirect(url_for("admin_login"))
    return render_template("admin_login.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if not session.get("admin"):
        flash("Admin access required", "warning")
        return redirect(url_for("admin_login"))

    try:
        conn = psycopg2.connect(os.environ.get("DATABASE_URL"))
        cur = conn.cursor()
        # Fetch all columns including is_disabled
        cur.execute("""
            SELECT id, email, name, subscription, subscription_expiry, is_disabled
            FROM users ORDER BY id DESC
        """)
        rows = cur.fetchall()
        cur.close()
        conn.close()

        users = []
        for row in rows:
            user_id, email, name, sub, expiry, disabled = row
            # Compute status and action
            sub_lower = (sub or "free").lower()
            expiry_dt = None
            if expiry:
                try:
                    expiry_dt = datetime.fromisoformat(str(expiry))
                except:
                    pass
            now = datetime.utcnow()

            if sub_lower == "free":
                status = "Free User"
                action = "--"
            elif disabled:
                status = "Premium Disabled"
                action = "Premium Disabled"   # no button
            elif expiry_dt and expiry_dt < now:
                status = "Subscription Expired"
                action = "Renew Required"
            else:
                status = "Premium Active"
                action = "Disable Premium"    # button

            users.append({
                "id": user_id,
                "email": email,
                "name": name or "",
                "subscription": sub,
                "subscription_expiry": expiry,
                "is_disabled": disabled,
                "status": status,
                "action": action
            })

        return render_template("admin_dashboard.html", users=users)
    except Exception as e:
        print(f"Admin dashboard error: {e}")
        flash(f"Database error: {str(e)}", "danger")
        return redirect(url_for("admin_login"))

@app.route("/admin/deactivate/<int:user_id>")
def deactivate_user(user_id):
    if not session.get("admin"):
        flash("Admin access required", "warning")
        return redirect(url_for("admin_login"))

    # First get user to check if they are premium active
    conn = psycopg2.connect(os.environ.get("DATABASE_URL"))
    cur = conn.cursor()
    cur.execute("SELECT subscription, subscription_expiry, is_disabled FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    if not row:
        flash("User not found", "danger")
        conn.close()
        return redirect(url_for("admin_dashboard"))

    sub, expiry, disabled = row
    if disabled:
        flash("User is already disabled", "warning")
        conn.close()
        return redirect(url_for("admin_dashboard"))

    # Only allow disabling if user has a paid plan and is not expired
    sub_lower = (sub or "free").lower()
    if sub_lower == "free":
        flash("Cannot disable a free user", "warning")
        conn.close()
        return redirect(url_for("admin_dashboard"))

    expiry_dt = None
    if expiry:
        try:
            expiry_dt = datetime.fromisoformat(str(expiry))
        except:
            pass
    now = datetime.utcnow()
    if expiry_dt and expiry_dt < now:
        flash("User subscription is already expired", "warning")
        conn.close()
        return redirect(url_for("admin_dashboard"))

    # Perform deactivation
    success = set_user_disabled(user_id, True)
    conn.close()
    if success:
        flash(f"User {user_id} has been disabled (premium revoked).", "success")
    else:
        flash("Failed to disable user", "danger")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    flash("Logged out from admin", "info")
    return redirect(url_for("home"))

# ---------------- Auth Routes ----------------
@app.route("/profile")
def profile():
    if "email" not in session:
        flash("Login required", "warning")
        return redirect(url_for("login"))

    user = get_user_by_email(session["email"])
    sub_details = get_subscription_details(session["email"]) or {}

    days_left = None
    expiry = sub_details.get("subscription_expiry")
    if sub_details.get("subscription") and sub_details["subscription"] != "free" and expiry:
        try:
            if isinstance(expiry, datetime):
                expiry_date = expiry.date()
            else:
                expiry_date = None
            if expiry_date:
                today = datetime.utcnow().date()
                days_left = (expiry_date - today).days
                if days_left < 0:
                    days_left = 0
        except Exception as e:
            print("days_left calculation error:", e)

    return render_template("profile.html", user=user, subscription=sub_details, days_left=days_left)


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

            update_device_login(email, device_id)

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


# ---------------- PAYMENT ROUTES ----------------
@app.route("/create_order", methods=["POST"])
def create_order():
    if "email" not in session:
        return jsonify({"error": "Login required"}), 401

    if not razorpay_client:
        return jsonify({"error": "Payment gateway not configured"}), 500

    plan = request.json.get("plan", "basic")
    amount_map = {"basic": 100, "standard": 349900, "premium": 599900}  # in paise

    if plan not in amount_map:
        return jsonify({"error": "Invalid plan"}), 400

    try:
        receipt_str = f"{uuid.uuid4().hex[:30]}"
        order = razorpay_client.order.create({
            "amount": amount_map[plan],
            "currency": "INR",
            "receipt": f"receipt_{receipt_str}",
            "notes": {
                "email": session["email"],
                "plan": plan
            }
        })
        return jsonify(order)
    except Exception as e:
        print("Razorpay order error:", e)
        return jsonify({"error": "Payment gateway error"}), 500


@app.route("/payment_success", methods=["POST"])
def payment_success():
    if "email" not in session:
        flash("Login required", "warning")
        return redirect(url_for("login"))

    if not razorpay_client:
        flash("Payment gateway not configured", "danger")
        return redirect(url_for("pricing"))

    payment_id = request.form.get("razorpay_payment_id")
    order_id = request.form.get("razorpay_order_id")
    signature = request.form.get("razorpay_signature")
    plan = request.form.get("plan", "basic")

    try:
        params_dict = {
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }
        razorpay_client.utility.verify_payment_signature(params_dict)

        # Activate subscription – this also sets is_disabled=False
        success = activate_subscription(session["email"], plan)
        if success:
            _apply_session_subscription_from_db(session["email"])
            flash("Payment successful! Subscription activated.", "success")
        else:
            flash("Payment successful but subscription activation failed. Contact support.", "warning")
    except Exception as e:
        print("Payment verification error:", e)
        flash("Payment verification failed", "danger")
        return redirect(url_for("profile"))

    return redirect(url_for("home"))


@app.route("/webhook", methods=["POST"])
def webhook():
    if not razorpay_client:
        return jsonify({"error": "Payment gateway not configured"}), 500

    signature = request.headers.get('X-Razorpay-Signature')
    webhook_body = request.get_data()

    try:
        razorpay_client.utility.verify_webhook_signature(
            webhook_body, signature, RAZORPAY_WEBHOOK_SECRET
        )
        payload = json.loads(webhook_body)
        event = payload.get('event')

        if event == 'payment.captured':
            payment = payload.get('payload', {}).get('payment', {}).get('entity', {})
            notes = payment.get('notes', {})
            email = notes.get('email')
            plan = notes.get('plan', 'basic')
            if email:
                activate_subscription(email, plan)   # sets is_disabled=False
                print(f"Webhook: Subscription activated for {email}, plan: {plan}")

        return jsonify({"status": "success"}), 200
    except Exception as e:
        print("Webhook error:", e)
        return jsonify({"error": "Invalid signature or webhook processing error"}), 400


# ---------------- BASIC PAGES ----------------
@app.route("/")
def home():
    return render_template("welovedoc.html")


@app.route("/pricing")
def pricing():
    active_subscription = False

    if "email" in session:
        active_subscription = is_subscription_active(session["email"])

    return render_template(
        "pricing.html",
        razorpay_key_id=RAZORPAY_KEY_ID,
        active_subscription=active_subscription
    )


@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory(os.path.dirname(__file__), 'sitemap.xml')

@app.route('/robots.txt')
def robots():
    return send_from_directory(os.path.dirname(__file__), 'robots.txt')


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
    if not is_subscription_active(session["email"]):
        flash("This feature is for paid users only", "danger")
        return redirect(url_for("pricing"))
    return render_template("esic-highlight.html")


@app.route("/pf-highlight")
def pf_highlight_page():
    if not _require_login():
        return redirect(url_for("login"))
    if not is_subscription_active(session["email"]):
        flash("This feature is for paid users only", "danger")
        return redirect(url_for("pricing"))
    return render_template("pf-highlight.html")


# ---------------- PDF TOOLS ROUTES (FREE ACCESS) ----------------
@app.route("/merge-pdf")
def merge_pdf_page():
    return render_template("merge-pdf.html")

@app.route("/split-pdf")
def split_pdf_page():
    return render_template("split-pdf.html")

@app.route("/compress-pdf")
def compress_pdf_page():
    return render_template("compress-pdf.html")

@app.route("/jpg-to-pdf")
def jpg_to_pdf_page():
    return render_template("jpg-to-pdf.html")

@app.route("/word-to-pdf")
def word_to_pdf_page():
    return render_template("word-to-pdf.html")

@app.route("/pdf-to-word")
def pdf_to_word_page():
    return render_template("pdf-to-word.html")

@app.route("/excel-to-pdf")
def excel_to_pdf_page():
    return render_template("excel-to-pdf.html")

@app.route("/pdf-to-excel")
def pdf_to_excel_page():
    return render_template("pdf-to-excel.html")

@app.route("/pdf-to-jpg")
def pdf_to_jpg_page():
    return render_template("pdf-to-jpg.html")

@app.route("/rotate-pdf")
def rotate_pdf_page():
    return render_template("rotate-pdf.html")

@app.route("/extract-pages")
def extract_pages_page():
    return render_template("extract-pages.html")

@app.route("/protect-pdf")
def protect_pdf_page():
    return render_template("protect-pdf.html")

@app.route("/pf-esic-ecr")
def pf_esic_ecr_page():
    return render_template("pf-esic-ecr.html")

@app.route("/stamp")
def stamp_page():
    return render_template("stamp.html")

@app.route("/about")
def about_page():
    return render_template("about.html")

@app.route("/faq")
def faq_page():
    return render_template("faq.html")

@app.route("/contact")
def contact_page():
    return render_template("contact.html")

@app.route("/privacy-policy")
def privacy_policy_page():
    return render_template("privacy_policy.html")

@app.route("/terms-of-service")
def terms_service_page():
    return render_template("terms_service.html")


# ---------------- PROCESS API ----------------
from pf_highlight import highlight_pf
from esic_highlight import highlight_esic

@app.route("/process", methods=["POST"])
def process():
    if "email" not in session or not is_subscription_active(session["email"]):
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
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
