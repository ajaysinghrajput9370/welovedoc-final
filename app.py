from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash, abort
import os
import uuid
import razorpay
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash 
from datetime import timedelta, datetime
from dotenv import load_dotenv
import json

# Import from file_manager.py
from file_manager import (
    ensure_schema,
    signup_user, login_user, check_subscription,
    activate_subscription, get_user_by_email,
    get_subscription_details, list_users, update_device_login
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
try:
    ensure_schema()
except Exception as e:
    print("Warning: ensure_schema() failed on import:", e)

# ---------------- Helpers ----------------
def has_active_subscription(email: str) -> bool:
    try:
        details = None
        try:
            details = get_subscription_details(email)
        except Exception as e:
            print("get_subscription_details error (ignored):", e)

        if details:
            sub = (details.get("subscription") or "").lower()
            expiry = details.get("subscription_expiry")
            if sub and sub != "free":
                if expiry:
                    expiry_dt = None
                    if isinstance(expiry, str):
                        try:
                            expiry_dt = datetime.fromisoformat(expiry)
                        except Exception:
                            try:
                                expiry_dt = datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S")
                            except Exception:
                                expiry_dt = None
                    elif isinstance(expiry, datetime):
                        expiry_dt = expiry

                    if expiry_dt:
                        return datetime.utcnow() <= expiry_dt
                    else:
                        return True
                else:
                    return True

        sess_sub = (session.get("subscription") or "").lower()
        sess_exp = session.get("subscription_expiry")
        if sess_sub and sess_sub != "free":
            if sess_exp:
                try:
                    sess_dt = datetime.fromisoformat(sess_exp)
                    return datetime.utcnow() <= sess_dt
                except Exception:
                    return True
            return True

    except Exception as e:
        print("has_active_subscription unexpected error:", e)

    try:
        return bool(check_subscription(email))
    except Exception:
        return False


def _apply_session_subscription_from_db(email):
    """Refresh session subscription info from DB; if DB missing, leave session untouched except default to 'free'."""
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
                if isinstance(expiry, str):
                    session["subscription_expiry"] = expiry
                else:
                    session["subscription_expiry"] = str(expiry)
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

    days_left = None
    expiry = sub_details.get("subscription_expiry")
    if sub_details.get("subscription") and sub_details["subscription"] != "free" and expiry:
        try:
            if isinstance(expiry, str):
                expiry_date = datetime.fromisoformat(expiry).date()
            elif isinstance(expiry, datetime):
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
        # ✅ Fix Razorpay receipt length (max 40 chars)
        receipt_str = f"{uuid.uuid4().hex[:30]}"  # truncated 30 chars
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
        # Verify payment signature
        params_dict = {
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }
        razorpay_client.utility.verify_payment_signature(params_dict)

        # Activate subscription (2 arguments: email + plan)
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

    # Redirect to home/profile instead of pricing
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
                activate_subscription(email, plan)
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
    # Only show pricing if user not subscribed
    if "email" in session and has_active_subscription(session["email"]):
        return redirect(url_for("home"))
    return render_template("pricing.html", razorpay_key_id=RAZORPAY_KEY_ID)


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
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
