from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for, session, flash
import os
import uuid
import sqlite3
import razorpay
import json
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from pf_highlight import highlight_pf
from esic_highlight import highlight_esic

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULT_FOLDER'] = 'results'
app.secret_key = "supersecretkey"   # ⚠️ Production mein strong key use karein
app.permanent_session_lifetime = timedelta(days=30)  # user login 30 din tak active rahega

# ---------------- Razorpay Configuration ----------------
RAZORPAY_KEY_ID = "rzp_live_RBtTz04eahUWDs"   # ✅ Your live key_id
RAZORPAY_KEY_SECRET = "P7zpcxxZIsYfgZnSqSz13XPc"  # ✅ Your live secret
WEBHOOK_SECRET = "Mount@Fly1920"  # 🔥 Razorpay dashboard mein jo secret set kiya hai

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# Ensure folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# ---------------- DB Setup ----------------
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            subscription TEXT DEFAULT 'free',
            subscription_expiry DATE,
            registration_date DATE DEFAULT CURRENT_DATE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            payment_id TEXT,
            order_id TEXT,
            amount INTEGER,
            currency TEXT,
            status TEXT,
            plan_type TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            device_info TEXT,
            location TEXT,
            login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_active DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------------- Subscription Check Function ----------------
def check_subscription(email):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT subscription, subscription_expiry FROM users WHERE email=?", (email,))
    result = cursor.fetchone()
    conn.close()

    if result:
        sub_type, expiry = result
        if sub_type == "paid" and expiry:
            try:
                if datetime.strptime(expiry, "%Y-%m-%d") >= datetime.today():
                    return True
            except Exception:
                return False
    return False

# ---------------- Session Tracking Middleware ----------------
@app.before_request
def track_session():
    if "email" in session and "user_id" in session:
        # Get client information
        user_agent = request.headers.get('User-Agent', 'Unknown Device')
        # Simple device detection
        if 'Windows' in user_agent:
            device = "Windows PC"
        elif 'Mac' in user_agent:
            device = "Mac Computer"
        elif 'Linux' in user_agent:
            device = "Linux PC"
        elif 'iPhone' in user_agent or 'iPad' in user_agent:
            device = "iOS Device"
        elif 'Android' in user_agent:
            device = "Android Device"
        else:
            device = "Unknown Device"
        
        if 'Chrome' in user_agent:
            browser = "Chrome"
        elif 'Firefox' in user_agent:
            browser = "Firefox"
        elif 'Safari' in user_agent:
            browser = "Safari"
        else:
            browser = "Other Browser"
        
        device_info = f"{device} - {browser}"
        
        # Get IP and approximate location (simplified)
        ip_address = request.remote_addr
        location = f"{ip_address} (Approximate Location)"
        
        # Update or create session in database
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        
        # Check if session already exists
        cursor.execute("SELECT id FROM user_sessions WHERE user_id=? AND device_info=?", (session["user_id"], device_info))
        existing_session = cursor.fetchone()
        
        if existing_session:
            # Update last active time
            cursor.execute("UPDATE user_sessions SET last_active=CURRENT_TIMESTAMP WHERE id=?", (existing_session[0],))
        else:
            # Create new session
            cursor.execute("INSERT INTO user_sessions (user_id, device_info, location) VALUES (?, ?, ?)",
                          (session["user_id"], device_info, location))
        
        conn.commit()
        conn.close()

# ---------------- AUTH ROUTES ----------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        hashed_pw = generate_password_hash(password)
        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_pw))
            conn.commit()
            
            # Get user ID for session
            cursor.execute("SELECT id FROM users WHERE email=?", (email,))
            user_id = cursor.fetchone()[0]
            conn.close()

            # ✅ signup ke baad direct login
            session.permanent = True
            session["user_id"] = user_id
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
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, password FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session.permanent = True
            session["user_id"] = user[0]
            session["user_name"] = user[1]
            session["email"] = email
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    if "user_id" in session:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE user_sessions SET is_active=0 WHERE user_id=?", (session["user_id"],))
        conn.commit()
        conn.close()
    
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route("/logout_all")
def logout_all():
    if "user_id" in session:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("UPDATE user_sessions SET is_active=0 WHERE user_id=?", (session["user_id"],))
        conn.commit()
        conn.close()
    
    session.clear()
    flash("Logged out from all devices", "info")
    return redirect(url_for("home"))

# ---------------- PROFILE ROUTE ----------------
@app.route("/profile")
def profile():
    if "email" not in session:
        flash("Please login to view your profile", "warning")
        return redirect(url_for("login"))
    
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # Get user details
    cursor.execute("SELECT id, name, email, subscription, subscription_expiry, registration_date FROM users WHERE email=?", (session["email"],))
    user = cursor.fetchone()
    
    if not user:
        flash("User not found", "danger")
        return redirect(url_for("login"))
    
    user_id, name, email, subscription, expiry, reg_date = user
    
    # Get subscription details from payments
    cursor.execute("SELECT plan_type, created_at FROM payments WHERE user_id=? AND status='completed' ORDER BY created_at DESC LIMIT 1", (user_id,))
    payment = cursor.fetchone()
    
    plan_type = "Free"
    plan_start = None
    if payment:
        plan_type, plan_start = payment
    
    # Get active sessions
    cursor.execute("SELECT device_info, location, login_time FROM user_sessions WHERE user_id=? AND is_active=1 ORDER BY last_active DESC", (user_id,))
    active_sessions = cursor.fetchall()
    
    conn.close()
    
    # Calculate days remaining if subscribed
    days_remaining = 0
    if expiry and subscription == "paid":
        expiry_date = datetime.strptime(expiry, "%Y-%m-%d")
        days_remaining = (expiry_date - datetime.today()).days
        days_remaining = max(0, days_remaining)  # Negative values avoid
    
    return render_template("profile.html", 
                         user_name=name,
                         user_email=email,
                         user_id=user_id,
                         reg_date=reg_date,
                         subscription_plan=plan_type,
                         subscription_start=plan_start,
                         subscription_end=expiry,
                         days_remaining=days_remaining,
                         active_sessions=active_sessions)

# ---------------- RAZORPAY PAYMENT ROUTES ----------------
@app.route("/create_order", methods=["POST"])
def create_order():
    try:
        if "email" not in session:
            return jsonify({"error": "Login required"}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        plan = data.get("plan")
        
        # Plan details based on your pricing section
        if plan == "basic":
            amount = 300000  # ₹3000 in paise
            days = 30
            plan_name = "Basic"
        elif plan == "standard":
            amount = 350000  # ₹3500 in paise
            days = 30
            plan_name = "Standard"
        elif plan == "premium":
            amount = 600000  # ₹6000 in paise
            days = 60  # 2 months
            plan_name = "Premium"
        else:
            return jsonify({"error": "Invalid plan"}), 400
        
        # Create Razorpay order
        order_data = {
            "amount": amount,
            "currency": "INR",
            "receipt": f"order_{session['email']}_{int(datetime.now().timestamp())}",
            "notes": {
                "plan": plan,
                "email": session["email"],
                "days": days,
                "plan_name": plan_name
            }
        }
        
        try:
            order = razorpay_client.order.create(data=order_data)
            return jsonify({
                "id": order["id"],
                "amount": order["amount"],
                "currency": order["currency"]
            })
        except Exception as e:
            print(f"Razorpay Error: {e}")
            return jsonify({"error": "Payment gateway error. Please try again."}), 500
            
    except Exception as e:
        print(f"Server Error: {e}")
        return jsonify({"error": "Server error. Please try again."}), 500

@app.route("/verify_payment", methods=["POST"])
def verify_payment():
    try:
        if "email" not in session:
            return jsonify({"error": "Login required"}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No payment data received"}), 400
            
        payment_id = data.get("razorpay_payment_id")
        order_id = data.get("razorpay_order_id")
        signature = data.get("razorpay_signature")
        plan = data.get("plan")
        
        if not all([payment_id, order_id, signature, plan]):
            return jsonify({"error": "Missing payment information"}), 400
        
        # Verify payment signature
        params_dict = {
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }
        
        try:
            razorpay_client.utility.verify_payment_signature(params_dict)
            
            # Payment successful - get payment details
            payment = razorpay_client.payment.fetch(payment_id)
            
            # Set plan details based on plan type
            if plan == "basic":
                days = 30
                plan_name = "Basic"
            elif plan == "standard":
                days = 30
                plan_name = "Standard"
            elif plan == "premium":
                days = 60
                plan_name = "Premium"
            else:
                return jsonify({"error": "Invalid plan type"}), 400
            
            expiry = datetime.today() + timedelta(days=days)
            
            # Update user subscription
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET subscription='paid', subscription_expiry=? WHERE email=?",
                           (expiry.strftime("%Y-%m-%d"), session["email"]))
            
            # Save payment details
            cursor.execute("INSERT INTO payments (user_id, payment_id, order_id, amount, currency, status, plan_type) VALUES (?, ?, ?, ?, ?, ?, ?)",
                          (session["user_id"], payment_id, order_id, payment["amount"], payment["currency"], "completed", plan_name))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                "success": True, 
                "message": f"{plan_name} subscription activated until {expiry.strftime('%Y-%m-%d')}",
                "redirect": url_for("home")
            })
        
        except razorpay.errors.SignatureVerificationError:
            return jsonify({"error": "Payment verification failed. Please try again."}), 400
        except Exception as e:
            print(f"Payment verification error: {e}")
            return jsonify({"error": "Payment processing error. Please contact support."}), 500
            
    except Exception as e:
        print(f"Server error in verify_payment: {e}")
        return jsonify({"error": "Server error. Please try again."}), 500

# ---------------- Razorpay Webhook Route ----------------
@app.route("/razorpay_webhook", methods=['POST'])
def razorpay_webhook():
    try:
        # Get webhook data and signature
        webhook_body = request.get_data().decode('utf-8')
        webhook_signature = request.headers.get('X-Razorpay-Signature')
        
        # Verify signature
        razorpay_client.utility.verify_webhook_signature(
            webhook_body, webhook_signature, WEBHOOK_SECRET
        )
        
        # Signature verified successfully
        event_data = json.loads(webhook_body)
        event_type = event_data.get('event')
        
        # Process different event types
        if event_type == 'payment.captured':
            payment_data = event_data['payload']['payment']['entity']
            payment_id = payment_data['id']
            order_id = payment_data['order_id']
            amount = payment_data['amount']
            currency = payment_data['currency']
            status = payment_data['status']
            
            # Yahan aap payment successful hone par apna logic implement karein
            # Jaise database mein status update karna, email bhejna, etc.
            print(f"Payment successful: {payment_id}")
            
            # Update payment status in database
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("UPDATE payments SET status = ? WHERE payment_id = ?", 
                          ("completed", payment_id))
            conn.commit()
            conn.close()
            
        elif event_type == 'payment.failed':
            payment_data = event_data['payload']['payment']['entity']
            payment_id = payment_data['id']
            error_description = payment_data['error_description']
            
            # Failed payment handling
            print(f"Payment failed: {payment_id}, Reason: {error_description}")
            
            # Update payment status in database
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("UPDATE payments SET status = ? WHERE payment_id = ?", 
                          ("failed", payment_id))
            conn.commit()
            conn.close()
            
        elif event_type == 'refund.created':
            refund_data = event_data['payload']['refund']['entity']
            refund_id = refund_data['id']
            payment_id = refund_data['payment_id']
            amount = refund_data['amount']
            
            # Refund handling
            print(f"Refund created: {refund_id} for payment: {payment_id}")
            
            # Update payment status in database for refund
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("UPDATE payments SET status = ? WHERE payment_id = ?", 
                          ("refunded", payment_id))
            conn.commit()
            conn.close()
        
        return jsonify({'status': 'success'}), 200
        
    except razorpay.errors.SignatureVerificationError:
        # Invalid signature - reject the request
        return jsonify({'error': 'Invalid signature'}), 400
    except Exception as e:
        print(f"Webhook error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

# ---------------- BASIC PAGES ----------------
@app.route("/")
def home():
    return render_template("welovedoc.html")

# ---------------- PROTECTED TOOL ROUTES ----------------
@app.route("/esic-highlight")
def esic_highlight_page():
    if "email" not in session:
        flash("Login required to access this tool", "warning")
        return redirect(url_for("login"))

    if not check_subscription(session["email"]):
        flash("This feature is for paid users only", "danger")
        return redirect(url_for("pricing"))

    return render_template("esic-highlight.html")

@app.route("/pf-highlight")
def pf_highlight_page():
    if "email" not in session:
        flash("Login required to access this tool", "warning")
        return redirect(url_for("login"))

    if not check_subscription(session["email"]):
        flash("This feature is for paid users only", "danger")
        return redirect(url_for("pricing"))

    return render_template("pf-highlight.html")

# ---------------- PROCESS API ----------------
@app.route("/process", methods=["POST"])
def process():
    if "email" not in session or not check_subscription(session["email"]):
        return jsonify({"error": "Subscription required"}), 403

    try:
        pdf_file = request.files['pdf_file']
        excel_file = request.files['excel_file']
        mode = request.form.get("mode", "pf")

        if pdf_file.filename == '' or excel_file.filename == '':
            return jsonify({"error": "Please select both PDF and Excel files"}), 400

        pdf_filename = f"{uuid.uuid4()}_{secure_filename(pdf_file.filename)}"
        excel_filename = f"{uuid.uuid4()}_{secure_filename(excel_file.filename)}"

        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
        excel_path = os.path.join(app.config['UPLOAD_FOLDER'], excel_filename)

        pdf_file.save(pdf_path)
        excel_file.save(excel_path)

        # Call correct function
        if mode.lower() == "pf":
            output_pdf, not_found_excel = highlight_pf(
                pdf_path, excel_path, output_folder=app.config['RESULT_FOLDER']
            )
        else:
            output_pdf, not_found_excel = highlight_esic(
                pdf_path, excel_path, output_folder=app.config['RESULT_FOLDER']
            )

        response = {}
        if output_pdf:
            response["pdf_url"] = f"/download/{os.path.basename(output_pdf)}"
        if not_found_excel:
            response["excel_url"] = f"/download/{os.path.basename(not_found_excel)}"

        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory(app.config['RESULT_FOLDER'], filename, as_attachment=True)

# ---------------- OTHER TOOLS ROUTES ----------------
@app.route("/merge-pdf")
def merge_pdf():
    return render_template("merge-pdf.html")

@app.route("/split-pdf")
def split_pdf():
    return render_template("split-pdf.html")

@app.route("/stamp")
def stamp():
    return render_template("stamp.html")

@app.route("/compress-pdf")
def compress_pdf():
    return render_template("compress-pdf.html")

@app.route("/pdf-to-word")
def pdf_to_word():
    return render_template("pdf-to-word.html")

@app.route("/word-to-pdf")
def word_to_pdf():
    return render_template("word-to-pdf.html")

@app.route("/pdf-to-excel")
def pdf_to_excel():
    return render_template("pdf-to-excel.html")

@app.route("/excel-to-pdf")
def excel_to_pdf():
    return render_template("excel-to-pdf.html")

@app.route("/pdf-to-jpg")
def pdf_to_jpg():
    return render_template("pdf-to-jpg.html")

@app.route("/jpg-to-pdf")
def jpg_to_pdf():
    return render_template("jpg-to-pdf.html")

@app.route("/rotate-pdf")
def rotate_pdf():
    return render_template("rotate-pdf.html")

@app.route("/extract-pages")
def extract_pages():
    return render_template("extract-pages.html")

@app.route("/protect-pdf")
def protect_pdf():
    return render_template("protect-pdf.html")

@app.route("/all-tools")
def all_tools():
    return render_template("all-tools.html")

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/faq")
def faq():
    return render_template("faq.html")

@app.route("/privacy-policy")
def privacy_policy():
    return render_template("privacy-policy.html")

@app.route("/terms-of-service")
def terms_of_service():
    return render_template("terms-of-service.html")

@app.route("/check_session")
def check_session():
    if "email" in session:
        return jsonify({"logged_in": True, "email": session["email"], "name": session.get("user_name", "")})
    else:
        return jsonify({"logged_in": False})

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
