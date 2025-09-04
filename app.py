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
from file_manager import check_subscription, activate_subscription, login_user

# ---------------- App Config ----------------
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['RESULT_FOLDER'] = 'results'
app.secret_key = "supersecretkey"   #⚠️ production में strong key रखो
app.permanent_session_lifetime = timedelta(days=30)

# Ensure folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['RESULT_FOLDER'], exist_ok=True)

# ---------------- Load ENV ----------------
load_dotenv()
razorpay_client = razorpay.Client(
    auth=(os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET"))
)

# ---------------- DB Setup ----------------
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            subscription TEXT DEFAULT 'free',
            subscription_expiry DATE,
            devices TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

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
            cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                           (name, email, hashed_pw))
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
        email = request.form["email"]
        password = request.form["password"]
        device_id = request.remote_addr  # simple device ID (IP)

        result = login_user(email, password, device_id)
        if result == True:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()
            cursor.execute("SELECT id, name FROM users WHERE email=?", (email,))
            user = cursor.fetchone()
            conn.close()

            session.permanent = True
            session["user_id"] = user[0]
            session["user_name"] = user[1]
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

    data = request.get_json()
    plan = data.get("plan")

    # Updated to match pricing.html amounts
    if plan == "basic":
        amount = 3000  # ₹3000 for Basic plan
        subscription_duration = 1  # 1 month
    elif plan == "standard":
        amount = 3500  # ₹3500 for Standard plan
        subscription_duration = 1  # 1 month
    elif plan == "premium":
        amount = 1     # ₹1 for Premium plan (test amount)
        subscription_duration = 2  # 2 months
    else:
        return jsonify({"error": "Invalid plan"}), 400

    # Store plan info in session BEFORE creating order
    session["selected_plan"] = plan
    session["selected_duration"] = subscription_duration
    session.modified = True

    order = razorpay_client.order.create({
        "amount": amount * 100,
        "currency": "INR", 
        "payment_capture": "1"
    })
    
    return jsonify(order)


@app.route("/payment_success", methods=["POST"])
def payment_success():
    try:
        print("Payment success endpoint called!")
        print("Form data received:", request.form)
        
        if "email" not in session:
            flash("Please login first", "danger")
            return redirect(url_for("login"))
            
        if "selected_plan" not in session:
            flash("Invalid payment session", "danger")
            return redirect(url_for("pricing"))

        plan = session["selected_plan"]
        duration = session.get("selected_duration", 1)
        email = session["email"]
        
        print(f"Activating {plan} plan for {email} with {duration} months duration")
        
        # Manual subscription activation (bypass Razorpay verification for testing)
        if activate_subscription(email, plan, duration):
            flash("✅ Subscription Activated Successfully!", "success")
            print("Subscription activated in database")
        else:
            flash("❌ Database error activating subscription", "danger")
            print("Failed to activate subscription in database")
            
        # Clear session data
        session.pop("selected_plan", None)
        session.pop("selected_duration", None)
        
        return redirect(url_for("home"))
        
    except Exception as e:
        print("Error in payment_success:", str(e))
        flash("Payment processing error occurred", "danger")
        return redirect(url_for("pricing"))


# Add this TEST route for immediate testing
@app.route("/test_payment/<plan>")
def test_payment(plan):
    if "email" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("login"))
    
    email = session["email"]
    
    if plan == "basic":
        duration = 1
    elif plan == "standard":
        duration = 1
    elif plan == "premium":
        duration = 2
    else:
        flash("Invalid plan", "danger")
        return redirect(url_for("pricing"))
    
    if activate_subscription(email, plan, duration):
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
    key_id = os.getenv("RAZORPAY_KEY_ID")
    return render_template("pricing.html", razorpay_key_id=key_id)

# ---------------- PROTECTED TOOL ROUTES ----------------
@app.route("/esic-highlight")
def esic_highlight_page():
    if "email" not in session:
        flash("Login required", "warning")
        return redirect(url_for("login"))

    if not check_subscription(session["email"]):
        flash("This feature is for paid users only", "danger")
        return redirect(url_for("pricing"))

    return render_template("esic-highlight.html")


@app.route("/pf-highlight")
def pf_highlight_page():
    if "email" not in session:
        flash("Login required", "warning")
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

        if mode.lower() == "pf":
            output_pdf, not_found_excel = highlight_pf(pdf_path, excel_path, output_folder=app.config['RESULT_FOLDER'])
        else:
            output_pdf, not_found_excel = highlight_esic(pdf_path, excel_path, output_folder=app.config['RESULT_FOLDER'])

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

# ---------------- MAIN ----------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
