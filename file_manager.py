import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

DB_NAME = "users.db"

# ---------------- User Signup ----------------
def signup_user(email, password, subscription="free"):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    if cursor.fetchone():
        conn.close()
        return False  # User already exists

    hashed_pw = generate_password_hash(password)
    cursor.execute("""
        INSERT INTO users (name, email, password, subscription, subscription_expiry)
        VALUES (?, ?, ?, ?, ?)
    """, ("", email, hashed_pw, subscription, None))
    
    conn.commit()
    conn.close()
    return True

# ---------------- Login with Device Limit Check ----------------
def login_user(email, password, device_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, password, subscription, subscription_expiry, devices
        FROM users WHERE email=?
    """, (email,))
    
    user = cursor.fetchone()
    if not user:
        conn.close()
        return False

    user_id, hashed_pw, sub_type, expiry, devices = user

    if not check_password_hash(hashed_pw, password):
        conn.close()
        return False

    # Device Management
    devices_list = devices.split(",") if devices else []
    if device_id not in devices_list:
        if len(devices_list) >= get_device_limit(sub_type):
            conn.close()
            return "device_limit"
        devices_list.append(device_id)
        cursor.execute("UPDATE users SET devices=? WHERE id=?", (",".join(devices_list), user_id))
        conn.commit()

    conn.close()
    return True

# ---------------- Device Limit Per Plan ----------------
def get_device_limit(subscription):
    if subscription == "basic":
        return 1
    elif subscription == "standard":
        return 2
    elif subscription == "premium":
        return 3
    return 1  # Free plan default
# ---------------- Subscription Check ----------------
def check_subscription(email):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT subscription, subscription_expiry FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return False

    sub_type, expiry = row

    # Free users never allowed
    if sub_type == "free" or not expiry:
        return False

    try:
        # Handle both datetime and date-only formats
        expiry_date = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                expiry_date = datetime.strptime(expiry, fmt)
                break
            except ValueError:
                continue

        if expiry_date and expiry_date >= datetime.now():
            return True
    except Exception as e:
        print("⚠️ Date parse error in check_subscription:", e)

    return False

# ---------------- Subscription Activation ----------------
def activate_subscription(email, plan, duration_months=1):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Calculate new expiry
        new_expiry = datetime.now() + timedelta(days=30 * duration_months)
        expiry_str = new_expiry.strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            UPDATE users
            SET subscription=?, subscription_expiry=?
            WHERE email=?
        """, (plan, expiry_str, email))
        conn.commit()

        # Verify update
        cursor.execute("SELECT subscription, subscription_expiry FROM users WHERE email=?", (email,))
        result = cursor.fetchone()
        print(f"✅ Subscription updated for {email}: {result}")

        conn.close()
        return True

    except Exception as e:
        print("❌ Error in activate_subscription:", str(e))
        return False
