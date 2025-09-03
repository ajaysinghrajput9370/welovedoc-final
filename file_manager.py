import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

DB_NAME = "users.db"

# ---------------- User Management ----------------
def signup_user(email, password, subscription="free"):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    existing = cursor.fetchone()
    if existing:
        conn.close()
        return False
    
    hashed_pw = generate_password_hash(password)
    cursor.execute(
        "INSERT INTO users (name, email, password, subscription, subscription_expiry) VALUES (?, ?, ?, ?, ?)", 
        ("", email, hashed_pw, subscription, None)
    )
    conn.commit()
    conn.close()
    return True


def login_user(email, password, device_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password, subscription, subscription_expiry, devices FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return False
    
    user_id, hashed_pw, sub_type, expiry, devices = user
    if not check_password_hash(hashed_pw, password):
        conn.close()
        return False

    # Device check
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


def get_device_limit(subscription):
    if subscription == "basic":
        return 2
    elif subscription in ["standard", "premium"]:
        return 4
    return 1


def check_subscription(email):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT subscription, subscription_expiry FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return False
    sub_type, expiry = row
    
    if not expiry:
        return False

    # Compare only date, ignore time
    expiry_date = datetime.strptime(expiry, "%Y-%m-%d").date()
    today = datetime.today().date()

    return expiry_date >= today


def activate_subscription(email, plan, duration_months=1):
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Expiry = end of day after duration
        expiry_date = (datetime.now() + timedelta(days=30 * duration_months)).date()
        
        cursor.execute(
            "UPDATE users SET subscription=?, subscription_expiry=? WHERE email=?",
            (plan, expiry_date.strftime("%Y-%m-%d"), email)
        )
        conn.commit()
        
        cursor.execute("SELECT subscription, subscription_expiry FROM users WHERE email=?", (email,))
        result = cursor.fetchone()
        print(f"✅ Subscription updated in DB: {result}")
        
        conn.close()
        return True
        
    except Exception as e:
        print("❌ Error in activate_subscription:", str(e))
        return False
