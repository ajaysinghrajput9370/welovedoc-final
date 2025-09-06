# file_manager.py — Fixed version
import os
import sqlite3
import json
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone

DB_NAME = "users.db"
DB_PATH = DB_NAME

# ---------------- DB helpers ----------------
def get_conn():
    return sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)

def init_db():
    """Create users table if not exists"""
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            subscription TEXT DEFAULT 'free',
            subscription_expiry TEXT,
            devices TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def ensure_schema():
    """Ensure important columns exist (safe on existing DB)."""
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in cursor.fetchall()]

    if "subscription" not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN subscription TEXT DEFAULT 'free'")
    if "subscription_expiry" not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN subscription_expiry TEXT")
    if "devices" not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN devices TEXT")
    if "created_at" not in cols:
        # Add column without default (SQLite limitation)
        cursor.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP")
        # Fill existing rows with current timestamp
        cursor.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")

    conn.commit()
    conn.close()

# ---------------- Initialize DB ----------------
ensure_schema()
init_db()

# ---------------- User CRUD ----------------
def signup_user(name, email, password, subscription="free"):
    email = (email or "").strip().lower()
    if not email or not password:
        return False

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email=?", (email,))
    if cursor.fetchone():
        conn.close()
        return False

    hashed_pw = generate_password_hash(password)
    cursor.execute("""
        INSERT INTO users (name, email, password, subscription, subscription_expiry, devices)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (name or "", email, hashed_pw, subscription or "free", None, json.dumps({})))
    conn.commit()
    conn.close()
    return True

def get_user_by_email(email):
    email = (email or "").strip().lower()
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, name, email, password, subscription, subscription_expiry, devices
        FROM users WHERE email=?
    """, (email,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "name": row[1] or "",
        "email": row[2] or "",
        "password": row[3] or "",
        "subscription": row[4] or "free",
        "subscription_expiry": row[5] or "",
        "devices": row[6] or "{}"
    }

# ---------------- Device / Login ----------------
def get_device_limit(subscription):
    s = (subscription or "").lower()
    if s == "basic":
        return 2
    elif s in ["standard", "premium"]:
        return 4
    return 1  # free default

def login_user(email, password, device_id):
    """Authenticate user and enforce device limit."""
    email = (email or "").strip().lower()
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, password, subscription, subscription_expiry, devices FROM users WHERE email=?",
        (email,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    user_id, hashed_pw, subscription, expiry, devices_json = row
    if not check_password_hash(hashed_pw, password):
        conn.close()
        return False

    # Handle devices
    try:
        devices = json.loads(devices_json or "{}")
    except:
        devices = {}
    
    limit = get_device_limit(subscription)
    
    # If device exists, allow login
    if device_id in devices:
        conn.close()
        return True
    
    # If device doesn't exist, check limit
    if len(devices) >= limit:
        # Remove oldest device if limit exceeded
        oldest_device = min(devices.items(), key=lambda x: x[1])[0] if devices else None
        if oldest_device:
            del devices[oldest_device]
    
    # Add new device
    devices[device_id] = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("UPDATE users SET devices=? WHERE id=?", (json.dumps(devices), user_id))
    conn.commit()
    conn.close()
    return True

def update_device_login(email, device_id):
    """Update device login timestamp."""
    email = (email or "").strip().lower()
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT devices FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    
    if row and row[0]:
        try:
            devices = json.loads(row[0])
            devices[device_id] = datetime.now(timezone.utc).isoformat()
            cursor.execute("UPDATE users SET devices=? WHERE email=?", (json.dumps(devices), email))
            conn.commit()
        except:
            pass
    
    conn.close()

# ---------------- Subscription logic ----------------
def parse_datetime_safe(s):
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    try:
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    except Exception:
        return None

def check_subscription(email):
    """Return True if user has active paid subscription."""
    u = get_user_by_email(email)
    if not u:
        return False
    sub = (u.get("subscription") or "free").lower()
    if sub == "free":
        return False
    expiry_dt = parse_datetime_safe(u.get("subscription_expiry"))
    if expiry_dt:
        now_utc = datetime.now(timezone.utc)
        return now_utc <= expiry_dt
    return True  # No expiry set → treat as active

def get_days_left(email):
    """Return integer days left for subscription (0 if expired or free)."""
    u = get_user_by_email(email)
    if not u:
        return 0
    expiry_dt = parse_datetime_safe(u.get("subscription_expiry"))
    if not expiry_dt:
        return 0
    now_utc = datetime.now(timezone.utc)
    delta = expiry_dt - now_utc
    return max(0, delta.days)

def get_subscription_details(email):
    u = get_user_by_email(email)
    if not u:
        return None
    expiry_dt = parse_datetime_safe(u.get("subscription_expiry"))
    return {
        "subscription": u.get("subscription") or "free",
        "subscription_expiry": expiry_dt
    }

def activate_subscription(email, plan, duration_months=1):
    """Activate or extend subscription with UTC-safe expiry."""
    email = (email or "").strip().lower()
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT subscription_expiry FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
        now_utc = datetime.now(timezone.utc)
        if row and row[0]:
            existing = parse_datetime_safe(row[0])
            base = existing if existing and existing > now_utc else now_utc
        else:
            base = now_utc

        new_expiry = base + timedelta(days=30 * max(1, int(duration_months)))
        expiry_str = new_expiry.isoformat()

        cursor.execute("""
            UPDATE users
            SET subscription=?, subscription_expiry=?
            WHERE email=?
        """, (plan or "premium", expiry_str, email))
        conn.commit()
        conn.close()
        print(f"✅ Subscription updated for {email}: {plan}, {expiry_str}")
        return True
    except Exception as e:
        print("❌ Error in activate_subscription:", e)
        return False

# ---------------- Admin helpers ----------------
def list_users(limit=100):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, name, email, subscription, subscription_expiry, devices, created_at
        FROM users ORDER BY created_at DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [{
        "id": r[0],
        "name": r[1] or "",
        "email": r[2] or "",
        "subscription": r[3] or "free",
        "subscription_expiry": r[4] or "",
        "devices": r[5] or "{}",
        "created_at": r[6] or ""
    } for r in rows]
