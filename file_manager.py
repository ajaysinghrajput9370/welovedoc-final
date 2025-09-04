# file_manager.py
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

DB_NAME = "users.db"
DB_PATH = DB_NAME  # change if you store elsewhere

# ---------------- DB helpers & init/migration ----------------
def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    """Create users table if not exists (with correct columns). Safe to call repeatedly."""
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
            devices TEXT
        )
    """)
    conn.commit()
    conn.close()

def ensure_schema():
    """
    Ensure important columns exist (useful if DB was created earlier without columns).
    Adds columns if missing. Safe to run on existing DB.
    """
    conn = get_conn()
    cursor = conn.cursor()

    # Get existing columns
    cursor.execute("PRAGMA table_info(users)")
    cols = [row[1] for row in cursor.fetchall()]

    if "subscription" not in cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN subscription TEXT DEFAULT 'free'")
        except Exception:
            pass
    if "subscription_expiry" not in cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN subscription_expiry TEXT")
        except Exception:
            pass
    if "devices" not in cols:
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN devices TEXT")
        except Exception:
            pass

    conn.commit()
    conn.close()

# initialize on import
ensure_schema()
init_db()

# ---------------- User CRUD ----------------
def signup_user(name, email, password, subscription="free"):
    """Register new user. Returns True on success, False if email exists."""
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
    """, (name or "", email, hashed_pw, subscription, None, None))
    conn.commit()
    conn.close()
    return True

def get_user_by_email(email):
    email = (email or "").strip().lower()
    conn = get_conn()
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

# ---------------- Device / Login ----------------
def get_device_limit(subscription):
    """Return device limit per plan (adjust as required)."""
    s = (subscription or "").lower()
    if s == "basic":
        return 1
    elif s == "standard":
        return 2
    elif s == "premium":
        return 3
    return 1  # default for free

def login_user(email, password, device_id):
    """
    Authenticate user and enforce device limit.
    Returns:
      - True on successful login
      - "device_limit" if device limit reached
      - False on invalid credentials
    """
    email = (email or "").strip().lower()
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id, password, subscription, subscription_expiry, devices FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    user_id, hashed_pw, subscription, expiry, devices = row

    if not check_password_hash(hashed_pw, password):
        conn.close()
        return False

    devices_list = [d for d in (devices or "").split(",") if d]
    if device_id not in devices_list:
        limit = get_device_limit(subscription)
        if len(devices_list) >= limit:
            conn.close()
            return "device_limit"
        devices_list.append(device_id)
        cursor.execute("UPDATE users SET devices=? WHERE id=?", (",".join(devices_list), user_id))
        conn.commit()

    conn.close()
    return True

# ---------------- Subscription logic ----------------
def parse_datetime_safe(s):
    """Try multiple formats; return datetime or None."""
    if not s:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue
    # try fromisoformat as last resort
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

def check_subscription(email):
    """
    Boolean check: returns True if user has an active paid subscription (non-free and not expired).
    This is used by web routes to allow/deny access.
    """
    u = get_user_by_email(email)
    if not u:
        return False
    sub = (u.get("subscription") or "free").lower()
    if sub in ("free", "", None):
        return False
    expiry = u.get("subscription_expiry")
    expiry_dt = parse_datetime_safe(expiry)
    if expiry_dt:
        return expiry_dt >= datetime.now()
    # If expiry missing but subscription set to paid, treat as active (you may change this behavior)
    return True

def get_subscription_details(email):
    """Return (subscription, expiry_datetime_or_None) for UI or admin pages."""
    u = get_user_by_email(email)
    if not u:
        return None
    expiry_dt = parse_datetime_safe(u.get("subscription_expiry"))
    return {
        "subscription": u.get("subscription"),
        "subscription_expiry": expiry_dt
    }

def activate_subscription(email, plan, duration_months=1):
    """
    Activate/extend subscription for `email`.
    - plan: string like 'premium'/'standard'/'basic'
    - duration_months: integer months to add (will set expiry to now + duration)
    Returns True on success, False on error.
    """
    email = (email or "").strip().lower()
    try:
        conn = get_conn()
        cursor = conn.cursor()

        # compute new expiry: If user already has expiry in future, extend from that expiry
        cursor.execute("SELECT subscription_expiry FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
        now = datetime.now()
        if row and row[0]:
            existing = parse_datetime_safe(row[0])
            if existing and existing > now:
                base = existing
            else:
                base = now
        else:
            base = now

        new_expiry = base + timedelta(days=30 * max(1, int(duration_months)))
        expiry_str = new_expiry.strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            UPDATE users
            SET subscription=?, subscription_expiry=?
            WHERE email=?
        """, (plan, expiry_str, email))
        conn.commit()

        # verify
        cursor.execute("SELECT subscription, subscription_expiry FROM users WHERE email=?", (email,))
        updated = cursor.fetchone()
        conn.close()
        print(f"✅ Subscription updated for {email}: {updated}")
        return True
    except Exception as e:
        print("❌ Error in activate_subscription:", e)
        return False

# ---------------- Admin helpers / debug ----------------
def list_users(limit=100):
    """Return list of users for debugging/admin UI."""
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, email, subscription, subscription_expiry, devices FROM users LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            "id": r[0],
            "name": r[1],
            "email": r[2],
            "subscription": r[3],
            "subscription_expiry": r[4],
            "devices": r[5]
        })
    return out

# ---------------- Quick manual helpers (one-off usage) ----------------
def add_device_to_user(email, device_id):
    """Manual helper for testing."""
    u = get_user_by_email(email)
    if not u:
        return False
    devices = [d for d in (u.get("devices") or "").split(",") if d]
    if device_id in devices:
        return True
    devices.append(device_id)
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET devices=? WHERE email=?", (",".join(devices), email))
    conn.commit()
    conn.close()
    return True
