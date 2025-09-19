# file_manager.py — PostgreSQL (SQLAlchemy) version with subscription + device limit + duration
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import IntegrityError

# ---------------- DB Setup ----------------
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/dbname")
engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ---------------- Plan Config ----------------
PLAN_DEVICE_LIMIT = {
    "free": 1,
    "basic": 2,
    "standard": 4,
    "premium": 4
}

PLAN_DURATION_MONTHS = {
    "free": 0,
    "basic": 1,
    "standard": 1,
    "premium": 2
}

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    subscription = Column(String, default="free")
    subscription_expiry = Column(DateTime(timezone=True), nullable=True)   # ✅ timezone-aware
    devices = Column(Text, default="{}")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))  # ✅ UTC safe

class AccessLog(Base):
    __tablename__ = "access_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, index=True)
    tool = Column(String, index=True)
    action = Column(String)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

# ---------------- Schema Init ----------------
def ensure_schema():
    try:
        Base.metadata.create_all(engine)
        print("✅ Database schema ensured.")
    except Exception as e:
        print("❌ Error ensuring schema:", e)
# ---------------- User CRUD ----------------
def signup_user(name, email, password, subscription="free"):
    email = (email or "").strip().lower()
    if not email or not password:
        return False
    db = SessionLocal()
    try:
        hashed_pw = generate_password_hash(password)
        new_user = User(
            name=name or "",
            email=email,
            password=hashed_pw,
            subscription=subscription or "free",
            subscription_expiry=None,
            devices=json.dumps({})
        )
        db.add(new_user)
        db.commit()
        return True
    except IntegrityError:
        db.rollback()
        return False
    finally:
        db.close()

def get_user_by_email(email):
    email = (email or "").strip().lower()
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    db.close()
    if not user:
        return None
    return {
        "id": user.id,
        "name": user.name or "",
        "email": user.email or "",
        "password": user.password or "",
        "subscription": user.subscription or "free",
        "subscription_expiry": user.subscription_expiry.isoformat() if user.subscription_expiry else "",
        "devices": user.devices or "{}"
    }

# ---------------- Device / Login ----------------
def get_device_limit(subscription):
    return PLAN_DEVICE_LIMIT.get((subscription or "free").lower(), 1)

def login_user(email, password, device_id):
    """Authenticate user and enforce device limit."""
    email = (email or "").strip().lower()
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        db.close()
        return False
    if not check_password_hash(user.password, password):
        db.close()
        return False

    try:
        devices = json.loads(user.devices or "{}")
    except:
        devices = {}

    limit = get_device_limit(user.subscription)
    if device_id in devices:
        log_activity(email, "login", "existing device")
        db.close()
        return True

    if len(devices) >= limit:
        oldest_device = min(devices.items(), key=lambda x: x[1])[0] if devices else None
        if oldest_device:
            del devices[oldest_device]

    devices[device_id] = datetime.now(timezone.utc).isoformat()
    user.devices = json.dumps(devices)
    db.commit()

    log_activity(email, "login", f"new device {device_id}")
    db.close()
    return True

# ---------------- Subscription logic ----------------
def parse_datetime_safe(s):
    if not s:
        return None
    if isinstance(s, datetime):
        return s if s.tzinfo else s.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(s))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None

def check_subscription(email):
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
    return False

def get_days_left(email):
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
    sub = (u.get("subscription") or "free").lower()
    return {
        "subscription": sub,
        "subscription_expiry": expiry_dt,
        "device_limit": get_device_limit(sub),
        "days_left": get_days_left(email)
    }

def activate_subscription(email, plan):
    """Activate or extend subscription based on PLAN_DURATION_MONTHS."""
    email = (email or "").strip().lower()
    plan = (plan or "free").lower()
    months = PLAN_DURATION_MONTHS.get(plan, 0)
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        db.close()
        return False

    now_utc = datetime.now(timezone.utc)
    existing = parse_datetime_safe(user.subscription_expiry)
    base = existing if existing and existing > now_utc else now_utc
    if months > 0:
        new_expiry = base + timedelta(days=30 * months)
        user.subscription = plan
        user.subscription_expiry = new_expiry
    else:
        user.subscription = "free"
        user.subscription_expiry = None

    try:
        db.commit()
        log_activity(email, "subscription", f"activated {plan}")
        return True
    except Exception:
        db.rollback()
        return False
    finally:
        db.close()

# ---------------- Activity helpers ----------------
def log_activity(user_email, tool, action):
    db = SessionLocal()
    try:
        entry = AccessLog(user_email=user_email, tool=tool, action=action)
        db.add(entry)
        db.commit()
    except Exception as e:
        db.rollback()
        print("log_activity error:", e)
    finally:
        db.close()

def get_recent_activity(limit=50):
    db = SessionLocal()
    try:
        rows = db.query(AccessLog).order_by(AccessLog.created_at.desc()).limit(limit).all()
        return [
            {
                "email": r.user_email,
                "tool": r.tool,
                "action": r.action,
                "time": r.created_at.isoformat()
            }
            for r in rows
        ]
    finally:
        db.close()
