# file_manager.py — PostgreSQL (SQLAlchemy) version with subscription & device limit fix
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

# ---------------- Device Limits per Plan ----------------
PLAN_DEVICE_LIMIT = {
    "free": 1,
    "basic": 2,
    "standard": 4,
    "premium": 4
}

# Number of months to add for a given plan when purchased/activated
PLAN_DURATION_MONTHS = {
    "free": 0,
    "basic": 1,
    "standard": 1,
    "premium": 2
}

# ---------------- Models ----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    subscription = Column(String, default="free")
    subscription_expiry = Column(DateTime, nullable=True)
    devices = Column(Text, default="{}")  # JSON string: {device_id: timestamp_iso}
    created_at = Column(DateTime, default=datetime.utcnow)

# ---------------- Schema Init ----------------
def ensure_schema():
    """Ensure all database tables exist."""
    try:
        Base.metadata.create_all(engine)
        print("✅ Database schema ensured.")
    except Exception as e:
        print("❌ Error ensuring schema:", e)

# ---------------- Helpers ----------------
def _now_utc():
    return datetime.now(timezone.utc)

def parse_dt(dt):
    """Return timezone-aware datetime or None. Accepts ISO string or datetime."""
    if not dt:
        return None
    if isinstance(dt, str):
        try:
            # parse simple ISO formats
            d = datetime.fromisoformat(dt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d
        except Exception:
            return None
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    return None

# ---------------- User CRUD ----------------
def signup_user(name, email, password, subscription="free"):
    """
    Create a new user. Returns True on success, False if email already exists or input invalid.
    """
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
    except Exception:
        db.rollback()
        return False
    finally:
        db.close()

def get_user_by_email(email):
    """
    Returns a dict representation of the user or None.
    """
    email = (email or "").strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return None
        return {
            "id": user.id,
            "name": user.name or "",
            "email": user.email or "",
            "password": user.password or "",
            "subscription": user.subscription or "free",
            "subscription_expiry": user.subscription_expiry.isoformat() if user.subscription_expiry else "",
            "devices": user.devices or "{}",
            "created_at": user.created_at.isoformat() if user.created_at else ""
        }
    finally:
        db.close()
# ---------------- Device / Login / Subscription ----------------

def get_device_limit(subscription):
    """Return the device limit for a subscription plan."""
    return PLAN_DEVICE_LIMIT.get((subscription or "free").lower(), 1)

def login_user(email, password, device_id):
    """
    Authenticate user and enforce device limit + subscription expiry.
    Returns True if login allowed, False otherwise.
    """
    email = (email or "").strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return False
        if not check_password_hash(user.password, password):
            return False

        # Normalize expiry datetime
        if user.subscription_expiry:
            user.subscription_expiry = parse_dt(user.subscription_expiry)

        # Check subscription expiry and downgrade if needed
        if user.subscription and user.subscription.lower() != "free":
            now_utc = _now_utc()
            expiry_dt = user.subscription_expiry
            if not expiry_dt or now_utc > expiry_dt:
                # Subscription expired -> revert to free
                user.subscription = "free"
                user.subscription_expiry = None
                user.devices = json.dumps({})
                db.commit()

        # Load devices JSON
        try:
            devices = json.loads(user.devices or "{}")
            if not isinstance(devices, dict):
                devices = {}
        except Exception:
            devices = {}

        limit = get_device_limit(user.subscription)

        # Allow login if device already registered
        if device_id in devices:
            return True

        # Enforce device limit
        if len(devices) >= limit:
            return False

        # Register new device
        devices[device_id] = _now_utc().isoformat()
        user.devices = json.dumps(devices)
        db.commit()
        return True
    finally:
        db.close()

def unregister_device(email, device_id):
    """
    Remove a registered device (e.g. user logs out from a device).
    Returns True if removed/updated, False otherwise.
    """
    email = (email or "").strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return False
        try:
            devices = json.loads(user.devices or "{}")
            if device_id in devices:
                devices.pop(device_id, None)
                user.devices = json.dumps(devices)
                db.commit()
        except Exception:
            user.devices = json.dumps({})
            db.commit()
        return True
    finally:
        db.close()

def reset_devices(email):
    """
    Clear all registered devices for a user (e.g. admin action or after downgrade).
    """
    email = (email or "").strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return False
        user.devices = json.dumps({})
        db.commit()
        return True
    finally:
        db.close()

# ---------------- Subscription Management ----------------
def save_subscription(email, plan):
    """
    Activate or extend subscription for a user.
    plan should be one of keys in PLAN_DURATION_MONTHS (basic/standard/premium).
    Returns True on success, False otherwise.
    """
    email = (email or "").strip().lower()
    plan = (plan or "").strip().lower()
    if not plan or plan not in PLAN_DURATION_MONTHS or PLAN_DURATION_MONTHS.get(plan, 0) <= 0:
        return False

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return False

        months = PLAN_DURATION_MONTHS.get(plan, 0)
        now_utc = _now_utc()

        # If existing expiry is in future, extend from there; otherwise start from now
        existing = parse_dt(user.subscription_expiry)
        if existing and existing > now_utc:
            new_expiry = existing + timedelta(days=30 * months)
        else:
            new_expiry = now_utc + timedelta(days=30 * months)

        user.subscription = plan
        user.subscription_expiry = new_expiry
        # keep existing devices (do not reset) — device limit will be enforced on next login
        db.commit()
        return True
    finally:
        db.close()

def check_subscription(email):
    """
    Return True if user has an active (non-free) subscription that has not expired.
    Otherwise return False.
    """
    email = (email or "").strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return False
        if not user.subscription or user.subscription.lower() == "free":
            return False
        expiry = parse_dt(user.subscription_expiry)
        if not expiry:
            return False
        if _now_utc() > expiry:
            return False
        return True
    finally:
        db.close()

# ---------------- Utility / Admin ----------------
def list_users(limit=100):
    """Return list of user emails (basic)."""
    db = SessionLocal()
    try:
        rows = db.query(User).order_by(User.id.desc()).limit(limit).all()
        return [{"id": r.id, "email": r.email, "subscription": r.subscription,
                 "expiry": r.subscription_expiry.isoformat() if r.subscription_expiry else "",
                 "devices": r.devices or "{}"} for r in rows]
    finally:
        db.close()

def delete_user(email):
    """Delete user by email. Returns True if deleted."""
    email = (email or "").strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return False
        db.delete(user)
        db.commit()
        return True
    finally:
        db.close()
