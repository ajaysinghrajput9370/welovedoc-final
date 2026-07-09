# file_manager.py — PostgreSQL (SQLAlchemy) with is_disabled + UTC-aware timezone
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
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
    subscription_expiry = Column(DateTime, nullable=True)
    devices = Column(Text, default="{}")
    is_disabled = Column(Boolean, default=False)          # NEW
    created_at = Column(DateTime, default=datetime.utcnow)

# ---------------- Schema Init ----------------
def ensure_schema():
    try:
        Base.metadata.create_all(engine)
        print("✅ Database schema ensured.")
    except Exception as e:
        print("❌ Error ensuring schema:", e)

# ---------------- Helpers: UTC-aware datetime ----------------
def parse_datetime_safe(value):
    """Convert any datetime to UTC-aware, assume naive as UTC."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            # treat naive as UTC
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return None

def now_utc():
    return datetime.now(timezone.utc)

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
            devices=json.dumps({}),
            is_disabled=False
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
        "devices": user.devices or "{}",
        "is_disabled": user.is_disabled if user.is_disabled is not None else False
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
        db.close()
        return True

    if len(devices) >= limit:
        oldest_device = min(devices.items(), key=lambda x: x[1])[0] if devices else None
        if oldest_device:
            del devices[oldest_device]

    devices[device_id] = now_utc().isoformat()
    user.devices = json.dumps(devices)
    db.commit()
    db.close()
    return True

def update_device_login(email, device_id):
    """Update device login timestamp for an existing device."""
    email = (email or "").strip().lower()
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if not user:
            return False
        try:
            devices = json.loads(user.devices or "{}")
            devices[device_id] = now_utc().isoformat()
            user.devices = json.dumps(devices)
            db.commit()
            return True
        except Exception:
            db.rollback()
            return False
    finally:
        db.close()

# ---------------- Subscription logic (core) ----------------
def is_subscription_active(email):
    """
    Returns True if the user has an active paid subscription,
    considering is_disabled, plan, and expiry.
    """
    user = get_user_by_email(email)
    if not user:
        return False

    # 1. Disabled → inactive
    if user.get("is_disabled", False):
        return False

    # 2. Free plan → inactive
    sub = (user.get("subscription") or "free").lower()
    if sub == "free":
        return False

    # 3. Check expiry
    expiry_str = user.get("subscription_expiry")
    if not expiry_str:
        return False
    expiry_dt = parse_datetime_safe(expiry_str)
    if expiry_dt is None:
        return False
    return now_utc() <= expiry_dt

def check_subscription(email):
    """Backward‑compatible alias for is_subscription_active."""
    return is_subscription_active(email)

def get_days_left(email):
    user = get_user_by_email(email)
    if not user:
        return 0
    expiry_dt = parse_datetime_safe(user.get("subscription_expiry"))
    if not expiry_dt:
        return 0
    delta = expiry_dt - now_utc()
    return max(0, delta.days)

def get_subscription_details(email):
    user = get_user_by_email(email)
    if not user:
        return None
    sub = (user.get("subscription") or "free").lower()
    expiry_dt = parse_datetime_safe(user.get("subscription_expiry"))
    return {
        "subscription": sub,
        "subscription_expiry": expiry_dt,
        "device_limit": get_device_limit(sub),
        "days_left": get_days_left(email),
        "is_disabled": user.get("is_disabled", False)
    }

def activate_subscription(email, plan="free"):
    """
    Activate or extend subscription.
    For paid plans: sets is_disabled=False and updates expiry.
    For free plan: clears expiry and keeps is_disabled unchanged (but set to False?).
    """
    email = (email or "").strip().lower()
    plan = (plan or "free").lower()
    months = PLAN_DURATION_MONTHS.get(plan, 0)
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        db.close()
        return False

    now = now_utc()
    existing = parse_datetime_safe(user.subscription_expiry)
    base = existing if existing and existing > now else now

    if months > 0:
        new_expiry = base + timedelta(days=30 * months)
        user.subscription = plan
        user.subscription_expiry = new_expiry
        user.is_disabled = False          # ensure enabled on payment
    else:
        user.subscription = "free"
        user.subscription_expiry = None
        # user.is_disabled remains as is (admin can still disable a free user? but no need)
        # We'll set it False for consistency.
        user.is_disabled = False

    try:
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False
    finally:
        db.close()

# ---------------- Admin helpers ----------------
def list_users(limit=100):
    db = SessionLocal()
    rows = db.query(User).order_by(User.created_at.desc()).limit(limit).all()
    users = []
    for u in rows:
        users.append({
            "id": u.id,
            "name": u.name or "",
            "email": u.email or "",
            "subscription": u.subscription or "free",
            "subscription_expiry": u.subscription_expiry.isoformat() if u.subscription_expiry else "",
            "devices": u.devices or "{}",
            "is_disabled": u.is_disabled if u.is_disabled is not None else False,
            "created_at": u.created_at.isoformat() if u.created_at else ""
        })
    db.close()
    return users

def set_user_disabled(user_id, disabled):
    """Set is_disabled flag for a user."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False
        user.is_disabled = disabled
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False
    finally:
        db.close()
