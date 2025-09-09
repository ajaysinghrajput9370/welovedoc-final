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
    devices = Column(Text, default="{}")  # JSON {device_id: timestamp_iso}
    created_at = Column(DateTime, default=datetime.utcnow)

# ---------------- Schema Init ----------------
def ensure_schema():
    """Ensure all database tables exist."""
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
    devices = Column(Text, default="{}")  # JSON {device_id: timestamp_iso}
    created_at = Column(DateTime, default=datetime.utcnow)

# ---------------- Schema Init ----------------
def ensure_schema():
    """Ensure all database tables exist."""
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
    """Authenticate user and enforce device limit + plan expiry."""
    email = (email or "").strip().lower()
    db = SessionLocal()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        db.close()
        return False
    if not check_password_hash(user.password, password):
        db.close()
        return False

    # Check subscription expiry
    if user.subscription != "free":
        now_utc = datetime.now(timezone.utc)
        expiry_dt = user.subscription_expiry
        if expiry_dt and expiry_dt.tzinfo is None:
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
        if not expiry_dt or now_utc > expiry_dt:
            # Subscription expired → revert to free
            user.subscription = "free"
            user.subscription_expiry = None
            user.devices = json.dumps({})
            db.commit()

    # Load devices
    try:
        devices = json.loads(user.devices or "{}")
    except:
        devices = {}

    limit = get_device_limit(user.subscription)

    # Allow login if device already registered
    if device_id in devices:
        db.close()
        return True

    # Enforce device limit
    if len(devices) >= limit:
        return False  # ❌ deny login if limit exceeded

    # Register new device
    devices[device_id] = datetime.now(timezone.utc).isoformat()
    user.devices = json.dumps(devices)
    db.commit()
    db.close()
    return True
