import os
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, User   # db aur User model app.py se import

# ---------------- User Management ----------------

def signup_user(email, password, subscription="free"):
    """
    Register a new user.
    Default subscription = "free" until payment.
    """
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return False  # already exists

    hashed_password = generate_password_hash(password)
    new_user = User(email=email, password=hashed_password, subscription=subscription)
    db.session.add(new_user)
    db.session.commit()
    return True


def login_user(email, password):
    """
    Validate login credentials.
    """
    user = User.query.filter_by(email=email).first()
    if not user:
        return False
    return check_password_hash(user.password, password)


def check_subscription(user):
    """
    Check if user has an active subscription.
    """
    if not user:
        return False
    return user.subscription == "active"


def activate_subscription(email):
    """
    Activate subscription for a user (e.g., after payment).
    """
    user = User.query.filter_by(email=email).first()
    if user:
        user.subscription = "active"
        db.session.commit()
        return True
    return False


def deactivate_subscription(email):
    """
    Cancel or deactivate subscription.
    """
    user = User.query.filter_by(email=email).first()
    if user:
        user.subscription = "free"
        db.session.commit()
        return True
    return False


def get_user_by_email(email):
    """
    Fetch user by email.
    """
    return User.query.filter_by(email=email).first()


# ---------------- File Utility ----------------
def get_unique_filename(filename, folder, prefix="file"):
    """
    Generate a unique filename in the folder by appending numbers if needed.
    Example: file.pdf -> file1.pdf, file2.pdf, etc.
    """
    base, ext = os.path.splitext(filename)
    new_name = f"{prefix}_{base}{ext}"
    counter = 1
    while os.path.exists(os.path.join(folder, new_name)):
        new_name = f"{prefix}_{base}_{counter}{ext}"
        counter += 1
    return os.path.join(folder, new_name)
