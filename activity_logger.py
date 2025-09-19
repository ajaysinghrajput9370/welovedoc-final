# activity_logger.py
import json
from datetime import datetime, timezone

LOG_FILE = "user_activity.log"  # is file me activity save hogi

def log_activity(user_email, tool_name, action="used tool"):
    """User ki activity ko record karega."""
    entry = {
        "email": user_email,
        "tool": tool_name,
        "action": action,
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    }

    # file me save karo
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

    print("✅ Activity logged:", entry)

def read_logs(limit=50):
    """Last activities dekhne ke liye"""
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
        return [json.loads(line.strip()) for line in lines]
    except FileNotFoundError:
        return []
