import sqlite3

# naya database file banega agar delete ho gaya hai
conn = sqlite3.connect("database.db")
c = conn.cursor()

# users table
c.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    referral_code TEXT,
    referred_by TEXT,
    subscription_plan TEXT DEFAULT 'free',
    subscription_expiry DATE,
    devices_allowed INTEGER DEFAULT 1,
    devices_used INTEGER DEFAULT 0
)''')

# tasks table
c.execute('''CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    task_type TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)''')

# payments table
c.execute('''CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    amount REAL,
    plan TEXT,
    payment_id TEXT,
    status TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)''')

conn.commit()
conn.close()

print("✅ Database aur tables dobara create ho gaye!")
