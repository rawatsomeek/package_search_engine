"""
Migration: Create admin_requests table
Run once: python migrate_admin_requests.py
"""
import os
import psycopg2

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise Exception("DATABASE_URL env var not set")

SQL = """
CREATE TABLE IF NOT EXISTS admin_requests (
    id SERIAL PRIMARY KEY,
    request_type VARCHAR(20) NOT NULL DEFAULT 'signup'
        CHECK (request_type IN ('signup', 'forgot_password', 'forgot_username')),
    username VARCHAR(100),
    password_hash VARCHAR(255),
    pin_hash VARCHAR(255),
    company VARCHAR(200),
    email VARCHAR(200) NOT NULL,
    full_name VARCHAR(200),
    phone VARCHAR(30),
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    approve_token VARCHAR(128) NOT NULL UNIQUE,
    reject_token  VARCHAR(128) NOT NULL UNIQUE,
    reset_token   VARCHAR(128) UNIQUE,
    reset_token_expires_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    processed_at TIMESTAMP,
    owner_note TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_admin_requests_approve_token ON admin_requests(approve_token);
CREATE INDEX IF NOT EXISTS idx_admin_requests_reject_token  ON admin_requests(reject_token);
CREATE INDEX IF NOT EXISTS idx_admin_requests_reset_token   ON admin_requests(reset_token) WHERE reset_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_admin_requests_email         ON admin_requests(email);
CREATE INDEX IF NOT EXISTS idx_admin_requests_status        ON admin_requests(status);
"""

conn = psycopg2.connect(DATABASE_URL)
cur = conn.cursor()
cur.execute(SQL)
conn.commit()
conn.close()
print("✅ admin_requests table created successfully.")