-- ============================================
-- AD Self-Service Password Reset Portal
-- PostgreSQL Database Schema
-- ============================================
-- Run this file once to initialize the database:
--   psql -U portal_user -d ad_password_reset -f server/db/schema.sql

-- Users table (tracks enrollment state, not AD credentials)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    display_name VARCHAR(255),
    email VARCHAR(255),
    is_enrolled BOOLEAN DEFAULT FALSE,
    totp_secret TEXT,                       -- AES-256-GCM encrypted
    totp_enabled BOOLEAN DEFAULT FALSE,
    security_questions_set BOOLEAN DEFAULT FALSE,
    locked BOOLEAN DEFAULT FALSE,
    failed_attempts INTEGER DEFAULT 0,
    last_failed_attempt TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Predefined security questions
CREATE TABLE IF NOT EXISTS security_questions (
    id SERIAL PRIMARY KEY,
    question_text TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

-- User's selected questions and bcrypt-hashed answers
CREATE TABLE IF NOT EXISTS user_security_answers (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    question_id INTEGER REFERENCES security_questions(id),
    answer_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, question_id)
);

-- Audit log for all security events
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(100),
    action VARCHAR(50) NOT NULL,
    method VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN DEFAULT TRUE,
    details TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Used reset tokens (to prevent replay)
CREATE TABLE IF NOT EXISTS used_reset_tokens (
    id SERIAL PRIMARY KEY,
    token_jti VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    used_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL
);

-- Last accepted TOTP time step; codes at or before it are rejected (replay protection)
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_used_step BIGINT;

-- Bumped on logout/lock to revoke all outstanding refresh tokens
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;

-- New authenticator awaiting verification (AES-256-GCM encrypted); the active one keeps working meanwhile
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending_secret TEXT;

-- Admin-managed words/phrases that new passwords may not contain (or equal)
CREATE TABLE IF NOT EXISTS password_exceptions (
    id SERIAL PRIMARY KEY,
    term VARCHAR(128) NOT NULL,
    match_type VARCHAR(10) NOT NULL DEFAULT 'contains' CHECK (match_type IN ('contains', 'exact')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_password_exceptions_term ON password_exceptions (LOWER(term));

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_audit_log_username ON audit_log(username);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_used_reset_tokens_jti ON used_reset_tokens(token_jti);
CREATE INDEX IF NOT EXISTS idx_used_reset_tokens_expires ON used_reset_tokens(expires_at);

-- Seed default security questions (only into an empty table, so re-running is safe)
INSERT INTO security_questions (question_text, sort_order)
SELECT q.question_text, q.sort_order FROM (VALUES
    ('What was the name of your first pet?', 1),
    ('What city were you born in?', 2),
    ('What is your mother''s maiden name?', 3),
    ('What was the name of your first school?', 4),
    ('What is the name of the street you grew up on?', 5),
    ('What was your childhood nickname?', 6),
    ('What is the name of your favorite childhood friend?', 7),
    ('What was the make and model of your first car?', 8),
    ('What is your favorite movie?', 9),
    ('What was the first concert you attended?', 10),
    ('What is the name of your favorite teacher?', 11),
    ('In what city did you have your first job?', 12),
    ('What is the middle name of your oldest sibling?', 13),
    ('What was your favorite food as a child?', 14),
    ('What is the name of the hospital where you were born?', 15)
) AS q(question_text, sort_order)
WHERE NOT EXISTS (SELECT 1 FROM security_questions);

-- Auto-cleanup expired reset tokens (run periodically or via cron)
-- DELETE FROM used_reset_tokens WHERE expires_at < NOW();
