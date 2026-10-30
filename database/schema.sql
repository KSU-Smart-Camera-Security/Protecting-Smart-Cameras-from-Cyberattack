-- Database schema for the smart camera security system (SQLite).
-- No users are created here: run `php setup_db.php` to create the admin account.

CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT NOT NULL UNIQUE,
    password            TEXT NOT NULL,          -- bcrypt hash (password_hash)
    email               TEXT,                   -- receives MFA codes
    mfa_enabled         INTEGER DEFAULT 0,
    brute_force_enabled INTEGER DEFAULT 1,
    rtsp_protected      INTEGER DEFAULT 0,
    login_attempts      INTEGER DEFAULT 0,
    lockout_until       INTEGER DEFAULT 0
);

-- Reserved for per-IP lockout tracking (the current code tracks attempts per session).
CREATE TABLE IF NOT EXISTS login_attempts (
    ip            TEXT PRIMARY KEY,
    attempts      INTEGER DEFAULT 0,
    last_attempt  INTEGER DEFAULT 0,
    blocked_until INTEGER DEFAULT 0
);
