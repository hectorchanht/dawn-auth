-- @dawn-studio/auth — D1 schema (extracted from OpenMusic's openmusic-accounts DB).
--
-- PII ISOLATION (house rule): keep this database separate from any analytics DB.
-- This DB holds emails; the analytics DB is no-PII by design.
--
-- Apply: wrangler d1 execute <DB> --file=schema.sql   (or split into statements
-- for the GitHub Actions d1-migrate workflow / cf-api batch route).

CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	email TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS magic_tokens (
	-- token_hash = hex(SHA-256('magic:' + token)); the RAW token never touches D1.
	token_hash TEXT PRIMARY KEY,
	email TEXT NOT NULL,
	-- epoch ms; the intent dies 15 min after issue (see config.magicLinkTtlMs).
	expires_at INTEGER NOT NULL,
	used INTEGER NOT NULL DEFAULT 0,
	-- optional native-handoff scheme the intent was minted with (e.g. 'openmusic://')
	scheme TEXT,
	-- code_hash = hex(SHA-256('code:' + code)); the raw 6-digit code only ever
	-- exists in the email. Link + code are TWO CREDENTIALS FOR ONE INTENT:
	-- burning either (used=1) invalidates the other.
	code_hash TEXT,
	code_attempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_magic_tokens_email ON magic_tokens(email);

CREATE TABLE IF NOT EXISTS sessions (
	-- token_hash = hex(SHA-256('session:' + token)); raw token never touches D1.
	token_hash TEXT PRIMARY KEY,
	user_id TEXT NOT NULL REFERENCES users(id),
	-- epoch ms; 30 days after issue (see config.sessionTtlMs).
	expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Fixed-window rate-limit buckets (see core.rateLimit / store layer).
CREATE TABLE IF NOT EXISTS rate_limits (
	key TEXT PRIMARY KEY,
	count INTEGER NOT NULL,
	window_start INTEGER NOT NULL
);
