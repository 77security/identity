CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS citext;

-- USERS
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email CITEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_verified BOOLEAN DEFAULT FALSE,
    verification_token_hash TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- PROFILES
CREATE TYPE display_preference AS ENUM ('full_email', 'domain_only', 'anonymous');

CREATE TABLE profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    region_code CHAR(2),
    industry VARCHAR(100),
    display_mode display_preference DEFAULT 'anonymous',
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- API KEYS (Unified Across Products)
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100),
    key_prefix VARCHAR(12) NOT NULL,
    key_hash BYTEA NOT NULL,
    scopes JSONB DEFAULT '{}',
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(key_hash)
);

CREATE INDEX idx_api_keys_user ON api_keys(user_id);
