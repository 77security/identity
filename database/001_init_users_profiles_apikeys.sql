CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS citext;

-- LOOKUP TABLES
-- Standardized Sector List
CREATE TABLE ref_industries (
industry_key VARCHAR(20) PRIMARY KEY, -- e.g., 'CRIT_ENERGY', 'FIN_BANK'
display_name VARCHAR(100) NOT NULL,    -- e.g., 'Critical Infrastructure: Energy'
created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO ref_industries (industry_key, display_name) VALUES
('CHEMICAL', 'Chemical Industry'),
('CRIT_ENERGY', 'Critical Infrastructure: Energy'),
('CRIT_WATER', 'Critical Infrastructure: Water & Waste'),
('EDU_RES', 'Education & Research'),
('FIN_BANK', 'Finance: Banking & Core Services'),
('FIN_INS', 'Finance: Insurance & Markets'),
('FOOD_AGRI', 'Food & Agriculture'),
('GOV_NAT', 'Government: National/Federal'),
('GOV_LOC', 'Government: State/Local/Regional'),
('DEF_BASE', 'Defense Industrial Base'),
('HEALTH', 'Healthcare & Public Health'),
('MANU_CRIT', 'Manufacturing: Critical/Heavy'),
('MANU_GEN', 'Manufacturing: General Consumer'),
('NON_PROF', 'Non-Profit & NGO'),
('TECH_SW', 'Technology: Software & SaaS'),
('TECH_HW', 'Technology: Hardware & Semi'),
('TELECOM', 'Telecommunications & ISP'),
('MEDIA', 'Media & Communications'),
('RETAIL', 'Retail & E-commerce'),
('TRANS_LOG', 'Transportation & Logistics'),
('OTHER', 'Other / Diversified')
ON CONFLICT (industry_key) DO NOTHING;

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
region_code CHAR(2), -- ISO 3166-1 alpha-2 (e.g., 'US', 'GB')
industry_key VARCHAR(20) REFERENCES ref_industries(industry_key), -- Foreign Key mapping
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