-- Arthroplasty Registry Cloud v1
-- PostgreSQL migration. JSONB record storage preserves the existing web app's
-- nested record model while users/audit/images are first-class relational tables.
CREATE TABLE IF NOT EXISTS users (
    user_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('data_entry','admin','surgeon')),
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS registry_records (
    record_id BIGSERIAL PRIMARY KEY,
    registry_id TEXT NOT NULL UNIQUE,
    mrn TEXT,
    record JSONB NOT NULL,
    created_by BIGINT REFERENCES users(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS images (
    image_id BIGSERIAL PRIMARY KEY,
    image_key TEXT NOT NULL UNIQUE,
    registry_id TEXT NOT NULL REFERENCES registry_records(registry_id) ON DELETE CASCADE,
    section TEXT NOT NULL CHECK (section IN ('preop','postop')),
    mime_type TEXT NOT NULL DEFAULT 'image/jpeg',
    image_data BYTEA NOT NULL,
    created_by BIGINT REFERENCES users(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    log_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(user_id),
    action TEXT NOT NULL,
    table_name TEXT,
    record_id TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details JSONB
);

CREATE INDEX IF NOT EXISTS idx_registry_records_mrn ON registry_records(mrn);
CREATE INDEX IF NOT EXISTS idx_registry_records_record_gin ON registry_records USING GIN(record);
CREATE INDEX IF NOT EXISTS idx_images_registry_id ON images(registry_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
