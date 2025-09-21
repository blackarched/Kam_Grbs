-- schema.sql
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    owner_key TEXT NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL, -- e.g., queued, running, done, error
    result TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);