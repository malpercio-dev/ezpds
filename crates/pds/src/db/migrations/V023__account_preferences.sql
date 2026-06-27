CREATE TABLE account_preferences (
    did         TEXT NOT NULL,
    preferences TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (did),
    FOREIGN KEY (did) REFERENCES accounts (did)
) WITHOUT ROWID;
