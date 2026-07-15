-- Durable audit trail for high-impact operator account repair actions.
-- Token plaintext is never recorded; reset-token issuance records only the action.
CREATE TABLE operator_account_audit_events (
    id TEXT PRIMARY KEY,
    did TEXT NOT NULL REFERENCES accounts(did),
    actor TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('email_updated', 'reset_token_issued')),
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_operator_account_audit_did_created_at
    ON operator_account_audit_events (did, created_at);
