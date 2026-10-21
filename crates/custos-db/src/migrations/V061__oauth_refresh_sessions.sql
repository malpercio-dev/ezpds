-- Refresh-token session families. Rotation now marks the old token superseded instead of
-- deleting it: a superseded token presented again within a short grace window is a
-- concurrent duplicate refresh (multi-tab / background+foreground) and stays serviceable,
-- while one presented later is a theft signal that revokes the whole family.
-- `session_id` groups every rotation of one authorization-code grant; existing rows are
-- their own single-member family.
ALTER TABLE oauth_tokens ADD COLUMN session_id TEXT;
ALTER TABLE oauth_tokens ADD COLUMN superseded_at TEXT;
UPDATE oauth_tokens SET session_id = id WHERE session_id IS NULL;
CREATE INDEX idx_oauth_tokens_session_id ON oauth_tokens(session_id);
