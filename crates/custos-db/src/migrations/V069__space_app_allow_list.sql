-- V069: the `allowList` app-access policy's client_id list.
--
-- A JSON array of OAuth client IDs, meaningful only when `app_access =
-- 'allowList'` (NULL reads as empty everywhere else) — the same shape the
-- reference stores, and the shape `getSpace` serves back. A list, not a table:
-- it is written and read whole by createSpace/updateSpace/getSpace and the
-- credential-mint check, and never queried across spaces.
ALTER TABLE spaces ADD COLUMN app_allowed TEXT;
