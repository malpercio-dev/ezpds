-- V054: Distinguish confirmed PLC registration from DID pre-storage
--
-- `pending_did` (V008) was overloaded as proof of a completed plc.directory
-- registration. The DID ceremony (POST /v1/dids) pre-stores `pending_did`
-- BEFORE the plc.directory POST, so a retry after a FAILED POST saw
-- `pending_did` set, took the skip-plc branch, and promoted a DID that may
-- never have been registered globally — an "active" account whose DID doesn't
-- resolve on the network.
--
-- `pending_plc_registered_at` records the distinct "plc.directory returned 2xx"
-- state. It is stamped only after a successful POST; the retry branch skips the
-- POST only when it is set, and otherwise re-POSTs (the signed genesis op is
-- idempotent on plc.directory — the same signed op yields the same DID).
--
-- NULL for pending accounts created before V054, and for any account whose
-- first plc.directory POST has not yet succeeded. The column is dropped together
-- with the pending_accounts row at promotion, like `pending_did` itself.

ALTER TABLE pending_accounts ADD COLUMN pending_plc_registered_at TEXT;
