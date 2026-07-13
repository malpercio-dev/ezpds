-- V044: Opt-in flag for Custos-managed did:web hosting.
--
-- The operator (and, later, any user-owned domain) can point `https://{host}/.well-known/did.json`
-- at Custos so the DID document is served here instead of from a standalone web server. Moving
-- hosting onto Custos removes the independence a separate host gave the identity, so serving is
-- deliberately *opt-in per account* rather than automatic: a `did:web:{host}` account only has its
-- document served once its owner has explicitly enabled hosting (and can flip it off just as
-- explicitly — the served-doc gate reads this column, so disabling stops serving immediately).
--
-- Status is derived, not stored (matching `deactivated_at` V008 / the moderation timestamps V026 /
-- `claim_codes` V004): NULL = hosting off (never enabled, or turned back off); a timestamp = when
-- hosting was last enabled. The `.well-known/did.json` route serves only while this is NOT NULL and
-- the account is otherwise servable (a `did:web:{host}` account, active lifecycle, with a stored
-- document). did:plc accounts never set this — their document lives on plc.directory, not here.
--
-- Only the flag lands here; the serve route, the opt-in toggle, and the authenticated non-PLC
-- document-update path are the code half.

ALTER TABLE accounts ADD COLUMN did_web_hosting_enabled_at TEXT;
