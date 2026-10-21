-- Push-to-approve delivery for the wallet-confirmed OAuth consent primitive (Phase C of the
-- wallet-confirmed-consent design): when the consent page's login_hint names a local account
-- with registered notification devices, Custos seals a `login-approval` push to those devices
-- and number matching becomes mandatory for approval on that request.
--
-- Derived-status doctrine (V008/V026): both columns NULL = no push was dispatched and no
-- number matching is required — exactly the pre-V060 behavior for every request. They are
-- written once, together, by the dispatch path immediately after the pending row is created,
-- and never updated afterwards.
ALTER TABLE pending_oauth_authorizations ADD COLUMN match_code TEXT;
ALTER TABLE pending_oauth_authorizations ADD COLUMN push_dispatched_at TEXT;
