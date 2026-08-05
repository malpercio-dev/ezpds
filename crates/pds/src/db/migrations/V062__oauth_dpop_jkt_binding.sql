-- Carry the client's DPoP key thumbprint from the pushed authorization request through to
-- the authorization code (RFC 9449 §10). A code issued for a flow whose client proved a key
-- at PAR time can then only be redeemed by that key, so a code intercepted on the redirect
-- leg is useless to anyone else.
--
-- Nullable in both tables and enforced only when present: non-PAR authorize requests and
-- clients that send no DPoP proof at PAR keep working exactly as before (the token endpoint
-- still binds the *issued* tokens to whatever key redeems the code).
ALTER TABLE oauth_authorization_codes ADD COLUMN dpop_jkt TEXT;
ALTER TABLE pending_oauth_authorizations ADD COLUMN dpop_jkt TEXT;
