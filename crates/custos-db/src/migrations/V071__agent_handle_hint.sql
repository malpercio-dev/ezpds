-- An anonymously-registering agent may propose the handle it wants for a child account it
-- hopes the confirming user will mint for it. Purely a hint: the wallet shows it in the
-- claim-approval screen and the user edits or discards it before signing the genesis op, so
-- nothing downstream trusts this value — the authoritative handle arrives with the child block
-- at claim-confirm and is validated there.
ALTER TABLE agent_identities ADD COLUMN handle_hint TEXT;
