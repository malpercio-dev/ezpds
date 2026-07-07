// pattern: Functional Core
//
// The multi-relay pairing document: which relays this device is paired to, and which
// one unqualified operator actions (claim-code mint, self-revoke) currently target.
// Pure data and invariant-preserving operations only — Keychain persistence lives in
// `keychain::{load_pairings, save_pairings}`, and id generation (UUID) stays with the
// imperative callers in `relay_client`, so every function here is deterministic.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Storage-format version pinned into every persisted document. A future format change
/// bumps this and ships an explicit migration; an unknown version is a load error, never
/// a silent reset (see `keychain::load_pairings`).
pub const PAIRING_DOC_VERSION: u32 = 1;

/// A single relay pairing: the relay this device registered with, the id the relay
/// assigned, the label sent at registration, and the operator-chosen nickname.
///
/// `id` is a locally generated UUID and is the stable handle for every operation —
/// relay-assigned `device_id`s change on re-pair and relay URLs can repeat, so neither
/// is an identity. Serializes camelCase for both the keychain JSON document and IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pairing {
    pub id: String,
    pub nickname: String,
    pub relay_url: String,
    pub device_id: String,
    pub device_label: String,
}

/// Returned by id-addressed operations when no pairing has the given id. Mapped to the
/// `NO_SUCH_PAIRING` IPC error code at the relay-client boundary.
#[derive(Debug, PartialEq, Eq)]
pub struct NoSuchPairing;

/// The versioned pairing document persisted as one keychain item.
///
/// Invariant: `active` is always the id of an entry in `pairings`, or `None` (and it is
/// always `None` when the list is empty). All mutation goes through methods that
/// preserve the invariant; the fields stay private so a caller can never construct or
/// edit a document that violates it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingDoc {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active: Option<String>,
    pairings: Vec<Pairing>,
}

impl PairingDoc {
    /// The document a device has before it ever pairs: current version, no entries.
    pub fn empty() -> Self {
        PairingDoc {
            version: PAIRING_DOC_VERSION,
            active: None,
            pairings: Vec::new(),
        }
    }

    /// All pairings, in insertion (pairing) order.
    pub fn pairings(&self) -> &[Pairing] {
        &self.pairings
    }

    /// The id of the active pairing, if one is selected.
    pub fn active_id(&self) -> Option<&str> {
        self.active.as_deref()
    }

    /// The active pairing itself, if one is selected.
    pub fn active_pairing(&self) -> Option<&Pairing> {
        self.active.as_deref().and_then(|id| self.get(id))
    }

    /// Look up a pairing by its local id.
    pub fn get(&self, id: &str) -> Option<&Pairing> {
        self.pairings.iter().find(|p| p.id == id)
    }

    /// Append a pairing and make it the active one. Duplicate relay URLs are allowed by
    /// design (re-pairing a relay appends a distinct entry); duplicate ids are not —
    /// callers generate a fresh UUID per pairing.
    pub fn append(&mut self, pairing: Pairing) {
        self.active = Some(pairing.id.clone());
        self.pairings.push(pairing);
    }

    /// Select the pairing that unqualified operator actions target. Unknown ids leave
    /// the current selection untouched.
    pub fn set_active(&mut self, id: &str) -> Result<(), NoSuchPairing> {
        if self.get(id).is_none() {
            return Err(NoSuchPairing);
        }
        self.active = Some(id.to_string());
        Ok(())
    }

    /// Update a pairing's operator-chosen nickname. Local-only: nicknames are display
    /// names and never leave the device.
    pub fn rename(&mut self, id: &str, nickname: &str) -> Result<(), NoSuchPairing> {
        let pairing = self
            .pairings
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(NoSuchPairing)?;
        pairing.nickname = nickname.to_string();
        Ok(())
    }

    /// Remove a pairing, returning it. When the *active* entry is removed: exactly one
    /// remaining pairing is auto-promoted (the choice is unambiguous); with two or more
    /// remaining, `active` is cleared so the UI must ask for an explicit pick — the
    /// selection never silently lands on another relay.
    pub fn remove(&mut self, id: &str) -> Result<Pairing, NoSuchPairing> {
        let index = self
            .pairings
            .iter()
            .position(|p| p.id == id)
            .ok_or(NoSuchPairing)?;
        let removed = self.pairings.remove(index);
        if self.active.as_deref() == Some(id) {
            self.active = if self.pairings.len() == 1 {
                Some(self.pairings[0].id.clone())
            } else {
                None
            };
        }
        Ok(removed)
    }

    /// Validate the invariants of a document that arrived from outside this module
    /// (i.e. was deserialized from the keychain): supported version, unique ids, and an
    /// `active` that references an existing entry. Returns a description of the first
    /// violation, suitable for a fail-loud keychain error.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != PAIRING_DOC_VERSION {
            return Err(format!(
                "unsupported pairing document version {}",
                self.version
            ));
        }
        let mut seen = HashSet::new();
        for pairing in &self.pairings {
            if !seen.insert(pairing.id.as_str()) {
                return Err(format!("duplicate pairing id {}", pairing.id));
            }
        }
        if let Some(active) = self.active.as_deref() {
            if self.get(active).is_none() {
                return Err(format!("active pairing {active} not present in document"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairing(id: &str, nickname: &str, relay_url: &str) -> Pairing {
        Pairing {
            id: id.to_string(),
            nickname: nickname.to_string(),
            relay_url: relay_url.to_string(),
            device_id: format!("device-for-{id}"),
            device_label: "Operator iPhone".to_string(),
        }
    }

    #[test]
    fn empty_doc_has_no_active_and_no_pairings() {
        let doc = PairingDoc::empty();
        assert_eq!(doc.pairings(), &[]);
        assert_eq!(doc.active_id(), None);
        assert_eq!(doc.active_pairing(), None);
    }

    #[test]
    fn append_makes_the_new_pairing_active_and_keeps_earlier_entries() {
        let mut doc = PairingDoc::empty();
        let pairing_a = pairing("id-a", "First", "https://relay-a.example");
        let pairing_b = pairing("id-b", "Second", "https://relay-b.example");

        doc.append(pairing_a.clone());
        doc.append(pairing_b.clone());

        let pairings = doc.pairings();
        assert_eq!(pairings.len(), 2);
        assert_eq!(pairings[0].id, "id-a");
        assert_eq!(pairings[0].nickname, "First");
        assert_eq!(pairings[0].relay_url, "https://relay-a.example");
        assert_eq!(pairings[0].device_id, "device-for-id-a");
        assert_eq!(pairings[0].device_label, "Operator iPhone");

        assert_eq!(pairings[1].id, "id-b");
        assert_eq!(pairings[1].nickname, "Second");
        assert_eq!(pairings[1].relay_url, "https://relay-b.example");
        assert_eq!(pairings[1].device_id, "device-for-id-b");
        assert_eq!(pairings[1].device_label, "Operator iPhone");

        assert_eq!(doc.active_id(), Some("id-b"));
        assert_eq!(doc.active_pairing().unwrap().id, "id-b");
    }

    #[test]
    fn append_allows_duplicate_relay_urls_under_distinct_ids() {
        let mut doc = PairingDoc::empty();
        let pairing_a = pairing("id-a", "First", "https://relay.example");
        let pairing_b = pairing("id-b", "Second", "https://relay.example");

        doc.append(pairing_a.clone());
        doc.append(pairing_b.clone());

        let pairings = doc.pairings();
        assert_eq!(pairings.len(), 2);
        assert_eq!(pairings[0].id, "id-a");
        assert_eq!(pairings[1].id, "id-b");
        assert_eq!(pairings[0].relay_url, pairings[1].relay_url);

        assert_eq!(doc.get("id-a").unwrap().id, "id-a");
        assert_eq!(doc.get("id-b").unwrap().id, "id-b");
        assert_eq!(doc.active_id(), Some("id-b"));
    }

    #[test]
    fn set_active_switches_selection() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.append(pairing("id-b", "Second", "https://relay-b.example"));

        assert_eq!(doc.active_id(), Some("id-b"));
        doc.set_active("id-a").expect("set active");
        assert_eq!(doc.active_id(), Some("id-a"));
        assert_eq!(doc.active_pairing().unwrap().id, "id-a");
    }

    #[test]
    fn set_active_unknown_id_errors_and_leaves_selection_unchanged() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));

        let result = doc.set_active("nope");
        assert_eq!(result, Err(NoSuchPairing));
        assert_eq!(doc.active_id(), Some("id-a"));
    }

    #[test]
    fn rename_updates_nickname_and_nothing_else() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "Original", "https://relay-a.example"));

        doc.rename("id-a", "Updated").expect("rename");
        let p = doc.get("id-a").unwrap();
        assert_eq!(p.nickname, "Updated");
        assert_eq!(p.id, "id-a");
        assert_eq!(p.relay_url, "https://relay-a.example");
        assert_eq!(p.device_id, "device-for-id-a");
        assert_eq!(p.device_label, "Operator iPhone");

        let result = doc.rename("unknown", "Nope");
        assert_eq!(result, Err(NoSuchPairing));
    }

    #[test]
    fn removing_the_active_pairing_with_one_remaining_auto_promotes() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.append(pairing("id-b", "Second", "https://relay-b.example"));

        assert_eq!(doc.active_id(), Some("id-b"));
        doc.remove("id-b").expect("remove");
        assert_eq!(doc.active_id(), Some("id-a"));
        assert_eq!(doc.pairings().len(), 1);
    }

    #[test]
    fn removing_the_active_pairing_with_two_or_more_remaining_clears_active() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.append(pairing("id-b", "Second", "https://relay-b.example"));
        doc.append(pairing("id-c", "Third", "https://relay-c.example"));

        assert_eq!(doc.active_id(), Some("id-c"));
        doc.remove("id-c").expect("remove");
        assert_eq!(doc.active_id(), None);
        assert_eq!(doc.pairings().len(), 2);
        assert_eq!(doc.get("id-a").unwrap().id, "id-a");
        assert_eq!(doc.get("id-b").unwrap().id, "id-b");
    }

    #[test]
    fn removing_a_non_active_pairing_keeps_the_selection() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.append(pairing("id-b", "Second", "https://relay-b.example"));

        assert_eq!(doc.active_id(), Some("id-b"));
        doc.remove("id-a").expect("remove");
        assert_eq!(doc.active_id(), Some("id-b"));
        assert_eq!(doc.pairings().len(), 1);
    }

    #[test]
    fn removing_the_last_pairing_leaves_an_empty_doc() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));

        assert_eq!(doc.active_id(), Some("id-a"));
        doc.remove("id-a").expect("remove");
        assert_eq!(doc.pairings(), &[]);
        assert_eq!(doc.active_id(), None);
    }

    #[test]
    fn remove_unknown_id_errors_and_changes_nothing() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));

        let result = doc.remove("unknown");
        assert_eq!(result, Err(NoSuchPairing));
        assert_eq!(doc.pairings().len(), 1);
        assert_eq!(doc.active_id(), Some("id-a"));
    }

    #[test]
    fn document_serializes_camel_case_and_omits_absent_active() {
        let empty_doc = PairingDoc::empty();
        let value = serde_json::to_value(&empty_doc).expect("serialize");
        assert_eq!(value.get("version").unwrap(), 1);
        assert_eq!(value.get("pairings").unwrap(), &serde_json::json!([]));
        assert_eq!(value.get("active"), None);

        let mut doc_with_entry = PairingDoc::empty();
        doc_with_entry.append(pairing("id-a", "First", "https://relay-a.example"));
        let value = serde_json::to_value(&doc_with_entry).expect("serialize");
        let pairings = value.get("pairings").unwrap().as_array().unwrap();
        assert_eq!(pairings.len(), 1);

        let entry = &pairings[0];
        assert_eq!(entry.get("id").unwrap().as_str().unwrap(), "id-a");
        assert_eq!(entry.get("nickname").unwrap().as_str().unwrap(), "First");
        assert_eq!(
            entry.get("relayUrl").unwrap().as_str().unwrap(),
            "https://relay-a.example"
        );
        assert_eq!(
            entry.get("deviceId").unwrap().as_str().unwrap(),
            "device-for-id-a"
        );
        assert_eq!(
            entry.get("deviceLabel").unwrap().as_str().unwrap(),
            "Operator iPhone"
        );
    }

    #[test]
    fn document_round_trips_through_json() {
        let mut doc = PairingDoc::empty();
        doc.append(pairing("id-a", "First", "https://relay-a.example"));
        doc.append(pairing("id-b", "Second", "https://relay-b.example"));

        let bytes = serde_json::to_vec(&doc).expect("serialize");
        let restored: PairingDoc = serde_json::from_slice(&bytes).expect("deserialize");

        assert_eq!(doc, restored);
    }

    #[test]
    fn validate_rejects_unsupported_version() {
        let json = r#"{"version":2,"pairings":[]}"#;
        let doc: PairingDoc = serde_json::from_str(json).expect("deserialize");
        let result = doc.validate();
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(err_msg.contains("version 2"));
    }

    #[test]
    fn validate_rejects_dangling_active_reference() {
        let json = r#"{"version":1,"active":"missing-id","pairings":[]}"#;
        let doc: PairingDoc = serde_json::from_str(json).expect("deserialize");
        let result = doc.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("active pairing"));
    }

    #[test]
    fn validate_rejects_duplicate_ids() {
        let json = r#"{"version":1,"pairings":[{"id":"same","nickname":"A","relayUrl":"https://a","deviceId":"d-a","deviceLabel":"L"},{"id":"same","nickname":"B","relayUrl":"https://b","deviceId":"d-b","deviceLabel":"L"}]}"#;
        let doc: PairingDoc = serde_json::from_str(json).expect("deserialize");
        let result = doc.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("duplicate pairing id"));
    }
}
