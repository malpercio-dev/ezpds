// pattern: Functional Core

//! Space URI syntax: `at:space/{spaceDid}/{spaceType}/{skey}`, optionally followed by
//! `/{authorDid}/{collection}/{rkey}` for one record inside the space.
//!
//! The `at:space/` prefix is what tells a space URI from a public one (`at://…`); there is no
//! `at://` form of a space URI, and only those two lengths are valid.
//!
//! Two callers share this: the lexicon layer's `space-ref` string format, and every
//! `com.atproto.space.*` route, which needs the parsed `(authority, type, skey)` triple to
//! evaluate a `space:` grant and to fill the `spaces` row's columns. Parsing is therefore the
//! only way a route obtains those parts, so a malformed ref can never reach the store.

/// What every space URI starts with.
pub const SPACE_URI_PREFIX: &str = "at:space/";

/// The canonical URI of the space `(authority, space_type, skey)`. Unvalidated: a caller holding
/// untrusted parts passes the result through [`parse_space_ref`].
pub fn space_uri(authority: &str, space_type: &str, skey: &str) -> String {
    format!("{SPACE_URI_PREFIX}{authority}/{space_type}/{skey}")
}

/// A space's identity, parsed from its canonical URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceRef {
    /// The canonical URI this was parsed from — the `spaces`/`space_repos` key.
    pub uri: String,
    /// The space authority's DID. Never a handle: a space's identity and membership are keyed
    /// on DIDs, so unlike a public AT-URI the authority may not be an at-identifier.
    pub authority: String,
    /// The space type NSID.
    pub space_type: String,
    /// The space key, which carries the same syntax requirements as a record key.
    pub skey: String,
}

impl SpaceRef {
    /// The URI of one record inside this space: the space ref, then the author, collection
    /// and rkey. This is the `uri` the record routes report and the order `listRecords` pages in.
    pub fn record_uri(&self, author: &str, collection: &str, rkey: &str) -> String {
        format!("{}/{author}/{collection}/{rkey}", self.uri)
    }
}

/// Parse a canonical space ref, or `None` if `value` is not one.
///
/// A URI naming a record *within* a space is not a space ref, and is refused here — use
/// [`is_space_at_uri`] to recognize the wider family.
///
/// Stricter than the reference's `isSpaceRefString` in one respect: a `?query` or `#fragment` is
/// refused rather than ignored. The reference's regex tolerates a fragment on a space ref, but
/// this URI is a primary key here — admitting two spellings of one space would split a repo
/// across two rows.
pub fn parse_space_ref(value: &str) -> Option<SpaceRef> {
    let (space, record_tail) = split_space_uri(value)?;
    record_tail.is_none().then_some(space)
}

/// Whether `value` is a valid space ref — the lexicon `space-ref` string format.
pub fn is_valid_space_ref(value: &str) -> bool {
    parse_space_ref(value).is_some()
}

/// Whether `value` is a valid AT-URI addressing permissioned space data: either a bare space ref
/// or one record inside a space.
///
/// Two gates ask this alongside the public form, exactly as the reference splits
/// `isPublicAtUriString` from `isSpaceAtUriString`: the lexicon `at-uri` string format, and
/// `auth::validation`'s write-time record-format gate. Deliberately *not* folded into
/// `repo_engine::AtUri` itself — that parser also yields the `(authority, collection, rkey)`
/// parts callers index public repos by, and a space URI's parts do not mean the same things.
pub fn is_space_at_uri(value: &str) -> bool {
    split_space_uri(value).is_some()
}

/// The shared parser: the three-segment space ref, plus the optional
/// `{authorDid}/{collection}/{rkey}` record tail. Both halves are validated, so neither caller
/// has to re-check what the other established.
fn split_space_uri(value: &str) -> Option<(SpaceRef, Option<()>)> {
    let rest = value.strip_prefix(SPACE_URI_PREFIX)?;
    if rest.contains(['?', '#']) {
        return None;
    }
    let mut parts = rest.split('/');
    let authority = parts.next()?;
    let space_type = parts.next()?;
    let skey = parts.next()?;

    if !crate::identity::did::is_valid_did(authority)
        || repo_engine::validate_collection(space_type).is_err()
        || !crate::lexicon::is_valid_record_key(skey)
    {
        return None;
    }

    // Whatever follows must be a complete record tail — a partial one is malformed, not a ref.
    let record_tail = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (None, _, _, _) => None,
        (Some(author), Some(collection), Some(rkey), None) => {
            // A space's records are keyed on DIDs, so the author is never a handle.
            if !crate::identity::did::is_valid_did(author)
                || repo_engine::validate_collection(collection).is_err()
                || !crate::lexicon::is_valid_record_key(rkey)
            {
                return None;
            }
            Some(())
        }
        _ => return None,
    };

    // Rebuilt rather than sliced from the input, so a record URI yields its space's canonical
    // ref rather than a prefix of itself.
    Some((
        SpaceRef {
            uri: space_uri(authority, space_type, skey),
            authority: authority.to_string(),
            space_type: space_type.to_string(),
            skey: skey.to_string(),
        },
        record_tail,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = "at:space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.group/default";

    #[test]
    fn parses_the_canonical_three_part_form() {
        let space = parse_space_ref(OK).expect("valid space ref");
        assert_eq!(space.authority, "did:plc:ewvi7nxzyoun6zhxrhs64oiz");
        assert_eq!(space.space_type, "app.bsky.group");
        assert_eq!(space.skey, "default");
        assert_eq!(space.uri, OK);
        assert_eq!(
            space_uri(&space.authority, &space.space_type, &space.skey),
            OK
        );
        assert_eq!(
            space.record_uri("did:plc:member", "org.example.note", "3jui7"),
            format!("{OK}/did:plc:member/org.example.note/3jui7")
        );
    }

    #[test]
    fn rejects_everything_that_is_not_a_bare_space_ref() {
        for bad in [
            // A record within a space is not a space ref (though it is a space AT-URI).
            "at:space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.group/default/did:plc:a/org.example.note/3jui7",
            // A public repo URI.
            "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3jui7",
            // The pre-2026-11-24 alpha form, and an `at://` spelling of the new one.
            "at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/space/app.bsky.group/default",
            "at://space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.group/default",
            // The authority must be a DID, never a handle.
            "at:space/alice.example.com/app.bsky.group/default",
            // Malformed space type / space key.
            "at:space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/notannsid/default",
            "at:space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.group/..",
            // Truncated, trailing slash, wrong scheme.
            "at:space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.group",
            "at:space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.group/default/",
            "https://space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.group/default",
            // Query and fragment would give one space two spellings, hence two rows.
            "at:space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.group/default?x=1",
            "at:space/did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.group/default#/foo",
        ] {
            assert!(parse_space_ref(bad).is_none(), "should reject: {bad}");
        }
    }

    /// The wider `at-uri` family: a bare ref and a record inside a space both qualify, a partial
    /// or malformed record tail does not, and a public repo URI is somebody else's business.
    #[test]
    fn space_at_uris_cover_refs_and_the_records_inside_them() {
        let record = format!("{OK}/did:plc:member/org.example.note/3jui7");
        assert!(is_space_at_uri(OK));
        assert!(is_space_at_uri(&record));

        for bad in [
            // A truncated record tail.
            &format!("{OK}/did:plc:member"),
            &format!("{OK}/did:plc:member/org.example.note"),
            // A fourth path segment past the rkey.
            &format!("{OK}/did:plc:member/org.example.note/3jui7/extra"),
            // The author must be a DID, and the collection an NSID.
            &format!("{OK}/member.example.com/org.example.note/3jui7"),
            &format!("{OK}/did:plc:member/notannsid/3jui7"),
            // The old form of a record URI.
            &"at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/space/app.bsky.group/default/did:plc:member/org.example.note/3jui7".to_string(),
            // Not a space URI at all.
            &"at://did:plc:ewvi7nxzyoun6zhxrhs64oiz/app.bsky.feed.post/3jui7".to_string(),
        ] {
            assert!(!is_space_at_uri(bad), "should reject: {bad}");
        }
    }
}
