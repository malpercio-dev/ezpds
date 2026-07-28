// pattern: Functional Core
//
// The OAuth authorization response's delivery mode (`response_mode`): parse/validate the
// request parameter and pick the separator a redirect answers with. Pure — no I/O.
//
// Homed in `auth/` (not a route file) because three route surfaces share it — `oauth_par`
// validates it, `oauth_authorize` threads it through both consent paths, and
// `oauth_consent` reads it back off the pending row — and routes may not import routes.

/// How the authorization response's parameters are delivered to `redirect_uri`
/// (OAuth 2.0 Multiple Response Type Encoding Practices' `response_mode`).
///
/// RFC 8414 gives `response_modes_supported` the default `["query", "fragment"]` when a
/// server's metadata omits it, so browser-based clients (the official
/// `@atproto/oauth-client-browser` defaults to `fragment`) legitimately request either.
/// Silently dropping the parameter and answering in the query string leaves a
/// fragment-mode client staring at an empty `location.hash` — a completed consent that
/// never logs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    Query,
    Fragment,
}

impl ResponseMode {
    /// Parse a request's `response_mode` value. Absent/empty defaults to `query`
    /// (RFC 6749's response mode for the `code` response type); anything other than the
    /// two advertised modes is rejected with the `error_description` text.
    pub fn parse(raw: Option<&str>) -> Result<Self, &'static str> {
        match raw.map(str::trim) {
            None | Some("") | Some("query") => Ok(ResponseMode::Query),
            Some("fragment") => Ok(ResponseMode::Fragment),
            Some(_) => Err("response_mode must be \"query\" or \"fragment\""),
        }
    }

    /// The canonical wire string, as stored in PAR params and pending consent rows.
    pub fn as_str(self) -> &'static str {
        match self {
            ResponseMode::Query => "query",
            ResponseMode::Fragment => "fragment",
        }
    }

    /// The separator that starts this mode's parameter block on `redirect_uri`.
    ///
    /// Registered redirect URIs cannot themselves carry a fragment (the client-metadata
    /// rules forbid it), so `#` always starts the fragment. A query-mode redirect must
    /// instead extend any query the redirect URI already has.
    pub(crate) fn separator(self, redirect_uri: &str) -> char {
        match self {
            ResponseMode::Fragment => '#',
            ResponseMode::Query if redirect_uri.contains('?') => '&',
            ResponseMode::Query => '?',
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Absent/empty defaults to `query`, both advertised modes parse, and anything else
    /// (e.g. `form_post`) is rejected — silently coercing an unknown mode would deliver
    /// the response somewhere the client isn't looking.
    #[test]
    fn parses_the_advertised_modes_and_rejects_others() {
        assert_eq!(ResponseMode::parse(None), Ok(ResponseMode::Query));
        assert_eq!(ResponseMode::parse(Some("")), Ok(ResponseMode::Query));
        assert_eq!(ResponseMode::parse(Some("query")), Ok(ResponseMode::Query));
        assert_eq!(
            ResponseMode::parse(Some("fragment")),
            Ok(ResponseMode::Fragment)
        );
        assert!(ResponseMode::parse(Some("form_post")).is_err());
        assert!(ResponseMode::parse(Some("Fragment")).is_err());
    }

    #[test]
    fn separator_matches_the_mode_and_existing_query() {
        assert_eq!(
            ResponseMode::Query.separator("https://app.example.com/cb"),
            '?'
        );
        assert_eq!(
            ResponseMode::Query.separator("https://app.example.com/cb?x=1"),
            '&'
        );
        assert_eq!(
            ResponseMode::Fragment.separator("https://app.example.com/cb?x=1"),
            '#'
        );
    }
}
