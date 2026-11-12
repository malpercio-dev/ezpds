// pattern: Functional Core

//! RFC 8707 resource indicators and the connector terms that hang off them (ADR-0042).
//!
//! A `resource` names what a token is for. This server issues tokens for two kinds of target:
//! itself, and the MCP resources the operator listed in `[oauth] connector_resources`. A request
//! naming one of the latter is a *connector request*: it may skip PAR and DPoP, and in exchange
//! its grant is capped by [`connector_scope_ceiling`]. Anything else is `invalid_target`.

use url::Url;

/// A `resource` that is neither this server nor a configured connector resource.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidTarget;

/// The comparison form of a resource: scheme, host, port and path as `url` canonicalises them
/// (lowercase host, default port dropped), minus a trailing slash. `None` for anything that is
/// not an absolute URI without a fragment (RFC 8707 §2).
fn normalise(resource: &str) -> Option<String> {
    let url = Url::parse(resource).ok()?;
    if url.fragment().is_some() {
        return None;
    }
    Some(url.as_str().trim_end_matches('/').to_string())
}

/// Classify a request's `resource`: `Ok(Some(canonical))` for a connector resource — the entry
/// exactly as the operator configured it, which becomes the token's `aud` — and `Ok(None)` for
/// this server or no resource at all.
pub fn connector_resource<'a>(
    config: &'a common::Config,
    resource: Option<&str>,
) -> Result<Option<&'a str>, InvalidTarget> {
    let Some(resource) = resource.filter(|r| !r.is_empty()) else {
        return Ok(None);
    };
    let wanted = normalise(resource).ok_or(InvalidTarget)?;
    if normalise(&config.public_url).as_deref() == Some(wanted.as_str()) {
        return Ok(None);
    }
    config
        .oauth
        .connector_resources
        .iter()
        .find(|c| normalise(c).as_deref() == Some(wanted.as_str()))
        .map(|c| Some(c.as_str()))
        .ok_or(InvalidTarget)
}

/// Drop every scope a connector grant may never carry: `identity:`, `account:` and
/// `transition:`. A connector's token is not bound to a key, so it is kept away from the scopes
/// that change who the account is or stand in for full access.
pub fn connector_scope_ceiling(scope: &str) -> String {
    scope
        .split_whitespace()
        .filter(|token| {
            !["identity:", "account:", "transition:"]
                .iter()
                .any(|prefix| token.starts_with(prefix))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn config(connectors: &[&str]) -> common::Config {
        let mut config = (*crate::test_support::test_state().await.config).clone();
        config.public_url = "https://pds.example.com".to_string();
        config.oauth.connector_resources = connectors.iter().map(|s| s.to_string()).collect();
        config
    }

    #[tokio::test]
    async fn no_resource_and_this_server_are_not_connector_requests() {
        let config = config(&["https://mcp.example.com/mcp"]).await;
        assert_eq!(connector_resource(&config, None), Ok(None));
        assert_eq!(connector_resource(&config, Some("")), Ok(None));
        assert_eq!(
            connector_resource(&config, Some("https://pds.example.com/")),
            Ok(None)
        );
    }

    #[tokio::test]
    async fn a_configured_resource_matches_across_case_port_and_trailing_slash() {
        let config = config(&["https://mcp.example.com/mcp"]).await;
        for sent in [
            "https://mcp.example.com/mcp",
            "https://MCP.example.com:443/mcp/",
        ] {
            assert_eq!(
                connector_resource(&config, Some(sent)),
                Ok(Some("https://mcp.example.com/mcp")),
                "{sent}"
            );
        }
    }

    #[tokio::test]
    async fn anything_else_is_an_invalid_target() {
        let config = config(&["https://mcp.example.com/mcp"]).await;
        for sent in [
            "https://mcp.example.com",
            "https://mcp.example.com/mcp/other",
            "https://evil.example.com/mcp",
            "https://mcp.example.com/mcp#frag",
            "not a uri",
        ] {
            assert_eq!(
                connector_resource(&config, Some(sent)),
                Err(InvalidTarget),
                "{sent}"
            );
        }
    }

    #[test]
    fn the_ceiling_drops_identity_account_and_transition_scopes() {
        assert_eq!(
            connector_scope_ceiling(
                "atproto identity:* account:email transition:generic \
                 repo:app.bsky.feed.post rpc:app.bsky.feed.getTimeline?aud=*"
            ),
            "atproto repo:app.bsky.feed.post rpc:app.bsky.feed.getTimeline?aud=*"
        );
    }
}
