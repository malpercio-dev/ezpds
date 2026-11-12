// pattern: Imperative Shell

//! Resolving a `client_id` at the start of an authorization request, shared by `/oauth/par` and
//! the plain connector request `/oauth/authorize` admits (routes may not import one another).

use custos_core::CoreState;
use custos_db::oauth::{get_oauth_client, upsert_oauth_client};

/// Why a `client_id` could not be resolved to a metadata document.
pub(super) enum ClientResolveError {
    /// The database failed; already logged.
    Db,
    /// Not a registered client and not a URL to resolve.
    NotRegistered,
    /// The URL client_id's document could not be fetched or is not valid. Carries the reason.
    Resolution(String),
}

/// A client's metadata document, and whether it still needs caching.
pub(super) struct ResolvedClient {
    pub metadata_json: String,
    freshly_fetched: bool,
}

impl ResolvedClient {
    /// Cache a freshly fetched document so the authorize and token endpoints' lookups find it.
    /// Call only once the whole request has validated, so a rejected request plants no row.
    pub(super) async fn cache(
        &self,
        state: &CoreState,
        client_id: &str,
    ) -> Result<(), sqlx::Error> {
        if self.freshly_fetched {
            upsert_oauth_client(&state.db, client_id, &self.metadata_json).await?;
        }
        Ok(())
    }
}

/// Look up the client: registered/cached rows first; on a miss, a URL-shaped client_id is
/// resolved by fetching its metadata document (ATProto OAuth — client_id IS the metadata URL).
pub(super) async fn resolve_client(
    state: &CoreState,
    client_id: &str,
) -> Result<ResolvedClient, ClientResolveError> {
    match get_oauth_client(&state.db, client_id).await {
        Ok(Some(row)) => Ok(ResolvedClient {
            metadata_json: row.client_metadata,
            freshly_fetched: false,
        }),
        Ok(None) if client_id.starts_with("https://") || client_id.starts_with("http://") => {
            // The fetched URL is caller-supplied (the client_id itself), so it must go through
            // the SSRF-hardened client, not the plain one used for trusted admin-configured
            // upstreams; `resolve_client_metadata` takes a `HardenedClient`, so no other compiles.
            custos_core::auth::oauth_client_resolution::resolve_client_metadata(
                &state.hardened_http_client,
                client_id,
            )
            .await
            .map(|metadata_json| ResolvedClient {
                metadata_json,
                freshly_fetched: true,
            })
            .map_err(|e| {
                tracing::info!(client_id = %client_id, error = %e, "URL client_id resolution failed");
                ClientResolveError::Resolution(e.to_string())
            })
        }
        Ok(None) => Err(ClientResolveError::NotRegistered),
        Err(e) => {
            tracing::error!(error = %e, "db error looking up OAuth client");
            Err(ClientResolveError::Db)
        }
    }
}
