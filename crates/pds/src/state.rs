// pattern: Imperative Shell

use std::ops::Deref;
use std::sync::Arc;

use axum::extract::FromRef;
use custos_core::CoreState;

use crate::auth::{ClaimPollTracker, SpaceTypeCache};

/// The state every `pds` handler extracts: the shared [`CoreState`] plus the fields only `pds`'s
/// features read. Core helpers take `&CoreState`; a `&AppState` reaches them through [`Deref`].
#[derive(Clone)]
pub struct AppState {
    pub core: CoreState,
    /// In-memory last-poll clock for the auth.md claim-polling grant, keyed by the SHA-256 of each
    /// agent's `claim_token`. Paces polling to the advertised `interval` (returns `slow_down` when
    /// exceeded). Shared across all token endpoint requests; ephemeral (resets on restart).
    pub poll_tracker: ClaimPollTracker,
    pub space_type_cache: SpaceTypeCache,
    /// In-memory firehose pipeline: every repo commit emits a sequenced event here, which
    /// `com.atproto.sync.subscribeRepos` fans out to connected relays/BGSes. Shared via Arc.
    pub firehose: Arc<crate::firehose::Firehose>,
    /// Outbound `requestCrawl` notifier: after each commit, pings the configured relays/BGSes
    /// so newly produced content is crawled promptly. Shared via Arc.
    pub crawlers: Arc<crate::crawler::CrawlerNotifier>,
    /// Bound Iroh QUIC endpoint, when `[iroh] enabled`. `None` when the tunnel is disabled.
    /// Handlers read `iroh.node_id` to advertise the pds's node id. Shared via Arc.
    pub iroh: Option<Arc<crate::iroh_tunnel::IrohState>>,
    /// Queue handle for the notification relay worker, present only when `[notifications]
    /// relay` names a relay. `None` is the feature's off switch at every send site: a trigger
    /// that finds it absent does nothing at all, which is why the whole feature is inert
    /// rather than merely quiet when unconfigured.
    pub notify_sender: Option<crate::notify_relay_client::NotifySender>,
    /// Outbound email sender (password reset, email confirmation, email update). The default
    /// `LogEmailSender` logs instead of sending, so tests and a fresh install need no mail server;
    /// `email.provider = "smtp"` swaps in real SMTP delivery. Shared via Arc.
    pub email: Arc<dyn crate::email::EmailSender>,
    /// Per-DID locks serializing each repo's logical write sequence (root read → commit CAS →
    /// post-commit GC) so one request's GC can never delete a concurrent same-repo write's
    /// freshly written blocks. Shared via Arc; see [`crate::record_write::RepoWriteLocks`].
    pub repo_write_locks: Arc<crate::record_write::RepoWriteLocks>,
}

// Field access only, not a smart pointer: lets `state.db` and `helper(&state)` keep compiling
// where a helper takes `&CoreState`. Writes go through `state.core`.
impl Deref for AppState {
    type Target = CoreState;

    fn deref(&self) -> &CoreState {
        &self.core
    }
}

impl FromRef<AppState> for CoreState {
    fn from_ref(state: &AppState) -> CoreState {
        state.core.clone()
    }
}

#[cfg(test)]
impl AppState {
    /// `core` plus test defaults for the `pds`-owned fields: a live firehose and crawler notifier
    /// over `core`'s pool and metrics (no crawler URLs), no iroh, notifications off, and the log
    /// email sender.
    pub async fn for_test(core: CoreState) -> AppState {
        let firehose = {
            let mut f = crate::firehose::Firehose::new(core.db.clone())
                .await
                .expect("test firehose");
            f.attach_metrics(core.metrics.clone());
            Arc::new(f)
        };
        let crawlers = {
            let mut c = crate::crawler::CrawlerNotifier::new(
                core.http_client.clone(),
                "test.example.com".to_string(),
                &[],
            );
            c.attach_metrics(core.metrics.clone());
            Arc::new(c)
        };
        AppState {
            poll_tracker: crate::auth::new_claim_poll_tracker(),
            space_type_cache: crate::auth::new_space_type_cache(),
            firehose,
            crawlers,
            iroh: None,
            notify_sender: None,
            email: Arc::new(crate::email::LogEmailSender),
            repo_write_locks: Arc::new(crate::record_write::RepoWriteLocks::new()),
            core,
        }
    }
}

#[cfg(test)]
pub(crate) async fn test_state() -> AppState {
    AppState::for_test(custos_core::test_support::test_state().await).await
}

#[cfg(test)]
pub async fn test_state_with_plc_url(plc_directory_url: String) -> AppState {
    AppState::for_test(custos_core::test_support::test_state_with_plc_url(plc_directory_url).await)
        .await
}
