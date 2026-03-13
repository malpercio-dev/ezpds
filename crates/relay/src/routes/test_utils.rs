use std::sync::Arc;

use crate::app::{test_state, AppState};

/// Minimal test state with admin_token set to `"test-admin-token"`.
///
/// Wraps `test_state()` and overrides the single config field that most
/// admin-endpoint tests need. Defined once here rather than duplicated in
/// every route test module.
pub async fn test_state_with_admin_token() -> AppState {
    let base = test_state().await;
    let mut config = (*base.config).clone();
    config.admin_token = Some("test-admin-token".to_string());
    AppState {
        config: Arc::new(config),
        db: base.db,
        http_client: base.http_client,
    }
}
