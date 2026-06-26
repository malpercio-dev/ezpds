// pattern: Imperative Shell
//
// Iroh QUIC tunnel: a NAT-traversing endpoint devices dial by node id instead of by a
// routable address. Bound at startup (when `[iroh] enabled`) alongside the HTTP server; its
// node id is advertised via `GET /v1/devices/:id/relay`. The accept loop speaks a minimal
// v0.1 echo protocol on the `ezpds/iroh/0` ALPN — enough to prove the bidirectional channel
// works end-to-end and to give devices a liveness probe. The real repo-sync / push protocols
// will register additional ALPNs (or message types) here later.

use iroh::endpoint::{presets, Incoming};
use iroh::{Endpoint, SecretKey};

/// ALPN protocol identifier for the ezpds device↔relay tunnel. Bumped if the wire protocol
/// changes incompatibly.
pub const ALPN: &[u8] = b"ezpds/iroh/0";

/// Upper bound on a single echo message (bytes). Bounds server-side reads so a peer cannot
/// force unbounded allocation on the relay.
const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Process-level Iroh endpoint state, shared via `AppState` behind an `Arc`.
pub struct IrohState {
    /// The bound endpoint. Cheaply cloneable (internally reference-counted); the accept loop
    /// holds one clone, handlers reach it through `AppState`.
    pub endpoint: Endpoint,
    /// The endpoint's node id rendered as a string — the value advertised to devices.
    pub node_id: String,
}

/// Build and bind an Iroh endpoint using the relay's persistent secret key.
///
/// Uses the `N0` preset (n0 discovery + relays) so a device can dial the relay by node id
/// alone — discovery resolves the relay's reachable addresses and QUIC holepunches through
/// NAT. The endpoint accepts only the `ezpds/iroh/0` ALPN.
pub async fn start(secret: [u8; 32]) -> anyhow::Result<IrohState> {
    let secret_key = SecretKey::from_bytes(&secret);
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| anyhow::anyhow!("failed to bind Iroh endpoint: {e}"))?;
    let node_id = endpoint.id().to_string();
    Ok(IrohState { endpoint, node_id })
}

/// Spawn the accept loop as a detached background task.
///
/// Fire-and-forget like the blob GC: the returned handle can be dropped. The loop runs until
/// the endpoint is closed (`endpoint.close()` makes `accept()` yield `None`), at which point
/// the task ends. Per-connection errors are logged, never propagated — one misbehaving peer
/// never stops the loop.
pub fn spawn_accept_loop(endpoint: Endpoint) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                if let Err(e) = handle_connection(incoming).await {
                    tracing::debug!(error = %e, "iroh connection ended with error");
                }
            });
        }
        tracing::info!("iroh accept loop stopped (endpoint closed)");
    })
}

/// Handle one accepted connection: echo every bidirectional stream until the peer hangs up.
async fn handle_connection(incoming: Incoming) -> anyhow::Result<()> {
    let connection = incoming.accept()?.await?;
    let remote = connection.remote_id();
    tracing::debug!(%remote, "iroh connection accepted");

    // v0.1 protocol: for each bi stream the peer opens, read the request and write the same
    // bytes back. `accept_bi` erroring means the peer closed the connection — a clean exit.
    loop {
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(_) => break,
        };
        let msg = recv.read_to_end(MAX_MESSAGE_LEN).await?;
        send.write_all(&msg).await?;
        send.finish()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_is_versioned() {
        assert_eq!(ALPN, b"ezpds/iroh/0");
    }
}
