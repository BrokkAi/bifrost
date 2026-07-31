//! An ordered observation point for inbound MCP messages.
//!
//! `rmcp` dispatches every notification and every request on its own task and
//! resolves a server-to-client response by waking the task that awaits it, so
//! by the time a handler runs, the order its messages arrived in is gone. That
//! matters for exactly one thing in Bifrost, and it is a security rule:
//! `notifications/roots/list_changed` revokes the client's authorization for
//! the directory Bifrost is analyzing, and a `tools/call` that arrived *after*
//! it must never be served from the revoked scope. Left to task scheduling,
//! that call wins the race often enough to measure.
//!
//! `Transport::receive` is the one place where order still exists -- the SDK
//! documents it as sequential, and the serve loop pulls one message at a time
//! from it. Wrapping the transport therefore restores the ordering guarantee
//! the previous single-reader-thread host had, without forking `rmcp` or
//! waiting on an upstream hook: by the time the serve loop hands a `tools/call`
//! to a handler, any revocation that preceded it on the wire has already been
//! counted here.

use rmcp::RoleServer;
use rmcp::model::ClientNotification;
use rmcp::service::RxJsonRpcMessage;
use rmcp::transport::Transport;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Counts workspace revocations in the order they arrived on the wire.
///
/// A binding records the count it was made under; any request that observes a
/// higher count knows the client revoked its authorization first, no matter
/// which task happens to run when.
#[derive(Debug, Default)]
pub struct RootsRevocations(AtomicU64);

impl RootsRevocations {
    /// The number of revocations seen so far. Monotonic.
    pub fn observed(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    fn record(&self) -> u64 {
        self.0.fetch_add(1, Ordering::AcqRel) + 1
    }
}

/// Wraps a transport to count `notifications/roots/list_changed` as it passes.
pub struct RootsOrderedTransport<T> {
    inner: T,
    revocations: Arc<RootsRevocations>,
}

impl<T> RootsOrderedTransport<T> {
    pub fn new(inner: T, revocations: Arc<RootsRevocations>) -> Self {
        Self { inner, revocations }
    }
}

impl<T> Transport<RoleServer> for RootsOrderedTransport<T>
where
    T: Transport<RoleServer> + Send,
{
    type Error = T::Error;

    fn send(
        &mut self,
        item: rmcp::service::TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        self.inner.send(item)
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        let message = self.inner.receive().await?;
        if let rmcp::model::JsonRpcMessage::Notification(notification) = &message
            && matches!(
                notification.notification,
                ClientNotification::RootsListChangedNotification(_)
            )
        {
            // Counted here, before the serve loop yields this message and long
            // before it spawns anything, so every later message is already on
            // the far side of the revocation.
            self.revocations.record();
        }
        Some(message)
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.close()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::ClientJsonRpcMessage;

    /// A transport that replays a fixed script, so the ordering rule can be
    /// checked without a real client.
    struct ScriptedTransport(std::collections::VecDeque<ClientJsonRpcMessage>);

    impl Transport<RoleServer> for ScriptedTransport {
        type Error = std::io::Error;

        fn send(
            &mut self,
            _item: rmcp::service::TxJsonRpcMessage<RoleServer>,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
            std::future::ready(Ok(()))
        }

        async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
            self.0.pop_front()
        }

        fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
            std::future::ready(Ok(()))
        }
    }

    fn parse(raw: serde_json::Value) -> ClientJsonRpcMessage {
        serde_json::from_value(raw).expect("valid client message")
    }

    #[tokio::test]
    async fn a_revocation_is_counted_before_the_message_after_it_is_delivered() {
        let revocations = Arc::new(RootsRevocations::default());
        let mut transport = RootsOrderedTransport::new(
            ScriptedTransport(
                [
                    parse(serde_json::json!({
                        "jsonrpc": "2.0",
                        "method": "notifications/roots/list_changed"
                    })),
                    parse(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": { "name": "search_symbols", "arguments": {} }
                    })),
                ]
                .into_iter()
                .collect(),
            ),
            Arc::clone(&revocations),
        );

        assert_eq!(revocations.observed(), 0);
        transport.receive().await.expect("the revocation");
        assert_eq!(
            revocations.observed(),
            1,
            "the revocation must be counted as it is read, not when a handler runs"
        );
        transport.receive().await.expect("the tool call");
        assert_eq!(
            revocations.observed(),
            1,
            "a request that arrived after a revocation always observes it"
        );
    }

    #[tokio::test]
    async fn unrelated_traffic_does_not_revoke() {
        let revocations = Arc::new(RootsRevocations::default());
        let mut transport = RootsOrderedTransport::new(
            ScriptedTransport(
                [parse(serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized"
                }))]
                .into_iter()
                .collect(),
            ),
            Arc::clone(&revocations),
        );
        transport.receive().await.expect("the notification");
        assert_eq!(revocations.observed(), 0);
    }
}
