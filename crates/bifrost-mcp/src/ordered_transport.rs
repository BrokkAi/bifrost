//! Ordered observation points for MCP messages crossing the transport.
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
//!
//! The transport is equally the only place that sees a response leave the
//! process, so it is also where the outbound transport-phase timings live:
//! `mcp_request.response_queue_wait` (result ready until delivery starts) and
//! `mcp_request.writer_delivery` (serialization and the stdout write). The
//! hand-written host emits both from its writer thread; the benchmark profile
//! contract in `src/benchmark/mcp_iteration.rs` requires them from whichever
//! host serves the session (#1491).

use crate::profiling;
use rmcp::RoleServer;
use rmcp::model::{ClientNotification, JsonRpcMessage, RequestId};
use rmcp::service::RxJsonRpcMessage;
use rmcp::transport::Transport;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

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

/// Format a transport-phase timing label the way the hand-written host does:
/// `mcp_request.<phase>[<tool>][<request correlation hash>]`.
///
/// The benchmark parser reads the phase and the first bracket; the correlation
/// hash ties the line to a specific request in a multi-request trace.
pub fn transport_phase_label(phase: &str, tool_name: &str, correlation_id: Option<&str>) -> String {
    match correlation_id {
        Some(correlation_id) => format!("mcp_request.{phase}[{tool_name}][{correlation_id}]"),
        None => format!("mcp_request.{phase}[{tool_name}]"),
    }
}

/// How many armed response timings may await delivery at once.
///
/// Sized far above any plausible number of concurrent tool calls. An entry can
/// only be orphaned when `rmcp` drops a response instead of sending it (a
/// request cancelled after its handler returned), so this bound exists to keep
/// that rare leak from growing without limit, not to be reached in practice.
const MAX_ARMED_RESPONSE_TIMINGS: usize = 256;

/// A response the handler finished computing, awaiting its trip through the
/// transport.
struct ArmedResponseTiming {
    tool_name: String,
    request_correlation_id: Option<String>,
    ready_at: Instant,
}

/// Transport-phase timing hand-off between the tool handler and the transport.
///
/// The handler knows which tool a response answers and when its result became
/// ready; only the transport sees the response leave. Keyed by the wire request
/// id, which both sides observe.
#[derive(Default)]
pub struct OutboundResponseTimings {
    armed: Mutex<HashMap<RequestId, ArmedResponseTiming>>,
}

impl OutboundResponseTimings {
    /// Record that the response for `request_id` is ready to leave the server.
    pub fn arm(
        &self,
        request_id: RequestId,
        tool_name: String,
        request_correlation_id: Option<String>,
    ) {
        let mut armed = self
            .armed
            .lock()
            .expect("outbound response timing lock poisoned");
        if armed.len() >= MAX_ARMED_RESPONSE_TIMINGS {
            eprintln!(
                "bifrost: dropping the transport-phase timing for {tool_name}; {MAX_ARMED_RESPONSE_TIMINGS} responses already await delivery"
            );
            return;
        }
        armed.insert(
            request_id,
            ArmedResponseTiming {
                tool_name,
                request_correlation_id,
                ready_at: Instant::now(),
            },
        );
    }

    fn take(&self, request_id: &RequestId) -> Option<ArmedResponseTiming> {
        self.armed
            .lock()
            .expect("outbound response timing lock poisoned")
            .remove(request_id)
    }

    #[cfg(test)]
    fn armed_len(&self) -> usize {
        self.armed
            .lock()
            .expect("outbound response timing lock poisoned")
            .len()
    }
}

/// Wraps a transport to emit `response_queue_wait` and `writer_delivery` for
/// responses the handler armed.
///
/// `Transport::send` takes `&mut self`, so deliveries are serialized: a
/// response's timing lines are on stderr before the next outbound message can
/// start sending. That is the ordering the benchmark's profile boundaries
/// rely on.
pub struct ResponseTimingTransport<T> {
    inner: T,
    timings: Arc<OutboundResponseTimings>,
}

impl<T> ResponseTimingTransport<T> {
    pub fn new(inner: T, timings: Arc<OutboundResponseTimings>) -> Self {
        Self { inner, timings }
    }
}

impl<T> Transport<RoleServer> for ResponseTimingTransport<T>
where
    T: Transport<RoleServer> + Send,
{
    type Error = T::Error;

    fn send(
        &mut self,
        item: rmcp::service::TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let timing = match &item {
            JsonRpcMessage::Response(response) => self.timings.take(&response.id),
            JsonRpcMessage::Error(error) => error.id.as_ref().and_then(|id| self.timings.take(id)),
            _ => None,
        };
        let send = self.inner.send(item);
        async move {
            if let Some(timing) = &timing {
                profiling::duration(
                    transport_phase_label(
                        "response_queue_wait",
                        &timing.tool_name,
                        timing.request_correlation_id.as_deref(),
                    ),
                    timing.ready_at.elapsed(),
                );
            }
            let delivery_started = Instant::now();
            let result = send.await;
            if let Some(timing) = &timing {
                profiling::duration(
                    transport_phase_label(
                        "writer_delivery",
                        &timing.tool_name,
                        timing.request_correlation_id.as_deref(),
                    ),
                    delivery_started.elapsed(),
                );
            }
            result
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        self.inner.receive().await
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

    #[tokio::test]
    async fn an_armed_response_timing_is_consumed_by_the_send_that_delivers_it() {
        let timings = Arc::new(OutboundResponseTimings::default());
        timings.arm(
            RequestId::Number(7),
            "search_symbols".to_string(),
            Some("sha256:abc".to_string()),
        );
        assert_eq!(timings.armed_len(), 1);

        let mut transport = ResponseTimingTransport::new(
            ScriptedTransport(std::collections::VecDeque::new()),
            Arc::clone(&timings),
        );
        transport
            .send(rmcp::model::JsonRpcMessage::response(
                rmcp::model::ServerResult::empty(()),
                RequestId::Number(7),
            ))
            .await
            .expect("send the response");
        assert_eq!(
            timings.armed_len(),
            0,
            "delivery must consume the armed timing so the map cannot grow"
        );
    }

    #[tokio::test]
    async fn an_error_response_also_consumes_its_armed_timing() {
        let timings = Arc::new(OutboundResponseTimings::default());
        timings.arm(RequestId::Number(9), "get_symbol_sources".to_string(), None);

        let mut transport = ResponseTimingTransport::new(
            ScriptedTransport(std::collections::VecDeque::new()),
            Arc::clone(&timings),
        );
        transport
            .send(rmcp::model::JsonRpcMessage::Error(
                rmcp::model::JsonRpcError::new(
                    Some(RequestId::Number(9)),
                    rmcp::model::ErrorData::internal_error("budget exhausted", None),
                ),
            ))
            .await
            .expect("send the error response");
        assert_eq!(timings.armed_len(), 0);
    }

    #[tokio::test]
    async fn an_unrelated_outbound_message_leaves_armed_timings_alone() {
        let timings = Arc::new(OutboundResponseTimings::default());
        timings.arm(RequestId::Number(3), "query_code".to_string(), None);

        let mut transport = ResponseTimingTransport::new(
            ScriptedTransport(std::collections::VecDeque::new()),
            Arc::clone(&timings),
        );
        transport
            .send(rmcp::model::JsonRpcMessage::response(
                rmcp::model::ServerResult::empty(()),
                RequestId::Number(4),
            ))
            .await
            .expect("send a different response");
        assert_eq!(timings.armed_len(), 1);
    }

    #[test]
    fn arming_beyond_the_bound_drops_the_new_timing_not_the_map() {
        let timings = OutboundResponseTimings::default();
        for id in 0..(MAX_ARMED_RESPONSE_TIMINGS as u32 + 10) {
            timings.arm(
                RequestId::Number(id.into()),
                "search_symbols".to_string(),
                None,
            );
        }
        assert_eq!(timings.armed_len(), MAX_ARMED_RESPONSE_TIMINGS);
    }

    #[test]
    fn transport_phase_labels_match_the_hand_written_host_format() {
        assert_eq!(
            transport_phase_label("response_queue_wait", "search_symbols", Some("sha256:abc")),
            "mcp_request.response_queue_wait[search_symbols][sha256:abc]"
        );
        assert_eq!(
            transport_phase_label("queue_wait", "search_symbols", None),
            "mcp_request.queue_wait[search_symbols]"
        );
    }
}
