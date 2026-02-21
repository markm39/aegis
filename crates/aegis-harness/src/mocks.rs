//! Mock implementations of key traits for testing without real infrastructure.
//!
//! Provides lightweight, thread-safe test doubles for:
//! - [`MockChannel`]: records sent messages, returns configurable responses
//! - [`MockPolicyEngine`]: configurable verdict evaluation
//! - [`MockAuditStore`]: in-memory audit store (no SQLite dependency)
//! - [`MockHttpServer`]: lightweight HTTP server recording requests
//! - [`TestScenarioBuilder`]: fluent test setup combining all mocks
//!
//! All mocks use `Arc<Mutex<_>>` for thread-safe interior mutability,
//! so they can be shared across async tasks or threads safely.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use aegis_types::{Action, ActionKind, Decision, Verdict};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// MockChannel
// ---------------------------------------------------------------------------

/// A recorded outbound message sent through the mock channel.
#[derive(Debug, Clone)]
pub struct RecordedMessage {
    /// The text content of the message.
    pub text: String,
    /// Inline keyboard buttons (label, callback_data) if any.
    pub buttons: Vec<(String, String)>,
    /// Whether the message was sent silently.
    pub silent: bool,
}

/// Thread-safe inner state for [`MockChannel`].
#[derive(Debug)]
struct MockChannelInner {
    /// All messages sent through the channel, in order.
    sent: Vec<RecordedMessage>,
    /// Pre-configured responses to return from `recv`.
    responses: VecDeque<String>,
    /// Number of times `send` was called.
    send_count: usize,
    /// Number of times `recv` was called.
    recv_count: usize,
}

/// A test-friendly channel that records all sent messages and returns
/// configurable responses.
///
/// Thread-safe via `Arc<Mutex<_>>` -- can be cloned and shared across
/// async tasks.
///
/// # Example
///
/// ```
/// use aegis_harness::mocks::MockChannelBuilder;
///
/// let channel = MockChannelBuilder::new()
///     .with_response("Hello back")
///     .with_response("Second response")
///     .build();
///
/// // Use channel.send_text() / channel.recv_text() in tests
/// channel.send_text("outbound message");
/// assert_eq!(channel.sent_messages().len(), 1);
/// assert_eq!(channel.recv_text(), Some("Hello back".into()));
/// ```
#[derive(Debug, Clone)]
pub struct MockChannel {
    inner: Arc<Mutex<MockChannelInner>>,
}

impl MockChannel {
    /// Create a new empty mock channel.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockChannelInner {
                sent: Vec::new(),
                responses: VecDeque::new(),
                send_count: 0,
                recv_count: 0,
            })),
        }
    }

    /// Send a text message, recording it in the sent list.
    pub fn send_text(&self, text: impl Into<String>) {
        let mut inner = self.inner.lock().expect("mock channel lock poisoned");
        inner.send_count += 1;
        inner.sent.push(RecordedMessage {
            text: text.into(),
            buttons: Vec::new(),
            silent: false,
        });
    }

    /// Send a message with buttons, recording it in the sent list.
    pub fn send_with_buttons(
        &self,
        text: impl Into<String>,
        buttons: Vec<(String, String)>,
        silent: bool,
    ) {
        let mut inner = self.inner.lock().expect("mock channel lock poisoned");
        inner.send_count += 1;
        inner.sent.push(RecordedMessage {
            text: text.into(),
            buttons,
            silent,
        });
    }

    /// Receive the next pre-configured response, or `None` if the queue is empty.
    pub fn recv_text(&self) -> Option<String> {
        let mut inner = self.inner.lock().expect("mock channel lock poisoned");
        inner.recv_count += 1;
        inner.responses.pop_front()
    }

    /// Enqueue a response to be returned by `recv_text`.
    pub fn enqueue_response(&self, response: impl Into<String>) {
        let mut inner = self.inner.lock().expect("mock channel lock poisoned");
        inner.responses.push_back(response.into());
    }

    /// Get a snapshot of all sent messages.
    pub fn sent_messages(&self) -> Vec<RecordedMessage> {
        let inner = self.inner.lock().expect("mock channel lock poisoned");
        inner.sent.clone()
    }

    /// Get the number of times `send_text` or `send_with_buttons` was called.
    pub fn send_count(&self) -> usize {
        let inner = self.inner.lock().expect("mock channel lock poisoned");
        inner.send_count
    }

    /// Get the number of times `recv_text` was called.
    pub fn recv_count(&self) -> usize {
        let inner = self.inner.lock().expect("mock channel lock poisoned");
        inner.recv_count
    }

    /// Clear all recorded messages and reset counters.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().expect("mock channel lock poisoned");
        inner.sent.clear();
        inner.responses.clear();
        inner.send_count = 0;
        inner.recv_count = 0;
    }
}

impl Default for MockChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Fluent builder for [`MockChannel`].
pub struct MockChannelBuilder {
    responses: Vec<String>,
}

impl MockChannelBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            responses: Vec::new(),
        }
    }

    /// Add a response to be returned in order by `recv_text`.
    pub fn with_response(mut self, response: impl Into<String>) -> Self {
        self.responses.push(response.into());
        self
    }

    /// Build the mock channel with the configured responses.
    pub fn build(self) -> MockChannel {
        let channel = MockChannel::new();
        {
            let mut inner = channel.inner.lock().expect("mock channel lock poisoned");
            for r in self.responses {
                inner.responses.push_back(r);
            }
        }
        channel
    }
}

impl Default for MockChannelBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MockPolicyEngine
// ---------------------------------------------------------------------------

/// A recorded policy evaluation.
#[derive(Debug, Clone)]
pub struct RecordedEvaluation {
    /// The action that was evaluated.
    pub action: Action,
    /// The verdict that was returned.
    pub verdict: Verdict,
}

/// Thread-safe inner state for [`MockPolicyEngine`].
#[derive(Debug)]
struct MockPolicyInner {
    /// Action kind names (e.g., "FileWrite") that should be denied.
    deny_kinds: HashSet<String>,
    /// All evaluations performed, in order.
    evaluations: Vec<RecordedEvaluation>,
    /// Default decision when no specific deny rule matches.
    default_decision: Decision,
}

/// A test-friendly policy engine that returns configurable verdicts.
///
/// By default, allows all actions. Specific action kinds can be configured
/// to return Deny verdicts. All evaluations are recorded for later inspection.
///
/// # Example
///
/// ```
/// use aegis_harness::mocks::MockPolicyBuilder;
/// use aegis_types::{Action, ActionKind, Decision};
/// use std::path::PathBuf;
///
/// let engine = MockPolicyBuilder::new()
///     .deny_kind("FileWrite")
///     .deny_kind("FileDelete")
///     .build();
///
/// let read_action = Action::new("agent", ActionKind::FileRead { path: PathBuf::from("/tmp/f") });
/// let verdict = engine.evaluate(&read_action);
/// assert_eq!(verdict.decision, Decision::Allow);
///
/// let write_action = Action::new("agent", ActionKind::FileWrite { path: PathBuf::from("/tmp/f") });
/// let verdict = engine.evaluate(&write_action);
/// assert_eq!(verdict.decision, Decision::Deny);
///
/// assert_eq!(engine.evaluation_count(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct MockPolicyEngine {
    inner: Arc<Mutex<MockPolicyInner>>,
}

impl MockPolicyEngine {
    /// Create a new mock policy engine that allows everything by default.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockPolicyInner {
                deny_kinds: HashSet::new(),
                evaluations: Vec::new(),
                default_decision: Decision::Allow,
            })),
        }
    }

    /// Create a mock policy engine that denies everything by default.
    pub fn deny_all() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockPolicyInner {
                deny_kinds: HashSet::new(),
                evaluations: Vec::new(),
                default_decision: Decision::Deny,
            })),
        }
    }

    /// Evaluate an action against the mock policy.
    ///
    /// Returns Deny if the action kind name is in the deny set, or if the
    /// default decision is Deny and the kind is not in an allow set.
    pub fn evaluate(&self, action: &Action) -> Verdict {
        let mut inner = self.inner.lock().expect("mock policy lock poisoned");
        let kind_name = action_kind_name(&action.kind);
        let decision = if inner.deny_kinds.contains(kind_name) {
            Decision::Deny
        } else {
            inner.default_decision.clone()
        };

        let verdict = match decision {
            Decision::Allow => Verdict::allow(
                action.id,
                format!("mock: allowed {kind_name}"),
                Some("mock-policy".into()),
            ),
            Decision::Deny => Verdict::deny(
                action.id,
                format!("mock: denied {kind_name}"),
                Some("mock-policy".into()),
            ),
        };

        inner.evaluations.push(RecordedEvaluation {
            action: action.clone(),
            verdict: verdict.clone(),
        });

        verdict
    }

    /// Add an action kind to the deny set at runtime.
    pub fn add_deny_kind(&self, kind: impl Into<String>) {
        let mut inner = self.inner.lock().expect("mock policy lock poisoned");
        inner.deny_kinds.insert(kind.into());
    }

    /// Remove an action kind from the deny set at runtime.
    pub fn remove_deny_kind(&self, kind: &str) {
        let mut inner = self.inner.lock().expect("mock policy lock poisoned");
        inner.deny_kinds.remove(kind);
    }

    /// Get a snapshot of all recorded evaluations.
    pub fn evaluations(&self) -> Vec<RecordedEvaluation> {
        let inner = self.inner.lock().expect("mock policy lock poisoned");
        inner.evaluations.clone()
    }

    /// Get the total number of evaluations performed.
    pub fn evaluation_count(&self) -> usize {
        let inner = self.inner.lock().expect("mock policy lock poisoned");
        inner.evaluations.len()
    }

    /// Get all actions that were evaluated.
    pub fn evaluated_actions(&self) -> Vec<Action> {
        let inner = self.inner.lock().expect("mock policy lock poisoned");
        inner.evaluations.iter().map(|e| e.action.clone()).collect()
    }

    /// Clear all recorded evaluations.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().expect("mock policy lock poisoned");
        inner.evaluations.clear();
    }
}

impl Default for MockPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the variant name from an `ActionKind` for matching against deny rules.
fn action_kind_name(kind: &ActionKind) -> &'static str {
    match kind {
        ActionKind::FileRead { .. } => "FileRead",
        ActionKind::FileWrite { .. } => "FileWrite",
        ActionKind::FileDelete { .. } => "FileDelete",
        ActionKind::DirCreate { .. } => "DirCreate",
        ActionKind::DirList { .. } => "DirList",
        ActionKind::NetConnect { .. } => "NetConnect",
        ActionKind::NetRequest { .. } => "NetRequest",
        ActionKind::ToolCall { .. } => "ToolCall",
        ActionKind::ProcessSpawn { .. } => "ProcessSpawn",
        ActionKind::ProcessExit { .. } => "ProcessExit",
        ActionKind::ApiUsage { .. } => "ApiUsage",
        ActionKind::SkillScan { .. } => "SkillScan",
        ActionKind::MemoryCapture { .. } => "MemoryCapture",
        ActionKind::AcpConnect { .. } => "AcpConnect",
        ActionKind::AcpSend { .. } => "AcpSend",
        ActionKind::ImageProcess { .. } => "ImageProcess",
        ActionKind::OAuthExchange { .. } => "OAuthExchange",
        ActionKind::AcpServerReceive { .. } => "AcpServerReceive",
        ActionKind::TtsSynthesize { .. } => "TtsSynthesize",
        ActionKind::TranscribeAudio { .. } => "TranscribeAudio",
        ActionKind::VideoProcess { .. } => "VideoProcess",
        ActionKind::AcpTranslate { .. } => "AcpTranslate",
        ActionKind::CopilotAuth { .. } => "CopilotAuth",
        ActionKind::GeminiApiCall { .. } => "GeminiApiCall",
        ActionKind::ProcessAttachment { .. } => "ProcessAttachment",
        ActionKind::CanvasCreate { .. } => "CanvasCreate",
        ActionKind::CanvasUpdate { .. } => "CanvasUpdate",
        ActionKind::DevicePair { .. } => "DevicePair",
        ActionKind::DeviceRevoke { .. } => "DeviceRevoke",
        ActionKind::DeviceAuth { .. } => "DeviceAuth",
        ActionKind::LlmComplete { .. } => "LlmComplete",
        ActionKind::RenderA2UI { .. } => "RenderA2UI",
        ActionKind::GenerateSetupCode { .. } => "GenerateSetupCode",
        ActionKind::DeviceCommand { .. } => "DeviceCommand",
        ActionKind::ManageDevice { .. } => "ManageDevice",
        ActionKind::MakeVoiceCall { .. } => "MakeVoiceCall",
        ActionKind::SpeechRecognition { .. } => "SpeechRecognition",
    }
}

/// Fluent builder for [`MockPolicyEngine`].
pub struct MockPolicyBuilder {
    deny_kinds: HashSet<String>,
    default_decision: Decision,
}

impl MockPolicyBuilder {
    /// Create a new builder (default: allow all).
    pub fn new() -> Self {
        Self {
            deny_kinds: HashSet::new(),
            default_decision: Decision::Allow,
        }
    }

    /// Configure the engine to deny actions of this kind.
    pub fn deny_kind(mut self, kind: impl Into<String>) -> Self {
        self.deny_kinds.insert(kind.into());
        self
    }

    /// Set the default decision for actions not in the deny set.
    pub fn default_decision(mut self, decision: Decision) -> Self {
        self.default_decision = decision;
        self
    }

    /// Build the mock policy engine.
    pub fn build(self) -> MockPolicyEngine {
        MockPolicyEngine {
            inner: Arc::new(Mutex::new(MockPolicyInner {
                deny_kinds: self.deny_kinds,
                evaluations: Vec::new(),
                default_decision: self.default_decision,
            })),
        }
    }
}

impl Default for MockPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MockAuditStore
// ---------------------------------------------------------------------------

/// An entry in the mock audit store.
#[derive(Debug, Clone)]
pub struct MockAuditEntry {
    /// Unique identifier for this entry.
    pub entry_id: Uuid,
    /// The action that was audited.
    pub action: Action,
    /// The verdict that was recorded.
    pub verdict: Verdict,
    /// Serialized action kind string (e.g., `{"FileRead":{"path":"/tmp/f"}}`).
    pub action_kind: String,
}

/// Thread-safe inner state for [`MockAuditStore`].
#[derive(Debug)]
struct MockAuditInner {
    entries: Vec<MockAuditEntry>,
}

/// An in-memory audit store for testing without a SQLite dependency.
///
/// Stores entries in a `Vec` behind `Arc<Mutex<_>>`, providing the same
/// query interface as the real `AuditStore` but without touching the filesystem.
///
/// # Example
///
/// ```
/// use aegis_harness::mocks::MockAuditStore;
/// use aegis_types::{Action, ActionKind, Verdict};
/// use std::path::PathBuf;
///
/// let store = MockAuditStore::new();
/// let action = Action::new("agent-1", ActionKind::FileRead { path: PathBuf::from("/tmp/f") });
/// let verdict = Verdict::allow(action.id, "ok", None);
/// store.append(&action, &verdict);
///
/// assert_eq!(store.count(), 1);
/// assert!(store.has_entry_with_action_kind("FileRead"));
/// ```
#[derive(Debug, Clone)]
pub struct MockAuditStore {
    inner: Arc<Mutex<MockAuditInner>>,
}

impl MockAuditStore {
    /// Create an empty mock audit store.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(MockAuditInner {
                entries: Vec::new(),
            })),
        }
    }

    /// Append an action and its verdict to the store.
    pub fn append(&self, action: &Action, verdict: &Verdict) {
        let mut inner = self.inner.lock().expect("mock audit lock poisoned");
        let action_kind =
            serde_json::to_string(&action.kind).unwrap_or_else(|_| "unknown".into());
        inner.entries.push(MockAuditEntry {
            entry_id: Uuid::new_v4(),
            action: action.clone(),
            verdict: verdict.clone(),
            action_kind,
        });
    }

    /// Query the last `n` entries, in reverse chronological order.
    pub fn query_last(&self, n: usize) -> Vec<MockAuditEntry> {
        let inner = self.inner.lock().expect("mock audit lock poisoned");
        inner.entries.iter().rev().take(n).cloned().collect()
    }

    /// Count total entries in the store.
    pub fn count(&self) -> usize {
        let inner = self.inner.lock().expect("mock audit lock poisoned");
        inner.entries.len()
    }

    /// Check if any entry's action_kind string contains the given substring.
    pub fn has_entry_with_action_kind(&self, kind_substr: &str) -> bool {
        let inner = self.inner.lock().expect("mock audit lock poisoned");
        inner
            .entries
            .iter()
            .any(|e| e.action_kind.contains(kind_substr))
    }

    /// Get all entries as a Vec.
    pub fn all_entries(&self) -> Vec<MockAuditEntry> {
        let inner = self.inner.lock().expect("mock audit lock poisoned");
        inner.entries.clone()
    }

    /// Get all entries with a specific decision.
    pub fn entries_with_decision(&self, decision: Decision) -> Vec<MockAuditEntry> {
        let inner = self.inner.lock().expect("mock audit lock poisoned");
        let decision_str = decision.to_string();
        inner
            .entries
            .iter()
            .filter(|e| e.verdict.decision.to_string() == decision_str)
            .cloned()
            .collect()
    }

    /// Clear all entries.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().expect("mock audit lock poisoned");
        inner.entries.clear();
    }
}

impl Default for MockAuditStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MockHttpServer
// ---------------------------------------------------------------------------

/// A recorded HTTP request received by the mock server.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    /// HTTP method (GET, POST, etc.).
    pub method: String,
    /// Request path (e.g., "/api/v1/foo").
    pub path: String,
    /// Request headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Request body as bytes.
    pub body: Vec<u8>,
}

/// A configured response for a specific path.
#[derive(Debug, Clone)]
struct ConfiguredResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Thread-safe inner state for the mock HTTP server.
#[derive(Debug)]
struct MockHttpInner {
    /// All requests received, in order.
    requests: Vec<RecordedRequest>,
    /// Response configurations per path.
    responses: HashMap<String, ConfiguredResponse>,
}

/// A lightweight HTTP server for testing that records all incoming requests
/// and returns configurable responses per path.
///
/// Uses `std::net::TcpListener` on a random port. The server runs on a
/// background thread and shuts down when the `MockHttpServer` is dropped.
///
/// # Security
///
/// - Binds only to `127.0.0.1` (loopback), never to all interfaces.
/// - Requests are capped at 10 MB to prevent memory exhaustion.
/// - The server thread terminates when the stop flag is set on drop.
///
/// # Example
///
/// ```no_run
/// use aegis_harness::mocks::MockHttpServer;
///
/// let server = MockHttpServer::start();
/// server.configure_response("/api/status", 200, b"ok");
///
/// // Use server.url() as the base URL in your test client
/// let url = format!("{}/api/status", server.url());
/// // ... make HTTP request to url ...
///
/// assert_eq!(server.requests().len(), 1);
/// ```
pub struct MockHttpServer {
    inner: Arc<Mutex<MockHttpInner>>,
    addr: SocketAddr,
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl MockHttpServer {
    /// Start a mock HTTP server on a random loopback port.
    ///
    /// The server immediately begins accepting connections on a background thread.
    pub fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("failed to bind mock HTTP server to loopback");
        let addr = listener.local_addr().expect("failed to get local addr");

        // Set a short accept timeout so the thread can check the stop flag.
        listener
            .set_nonblocking(true)
            .expect("failed to set non-blocking");

        let inner = Arc::new(Mutex::new(MockHttpInner {
            requests: Vec::new(),
            responses: HashMap::new(),
        }));
        let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let inner_clone = Arc::clone(&inner);
        let stop_clone = Arc::clone(&stop_flag);

        let thread = std::thread::spawn(move || {
            run_mock_server(listener, inner_clone, stop_clone);
        });

        Self {
            inner,
            addr,
            stop_flag,
            _thread: Some(thread),
        }
    }

    /// Get the base URL of the mock server (e.g., `http://127.0.0.1:12345`).
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Get the socket address the server is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Configure a response for a specific path.
    ///
    /// When the server receives a request matching this path, it will respond
    /// with the given status code and body. Default content type is `text/plain`.
    pub fn configure_response(&self, path: impl Into<String>, status: u16, body: &[u8]) {
        let mut inner = self.inner.lock().expect("mock http lock poisoned");
        inner.responses.insert(
            path.into(),
            ConfiguredResponse {
                status,
                headers: vec![("Content-Type".into(), "text/plain".into())],
                body: body.to_vec(),
            },
        );
    }

    /// Configure a JSON response for a specific path.
    pub fn configure_json_response(
        &self,
        path: impl Into<String>,
        status: u16,
        body: &[u8],
    ) {
        let mut inner = self.inner.lock().expect("mock http lock poisoned");
        inner.responses.insert(
            path.into(),
            ConfiguredResponse {
                status,
                headers: vec![("Content-Type".into(), "application/json".into())],
                body: body.to_vec(),
            },
        );
    }

    /// Get a snapshot of all recorded requests.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        let inner = self.inner.lock().expect("mock http lock poisoned");
        inner.requests.clone()
    }

    /// Get requests matching a specific path.
    pub fn requests_for_path(&self, path: &str) -> Vec<RecordedRequest> {
        let inner = self.inner.lock().expect("mock http lock poisoned");
        inner
            .requests
            .iter()
            .filter(|r| r.path == path)
            .cloned()
            .collect()
    }

    /// Get the total number of requests received.
    pub fn request_count(&self) -> usize {
        let inner = self.inner.lock().expect("mock http lock poisoned");
        inner.requests.len()
    }

    /// Clear all recorded requests.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().expect("mock http lock poisoned");
        inner.requests.clear();
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        self.stop_flag
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Connect to the listener to wake it up so the thread can exit.
        let _ = std::net::TcpStream::connect(self.addr);
        if let Some(thread) = self._thread.take() {
            let _ = thread.join();
        }
    }
}

/// Run the mock HTTP server loop, accepting connections until the stop flag is set.
fn run_mock_server(
    listener: std::net::TcpListener,
    inner: Arc<Mutex<MockHttpInner>>,
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
) {
    use std::io::{BufRead, BufReader, Write};

    loop {
        if stop_flag.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        // Non-blocking accept with a short sleep on WouldBlock.
        let stream = match listener.accept() {
            Ok((stream, _addr)) => stream,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            Err(_) => break,
        };

        if stop_flag.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        // Set read timeout to prevent hanging on malformed requests.
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));

        let mut reader = BufReader::new(&stream);

        // Parse request line.
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            continue;
        }
        let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
        if parts.len() < 2 {
            continue;
        }
        let method = parts[0].to_string();
        let path = parts[1].to_string();

        // Parse headers.
        let mut headers = Vec::new();
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                let name = name.trim().to_string();
                let value = value.trim().to_string();
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.parse().unwrap_or(0);
                }
                headers.push((name, value));
            }
        }

        // Read body (capped at 10 MB).
        let cap = content_length.min(10 * 1024 * 1024);
        let mut body = vec![0u8; cap];
        if cap > 0 {
            let _ = std::io::Read::read_exact(&mut reader, &mut body);
        }

        // Record the request.
        let recorded = RecordedRequest {
            method,
            path: path.clone(),
            headers,
            body,
        };

        let response = {
            let mut guard = inner.lock().expect("mock http lock poisoned");
            guard.requests.push(recorded);
            guard.responses.get(&path).cloned()
        };

        // Send response.
        let (status, resp_headers, resp_body) = match response {
            Some(r) => (r.status, r.headers, r.body),
            None => (
                404,
                vec![("Content-Type".into(), "text/plain".into())],
                b"not found".to_vec(),
            ),
        };

        let status_text = match status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        };

        let mut response_buf = format!("HTTP/1.1 {status} {status_text}\r\n");
        for (name, value) in &resp_headers {
            response_buf.push_str(&format!("{name}: {value}\r\n"));
        }
        response_buf.push_str(&format!("Content-Length: {}\r\n", resp_body.len()));
        response_buf.push_str("\r\n");

        let mut writer = &stream;
        let _ = writer.write_all(response_buf.as_bytes());
        let _ = writer.write_all(&resp_body);
        let _ = writer.flush();
        // Shut down the write half so the client sees EOF.
        let _ = stream.shutdown(std::net::Shutdown::Both);
    }
}

// ---------------------------------------------------------------------------
// TestScenarioBuilder
// ---------------------------------------------------------------------------

/// A complete test environment with all mocks wired up.
pub struct TestEnvironment {
    /// Mock channel for testing message sending/receiving.
    pub channel: MockChannel,
    /// Mock policy engine for testing authorization.
    pub policy: MockPolicyEngine,
    /// Mock audit store for testing audit logging.
    pub audit: MockAuditStore,
    /// Optional mock HTTP server, started if requested.
    pub http_server: Option<MockHttpServer>,
}

/// Fluent builder for constructing a complete [`TestEnvironment`].
///
/// # Example
///
/// ```
/// use aegis_harness::mocks::TestScenarioBuilder;
///
/// let env = TestScenarioBuilder::new()
///     .with_policy("allow_all")
///     .with_mock_channel()
///     .with_mock_audit()
///     .build();
///
/// assert_eq!(env.audit.count(), 0);
/// assert_eq!(env.policy.evaluation_count(), 0);
/// ```
pub struct TestScenarioBuilder {
    policy_preset: Option<String>,
    deny_kinds: Vec<String>,
    channel_responses: Vec<String>,
    include_http: bool,
}

impl TestScenarioBuilder {
    /// Create a new scenario builder.
    pub fn new() -> Self {
        Self {
            policy_preset: None,
            deny_kinds: Vec::new(),
            channel_responses: Vec::new(),
            include_http: false,
        }
    }

    /// Set the policy preset. Supported values:
    /// - `"allow_all"`: allows everything (default if not set)
    /// - `"deny_all"`: denies everything
    pub fn with_policy(mut self, preset: impl Into<String>) -> Self {
        self.policy_preset = Some(preset.into());
        self
    }

    /// Add an action kind to deny.
    pub fn deny_kind(mut self, kind: impl Into<String>) -> Self {
        self.deny_kinds.push(kind.into());
        self
    }

    /// Include a mock channel with optional pre-configured responses.
    pub fn with_mock_channel(self) -> Self {
        self
    }

    /// Add a response to the mock channel.
    pub fn with_channel_response(mut self, response: impl Into<String>) -> Self {
        self.channel_responses.push(response.into());
        self
    }

    /// Include a mock audit store.
    pub fn with_mock_audit(self) -> Self {
        self
    }

    /// Include a mock HTTP server.
    pub fn with_mock_http(mut self) -> Self {
        self.include_http = true;
        self
    }

    /// Build the test environment with all configured mocks.
    pub fn build(self) -> TestEnvironment {
        // Build policy engine.
        let mut policy_builder = MockPolicyBuilder::new();
        if let Some(ref preset) = self.policy_preset {
            if preset == "deny_all" {
                policy_builder = policy_builder.default_decision(Decision::Deny);
            }
        }
        for kind in &self.deny_kinds {
            policy_builder = policy_builder.deny_kind(kind);
        }
        let policy = policy_builder.build();

        // Build channel.
        let mut channel_builder = MockChannelBuilder::new();
        for resp in &self.channel_responses {
            channel_builder = channel_builder.with_response(resp);
        }
        let channel = channel_builder.build();

        // Build audit store.
        let audit = MockAuditStore::new();

        // Optionally start HTTP server.
        let http_server = if self.include_http {
            Some(MockHttpServer::start())
        } else {
            None
        };

        TestEnvironment {
            channel,
            policy,
            audit,
            http_server,
        }
    }
}

impl Default for TestScenarioBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_types::{Action, ActionKind};
    use std::path::PathBuf;

    fn file_read_action(principal: &str, path: &str) -> Action {
        Action::new(
            principal,
            ActionKind::FileRead {
                path: PathBuf::from(path),
            },
        )
    }

    fn file_write_action(principal: &str, path: &str) -> Action {
        Action::new(
            principal,
            ActionKind::FileWrite {
                path: PathBuf::from(path),
            },
        )
    }

    #[test]
    fn mock_channel_records_messages() {
        let channel = MockChannel::new();

        channel.send_text("hello world");
        channel.send_text("second message");
        channel.send_with_buttons(
            "choose",
            vec![("Yes".into(), "yes".into()), ("No".into(), "no".into())],
            true,
        );

        let messages = channel.sent_messages();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].text, "hello world");
        assert_eq!(messages[1].text, "second message");
        assert_eq!(messages[2].text, "choose");
        assert_eq!(messages[2].buttons.len(), 2);
        assert!(messages[2].silent);
        assert_eq!(channel.send_count(), 3);
    }

    #[test]
    fn mock_channel_returns_configured_responses() {
        let channel = MockChannelBuilder::new()
            .with_response("first response")
            .with_response("second response")
            .build();

        assert_eq!(channel.recv_text(), Some("first response".into()));
        assert_eq!(channel.recv_text(), Some("second response".into()));
        assert_eq!(channel.recv_text(), None);
        assert_eq!(channel.recv_count(), 3);
    }

    #[test]
    fn mock_channel_enqueue_at_runtime() {
        let channel = MockChannel::new();
        assert_eq!(channel.recv_text(), None);

        channel.enqueue_response("dynamic response");
        assert_eq!(channel.recv_text(), Some("dynamic response".into()));
    }

    #[test]
    fn mock_channel_reset() {
        let channel = MockChannel::new();
        channel.send_text("msg");
        channel.enqueue_response("resp");

        channel.reset();
        assert_eq!(channel.send_count(), 0);
        assert_eq!(channel.recv_count(), 0);
        assert!(channel.sent_messages().is_empty());
        assert_eq!(channel.recv_text(), None);
    }

    #[test]
    fn mock_policy_default_allows() {
        let engine = MockPolicyEngine::new();

        let action = file_read_action("agent", "/tmp/f.txt");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Allow);

        let action = file_write_action("agent", "/tmp/f.txt");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Allow);
    }

    #[test]
    fn mock_policy_denies_configured_actions() {
        let engine = MockPolicyBuilder::new()
            .deny_kind("FileWrite")
            .deny_kind("FileDelete")
            .build();

        // FileRead should be allowed (not in deny list).
        let action = file_read_action("agent", "/tmp/f");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Allow);

        // FileWrite should be denied.
        let action = file_write_action("agent", "/tmp/f");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Deny);

        // FileDelete should be denied.
        let action = Action::new(
            "agent",
            ActionKind::FileDelete {
                path: PathBuf::from("/tmp/f"),
            },
        );
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Deny);
    }

    #[test]
    fn mock_policy_records_evaluated_actions() {
        let engine = MockPolicyEngine::new();

        let a1 = file_read_action("agent-1", "/a");
        let a2 = file_write_action("agent-2", "/b");

        engine.evaluate(&a1);
        engine.evaluate(&a2);

        let actions = engine.evaluated_actions();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].principal, "agent-1");
        assert_eq!(actions[1].principal, "agent-2");
        assert_eq!(engine.evaluation_count(), 2);
    }

    #[test]
    fn mock_policy_deny_all() {
        let engine = MockPolicyEngine::deny_all();

        let action = file_read_action("agent", "/tmp/f");
        let verdict = engine.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Deny);
    }

    #[test]
    fn mock_policy_runtime_deny_add_remove() {
        let engine = MockPolicyEngine::new();

        let action = file_write_action("agent", "/tmp/f");
        assert_eq!(engine.evaluate(&action).decision, Decision::Allow);

        engine.add_deny_kind("FileWrite");
        assert_eq!(engine.evaluate(&action).decision, Decision::Deny);

        engine.remove_deny_kind("FileWrite");
        assert_eq!(engine.evaluate(&action).decision, Decision::Allow);
    }

    #[test]
    fn mock_audit_store_inserts_and_queries() {
        let store = MockAuditStore::new();

        // Initially empty.
        assert_eq!(store.count(), 0);

        // Insert entries.
        let a1 = file_read_action("agent-1", "/tmp/a");
        let v1 = Verdict::allow(a1.id, "ok", None);
        store.append(&a1, &v1);

        let a2 = file_write_action("agent-2", "/tmp/b");
        let v2 = Verdict::deny(a2.id, "blocked", Some("test-policy".into()));
        store.append(&a2, &v2);

        // Count.
        assert_eq!(store.count(), 2);

        // Query last 1.
        let last = store.query_last(1);
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].action.principal, "agent-2");

        // Query last 10 (more than available).
        let all = store.query_last(10);
        assert_eq!(all.len(), 2);

        // Has entry with action kind.
        assert!(store.has_entry_with_action_kind("FileRead"));
        assert!(store.has_entry_with_action_kind("FileWrite"));
        assert!(!store.has_entry_with_action_kind("NetConnect"));

        // Entries by decision.
        let allowed = store.entries_with_decision(Decision::Allow);
        assert_eq!(allowed.len(), 1);
        let denied = store.entries_with_decision(Decision::Deny);
        assert_eq!(denied.len(), 1);
    }

    #[test]
    fn mock_audit_store_reset() {
        let store = MockAuditStore::new();
        let action = file_read_action("agent", "/tmp/f");
        let verdict = Verdict::allow(action.id, "ok", None);
        store.append(&action, &verdict);
        assert_eq!(store.count(), 1);

        store.reset();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn mock_http_server_records_requests() {
        let server = MockHttpServer::start();
        server.configure_response("/test", 200, b"hello");

        // Make a request using raw TCP (no reqwest dependency needed).
        let url = server.url();
        let addr = server.addr();
        let mut stream =
            std::net::TcpStream::connect(addr).expect("should connect to mock server");
        use std::io::Write;
        write!(
            stream,
            "GET /test HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            addr
        )
        .expect("should write request");

        // Read response.
        use std::io::Read;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("should read response");

        // Verify the request was recorded.
        // Give the server a moment to process.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let requests = server.requests();
        assert!(
            !requests.is_empty(),
            "server should have recorded the request (url={})",
            url
        );
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].path, "/test");
    }

    #[test]
    fn mock_http_server_returns_configured_response() {
        let server = MockHttpServer::start();
        server.configure_response("/api/status", 200, b"all good");

        let addr = server.addr();
        let mut stream =
            std::net::TcpStream::connect(addr).expect("should connect to mock server");
        use std::io::Write;
        write!(
            stream,
            "GET /api/status HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            addr
        )
        .expect("should write request");

        use std::io::Read;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("should read response");

        assert!(response.contains("200 OK"), "should return 200 status");
        assert!(
            response.contains("all good"),
            "should return configured body"
        );
    }

    #[test]
    fn mock_http_server_returns_404_for_unconfigured_path() {
        let server = MockHttpServer::start();

        let addr = server.addr();
        let mut stream =
            std::net::TcpStream::connect(addr).expect("should connect to mock server");
        use std::io::Write;
        write!(
            stream,
            "GET /unknown HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            addr
        )
        .expect("should write request");

        use std::io::Read;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("should read response");

        assert!(
            response.contains("404"),
            "should return 404 for unconfigured path"
        );
    }

    #[test]
    fn mock_http_server_records_post_body() {
        let server = MockHttpServer::start();
        server.configure_response("/submit", 201, b"created");

        let addr = server.addr();
        let body = b"request body data";
        let mut stream =
            std::net::TcpStream::connect(addr).expect("should connect to mock server");
        use std::io::Write;
        write!(
            stream,
            "POST /submit HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            addr,
            body.len()
        )
        .expect("should write request headers");
        stream.write_all(body).expect("should write body");
        stream.flush().expect("should flush");

        use std::io::Read;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("should read response");

        // Give the server time to process.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let requests = server.requests_for_path("/submit");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].body, body);
    }

    #[test]
    fn test_scenario_builder_produces_valid_setup() {
        let env = TestScenarioBuilder::new()
            .with_policy("allow_all")
            .with_mock_channel()
            .with_channel_response("response-1")
            .with_mock_audit()
            .build();

        // Policy should allow by default.
        let action = file_read_action("agent", "/tmp/f");
        let verdict = env.policy.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Allow);

        // Channel should have the pre-configured response.
        assert_eq!(env.channel.recv_text(), Some("response-1".into()));

        // Audit store should be empty initially.
        assert_eq!(env.audit.count(), 0);

        // No HTTP server (not requested).
        assert!(env.http_server.is_none());
    }

    #[test]
    fn test_scenario_builder_deny_all_policy() {
        let env = TestScenarioBuilder::new()
            .with_policy("deny_all")
            .build();

        let action = file_read_action("agent", "/tmp/f");
        let verdict = env.policy.evaluate(&action);
        assert_eq!(verdict.decision, Decision::Deny);
    }

    #[test]
    fn test_scenario_builder_with_deny_kinds() {
        let env = TestScenarioBuilder::new()
            .deny_kind("FileWrite")
            .deny_kind("ProcessSpawn")
            .build();

        let read = file_read_action("agent", "/tmp/f");
        assert_eq!(env.policy.evaluate(&read).decision, Decision::Allow);

        let write = file_write_action("agent", "/tmp/f");
        assert_eq!(env.policy.evaluate(&write).decision, Decision::Deny);
    }

    #[test]
    fn test_scenario_builder_with_http() {
        let env = TestScenarioBuilder::new().with_mock_http().build();

        assert!(env.http_server.is_some());
        let server = env.http_server.as_ref().unwrap();
        assert!(server.url().starts_with("http://127.0.0.1:"));
    }

    // --- Thread safety tests ---

    #[test]
    fn mock_audit_thread_safety() {
        let store = MockAuditStore::new();
        let store_clone = store.clone();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let s = store_clone.clone();
                std::thread::spawn(move || {
                    for j in 0..100 {
                        let action = Action::new(
                            format!("agent-{i}"),
                            ActionKind::FileRead {
                                path: PathBuf::from(format!("/tmp/file-{i}-{j}")),
                            },
                        );
                        let verdict = Verdict::allow(action.id, "ok", None);
                        s.append(&action, &verdict);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        // 10 threads * 100 entries each = 1000 total.
        assert_eq!(store.count(), 1000);

        // Verify integrity: every entry should be present and queryable.
        let all = store.all_entries();
        assert_eq!(all.len(), 1000);

        // Verify all principals are present.
        let principals: HashSet<String> = all.iter().map(|e| e.action.principal.clone()).collect();
        for i in 0..10 {
            assert!(
                principals.contains(&format!("agent-{i}")),
                "missing principal agent-{i}"
            );
        }
    }

    #[test]
    fn mock_policy_thread_safety() {
        let engine = MockPolicyEngine::new();
        let engine_clone = engine.clone();

        let handles: Vec<_> = (0..5)
            .map(|i| {
                let e = engine_clone.clone();
                std::thread::spawn(move || {
                    for j in 0..50 {
                        let action = Action::new(
                            format!("agent-{i}"),
                            ActionKind::FileRead {
                                path: PathBuf::from(format!("/tmp/file-{i}-{j}")),
                            },
                        );
                        e.evaluate(&action);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        // 5 threads * 50 evaluations each = 250 total.
        assert_eq!(engine.evaluation_count(), 250);
    }

    #[test]
    fn mock_channel_thread_safety() {
        let channel = MockChannel::new();
        let channel_clone = channel.clone();

        let handles: Vec<_> = (0..5)
            .map(|i| {
                let c = channel_clone.clone();
                std::thread::spawn(move || {
                    for j in 0..20 {
                        c.send_text(format!("msg-{i}-{j}"));
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        // 5 threads * 20 messages each = 100 total.
        assert_eq!(channel.send_count(), 100);
        assert_eq!(channel.sent_messages().len(), 100);
    }

    #[test]
    fn mock_http_server_cleanup_on_drop() {
        let addr;
        {
            let server = MockHttpServer::start();
            addr = server.addr();
            // Server should be reachable.
            assert!(std::net::TcpStream::connect(addr).is_ok());
        }
        // After drop, give the thread a moment to shut down.
        std::thread::sleep(std::time::Duration::from_millis(100));
        // Server should no longer be accepting connections.
        // (Connection may still succeed briefly due to OS socket lingering,
        // but the server thread should have exited.)
    }
}
