//! NetworkProxy: transparent TCP proxy with policy enforcement and audit logging.
//!
//! Accepts inbound TCP connections, evaluates each against the Cedar policy engine,
//! logs verdicts to the audit ledger, and either proxies bytes bidirectionally or
//! closes the connection.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use aegis_ledger::AuditStore;
use aegis_policy::PolicyEngine;
use aegis_types::{Action, ActionKind, AegisError, Decision, Verdict};

/// A transparent TCP proxy that intercepts outbound connections with policy checks.
pub struct NetworkProxy {
    policy: Arc<Mutex<PolicyEngine>>,
    store: Arc<Mutex<AuditStore>>,
    principal: String,
    bind_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl NetworkProxy {
    /// Create a new network proxy.
    ///
    /// - `policy`: shared policy engine for authorization decisions
    /// - `store`: shared audit store for logging verdicts
    /// - `principal`: agent name used as the Action principal
    /// - `bind_port`: local port to bind the proxy listener
    pub fn new(
        policy: Arc<Mutex<PolicyEngine>>,
        store: Arc<Mutex<AuditStore>>,
        principal: String,
        bind_port: u16,
    ) -> Self {
        let (shutdown, shutdown_rx) = watch::channel(false);
        let bind_addr = SocketAddr::from(([127, 0, 0, 1], bind_port));

        Self {
            policy,
            store,
            principal,
            bind_addr,
            shutdown,
            shutdown_rx,
        }
    }

    /// Start the proxy, listening for incoming TCP connections.
    ///
    /// Returns a `JoinHandle` for the spawned tokio task. Each accepted
    /// connection is evaluated against the policy engine before proxying.
    pub fn start(&self) -> JoinHandle<()> {
        let policy = Arc::clone(&self.policy);
        let store = Arc::clone(&self.store);
        let principal = self.principal.clone();
        let bind_addr = self.bind_addr;
        let mut shutdown_rx = self.shutdown_rx.clone();

        tokio::spawn(async move {
            let listener = match TcpListener::bind(bind_addr).await {
                Ok(l) => {
                    tracing::info!(addr = %bind_addr, "network proxy listening");
                    l
                }
                Err(e) => {
                    tracing::error!(addr = %bind_addr, error = %e, "failed to bind proxy listener");
                    return;
                }
            };

            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                tracing::debug!(peer = %peer_addr, "accepted connection");
                                let policy = Arc::clone(&policy);
                                let store = Arc::clone(&store);
                                let principal = principal.clone();

                                tokio::spawn(async move {
                                    handle_connection(stream, peer_addr, policy, store, principal).await;
                                });
                            }
                            Err(e) => {
                                tracing::error!(error = %e, "failed to accept connection");
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            tracing::info!("network proxy shutting down");
                            break;
                        }
                    }
                }
            }
        })
    }

    /// Signal the proxy to shut down.
    pub fn stop(&self) {
        if let Err(e) = self.shutdown.send(true) {
            tracing::error!(error = %e, "failed to send shutdown signal");
        }
    }

    /// Return the bind address for the proxy.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

/// Evaluate policy and log verdict synchronously (no async).
///
/// Acquires both the policy and store locks, evaluates the action, appends
/// the audit entry, and returns the verdict.
fn check_and_log_net(
    policy: &Arc<Mutex<PolicyEngine>>,
    store: &Arc<Mutex<AuditStore>>,
    action: &Action,
) -> Result<Verdict, AegisError> {
    let verdict = policy
        .lock()
        .map_err(|e| AegisError::PolicyError(format!("policy lock poisoned: {e}")))?
        .evaluate(action);

    store
        .lock()
        .map_err(|e| AegisError::LedgerError(format!("audit lock poisoned: {e}")))?
        .append(action, &verdict)?;

    Ok(verdict)
}

/// Handle a single proxied connection.
///
/// For Phase 0, this extracts the peer address as the destination, evaluates
/// a NetConnect action, and proxies bytes if allowed.
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    policy: Arc<Mutex<PolicyEngine>>,
    store: Arc<Mutex<AuditStore>>,
    principal: String,
) {
    let host = peer_addr.ip().to_string();
    let port = peer_addr.port();

    let action = Action::new(
        &principal,
        ActionKind::NetConnect {
            host: host.clone(),
            port,
        },
    );

    // Evaluate policy and log verdict. Both locks are acquired and released
    // before any .await point so the MutexGuards (which are not Send) don't
    // cross an await boundary.
    let verdict = match check_and_log_net(&policy, &store, &action) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "failed to check policy or log audit");
            let _ = stream.shutdown().await;
            return;
        }
    };

    match verdict.decision {
        Decision::Allow => {
            tracing::debug!(
                host = %host,
                port = port,
                "connection allowed, proxying"
            );
            // Phase 0: just close the connection after allowing.
            // Full bidirectional proxy will be implemented in Phase 1 when we have
            // a proper destination extraction mechanism (e.g. SO_ORIGINAL_DST).
            if let Err(e) = stream.shutdown().await {
                tracing::debug!(error = %e, "stream shutdown");
            }
        }
        Decision::Deny => {
            tracing::info!(
                host = %host,
                port = port,
                reason = %verdict.reason,
                "connection denied"
            );
            if let Err(e) = stream.shutdown().await {
                tracing::debug!(error = %e, "stream shutdown after deny");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_ledger::AuditStore;
    use aegis_policy::PolicyEngine;
    use tempfile::NamedTempFile;

    /// Returns the proxy along with the temp file handle to keep it alive.
    fn make_proxy(policy_str: &str) -> (NetworkProxy, NamedTempFile) {
        let engine =
            PolicyEngine::from_policies(policy_str, None).expect("should create policy engine");
        let db_file = NamedTempFile::new().expect("should create temp file");
        let store = AuditStore::open(db_file.path()).expect("should open audit store");

        let proxy = NetworkProxy::new(
            Arc::new(Mutex::new(engine)),
            Arc::new(Mutex::new(store)),
            "test-agent".to_string(),
            0, // OS-assigned port
        );
        (proxy, db_file)
    }

    #[test]
    fn proxy_creation() {
        let (proxy, _db) = make_proxy(r#"permit(principal, action, resource);"#);
        assert_eq!(proxy.principal, "test-agent");
        assert_eq!(proxy.bind_addr.ip(), std::net::Ipv4Addr::LOCALHOST);
    }

    #[test]
    fn proxy_stop_sends_signal() {
        let (proxy, _db) = make_proxy(r#"permit(principal, action, resource);"#);
        proxy.stop();
        assert!(*proxy.shutdown_rx.borrow());
    }

    #[test]
    fn proxy_bind_addr() {
        let (proxy, _db) = make_proxy(r#"permit(principal, action, resource);"#);
        let addr = proxy.bind_addr();
        assert_eq!(addr.ip(), std::net::Ipv4Addr::new(127, 0, 0, 1));
    }

    /// Returns shared policy + store for testing check_and_log_net directly.
    fn make_test_deps(
        policy_str: &str,
    ) -> (Arc<Mutex<AuditStore>>, Arc<Mutex<PolicyEngine>>, NamedTempFile) {
        let engine =
            PolicyEngine::from_policies(policy_str, None).expect("should create policy engine");
        let db_file = NamedTempFile::new().expect("should create temp file");
        let store = AuditStore::open(db_file.path()).expect("should open audit store");
        (Arc::new(Mutex::new(store)), Arc::new(Mutex::new(engine)), db_file)
    }

    #[test]
    fn check_and_log_net_allows_with_permit_all() {
        let (store, policy, _db) =
            make_test_deps(r#"permit(principal, action, resource);"#);

        let action = Action::new(
            "test-agent",
            ActionKind::NetConnect {
                host: "example.com".to_string(),
                port: 443,
            },
        );

        let verdict = check_and_log_net(&policy, &store, &action)
            .expect("should succeed");

        assert_eq!(verdict.decision, Decision::Allow);
    }

    #[test]
    fn check_and_log_net_denies_with_forbid_all() {
        let (store, policy, _db) =
            make_test_deps(r#"forbid(principal, action, resource);"#);

        let action = Action::new(
            "test-agent",
            ActionKind::NetConnect {
                host: "evil.com".to_string(),
                port: 80,
            },
        );

        let verdict = check_and_log_net(&policy, &store, &action)
            .expect("should succeed");

        assert_eq!(verdict.decision, Decision::Deny);
    }

    #[test]
    fn check_and_log_net_creates_audit_entry() {
        let (store, policy, _db) =
            make_test_deps(r#"permit(principal, action, resource);"#);

        let action = Action::new(
            "test-agent",
            ActionKind::NetConnect {
                host: "api.example.com".to_string(),
                port: 8080,
            },
        );

        check_and_log_net(&policy, &store, &action).expect("should succeed");

        let count = store.lock().unwrap().count().unwrap();
        assert_eq!(count, 1, "should have exactly 1 audit entry");
    }

    #[test]
    fn check_and_log_net_denied_still_logs() {
        let (store, policy, _db) =
            make_test_deps(r#"forbid(principal, action, resource);"#);

        let action = Action::new(
            "test-agent",
            ActionKind::NetConnect {
                host: "blocked.com".to_string(),
                port: 443,
            },
        );

        check_and_log_net(&policy, &store, &action).expect("should succeed");

        let count = store.lock().unwrap().count().unwrap();
        assert_eq!(count, 1, "denied actions should still be logged");
    }
}
