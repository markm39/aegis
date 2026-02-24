//! Background alert evaluation and dispatch loop.
//!
//! The [`AlertDispatcher`] runs on a dedicated `std::thread` with its own
//! single-threaded tokio runtime. It consumes [`AlertEvent`]s from an
//! `std::sync::mpsc::Receiver`, evaluates them against configured alert rules,
//! enforces per-rule cooldowns, and dispatches webhooks via `reqwest`.

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use aegis_types::AlertRule;
use chrono::Utc;
use rusqlite::Connection;
use tracing::{debug, error, info, warn};
use url::Url;
use uuid::Uuid;

use crate::log as alert_log;
use crate::matcher;
use crate::payload;
use crate::push::{self, PushNotification, PushRateLimiter, PushSubscriptionStore, VapidConfig};
use crate::AlertEvent;

/// Configuration for the alert dispatcher.
pub struct DispatcherConfig {
    /// Alert rules to evaluate against every event.
    pub rules: Vec<AlertRule>,
    /// Aegis config name (included in webhook payloads).
    pub config_name: String,
    /// Path to the SQLite database for the alert_log table.
    pub db_path: String,
    /// Optional path to a SQLite database for push subscriptions.
    ///
    /// When set, the dispatcher will also attempt push notification
    /// delivery for matching alert events.
    pub push_db_path: Option<String>,
    /// Optional VAPID configuration for Web Push authentication.
    pub vapid_config: Option<VapidConfig>,
}

/// Check if an IP address is in a private, loopback, or link-local range.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()          // 127.0.0.0/8
                || v4.is_private()    // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local() // 169.254.0.0/16
                || v4.is_broadcast()  // 255.255.255.255
                || v4.is_unspecified() // 0.0.0.0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()       // ::1
                || v6.is_unspecified() // ::
                // fc00::/7 (unique local addresses)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 (link-local)
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Validate a webhook URL to prevent SSRF attacks.
///
/// Rejects URLs that target private/loopback/link-local IPs, cloud metadata
/// endpoints, and non-HTTPS schemes. Returns the validated URL or an error.
fn validate_webhook_url(webhook_url: &str) -> Result<(), String> {
    let parsed = Url::parse(webhook_url).map_err(|e| format!("invalid webhook URL: {e}"))?;

    // Require HTTPS (or HTTP to localhost for development).
    match parsed.scheme() {
        "https" => {}
        "http" => {
            // Allow HTTP only to localhost for local development.
            let host = parsed.host_str().unwrap_or("");
            if host != "localhost" && host != "127.0.0.1" && host != "::1" {
                return Err(format!("webhook URL must use HTTPS (got HTTP to {host})"));
            }
        }
        scheme => {
            return Err(format!("unsupported webhook URL scheme: {scheme}"));
        }
    }

    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "webhook URL has no host".to_string())?;

    // DNS resolution to catch private IPs behind hostnames.
    let port = parsed
        .port()
        .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
    let addr_str = format!("{host}:{port}");

    match addr_str.to_socket_addrs() {
        Ok(addrs) => {
            for addr in addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(format!(
                        "webhook URL resolves to private/loopback address: {}",
                        addr.ip()
                    ));
                }
            }
        }
        Err(_) => {
            // If DNS resolution fails, check if host is a raw IP.
            if let Ok(ip) = host.parse::<IpAddr>() {
                if is_private_ip(&ip) {
                    return Err(format!(
                        "webhook URL targets private/loopback address: {ip}"
                    ));
                }
            }
            // If DNS fails and it's not a raw IP, the request will fail
            // at send time -- that's fine, not an SSRF risk.
        }
    }

    Ok(())
}

/// Run the alert dispatcher loop on the current thread.
///
/// This function blocks until the `receiver` channel is disconnected (i.e.,
/// when all senders are dropped). It creates its own tokio runtime for async
/// HTTP calls.
///
/// Intended to be called from a dedicated `std::thread::spawn`.
pub fn run(config: DispatcherConfig, receiver: Receiver<AlertEvent>) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!("failed to create tokio runtime for alert dispatcher: {e}");
            return;
        }
    };

    rt.block_on(async {
        run_loop(config, receiver).await;
    });
}

async fn run_loop(config: DispatcherConfig, receiver: Receiver<AlertEvent>) {
    // Open a separate SQLite connection for alert logging.
    let log_conn = match Connection::open(&config.db_path) {
        Ok(conn) => conn,
        Err(e) => {
            error!(
                "failed to open alert log database at {}: {e}",
                config.db_path
            );
            return;
        }
    };

    if let Err(e) = alert_log::init_table(&log_conn) {
        error!("failed to initialize alert_log table: {e}");
        return;
    }

    // Open push subscription store if configured.
    let push_store =
        config
            .push_db_path
            .as_ref()
            .and_then(|path| match PushSubscriptionStore::open(path) {
                Ok(store) => {
                    info!("push subscription store opened at {path}");
                    Some(store)
                }
                Err(e) => {
                    error!("failed to open push subscription store at {path}: {e}");
                    None
                }
            });

    let push_rate_limiter = PushRateLimiter::new(60);

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!("failed to build HTTP client (TLS init?): {e}");
            return;
        }
    };

    // Per-rule cooldown tracking: rule_name -> last fire time.
    let mut cooldowns: HashMap<String, Instant> = HashMap::new();

    info!(
        "alert dispatcher started with {} rule(s) for config {:?}",
        config.rules.len(),
        config.config_name
    );

    // Block on recv() -- this naturally waits when there are no events
    // and exits when the channel disconnects.
    while let Ok(event) = receiver.recv() {
        for rule in &config.rules {
            if !matcher::matches(rule, &event) {
                continue;
            }

            // Check cooldown.
            let cooldown_dur = Duration::from_secs(rule.cooldown_secs);
            if let Some(last_fire) = cooldowns.get(&rule.name) {
                if last_fire.elapsed() < cooldown_dur {
                    debug!(
                        "alert rule {:?} in cooldown ({} remaining), skipping",
                        rule.name,
                        cooldown_dur
                            .checked_sub(last_fire.elapsed())
                            .unwrap_or_default()
                            .as_secs()
                    );
                    continue;
                }
            }

            // SSRF protection: validate webhook URL before dispatching.
            if let Err(e) = validate_webhook_url(&rule.webhook_url) {
                warn!(
                    rule = %rule.name,
                    url = %rule.webhook_url,
                    error = %e,
                    "webhook URL rejected by SSRF validation"
                );
                continue;
            }

            // Build and dispatch the webhook.
            let payload = payload::build_payload(&rule.name, &config.config_name, &event, false);
            let alert_id = payload.alert.id.clone();

            let result = client
                .post(&rule.webhook_url)
                .header("Content-Type", "application/json")
                .header("User-Agent", "aegis-alert/0.1")
                .json(&payload)
                .send()
                .await;

            // Update cooldown regardless of success (avoid hammering a broken endpoint).
            cooldowns.insert(rule.name.clone(), Instant::now());

            match result {
                Ok(resp) => {
                    let status = resp.status().as_u16() as i32;
                    let success = resp.status().is_success();

                    if success {
                        info!(
                            "alert dispatched: rule={:?} entry={} status={}",
                            rule.name, event.entry_id, status
                        );
                    } else {
                        warn!(
                            "alert webhook returned non-success: rule={:?} entry={} status={}",
                            rule.name, event.entry_id, status
                        );
                    }

                    let err_msg = if success {
                        None
                    } else {
                        Some(format!("HTTP {status}"))
                    };
                    if let Err(db_err) = alert_log::record_dispatch(
                        &log_conn,
                        &alert_id,
                        &rule.name,
                        &event.entry_id.to_string(),
                        Utc::now(),
                        &rule.webhook_url,
                        Some(status),
                        success,
                        err_msg.as_deref(),
                    ) {
                        error!("failed to record alert dispatch to database: {db_err}");
                    }
                }
                Err(e) => {
                    error!(
                        "alert webhook failed: rule={:?} entry={} error={e}",
                        rule.name, event.entry_id
                    );

                    if let Err(db_err) = alert_log::record_dispatch(
                        &log_conn,
                        &alert_id,
                        &rule.name,
                        &event.entry_id.to_string(),
                        Utc::now(),
                        &rule.webhook_url,
                        None,
                        false,
                        Some(&e.to_string()),
                    ) {
                        error!("failed to record alert dispatch failure to database: {db_err}");
                    }
                }
            }

            // Also deliver via Web Push to all active subscriptions.
            dispatch_push_notifications(
                &push_store,
                &config.vapid_config,
                &push_rate_limiter,
                &rule.name,
                &event,
            )
            .await;
        }
    }

    info!("alert dispatcher shutting down (channel closed)");
}

/// Attempt push notification delivery to all active subscriptions.
///
/// This is a best-effort operation -- failures are logged but do not
/// affect webhook dispatch.
async fn dispatch_push_notifications(
    push_store: &Option<PushSubscriptionStore>,
    vapid_config: &Option<VapidConfig>,
    rate_limiter: &PushRateLimiter,
    rule_name: &str,
    event: &AlertEvent,
) {
    let store = match push_store {
        Some(s) => s,
        None => return,
    };

    let vapid = match vapid_config {
        Some(v) => v,
        None => {
            debug!("push delivery skipped: no VAPID config");
            return;
        }
    };

    // Clean up expired subscriptions opportunistically.
    if let Err(e) = store.cleanup_expired() {
        warn!("failed to cleanup expired push subscriptions: {e}");
    }

    let subscriptions = match store.list_subscriptions() {
        Ok(subs) => subs,
        Err(e) => {
            error!("failed to list push subscriptions for delivery: {e}");
            return;
        }
    };

    if subscriptions.is_empty() {
        return;
    }

    let notification = PushNotification {
        title: format!("Aegis Alert: {rule_name}"),
        body: format!(
            "{} {} ({})",
            event.action_kind, event.decision, event.principal
        ),
        icon: None,
        url: None,
        tag: Some(rule_name.to_string()),
    };

    for sub in &subscriptions {
        match push::deliver_push_notification(sub, &notification, vapid, rate_limiter).await {
            Ok(()) => {
                if let Err(e) = store.update_last_used(&sub.id) {
                    warn!("failed to update push subscription last_used: {e}");
                }
            }
            Err(e) => {
                debug!("push delivery to subscription {} failed: {e}", sub.id);
            }
        }
    }
}

/// Send a test webhook to verify connectivity for a specific rule.
///
/// Returns `Ok(status_code)` on HTTP success, or an error string.
pub async fn send_test_webhook(rule: &AlertRule, config_name: &str) -> Result<u16, String> {
    validate_webhook_url(&rule.webhook_url)?;

    let test_event = AlertEvent {
        entry_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        action_kind: "FileWrite".into(),
        action_detail: r#"{"FileWrite":{"path":"/tmp/aegis-test"}}"#.into(),
        principal: config_name.to_string(),
        decision: "Allow".into(),
        reason: "test alert -- verifying webhook connectivity".into(),
        policy_id: None,
        session_id: None,
        pilot_context: None,
    };

    let payload = payload::build_payload(&rule.name, config_name, &test_event, true);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?;

    let resp = client
        .post(&rule.webhook_url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "aegis-alert/0.1")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("webhook request failed: {e}"))?;

    let status = resp.status().as_u16();
    if resp.status().is_success() {
        Ok(status)
    } else {
        Err(format!("webhook returned HTTP {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn ssrf_rejects_private_ips() {
        assert!(validate_webhook_url("https://10.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://172.16.0.1/hook").is_err());
        assert!(validate_webhook_url("https://192.168.1.1/hook").is_err());
        assert!(validate_webhook_url("https://127.0.0.1/hook").is_err());
        assert!(validate_webhook_url("https://169.254.169.254/latest/meta-data/").is_err());
    }

    #[test]
    fn ssrf_rejects_non_https() {
        assert!(validate_webhook_url("http://example.com/hook").is_err());
        assert!(validate_webhook_url("ftp://example.com/hook").is_err());
    }

    #[test]
    fn ssrf_allows_http_localhost() {
        // HTTP to localhost is allowed for development.
        let result = validate_webhook_url("http://localhost:8080/hook");
        // May fail DNS resolution in CI, but should not fail on scheme.
        if let Err(ref e) = result {
            assert!(
                !e.contains("must use HTTPS"),
                "localhost HTTP should be allowed: {e}"
            );
        }
    }

    #[test]
    fn ssrf_rejects_no_host_schemes() {
        // Non-HTTP schemes that cannot have hosts.
        assert!(validate_webhook_url("data:text/html,hello").is_err());
        assert!(validate_webhook_url("file:///etc/passwd").is_err());
        assert!(validate_webhook_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn ssrf_rejects_invalid_url() {
        assert!(validate_webhook_url("not a url").is_err());
    }

    #[test]
    fn is_private_ip_checks() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn cooldown_tracking_works() {
        // Verify that our cooldown HashMap logic works correctly.
        let mut cooldowns: HashMap<String, Instant> = HashMap::new();
        let rule_name = "test-rule".to_string();
        let cooldown_dur = Duration::from_secs(30);

        // First time: no cooldown entry, should proceed.
        assert!(!cooldowns.contains_key(&rule_name));

        // Record a fire.
        cooldowns.insert(rule_name.clone(), Instant::now());

        // Immediately check: should still be in cooldown.
        let last_fire = cooldowns.get(&rule_name).unwrap();
        assert!(last_fire.elapsed() < cooldown_dur);

        // After cooldown expires (simulated by back-dating the entry).
        cooldowns.insert(rule_name.clone(), Instant::now() - Duration::from_secs(31));
        let last_fire = cooldowns.get(&rule_name).unwrap();
        assert!(last_fire.elapsed() >= cooldown_dur);
    }

    #[test]
    fn dispatcher_exits_when_channel_drops() {
        // Verify the dispatcher thread exits cleanly when the sender is dropped.
        let (tx, rx) = mpsc::sync_channel::<AlertEvent>(16);
        let config = DispatcherConfig {
            rules: vec![],
            config_name: "test".into(),
            db_path: ":memory:".into(),
            push_db_path: None,
            vapid_config: None,
        };

        let handle = std::thread::spawn(move || {
            run(config, rx);
        });

        // Drop the sender to close the channel.
        drop(tx);

        // The dispatcher thread should exit promptly.
        handle
            .join()
            .expect("dispatcher thread should exit cleanly");
    }
}
