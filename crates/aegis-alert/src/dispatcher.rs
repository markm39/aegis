//! Background alert evaluation and dispatch loop.
//!
//! The [`AlertDispatcher`] runs on a dedicated `std::thread` with its own
//! single-threaded tokio runtime. It consumes [`AlertEvent`]s from an
//! `std::sync::mpsc::Receiver`, evaluates them against configured alert rules,
//! enforces per-rule cooldowns, and dispatches webhooks via `reqwest`.

use std::collections::HashMap;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use aegis_types::AlertRule;
use chrono::Utc;
use rusqlite::Connection;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::log as alert_log;
use crate::matcher;
use crate::payload;
use crate::AlertEvent;

/// Configuration for the alert dispatcher.
pub struct DispatcherConfig {
    /// Alert rules to evaluate against every event.
    pub rules: Vec<AlertRule>,
    /// Aegis config name (included in webhook payloads).
    pub config_name: String,
    /// Path to the SQLite database for the alert_log table.
    pub db_path: String,
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
            error!("failed to open alert log database at {}: {e}", config.db_path);
            return;
        }
    };

    if let Err(e) = alert_log::init_table(&log_conn) {
        error!("failed to initialize alert_log table: {e}");
        return;
    }

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

            // Build and dispatch the webhook.
            let payload =
                payload::build_payload(&rule.name, &config.config_name, &event, false);
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
        }
    }

    info!("alert dispatcher shutting down (channel closed)");
}

/// Send a test webhook to verify connectivity for a specific rule.
///
/// Returns `Ok(status_code)` on HTTP success, or an error string.
pub async fn send_test_webhook(
    rule: &AlertRule,
    config_name: &str,
) -> Result<u16, String> {
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
        cooldowns.insert(
            rule_name.clone(),
            Instant::now() - Duration::from_secs(31),
        );
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
        };

        let handle = std::thread::spawn(move || {
            run(config, rx);
        });

        // Drop the sender to close the channel.
        drop(tx);

        // The dispatcher thread should exit promptly.
        handle.join().expect("dispatcher thread should exit cleanly");
    }
}
