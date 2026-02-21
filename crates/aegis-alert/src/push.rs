//! Web Push notification subscriptions with VAPID support.
//!
//! Provides subscription management (CRUD backed by SQLite), endpoint
//! validation with SSRF protection, key validation, payload sanitization,
//! and rate limiting.  Actual ECDH/HKDF/AES-GCM encryption and HTTP
//! delivery are stubbed with TODO markers because they require the `p256`
//! and `aes-gcm` crates which are not yet in the workspace.

use std::sync::Mutex;
use std::time::Instant;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use rusqlite::Connection;
use tracing::{debug, info, warn};
use url::Url;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A Web Push subscription from a browser client.
#[derive(Debug, Clone)]
pub struct PushSubscription {
    /// Unique subscription identifier.
    pub id: Uuid,
    /// Push service endpoint URL (must be HTTPS).
    pub endpoint: String,
    /// Client public key for ECDH (base64url, 65 bytes uncompressed P-256).
    pub p256dh: String,
    /// Client auth secret (base64url, 16 bytes).
    pub auth: String,
    /// Optional human label ("Mark's phone", etc.).
    pub user_label: Option<String>,
    /// When the subscription was created.
    pub created_at: DateTime<Utc>,
    /// When the subscription was last used to send a notification.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Optional expiration time for the subscription.
    pub expires_at: Option<DateTime<Utc>>,
}

/// VAPID (Voluntary Application Server Identification) configuration.
///
/// The private key must be stored with restrictive file permissions (0600)
/// and must never appear in logs.
#[derive(Debug, Clone)]
pub struct VapidConfig {
    /// VAPID subject (typically `mailto:admin@example.com`).
    pub subject: String,
    /// VAPID public key (base64url-encoded, 65 bytes uncompressed P-256).
    pub public_key: String,
    /// VAPID private key (base64url-encoded, 32 bytes raw P-256 scalar).
    ///
    /// **Security**: Never log this value.
    pub private_key: String,
}

/// A push notification payload ready for delivery.
#[derive(Debug, Clone)]
pub struct PushNotification {
    /// Notification title.
    pub title: String,
    /// Notification body text.
    pub body: String,
    /// Optional icon URL.
    pub icon: Option<String>,
    /// Optional click-through URL.
    pub url: Option<String>,
    /// Optional tag for notification collapsing.
    pub tag: Option<String>,
}

// ---------------------------------------------------------------------------
// Known push service origins (allowlist)
// ---------------------------------------------------------------------------

/// Known push service endpoint origins.  We reject endpoints that do not
/// match any of these to prevent SSRF against internal services.
const KNOWN_PUSH_ORIGINS: &[&str] = &[
    "fcm.googleapis.com",
    "push.services.mozilla.com",
    "updates.push.services.mozilla.com",
    "wns.windows.com",
    "notify.windows.com",
    "web.push.apple.com",
    "push.apple.com",
];

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a push subscription endpoint URL.
///
/// Security checks:
/// 1. Must be HTTPS.
/// 2. Must be a valid URL.
/// 3. Must not target private/loopback/link-local IPs (SSRF protection).
/// 4. Must match a known push service origin.
pub fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    let url = Url::parse(endpoint).map_err(|e| format!("invalid URL: {e}"))?;

    // Require HTTPS -- push services mandate encrypted transport.
    if url.scheme() != "https" {
        return Err("push endpoint must use HTTPS".into());
    }

    let host = url
        .host_str()
        .ok_or_else(|| "push endpoint must have a host".to_string())?;

    // Block private/loopback/link-local IPs (SSRF protection).
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip.is_loopback() || is_private_ip(ip) || is_link_local(ip) {
            return Err("push endpoint must not target private or loopback addresses".into());
        }
    }

    // Block localhost by name.
    let host_lower = host.to_lowercase();
    if host_lower == "localhost" || host_lower.ends_with(".local") {
        return Err("push endpoint must not target localhost".into());
    }

    // Verify the endpoint matches a known push service origin.
    let is_known = KNOWN_PUSH_ORIGINS
        .iter()
        .any(|origin| host_lower == *origin || host_lower.ends_with(&format!(".{origin}")));
    if !is_known {
        return Err(format!(
            "push endpoint host {host_lower} is not a recognized push service"
        ));
    }

    Ok(())
}

/// Check whether the given IP is in a private range (RFC 1918 / RFC 4193).
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 169.254.0.0/16 (link-local)
            || (octets[0] == 169 && octets[1] == 254)
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            // fc00::/7 (unique local)
            (segments[0] & 0xfe00) == 0xfc00
            // ::1 loopback
            || v6.is_loopback()
        }
    }
}

/// Check for link-local addresses.
fn is_link_local(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 169 && octets[1] == 254
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Validate a P-256 public key encoded as base64url.
///
/// An uncompressed P-256 public key is exactly 65 bytes (0x04 || x || y).
pub fn validate_p256dh(key: &str) -> Result<(), String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(key)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(key))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(key))
        .map_err(|e| format!("p256dh is not valid base64: {e}"))?;

    if bytes.len() != 65 {
        return Err(format!(
            "p256dh must be 65 bytes (uncompressed P-256), got {}",
            bytes.len()
        ));
    }

    if bytes[0] != 0x04 {
        return Err("p256dh must start with 0x04 (uncompressed point)".into());
    }

    Ok(())
}

/// Validate a push subscription auth secret encoded as base64url.
///
/// The auth secret is exactly 16 bytes.
pub fn validate_auth_key(key: &str) -> Result<(), String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(key)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(key))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(key))
        .map_err(|e| format!("auth key is not valid base64: {e}"))?;

    if bytes.len() != 16 {
        return Err(format!(
            "auth key must be 16 bytes, got {}",
            bytes.len()
        ));
    }

    Ok(())
}

/// Sanitize a notification payload by removing control characters.
///
/// Strips ASCII control chars (0x00-0x1F, 0x7F) except for newline (0x0A)
/// and tab (0x09) which are sometimes meaningful.
pub fn sanitize_text(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect()
}

/// Sanitize a full `PushNotification` payload in place.
pub fn sanitize_notification(notif: &mut PushNotification) {
    notif.title = sanitize_text(&notif.title);
    notif.body = sanitize_text(&notif.body);
    if let Some(ref mut url) = notif.url {
        *url = sanitize_text(url);
    }
    if let Some(ref mut tag) = notif.tag {
        *tag = sanitize_text(tag);
    }
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/// Simple token-bucket rate limiter: max 60 push notifications per minute.
pub struct PushRateLimiter {
    inner: Mutex<RateLimiterInner>,
}

struct RateLimiterInner {
    /// Timestamps of recent sends.
    timestamps: Vec<Instant>,
    /// Maximum sends per window.
    max_per_window: usize,
    /// Window duration.
    window: std::time::Duration,
}

impl PushRateLimiter {
    /// Create a new rate limiter allowing `max_per_minute` pushes per 60 seconds.
    pub fn new(max_per_minute: usize) -> Self {
        Self {
            inner: Mutex::new(RateLimiterInner {
                timestamps: Vec::new(),
                max_per_window: max_per_minute,
                window: std::time::Duration::from_secs(60),
            }),
        }
    }

    /// Check if a push is allowed. Returns `true` and records the attempt if
    /// within the rate limit; returns `false` if the limit is exceeded.
    pub fn check_and_record(&self) -> bool {
        let mut inner = self.inner.lock().expect("rate limiter lock poisoned");
        let now = Instant::now();

        // Prune timestamps outside the window.
        let window = inner.window;
        inner.timestamps.retain(|t| now.duration_since(*t) < window);

        if inner.timestamps.len() >= inner.max_per_window {
            false
        } else {
            inner.timestamps.push(now);
            true
        }
    }
}

// ---------------------------------------------------------------------------
// SQLite-backed subscription store
// ---------------------------------------------------------------------------

/// Manages push subscriptions in a SQLite database.
pub struct PushSubscriptionStore {
    conn: Connection,
}

impl PushSubscriptionStore {
    /// Open (or create) the subscription store at the given database path.
    ///
    /// Creates the `push_subscriptions` table if it does not exist.
    pub fn open(db_path: &str) -> Result<Self, String> {
        let conn =
            Connection::open(db_path).map_err(|e| format!("failed to open push DB: {e}"))?;
        Self::init_table(&conn)?;
        Ok(Self { conn })
    }

    /// Open an in-memory store (useful for testing).
    #[cfg(test)]
    pub fn open_memory() -> Result<Self, String> {
        Self::open(":memory:")
    }

    fn init_table(conn: &Connection) -> Result<(), String> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS push_subscriptions (
                id TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                p256dh TEXT NOT NULL,
                auth TEXT NOT NULL,
                user_label TEXT,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                expires_at TEXT
            );",
        )
        .map_err(|e| format!("failed to create push_subscriptions table: {e}"))
    }

    /// Add a new subscription after validating all fields.
    ///
    /// Returns the newly assigned subscription ID.
    pub fn add_subscription(
        &self,
        endpoint: &str,
        p256dh: &str,
        auth: &str,
        label: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Uuid, String> {
        // Validate endpoint (SSRF protection).
        validate_endpoint(endpoint)?;
        // Validate cryptographic keys.
        validate_p256dh(p256dh)?;
        validate_auth_key(auth)?;

        let id = Uuid::new_v4();
        let now = Utc::now();

        self.conn
            .execute(
                "INSERT INTO push_subscriptions (id, endpoint, p256dh, auth, user_label, created_at, last_used_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
                rusqlite::params![
                    id.to_string(),
                    endpoint,
                    p256dh,
                    auth,
                    label,
                    now.to_rfc3339(),
                    expires_at.map(|t| t.to_rfc3339()),
                ],
            )
            .map_err(|e| format!("failed to insert push subscription: {e}"))?;

        info!("push subscription added: id={id}");
        Ok(id)
    }

    /// Remove a subscription by ID.
    pub fn remove_subscription(&self, id: &Uuid) -> Result<bool, String> {
        let deleted = self
            .conn
            .execute(
                "DELETE FROM push_subscriptions WHERE id = ?1",
                rusqlite::params![id.to_string()],
            )
            .map_err(|e| format!("failed to delete push subscription: {e}"))?;

        if deleted > 0 {
            info!("push subscription removed: id={id}");
        }

        Ok(deleted > 0)
    }

    /// List all subscriptions.
    pub fn list_subscriptions(&self) -> Result<Vec<PushSubscription>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, endpoint, p256dh, auth, user_label, created_at, last_used_at, expires_at
                 FROM push_subscriptions ORDER BY created_at DESC",
            )
            .map_err(|e| format!("failed to prepare list query: {e}"))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(PushSubscription {
                    id: row
                        .get::<_, String>(0)
                        .map(|s| Uuid::parse_str(&s).unwrap_or_default())?,
                    endpoint: row.get(1)?,
                    p256dh: row.get(2)?,
                    auth: row.get(3)?,
                    user_label: row.get(4)?,
                    created_at: row
                        .get::<_, String>(5)
                        .map(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|dt| dt.with_timezone(&Utc))
                                .unwrap_or_default()
                        })?,
                    last_used_at: row.get::<_, Option<String>>(6).map(|opt| {
                        opt.and_then(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|dt| dt.with_timezone(&Utc))
                                .ok()
                        })
                    })?,
                    expires_at: row.get::<_, Option<String>>(7).map(|opt| {
                        opt.and_then(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|dt| dt.with_timezone(&Utc))
                                .ok()
                        })
                    })?,
                })
            })
            .map_err(|e| format!("failed to query push subscriptions: {e}"))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| format!("failed to read subscription row: {e}"))?);
        }
        Ok(result)
    }

    /// Get a single subscription by ID.
    pub fn get_subscription(&self, id: &Uuid) -> Result<Option<PushSubscription>, String> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, endpoint, p256dh, auth, user_label, created_at, last_used_at, expires_at
                 FROM push_subscriptions WHERE id = ?1",
            )
            .map_err(|e| format!("failed to prepare get query: {e}"))?;

        let mut rows = stmt
            .query_map(rusqlite::params![id.to_string()], |row| {
                Ok(PushSubscription {
                    id: row
                        .get::<_, String>(0)
                        .map(|s| Uuid::parse_str(&s).unwrap_or_default())?,
                    endpoint: row.get(1)?,
                    p256dh: row.get(2)?,
                    auth: row.get(3)?,
                    user_label: row.get(4)?,
                    created_at: row
                        .get::<_, String>(5)
                        .map(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|dt| dt.with_timezone(&Utc))
                                .unwrap_or_default()
                        })?,
                    last_used_at: row.get::<_, Option<String>>(6).map(|opt| {
                        opt.and_then(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|dt| dt.with_timezone(&Utc))
                                .ok()
                        })
                    })?,
                    expires_at: row.get::<_, Option<String>>(7).map(|opt| {
                        opt.and_then(|s| {
                            DateTime::parse_from_rfc3339(&s)
                                .map(|dt| dt.with_timezone(&Utc))
                                .ok()
                        })
                    })?,
                })
            })
            .map_err(|e| format!("failed to query push subscription: {e}"))?;

        match rows.next() {
            Some(Ok(sub)) => Ok(Some(sub)),
            Some(Err(e)) => Err(format!("failed to read subscription: {e}")),
            None => Ok(None),
        }
    }

    /// Update the `last_used_at` timestamp for a subscription.
    pub fn update_last_used(&self, id: &Uuid) -> Result<(), String> {
        let now = Utc::now();
        self.conn
            .execute(
                "UPDATE push_subscriptions SET last_used_at = ?1 WHERE id = ?2",
                rusqlite::params![now.to_rfc3339(), id.to_string()],
            )
            .map_err(|e| format!("failed to update last_used_at: {e}"))?;
        Ok(())
    }

    /// Remove all subscriptions whose `expires_at` is in the past.
    ///
    /// Returns the number of cleaned-up subscriptions.
    pub fn cleanup_expired(&self) -> Result<usize, String> {
        let now = Utc::now().to_rfc3339();
        let deleted = self
            .conn
            .execute(
                "DELETE FROM push_subscriptions WHERE expires_at IS NOT NULL AND expires_at < ?1",
                rusqlite::params![now],
            )
            .map_err(|e| format!("failed to cleanup expired subscriptions: {e}"))?;

        if deleted > 0 {
            info!("cleaned up {deleted} expired push subscription(s)");
        }
        Ok(deleted)
    }
}

// ---------------------------------------------------------------------------
// VAPID JWT generation (stub)
// ---------------------------------------------------------------------------

/// Generate a VAPID JWT for authenticating with a push service.
///
/// The JWT is signed with ES256 using the VAPID private key.
///
/// # Arguments
/// * `vapid` - VAPID configuration containing keys and subject.
/// * `audience` - The push service origin (e.g., "https://fcm.googleapis.com").
///
/// # Returns
/// A signed JWT string.
///
/// # Current Status
/// This is a stub implementation. The actual ES256 signing requires the
/// `p256` crate which is not yet in the workspace. The function validates
/// inputs and returns a placeholder error.
pub fn generate_vapid_jwt(vapid: &VapidConfig, audience: &str) -> Result<String, String> {
    // Validate inputs.
    if vapid.subject.is_empty() {
        return Err("VAPID subject must not be empty".into());
    }

    let aud_url = Url::parse(audience).map_err(|e| format!("invalid audience URL: {e}"))?;
    let _audience_origin = format!(
        "{}://{}",
        aud_url.scheme(),
        aud_url.host_str().unwrap_or("")
    );

    // Validate the private key is valid base64 and correct length.
    let pk_bytes = URL_SAFE_NO_PAD
        .decode(&vapid.private_key)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&vapid.private_key))
        .map_err(|e| format!("VAPID private key is not valid base64: {e}"))?;

    if pk_bytes.len() != 32 {
        return Err(format!(
            "VAPID private key must be 32 bytes, got {}",
            pk_bytes.len()
        ));
    }

    // TODO: Implement actual ES256 JWT signing.
    //
    // The JWT structure should be:
    //   Header: {"typ":"JWT","alg":"ES256"}
    //   Payload: {"aud": audience_origin, "exp": now + 24h, "sub": vapid.subject}
    //   Signature: ECDSA-P256-SHA256(header.payload, private_key)
    //
    // This requires the `p256` crate for ECDSA signing and `serde_json`
    // for encoding the header/payload.  Once the crate is added:
    //
    //   let header = base64url(json!({"typ":"JWT","alg":"ES256"}));
    //   let payload = base64url(json!({"aud": audience_origin, "exp": exp, "sub": vapid.subject}));
    //   let signing_input = format!("{header}.{payload}");
    //   let signature = p256::ecdsa::sign(signing_input, private_key);
    //   Ok(format!("{signing_input}.{}", base64url(signature)))

    debug!(
        "VAPID JWT generation stubbed (p256 crate not yet available), subject={}",
        vapid.subject
    );

    Err("VAPID JWT signing not yet implemented (requires p256 crate)".into())
}

// ---------------------------------------------------------------------------
// Push delivery (stub)
// ---------------------------------------------------------------------------

/// Deliver a push notification to a subscription endpoint.
///
/// # Current Status
/// This is a stub. The full implementation requires:
/// 1. ECDH key agreement (p256 crate)
/// 2. HKDF key derivation
/// 3. AES-128-GCM payload encryption (aes-gcm crate)
/// 4. VAPID JWT for authentication
/// 5. HTTP POST to the subscription endpoint
///
/// For now, this validates inputs, sanitizes the payload, and logs the attempt.
pub fn deliver_push_notification(
    subscription: &PushSubscription,
    notification: &PushNotification,
    _vapid: &VapidConfig,
    rate_limiter: &PushRateLimiter,
) -> Result<(), String> {
    // Rate limit check.
    if !rate_limiter.check_and_record() {
        warn!("push notification rate limit exceeded (60/min)");
        return Err("push notification rate limit exceeded".into());
    }

    // Sanitize payload.
    let mut notif = notification.clone();
    sanitize_notification(&mut notif);

    // Validate endpoint is still a known push service.
    validate_endpoint(&subscription.endpoint)?;

    // TODO: Implement actual Web Push delivery.
    //
    // Steps:
    // 1. Generate ECDH shared secret from our ephemeral key + subscription p256dh
    // 2. Derive encryption keys via HKDF
    // 3. Encrypt notification payload with AES-128-GCM
    // 4. Generate VAPID JWT for Authorization header
    // 5. POST encrypted payload to subscription.endpoint with:
    //    - Authorization: vapid t=<jwt>, k=<public_key>
    //    - Content-Encoding: aes128gcm
    //    - Content-Type: application/octet-stream
    //    - TTL: 86400

    info!(
        "push notification delivery stubbed: id={}, endpoint={} (truncated), title={:?}",
        subscription.id,
        &subscription.endpoint[..subscription.endpoint.len().min(60)],
        notif.title,
    );

    Err("push delivery not yet implemented (requires p256 + aes-gcm crates)".into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // -- helpers for valid test data --

    /// A valid 65-byte uncompressed P-256 point, base64url-encoded.
    fn valid_p256dh() -> String {
        // 0x04 followed by 64 bytes of fake coordinate data.
        let mut bytes = vec![0x04u8];
        bytes.extend_from_slice(&[0xAA; 32]); // x
        bytes.extend_from_slice(&[0xBB; 32]); // y
        URL_SAFE_NO_PAD.encode(&bytes)
    }

    /// A valid 16-byte auth secret, base64url-encoded.
    fn valid_auth() -> String {
        URL_SAFE_NO_PAD.encode(&[0xCC; 16])
    }

    /// A valid HTTPS FCM endpoint.
    fn valid_endpoint() -> String {
        "https://fcm.googleapis.com/fcm/send/some-token-here".to_string()
    }

    /// A valid Mozilla push endpoint.
    fn valid_mozilla_endpoint() -> String {
        "https://updates.push.services.mozilla.com/wpush/v2/some-token".to_string()
    }

    // -- Subscription CRUD tests --

    #[test]
    fn push_subscription_crud() {
        let store = PushSubscriptionStore::open_memory().unwrap();

        // Add a subscription.
        let id = store
            .add_subscription(
                &valid_endpoint(),
                &valid_p256dh(),
                &valid_auth(),
                Some("Test Device"),
                None,
            )
            .unwrap();

        // List should return it.
        let subs = store.list_subscriptions().unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].id, id);
        assert_eq!(subs[0].user_label.as_deref(), Some("Test Device"));

        // Get by ID.
        let sub = store.get_subscription(&id).unwrap();
        assert!(sub.is_some());
        assert_eq!(sub.unwrap().endpoint, valid_endpoint());

        // Update last_used.
        store.update_last_used(&id).unwrap();
        let sub = store.get_subscription(&id).unwrap().unwrap();
        assert!(sub.last_used_at.is_some());

        // Remove.
        let removed = store.remove_subscription(&id).unwrap();
        assert!(removed);
        let subs = store.list_subscriptions().unwrap();
        assert!(subs.is_empty());

        // Remove non-existent returns false.
        let removed = store.remove_subscription(&Uuid::new_v4()).unwrap();
        assert!(!removed);
    }

    #[test]
    fn push_subscription_validates_endpoint() {
        let store = PushSubscriptionStore::open_memory().unwrap();
        let p256dh = valid_p256dh();
        let auth = valid_auth();

        // HTTP endpoint rejected.
        let result = store.add_subscription(
            "http://fcm.googleapis.com/fcm/send/token",
            &p256dh,
            &auth,
            None,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));

        // Private IP rejected.
        let result = store.add_subscription(
            "https://192.168.1.1/push",
            &p256dh,
            &auth,
            None,
            None,
        );
        assert!(result.is_err());

        // Unknown host rejected.
        let result = store.add_subscription(
            "https://evil.example.com/push",
            &p256dh,
            &auth,
            None,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a recognized push service"));

        // Valid FCM endpoint accepted.
        let result = store.add_subscription(&valid_endpoint(), &p256dh, &auth, None, None);
        assert!(result.is_ok());

        // Valid Mozilla endpoint accepted.
        let store2 = PushSubscriptionStore::open_memory().unwrap();
        let result =
            store2.add_subscription(&valid_mozilla_endpoint(), &p256dh, &auth, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn push_subscription_validates_keys() {
        let store = PushSubscriptionStore::open_memory().unwrap();

        // Invalid base64 for p256dh.
        let result = store.add_subscription(
            &valid_endpoint(),
            "not-valid-base64!!!",
            &valid_auth(),
            None,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("p256dh"));

        // Wrong length p256dh (32 bytes instead of 65).
        let short_key = URL_SAFE_NO_PAD.encode(&[0xAA; 32]);
        let result = store.add_subscription(
            &valid_endpoint(),
            &short_key,
            &valid_auth(),
            None,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("65 bytes"));

        // Wrong first byte for p256dh (not 0x04).
        let mut bad_point = vec![0x03u8];
        bad_point.extend_from_slice(&[0xAA; 64]);
        let bad_key = URL_SAFE_NO_PAD.encode(&bad_point);
        let result = store.add_subscription(
            &valid_endpoint(),
            &bad_key,
            &valid_auth(),
            None,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("0x04"));

        // Invalid base64 for auth.
        let result = store.add_subscription(
            &valid_endpoint(),
            &valid_p256dh(),
            "not-valid-base64!!!",
            None,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("auth"));

        // Wrong length auth (8 bytes instead of 16).
        let short_auth = URL_SAFE_NO_PAD.encode(&[0xCC; 8]);
        let result = store.add_subscription(
            &valid_endpoint(),
            &valid_p256dh(),
            &short_auth,
            None,
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("16 bytes"));
    }

    #[test]
    fn expired_subscription_cleanup() {
        let store = PushSubscriptionStore::open_memory().unwrap();

        let past = Utc::now() - Duration::hours(1);
        let future = Utc::now() + Duration::hours(24);

        // Add one expired and one unexpired subscription.
        let _id1 = store
            .add_subscription(
                &valid_endpoint(),
                &valid_p256dh(),
                &valid_auth(),
                Some("expired"),
                Some(past),
            )
            .unwrap();
        let _id2 = store
            .add_subscription(
                &valid_mozilla_endpoint(),
                &valid_p256dh(),
                &valid_auth(),
                Some("active"),
                Some(future),
            )
            .unwrap();

        let subs = store.list_subscriptions().unwrap();
        assert_eq!(subs.len(), 2);

        // Cleanup should remove only the expired one.
        let cleaned = store.cleanup_expired().unwrap();
        assert_eq!(cleaned, 1);

        let subs = store.list_subscriptions().unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].user_label.as_deref(), Some("active"));
    }

    #[test]
    fn push_notification_sanitization() {
        let mut notif = PushNotification {
            title: "Alert\x00 from \x07Aegis".into(),
            body: "Agent \x1Bclaude-1\x08 needs\nattention".into(),
            icon: None,
            url: Some("https://example.com/\x00dashboard".into()),
            tag: Some("urgent\x07".into()),
        };

        sanitize_notification(&mut notif);

        // Control characters stripped, but newline preserved.
        assert_eq!(notif.title, "Alert from Aegis");
        assert_eq!(notif.body, "Agent claude-1 needs\nattention");
        assert_eq!(
            notif.url.as_deref(),
            Some("https://example.com/dashboard")
        );
        assert_eq!(notif.tag.as_deref(), Some("urgent"));
    }

    #[test]
    fn security_test_ssrf_blocked() {
        // Loopback addresses.
        assert!(validate_endpoint("https://127.0.0.1/push").is_err());
        assert!(validate_endpoint("https://[::1]/push").is_err());

        // Private ranges.
        assert!(validate_endpoint("https://10.0.0.1/push").is_err());
        assert!(validate_endpoint("https://172.16.0.1/push").is_err());
        assert!(validate_endpoint("https://192.168.0.1/push").is_err());

        // Link-local.
        assert!(validate_endpoint("https://169.254.1.1/push").is_err());

        // Localhost by name.
        assert!(validate_endpoint("https://localhost/push").is_err());
        assert!(validate_endpoint("https://myhost.local/push").is_err());

        // HTTP (not HTTPS).
        assert!(validate_endpoint("http://fcm.googleapis.com/push").is_err());

        // Not a recognized push service.
        assert!(validate_endpoint("https://evil.example.com/push").is_err());
        assert!(validate_endpoint("https://attacker.com/push").is_err());

        // Valid endpoints pass.
        assert!(validate_endpoint(&valid_endpoint()).is_ok());
        assert!(validate_endpoint(&valid_mozilla_endpoint()).is_ok());
        assert!(validate_endpoint("https://web.push.apple.com/push/token").is_ok());
    }

    #[test]
    fn security_test_rate_limiting() {
        let limiter = PushRateLimiter::new(5); // 5 per minute for fast testing.

        // First 5 should succeed.
        for _ in 0..5 {
            assert!(limiter.check_and_record());
        }

        // 6th should fail.
        assert!(!limiter.check_and_record());

        // Still fails.
        assert!(!limiter.check_and_record());
    }

    #[test]
    fn validate_endpoint_rejects_invalid_url() {
        assert!(validate_endpoint("not a url").is_err());
        assert!(validate_endpoint("").is_err());
        assert!(validate_endpoint("ftp://push.example.com").is_err());
    }

    #[test]
    fn vapid_jwt_rejects_empty_subject() {
        let config = VapidConfig {
            subject: String::new(),
            public_key: String::new(),
            private_key: URL_SAFE_NO_PAD.encode(&[0xAA; 32]),
        };
        let result = generate_vapid_jwt(&config, "https://fcm.googleapis.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("subject"));
    }

    #[test]
    fn vapid_jwt_rejects_invalid_private_key_length() {
        let config = VapidConfig {
            subject: "mailto:test@example.com".into(),
            public_key: String::new(),
            private_key: URL_SAFE_NO_PAD.encode(&[0xAA; 16]), // 16 bytes, not 32
        };
        let result = generate_vapid_jwt(&config, "https://fcm.googleapis.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("32 bytes"));
    }

    #[test]
    fn sanitize_text_removes_control_chars() {
        assert_eq!(sanitize_text("hello\x00world"), "helloworld");
        assert_eq!(sanitize_text("ok\nline"), "ok\nline"); // newline preserved
        assert_eq!(sanitize_text("tab\there"), "tab\there"); // tab preserved
        assert_eq!(sanitize_text("\x07bell"), "bell");
        assert_eq!(sanitize_text("clean text"), "clean text");
    }
}
