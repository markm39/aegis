//! Web Push notification subscriptions with VAPID support.
//!
//! Provides subscription management (CRUD backed by SQLite), endpoint
//! validation with SSRF protection, key validation, payload sanitization,
//! rate limiting, ECDH/HKDF/AES-GCM encryption (RFC 8291), and VAPID
//! JWT authentication (RFC 8292).

use std::sync::Mutex;
use std::time::Instant;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::{EncodedPoint, PublicKey};
use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::Connection;
use sha2::Sha256;
use tracing::{info, warn};
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
        return Err(format!("auth key must be 16 bytes, got {}", bytes.len()));
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
        let conn = Connection::open(db_path).map_err(|e| format!("failed to open push DB: {e}"))?;
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
                    created_at: row.get::<_, String>(5).map(|s| {
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
                    created_at: row.get::<_, String>(5).map(|s| {
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
    if vapid.subject.is_empty() {
        return Err("VAPID subject must not be empty".into());
    }

    let aud_url = Url::parse(audience).map_err(|e| format!("invalid audience URL: {e}"))?;
    let audience_origin = format!(
        "{}://{}",
        aud_url.scheme(),
        aud_url.host_str().unwrap_or("")
    );

    // Decode and validate the VAPID private key (32-byte P-256 scalar).
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

    let signing_key = SigningKey::from_bytes(pk_bytes.as_slice().into())
        .map_err(|e| format!("invalid VAPID private key: {e}"))?;

    // Build JWT header and payload.
    let header = serde_json::json!({"typ": "JWT", "alg": "ES256"});
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("system time error: {e}"))?
        .as_secs()
        + 86400; // 24 hours

    let payload = serde_json::json!({
        "aud": audience_origin,
        "exp": exp,
        "sub": vapid.subject,
    });

    let header_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|e| format!("JSON encode error: {e}"))?);
    let payload_b64 = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).map_err(|e| format!("JSON encode error: {e}"))?);
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with ES256 (ECDSA P-256 + SHA-256).
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

// ---------------------------------------------------------------------------
// Push delivery (stub)
// ---------------------------------------------------------------------------

/// Deliver a push notification to a subscription endpoint.
///
/// Implements RFC 8291 (Web Push Message Encryption) with aes128gcm encoding:
/// 1. ECDH key agreement with ephemeral P-256 key
/// 2. HKDF-SHA256 key derivation for content encryption key + nonce
/// 3. AES-128-GCM payload encryption
/// 4. VAPID JWT authentication (RFC 8292)
/// 5. HTTP POST to the push service endpoint
pub async fn deliver_push_notification(
    subscription: &PushSubscription,
    notification: &PushNotification,
    vapid: &VapidConfig,
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

    // 1. Decode the subscriber's P-256 public key and auth secret.
    let ua_public_bytes = URL_SAFE_NO_PAD
        .decode(&subscription.p256dh)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&subscription.p256dh))
        .map_err(|e| format!("failed to decode p256dh: {e}"))?;
    let ua_public = PublicKey::from_sec1_bytes(&ua_public_bytes)
        .map_err(|e| format!("invalid p256dh public key: {e}"))?;

    let auth_secret = URL_SAFE_NO_PAD
        .decode(&subscription.auth)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&subscription.auth))
        .map_err(|e| format!("failed to decode auth secret: {e}"))?;

    // 2. Generate ephemeral ECDH P-256 key pair.
    let ephemeral_secret = EphemeralSecret::random(&mut OsRng);
    let server_public = PublicKey::from(&ephemeral_secret);
    let server_public_point = EncodedPoint::from(server_public);

    // 3. ECDH shared secret.
    let shared_secret = ephemeral_secret.diffie_hellman(&ua_public);

    // 4. RFC 8291 key derivation.
    // Step A: Extract IKM from auth secret + ECDH shared secret.
    let hkdf_auth = Hkdf::<Sha256>::new(
        Some(&auth_secret),
        shared_secret.raw_secret_bytes().as_slice(),
    );

    // key_info = "WebPush: info\x00" + ua_public (65 bytes) + server_public (65 bytes)
    let mut key_info = Vec::with_capacity(144);
    key_info.extend_from_slice(b"WebPush: info\x00");
    key_info.extend_from_slice(&ua_public_bytes);
    key_info.extend_from_slice(server_public_point.as_bytes());

    let mut ikm = [0u8; 32];
    hkdf_auth
        .expand(&key_info, &mut ikm)
        .map_err(|e| format!("HKDF auth expand failed: {e}"))?;

    // Step B: Generate random 16-byte salt for content encryption.
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // Step C: Derive content encryption key (16 bytes) and nonce (12 bytes).
    let hkdf_content = Hkdf::<Sha256>::new(Some(&salt), &ikm);

    let mut cek = [0u8; 16];
    hkdf_content
        .expand(b"Content-Encoding: aes128gcm\x00", &mut cek)
        .map_err(|e| format!("HKDF CEK derivation failed: {e}"))?;

    let mut nonce_bytes = [0u8; 12];
    hkdf_content
        .expand(b"Content-Encoding: nonce\x00", &mut nonce_bytes)
        .map_err(|e| format!("HKDF nonce derivation failed: {e}"))?;

    // 5. Encrypt notification payload with AES-128-GCM.
    let payload_json = serde_json::json!({
        "title": notif.title,
        "body": notif.body,
        "icon": notif.icon,
        "url": notif.url,
        "tag": notif.tag,
    });
    let mut plaintext = serde_json::to_vec(&payload_json)
        .map_err(|e| format!("failed to serialize notification: {e}"))?;
    // RFC 8188: add padding delimiter byte (0x02 = last record).
    plaintext.push(0x02);

    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&cek));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("AES-GCM encryption failed: {e}"))?;

    // 6. Build aes128gcm content encoding payload.
    // Format: salt (16) + rs (4, big-endian) + idlen (1) + keyid (65) + ciphertext
    let rs: u32 = 4096;
    let server_pub_bytes = server_public_point.as_bytes();
    let idlen = server_pub_bytes.len() as u8;

    let mut body = Vec::with_capacity(16 + 4 + 1 + server_pub_bytes.len() + ciphertext.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&rs.to_be_bytes());
    body.push(idlen);
    body.extend_from_slice(server_pub_bytes);
    body.extend_from_slice(&ciphertext);

    // 7. Generate VAPID JWT for authorization.
    let jwt = generate_vapid_jwt(vapid, &subscription.endpoint)?;
    let vapid_header = format!("vapid t={}, k={}", jwt, vapid.public_key);

    // 8. HTTP POST to push service endpoint.
    let client = reqwest::Client::new();
    let response = client
        .post(&subscription.endpoint)
        .header("Authorization", &vapid_header)
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header("TTL", "86400")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("push delivery failed: {e}"))?;

    let status = response.status();
    if status.is_success() || status.as_u16() == 201 {
        info!(
            "push notification delivered: id={}, status={status}",
            subscription.id
        );
        Ok(())
    } else {
        let error_body = response.text().await.unwrap_or_default();
        Err(format!(
            "push service returned {status}: {}",
            &error_body[..error_body.len().min(200)]
        ))
    }
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
        let result = store.add_subscription("https://192.168.1.1/push", &p256dh, &auth, None, None);
        assert!(result.is_err());

        // Unknown host rejected.
        let result =
            store.add_subscription("https://evil.example.com/push", &p256dh, &auth, None, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("not a recognized push service"));

        // Valid FCM endpoint accepted.
        let result = store.add_subscription(&valid_endpoint(), &p256dh, &auth, None, None);
        assert!(result.is_ok());

        // Valid Mozilla endpoint accepted.
        let store2 = PushSubscriptionStore::open_memory().unwrap();
        let result = store2.add_subscription(&valid_mozilla_endpoint(), &p256dh, &auth, None, None);
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
        let result =
            store.add_subscription(&valid_endpoint(), &short_key, &valid_auth(), None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("65 bytes"));

        // Wrong first byte for p256dh (not 0x04).
        let mut bad_point = vec![0x03u8];
        bad_point.extend_from_slice(&[0xAA; 64]);
        let bad_key = URL_SAFE_NO_PAD.encode(&bad_point);
        let result = store.add_subscription(&valid_endpoint(), &bad_key, &valid_auth(), None, None);
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
        let result =
            store.add_subscription(&valid_endpoint(), &valid_p256dh(), &short_auth, None, None);
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
        assert_eq!(notif.url.as_deref(), Some("https://example.com/dashboard"));
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
    fn vapid_jwt_signs_with_valid_key() {
        // Generate a real P-256 signing key.
        let signing_key = SigningKey::random(&mut OsRng);
        let private_key_b64 = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());

        let config = VapidConfig {
            subject: "mailto:test@example.com".into(),
            public_key: String::new(), // not needed for JWT generation
            private_key: private_key_b64,
        };

        let jwt = generate_vapid_jwt(&config, "https://fcm.googleapis.com").unwrap();

        // JWT should have 3 dot-separated parts.
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");

        // Decode and verify header.
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");

        // Decode and verify payload.
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["aud"], "https://fcm.googleapis.com");
        assert_eq!(payload["sub"], "mailto:test@example.com");
        assert!(payload["exp"].as_u64().unwrap() > 0);

        // Signature should be 64 bytes (P-256 ECDSA).
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(sig_bytes.len(), 64);
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
