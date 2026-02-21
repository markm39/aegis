//! Device registry with secure pairing flow and authentication.
//!
//! Manages a registry of paired devices (phones, tablets, desktops) that can
//! interact with the Aegis daemon remotely. Each device goes through a
//! time-limited pairing flow using a 6-digit numeric code, then authenticates
//! with an HMAC-SHA256 token on subsequent requests.
//!
//! # Security Properties
//!
//! - Auth tokens are HMAC-SHA256 based, stored as SHA-256 hashes only (never plaintext).
//! - Pairing codes are 6-digit numeric, expire after 5 minutes, and use constant-time comparison.
//! - Device authentication uses constant-time hash comparison via the `subtle` crate.
//! - Revocation immediately clears the auth token hash, invalidating all sessions.
//! - Device names are sanitized: control characters stripped, max 64 characters.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Maximum length for device names after sanitization.
const MAX_DEVICE_NAME_LENGTH: usize = 64;

/// Duration a pairing code remains valid.
const PAIRING_CODE_TTL: Duration = Duration::from_secs(300); // 5 minutes

/// Length of the numeric pairing code.
const PAIRING_CODE_LENGTH: usize = 6;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Unique identifier for a registered device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub Uuid);

impl DeviceId {
    /// Generate a new random device ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Platform the device is running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePlatform {
    Ios,
    Android,
    MacOs,
    Linux,
    Windows,
    Web,
}

impl std::fmt::Display for DevicePlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DevicePlatform::Ios => write!(f, "iOS"),
            DevicePlatform::Android => write!(f, "Android"),
            DevicePlatform::MacOs => write!(f, "macOS"),
            DevicePlatform::Linux => write!(f, "Linux"),
            DevicePlatform::Windows => write!(f, "Windows"),
            DevicePlatform::Web => write!(f, "Web"),
        }
    }
}

/// Capabilities a device supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceCapability {
    PushNotifications,
    RemoteControl,
    AudioCapture,
    VideoCapture,
}

impl std::fmt::Display for DeviceCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceCapability::PushNotifications => write!(f, "push_notifications"),
            DeviceCapability::RemoteControl => write!(f, "remote_control"),
            DeviceCapability::AudioCapture => write!(f, "audio_capture"),
            DeviceCapability::VideoCapture => write!(f, "video_capture"),
        }
    }
}

/// Current status of a device in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Device has been paired but hasn't connected yet.
    Paired,
    /// Device is actively connected and authenticated.
    Active,
    /// Device access has been revoked.
    Revoked,
}

impl std::fmt::Display for DeviceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceStatus::Paired => write!(f, "paired"),
            DeviceStatus::Active => write!(f, "active"),
            DeviceStatus::Revoked => write!(f, "revoked"),
        }
    }
}

/// A registered device in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Unique device identifier.
    pub id: DeviceId,
    /// Human-readable device name (sanitized).
    pub name: String,
    /// Device type description (e.g., "iPhone 15", "Pixel 8").
    pub device_type: String,
    /// Platform the device runs on.
    pub platform: DevicePlatform,
    /// Capabilities the device supports.
    pub capabilities: Vec<DeviceCapability>,
    /// When the device was paired.
    pub paired_at: DateTime<Utc>,
    /// When the device was last seen (authenticated).
    pub last_seen: DateTime<Utc>,
    /// Current device status.
    pub status: DeviceStatus,
    /// SHA-256 hash of the auth token. Never store the raw token.
    #[serde(skip_serializing)]
    pub auth_token_hash: Option<String>,
}

/// Information provided by a device during pairing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Human-readable device name.
    pub name: String,
    /// Device type description.
    pub device_type: String,
    /// Platform the device runs on.
    pub platform: DevicePlatform,
    /// Capabilities the device supports.
    pub capabilities: Vec<DeviceCapability>,
}

/// A pending pairing code with its expiration.
#[derive(Debug)]
struct PendingPairing {
    code: String,
    expiry: Instant,
}

// ---------------------------------------------------------------------------
// Device store (SQLite)
// ---------------------------------------------------------------------------

/// SQLite-backed storage for the device registry.
pub struct DeviceStore {
    conn: Connection,
    /// Pending pairing codes (in-memory, not persisted).
    pending_pairings: Vec<PendingPairing>,
    /// HMAC key for generating auth tokens. Derived from a random seed
    /// stored in the database on first use.
    hmac_key: Vec<u8>,
}

impl DeviceStore {
    /// Open or create a device store at the given SQLite path.
    pub fn open(db_path: &std::path::Path) -> Result<Self, anyhow::Error> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        Self::from_connection(conn)
    }

    /// Create a device store from an existing connection (useful for testing with :memory:).
    pub fn from_connection(conn: Connection) -> Result<Self, anyhow::Error> {
        Self::create_tables(&conn)?;
        let hmac_key = Self::load_or_create_hmac_key(&conn)?;
        Ok(Self {
            conn,
            pending_pairings: Vec::new(),
            hmac_key,
        })
    }

    /// Create the required tables if they don't exist.
    fn create_tables(conn: &Connection) -> Result<(), anyhow::Error> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                device_type TEXT NOT NULL,
                platform TEXT NOT NULL,
                capabilities TEXT NOT NULL,
                paired_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL,
                auth_token_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS device_store_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;
        Ok(())
    }

    /// Load the HMAC key from the database, or generate and store a new one.
    fn load_or_create_hmac_key(conn: &Connection) -> Result<Vec<u8>, anyhow::Error> {
        let existing: Option<String> = conn
            .query_row(
                "SELECT value FROM device_store_meta WHERE key = 'hmac_key'",
                [],
                |row| row.get(0),
            )
            .ok();

        if let Some(hex_key) = existing {
            Ok(hex::decode(hex_key)?)
        } else {
            // Generate a 32-byte key from two UUIDs (128 bits each = 256 bits total).
            // UUIDs v4 use the OS CSPRNG, so this is cryptographically secure.
            let u1 = Uuid::new_v4();
            let u2 = Uuid::new_v4();
            let mut key = Vec::with_capacity(32);
            key.extend_from_slice(u1.as_bytes());
            key.extend_from_slice(u2.as_bytes());

            let hex_key = hex::encode(&key);
            conn.execute(
                "INSERT INTO device_store_meta (key, value) VALUES ('hmac_key', ?1)",
                params![hex_key],
            )?;
            Ok(key)
        }
    }

    /// Get a copy of the HMAC key for use by other components (e.g., setup code manager).
    ///
    /// The caller must treat this key as a secret. It is used for HMAC-SHA256
    /// token generation and must not be logged or exposed.
    pub fn hmac_key(&self) -> &[u8] {
        &self.hmac_key
    }

    // -----------------------------------------------------------------------
    // Pairing flow
    // -----------------------------------------------------------------------

    /// Generate a 6-digit numeric pairing code that expires in 5 minutes.
    ///
    /// Returns `(code, expiry)`. The code must be displayed to the user so they
    /// can enter it on the device being paired.
    pub fn generate_pairing_code(&mut self) -> (String, Instant) {
        // Purge expired codes first
        self.purge_expired_codes();

        // Generate a 6-digit code from UUID random bytes.
        let raw = Uuid::new_v4();
        let bytes = raw.as_bytes();
        // Use first 4 bytes as a u32, then mod 1_000_000 for 6 digits
        let num = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 1_000_000;
        let code = format!("{num:0>6}");
        debug_assert_eq!(code.len(), PAIRING_CODE_LENGTH);

        let expiry = Instant::now() + PAIRING_CODE_TTL;
        self.pending_pairings.push(PendingPairing {
            code: code.clone(),
            expiry,
        });

        (code, expiry)
    }

    /// Validate a pairing code using constant-time comparison.
    ///
    /// Returns `Ok(())` if the code is valid and not expired.
    /// Returns `Err` if the code is invalid, expired, or no codes are pending.
    pub fn validate_pairing_code(&self, code: &str) -> Result<(), anyhow::Error> {
        self.purge_expired_codes_readonly();

        let code_bytes = code.as_bytes();

        // Check all pending codes with constant-time comparison to prevent timing attacks.
        // We iterate all codes even after finding a match to avoid timing leaks.
        let mut found = false;
        for pending in &self.pending_pairings {
            if pending.expiry > Instant::now() {
                let pending_bytes = pending.code.as_bytes();
                if code_bytes.len() == pending_bytes.len()
                    && bool::from(code_bytes.ct_eq(pending_bytes))
                {
                    found = true;
                }
            }
        }

        if found {
            Ok(())
        } else {
            Err(anyhow::anyhow!("invalid or expired pairing code"))
        }
    }

    /// Complete the pairing flow: validate the code, create the device, and return
    /// the device record along with the raw auth token (which must be sent to the device
    /// and never stored on the server).
    ///
    /// The auth token is HMAC-SHA256 based. Only its SHA-256 hash is stored.
    pub fn complete_pairing(
        &mut self,
        code: &str,
        device_info: DeviceInfo,
    ) -> Result<(Device, String), anyhow::Error> {
        // Validate code first
        self.validate_pairing_code(code)?;

        // Remove the used code
        self.remove_pairing_code(code);

        // Generate device
        let device_id = DeviceId::new();
        let now = Utc::now();

        // Generate auth token via HMAC-SHA256
        let auth_token = self.generate_auth_token(&device_id)?;
        let token_hash = sha256_hex(&auth_token);

        // Sanitize device name
        let name = sanitize_device_name(&device_info.name);

        let device = Device {
            id: device_id,
            name,
            device_type: device_info.device_type,
            platform: device_info.platform,
            capabilities: device_info.capabilities,
            paired_at: now,
            last_seen: now,
            status: DeviceStatus::Paired,
            auth_token_hash: Some(token_hash),
        };

        self.insert_device(&device)?;

        Ok((device, auth_token))
    }

    // -----------------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------------

    /// Authenticate a device using its ID and token.
    ///
    /// Uses constant-time hash comparison to prevent timing attacks.
    /// Updates `last_seen` and sets status to `Active` on success.
    pub fn authenticate(
        &mut self,
        device_id: &DeviceId,
        token: &str,
    ) -> Result<Device, anyhow::Error> {
        let mut device = self
            .get_device(device_id)?
            .ok_or_else(|| anyhow::anyhow!("device not found: {device_id}"))?;

        if device.status == DeviceStatus::Revoked {
            return Err(anyhow::anyhow!("device has been revoked: {device_id}"));
        }

        let stored_hash = device
            .auth_token_hash
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("device has no auth token: {device_id}"))?;

        // Compute hash of provided token and compare in constant time
        let provided_hash = sha256_hex(token);
        let stored_bytes = stored_hash.as_bytes();
        let provided_bytes = provided_hash.as_bytes();

        if stored_bytes.len() != provided_bytes.len()
            || !bool::from(stored_bytes.ct_eq(provided_bytes))
        {
            return Err(anyhow::anyhow!("authentication failed: invalid token"));
        }

        // Update last_seen and status
        let now = Utc::now();
        device.last_seen = now;
        device.status = DeviceStatus::Active;
        self.update_device_status(&device.id, DeviceStatus::Active, Some(now))?;

        Ok(device)
    }

    // -----------------------------------------------------------------------
    // Revocation
    // -----------------------------------------------------------------------

    /// Revoke a device, immediately invalidating its auth token.
    ///
    /// Sets status to `Revoked` and clears the auth token hash so no
    /// subsequent authentication can succeed even if the token is replayed.
    pub fn revoke(&mut self, device_id: &DeviceId) -> Result<(), anyhow::Error> {
        let device = self
            .get_device(device_id)?
            .ok_or_else(|| anyhow::anyhow!("device not found: {device_id}"))?;

        if device.status == DeviceStatus::Revoked {
            return Err(anyhow::anyhow!("device already revoked: {device_id}"));
        }

        self.conn.execute(
            "UPDATE devices SET status = 'revoked', auth_token_hash = NULL WHERE id = ?1",
            params![device_id.0.to_string()],
        )?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // CRUD
    // -----------------------------------------------------------------------

    /// Insert a device into the database.
    fn insert_device(&self, device: &Device) -> Result<(), anyhow::Error> {
        let capabilities_json = serde_json::to_string(&device.capabilities)?;
        self.conn.execute(
            "INSERT INTO devices (id, name, device_type, platform, capabilities, paired_at, last_seen, status, auth_token_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                device.id.0.to_string(),
                device.name,
                device.device_type,
                serde_json::to_string(&device.platform)?,
                capabilities_json,
                device.paired_at.to_rfc3339(),
                device.last_seen.to_rfc3339(),
                device.status.to_string(),
                device.auth_token_hash,
            ],
        )?;
        Ok(())
    }

    /// Get a device by its ID.
    pub fn get_device(&self, device_id: &DeviceId) -> Result<Option<Device>, anyhow::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, device_type, platform, capabilities, paired_at, last_seen, status, auth_token_hash
             FROM devices WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![device_id.0.to_string()], |row| {
            Ok(DeviceRow {
                id: row.get(0)?,
                name: row.get(1)?,
                device_type: row.get(2)?,
                platform: row.get(3)?,
                capabilities: row.get(4)?,
                paired_at: row.get(5)?,
                last_seen: row.get(6)?,
                status: row.get(7)?,
                auth_token_hash: row.get(8)?,
            })
        });

        match result {
            Ok(row) => Ok(Some(row.into_device()?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all devices, optionally filtered by status.
    pub fn list_devices(
        &self,
        status_filter: Option<DeviceStatus>,
    ) -> Result<Vec<Device>, anyhow::Error> {
        let (query, filter_str);
        match status_filter {
            Some(status) => {
                filter_str = status.to_string();
                query = format!(
                    "SELECT id, name, device_type, platform, capabilities, paired_at, last_seen, status, auth_token_hash
                     FROM devices WHERE status = '{}' ORDER BY paired_at DESC",
                    filter_str
                );
            }
            None => {
                query =
                    "SELECT id, name, device_type, platform, capabilities, paired_at, last_seen, status, auth_token_hash
                     FROM devices ORDER BY paired_at DESC"
                        .to_string();
            }
        }

        let mut stmt = self.conn.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            Ok(DeviceRow {
                id: row.get(0)?,
                name: row.get(1)?,
                device_type: row.get(2)?,
                platform: row.get(3)?,
                capabilities: row.get(4)?,
                paired_at: row.get(5)?,
                last_seen: row.get(6)?,
                status: row.get(7)?,
                auth_token_hash: row.get(8)?,
            })
        })?;

        let mut devices = Vec::new();
        for row in rows {
            devices.push(row?.into_device()?);
        }
        Ok(devices)
    }

    /// Delete a device from the database entirely.
    pub fn delete_device(&mut self, device_id: &DeviceId) -> Result<bool, anyhow::Error> {
        let affected = self.conn.execute(
            "DELETE FROM devices WHERE id = ?1",
            params![device_id.0.to_string()],
        )?;
        Ok(affected > 0)
    }

    /// Update a device's status and optionally its last_seen timestamp.
    fn update_device_status(
        &self,
        device_id: &DeviceId,
        status: DeviceStatus,
        last_seen: Option<DateTime<Utc>>,
    ) -> Result<(), anyhow::Error> {
        match last_seen {
            Some(ts) => {
                self.conn.execute(
                    "UPDATE devices SET status = ?1, last_seen = ?2 WHERE id = ?3",
                    params![status.to_string(), ts.to_rfc3339(), device_id.0.to_string()],
                )?;
            }
            None => {
                self.conn.execute(
                    "UPDATE devices SET status = ?1 WHERE id = ?2",
                    params![status.to_string(), device_id.0.to_string()],
                )?;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Token generation (internal)
    // -----------------------------------------------------------------------

    /// Generate an HMAC-SHA256 auth token for a device.
    ///
    /// The token encodes the device ID and a random nonce, signed with the
    /// store's HMAC key. The raw token is returned; only its SHA-256 hash
    /// should be stored.
    fn generate_auth_token(&self, device_id: &DeviceId) -> Result<String, anyhow::Error> {
        let nonce = Uuid::new_v4();
        let message = format!("{}:{}", device_id.0, nonce);

        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.hmac_key).expect("HMAC can take key of any size");
        mac.update(message.as_bytes());
        let result = mac.finalize();
        let tag = result.into_bytes();

        // Token format: hex(hmac_tag):device_id:nonce
        Ok(format!("{}:{}:{}", hex::encode(tag), device_id.0, nonce))
    }

    // -----------------------------------------------------------------------
    // Pairing code helpers
    // -----------------------------------------------------------------------

    /// Remove expired pairing codes (mutable).
    fn purge_expired_codes(&mut self) {
        let now = Instant::now();
        self.pending_pairings.retain(|p| p.expiry > now);
    }

    /// Check which codes are expired without mutating (for validate which takes &self).
    fn purge_expired_codes_readonly(&self) {
        // This is a no-op; validate checks expiry inline. The method exists
        // for symmetry and could be extended if we add metrics.
    }

    /// Remove a specific pairing code (after successful use).
    fn remove_pairing_code(&mut self, code: &str) {
        let code_bytes = code.as_bytes();
        self.pending_pairings.retain(|p| {
            let pending_bytes = p.code.as_bytes();
            // Use constant-time comparison even for removal to avoid leaking
            // which code matched through timing.
            code_bytes.len() != pending_bytes.len() || !bool::from(code_bytes.ct_eq(pending_bytes))
        });
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Intermediate row type for reading from SQLite.
struct DeviceRow {
    id: String,
    name: String,
    device_type: String,
    platform: String,
    capabilities: String,
    paired_at: String,
    last_seen: String,
    status: String,
    auth_token_hash: Option<String>,
}

impl DeviceRow {
    fn into_device(self) -> Result<Device, anyhow::Error> {
        let id = Uuid::parse_str(&self.id)?;
        let platform: DevicePlatform = serde_json::from_str(&self.platform)?;
        let capabilities: Vec<DeviceCapability> = serde_json::from_str(&self.capabilities)?;
        let paired_at = DateTime::parse_from_rfc3339(&self.paired_at)?.with_timezone(&Utc);
        let last_seen = DateTime::parse_from_rfc3339(&self.last_seen)?.with_timezone(&Utc);
        let status = match self.status.as_str() {
            "paired" => DeviceStatus::Paired,
            "active" => DeviceStatus::Active,
            "revoked" => DeviceStatus::Revoked,
            other => return Err(anyhow::anyhow!("unknown device status: {other}")),
        };

        Ok(Device {
            id: DeviceId(id),
            name: self.name,
            device_type: self.device_type,
            platform,
            capabilities,
            paired_at,
            last_seen,
            status,
            auth_token_hash: self.auth_token_hash,
        })
    }
}

/// Compute the SHA-256 hex digest of a string.
fn sha256_hex(input: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Sanitize a device name: strip control characters, trim whitespace, truncate.
pub fn sanitize_device_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();

    if cleaned.len() > MAX_DEVICE_NAME_LENGTH {
        cleaned
            .char_indices()
            .take_while(|(i, _)| *i < MAX_DEVICE_NAME_LENGTH)
            .map(|(_, c)| c)
            .collect()
    } else {
        cleaned
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> DeviceStore {
        let conn = Connection::open_in_memory().expect("in-memory SQLite");
        DeviceStore::from_connection(conn).expect("create store")
    }

    fn sample_device_info() -> DeviceInfo {
        DeviceInfo {
            name: "Test Phone".into(),
            device_type: "iPhone 15 Pro".into(),
            platform: DevicePlatform::Ios,
            capabilities: vec![DeviceCapability::PushNotifications],
        }
    }

    #[test]
    fn device_registration_creates_entry() {
        let mut store = test_store();
        let (code, _expiry) = store.generate_pairing_code();
        let (device, token) = store
            .complete_pairing(&code, sample_device_info())
            .expect("pairing should succeed");

        assert_eq!(device.name, "Test Phone");
        assert_eq!(device.platform, DevicePlatform::Ios);
        assert_eq!(device.status, DeviceStatus::Paired);
        assert!(!token.is_empty());

        // Verify it's in the database
        let fetched = store
            .get_device(&device.id)
            .expect("get should work")
            .expect("device should exist");
        assert_eq!(fetched.id, device.id);
        assert_eq!(fetched.name, "Test Phone");
    }

    #[test]
    fn pairing_code_generation_format() {
        let mut store = test_store();
        let (code, expiry) = store.generate_pairing_code();

        // Must be exactly 6 digits
        assert_eq!(code.len(), PAIRING_CODE_LENGTH);
        assert!(code.chars().all(|c| c.is_ascii_digit()));

        // Expiry must be in the future
        assert!(expiry > Instant::now());
    }

    #[test]
    fn pairing_code_validation() {
        let mut store = test_store();
        let (code, _) = store.generate_pairing_code();

        // Valid code should pass
        assert!(store.validate_pairing_code(&code).is_ok());

        // Wrong code should fail
        assert!(store.validate_pairing_code("000000").is_err() || code == "000000");

        // After using the code for pairing, it should be consumed
        let _ = store.complete_pairing(&code, sample_device_info());
        assert!(store.validate_pairing_code(&code).is_err());
    }

    #[test]
    fn pairing_code_expiry() {
        let mut store = test_store();

        // Manually insert an expired code
        store.pending_pairings.push(PendingPairing {
            code: "123456".into(),
            expiry: Instant::now() - Duration::from_secs(1),
        });

        // Expired code should fail validation
        assert!(store.validate_pairing_code("123456").is_err());
    }

    #[test]
    fn device_auth_token_verification() {
        let mut store = test_store();
        let (code, _) = store.generate_pairing_code();
        let (device, token) = store
            .complete_pairing(&code, sample_device_info())
            .expect("pairing");

        // Authentication with the correct token should succeed
        let authed = store
            .authenticate(&device.id, &token)
            .expect("auth should succeed");
        assert_eq!(authed.id, device.id);
        assert_eq!(authed.status, DeviceStatus::Active);
    }

    #[test]
    fn device_auth_rejects_wrong_token() {
        let mut store = test_store();
        let (code, _) = store.generate_pairing_code();
        let (device, _token) = store
            .complete_pairing(&code, sample_device_info())
            .expect("pairing");

        // Authentication with a wrong token must fail
        let result = store.authenticate(&device.id, "wrong-token-value");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("authentication failed"));
    }

    #[test]
    fn device_revocation_invalidates() {
        let mut store = test_store();
        let (code, _) = store.generate_pairing_code();
        let (device, token) = store
            .complete_pairing(&code, sample_device_info())
            .expect("pairing");

        // Revoke the device
        store.revoke(&device.id).expect("revoke should succeed");

        // Authentication must fail after revocation
        let result = store.authenticate(&device.id, &token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("revoked"));

        // Device should be marked as revoked
        let fetched = store.get_device(&device.id).unwrap().unwrap();
        assert_eq!(fetched.status, DeviceStatus::Revoked);
        assert!(fetched.auth_token_hash.is_none());
    }

    #[test]
    fn device_listing() {
        let mut store = test_store();

        // Pair two devices
        let (code1, _) = store.generate_pairing_code();
        let (device1, _) = store
            .complete_pairing(&code1, sample_device_info())
            .expect("pair 1");

        let (code2, _) = store.generate_pairing_code();
        let info2 = DeviceInfo {
            name: "Test Laptop".into(),
            device_type: "MacBook Pro".into(),
            platform: DevicePlatform::MacOs,
            capabilities: vec![DeviceCapability::RemoteControl],
        };
        let (_device2, _) = store.complete_pairing(&code2, info2).expect("pair 2");

        // List all should return 2
        let all = store.list_devices(None).expect("list all");
        assert_eq!(all.len(), 2);

        // Revoke one
        store.revoke(&device1.id).expect("revoke");

        // Filter by Paired should return 1
        let paired = store
            .list_devices(Some(DeviceStatus::Paired))
            .expect("list paired");
        assert_eq!(paired.len(), 1);
        assert_eq!(paired[0].platform, DevicePlatform::MacOs);

        // Filter by Revoked should return 1
        let revoked = store
            .list_devices(Some(DeviceStatus::Revoked))
            .expect("list revoked");
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].platform, DevicePlatform::Ios);
    }

    #[test]
    fn constant_time_auth_comparison() {
        // Security test: verify that our authentication uses constant-time comparison.
        //
        // We cannot directly test timing properties in a unit test, but we can verify
        // the structural guarantee: both valid and invalid tokens go through the same
        // ct_eq code path by checking that:
        // 1. The SHA-256 hash is computed for both stored and provided tokens
        // 2. The subtle::ConstantTimeEq trait is used for comparison
        //
        // This test verifies the security invariant by testing that authentication
        // fails with a token that differs by only a single character (which would
        // succeed with a naive early-exit comparison if hashing were bypassed).
        let mut store = test_store();
        let (code, _) = store.generate_pairing_code();
        let (device, token) = store
            .complete_pairing(&code, sample_device_info())
            .expect("pairing");

        // Flip the last character of the token
        let mut wrong_token = token.clone();
        let last = wrong_token.pop().unwrap();
        let flipped = if last == 'a' { 'b' } else { 'a' };
        wrong_token.push(flipped);

        // Must reject even a single-character difference
        assert!(store.authenticate(&device.id, &wrong_token).is_err());

        // Correct token must still work
        assert!(store.authenticate(&device.id, &token).is_ok());
    }

    #[test]
    fn auth_token_never_stored_plaintext() {
        // Security test: verify that the raw auth token is never stored in the database.
        // Only the SHA-256 hash of the token should be persisted.
        let mut store = test_store();
        let (code, _) = store.generate_pairing_code();
        let (device, token) = store
            .complete_pairing(&code, sample_device_info())
            .expect("pairing");

        // Read the stored hash directly from the database
        let stored_hash: String = store
            .conn
            .query_row(
                "SELECT auth_token_hash FROM devices WHERE id = ?1",
                params![device.id.0.to_string()],
                |row| row.get(0),
            )
            .expect("query should work");

        // The stored value must NOT be the raw token
        assert_ne!(stored_hash, token, "raw token must never be stored in DB");

        // The stored value must be the SHA-256 hash of the raw token
        let expected_hash = sha256_hex(&token);
        assert_eq!(
            stored_hash, expected_hash,
            "stored hash must be SHA-256 of the token"
        );

        // The stored hash must be a valid 64-char hex string (SHA-256 output)
        assert_eq!(stored_hash.len(), 64);
        assert!(stored_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn device_store_crud() {
        let mut store = test_store();

        // Create via pairing
        let (code, _) = store.generate_pairing_code();
        let (device, _) = store
            .complete_pairing(&code, sample_device_info())
            .expect("pairing");

        // Read
        let fetched = store.get_device(&device.id).unwrap().unwrap();
        assert_eq!(fetched.name, "Test Phone");

        // List
        let all = store.list_devices(None).unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        let deleted = store.delete_device(&device.id).unwrap();
        assert!(deleted);

        // Verify gone
        let gone = store.get_device(&device.id).unwrap();
        assert!(gone.is_none());

        // List should be empty
        let empty = store.list_devices(None).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn sanitize_device_name_strips_control_chars() {
        assert_eq!(sanitize_device_name("My\x00Phone"), "MyPhone");
        assert_eq!(sanitize_device_name("Tab\there"), "Tabhere");
        assert_eq!(sanitize_device_name("New\nline"), "Newline");
    }

    #[test]
    fn sanitize_device_name_truncates() {
        let long_name = "a".repeat(100);
        let sanitized = sanitize_device_name(&long_name);
        assert!(sanitized.len() <= MAX_DEVICE_NAME_LENGTH);
    }

    #[test]
    fn sanitize_device_name_trims_whitespace() {
        assert_eq!(sanitize_device_name("  My Phone  "), "My Phone");
    }

    #[test]
    fn device_id_display() {
        let id = DeviceId(Uuid::nil());
        assert_eq!(
            id.to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn double_revocation_fails() {
        let mut store = test_store();
        let (code, _) = store.generate_pairing_code();
        let (device, _) = store
            .complete_pairing(&code, sample_device_info())
            .expect("pairing");

        store.revoke(&device.id).expect("first revoke");
        assert!(store.revoke(&device.id).is_err());
    }
}
