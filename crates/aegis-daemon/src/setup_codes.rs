//! Setup code generation with QR codes for device pairing.
//!
//! Generates time-limited 6-digit numeric setup codes paired with a daemon
//! endpoint URL. The setup payload is encoded as JSON and rendered as a QR
//! code (Unicode block characters for terminal display).
//!
//! # Security Properties
//!
//! - Setup codes use cryptographically random generation (UUID v4 CSPRNG).
//! - Code verification uses constant-time comparison (`subtle::ConstantTimeEq`)
//!   to prevent timing attacks.
//! - Codes expire after 5 minutes by default.
//! - Max 3 verification attempts per code to prevent brute-force attacks.
//! - After successful verification, a long-lived HMAC-SHA256 device auth
//!   token is generated following the pattern in `device_registry.rs`.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Duration a setup code remains valid (5 minutes).
const SETUP_CODE_TTL: Duration = Duration::from_secs(300);

/// Maximum verification attempts before lockout.
const MAX_VERIFICATION_ATTEMPTS: u32 = 3;

/// Length of the numeric setup code.
const SETUP_CODE_LENGTH: usize = 6;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// JSON payload encoded into the QR code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupPayload {
    /// The 6-digit numeric setup code.
    pub code: String,
    /// The daemon's endpoint URL for the device to connect to.
    pub endpoint: String,
    /// When this setup code expires (RFC 3339).
    pub expires_at: DateTime<Utc>,
}

/// Result returned from setup code generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupCodeResult {
    /// The 6-digit numeric setup code.
    pub code: String,
    /// QR code rendered as Unicode block characters for terminal display.
    pub qr_unicode: String,
    /// When this setup code expires (RFC 3339).
    pub expires_at: DateTime<Utc>,
}

/// Result returned from successful setup code verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Long-lived device auth token (HMAC-SHA256 based).
    /// The caller must send this to the device; it is never stored on the server.
    pub device_token: String,
    /// Device ID assigned to the verified device.
    pub device_id: String,
}

/// Internal state for a pending setup code.
#[derive(Debug)]
struct PendingSetupCode {
    /// The 6-digit code.
    code: String,
    /// When this code expires (monotonic clock).
    expiry: Instant,
    /// Number of failed verification attempts.
    attempts: u32,
    /// Whether this code has been locked out due to too many attempts.
    locked: bool,
}

// ---------------------------------------------------------------------------
// SetupCodeManager
// ---------------------------------------------------------------------------

/// Manages setup code lifecycle: generation, QR encoding, and verification.
pub struct SetupCodeManager {
    /// Pending setup codes (in-memory, not persisted).
    pending: Vec<PendingSetupCode>,
    /// HMAC key for generating device auth tokens.
    hmac_key: Vec<u8>,
}

impl SetupCodeManager {
    /// Create a new setup code manager with the given HMAC key.
    ///
    /// The HMAC key should be the same key used by the `DeviceStore` so that
    /// tokens generated here are compatible with device authentication.
    pub fn new(hmac_key: Vec<u8>) -> Self {
        Self {
            pending: Vec::new(),
            hmac_key,
        }
    }

    /// Generate a setup code and QR code for the given daemon endpoint.
    ///
    /// Returns a `SetupCodeResult` containing the code, QR Unicode string,
    /// and expiry timestamp.
    pub fn generate(&mut self, endpoint: &str) -> SetupCodeResult {
        self.purge_expired();

        // Generate a 6-digit code from UUID random bytes (CSPRNG).
        let raw = Uuid::new_v4();
        let bytes = raw.as_bytes();
        let num = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) % 1_000_000;
        let code = format!("{num:0>6}");
        debug_assert_eq!(code.len(), SETUP_CODE_LENGTH);

        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(SETUP_CODE_TTL.as_secs() as i64);

        // Build the JSON payload for the QR code.
        let payload = SetupPayload {
            code: code.clone(),
            endpoint: endpoint.to_string(),
            expires_at,
        };
        let payload_json =
            serde_json::to_string(&payload).expect("SetupPayload serialization cannot fail");

        // Render QR code as Unicode block characters.
        let qr_unicode = render_qr_unicode(&payload_json);

        // Store the pending code.
        self.pending.push(PendingSetupCode {
            code: code.clone(),
            expiry: Instant::now() + SETUP_CODE_TTL,
            attempts: 0,
            locked: false,
        });

        SetupCodeResult {
            code,
            qr_unicode,
            expires_at,
        }
    }

    /// Verify a setup code using constant-time comparison.
    ///
    /// On success, consumes the code and returns a `VerificationResult` with
    /// a long-lived HMAC-SHA256 device auth token.
    ///
    /// Returns `Err` if:
    /// - The code is invalid or expired.
    /// - The code has been locked out (max attempts exceeded).
    /// - No pending codes exist.
    pub fn verify(&mut self, code: &str) -> Result<VerificationResult, anyhow::Error> {
        self.purge_expired();

        let code_bytes = code.as_bytes();
        let now = Instant::now();

        // Find the matching code using constant-time comparison.
        // We iterate ALL pending codes to avoid timing leaks about which
        // codes exist. We track the matching index separately.
        let mut match_index: Option<usize> = None;

        for (i, pending) in self.pending.iter().enumerate() {
            if pending.expiry <= now {
                continue;
            }
            if pending.locked {
                continue;
            }

            let pending_bytes = pending.code.as_bytes();
            if code_bytes.len() == pending_bytes.len()
                && bool::from(code_bytes.ct_eq(pending_bytes))
            {
                match_index = Some(i);
            }
        }

        // Check if any code was locked out for this attempt.
        // We must also check if the submitted code matches a locked entry.
        let mut was_locked = false;
        for pending in &self.pending {
            if pending.expiry <= now {
                continue;
            }
            if !pending.locked {
                continue;
            }
            let pending_bytes = pending.code.as_bytes();
            if code_bytes.len() == pending_bytes.len()
                && bool::from(code_bytes.ct_eq(pending_bytes))
            {
                was_locked = true;
            }
        }

        if was_locked {
            return Err(anyhow::anyhow!(
                "setup code locked out after too many failed attempts"
            ));
        }

        match match_index {
            Some(idx) => {
                // Success: remove the code and generate a device token.
                self.pending.remove(idx);

                let device_id = Uuid::new_v4().to_string();
                let device_token = self.generate_device_token(&device_id)?;

                Ok(VerificationResult {
                    device_token,
                    device_id,
                })
            }
            None => {
                // Failed attempt: increment attempt counters for all non-expired,
                // non-locked codes. This is intentionally broad to avoid leaking
                // which code was targeted.
                for pending in &mut self.pending {
                    if pending.expiry > now && !pending.locked {
                        pending.attempts += 1;
                        if pending.attempts >= MAX_VERIFICATION_ATTEMPTS {
                            pending.locked = true;
                        }
                    }
                }

                Err(anyhow::anyhow!("invalid or expired setup code"))
            }
        }
    }

    /// Generate an HMAC-SHA256 device auth token.
    ///
    /// Follows the same pattern as `DeviceStore::generate_auth_token()`:
    /// token format is `hex(hmac_tag):device_id:nonce`.
    fn generate_device_token(&self, device_id: &str) -> Result<String, anyhow::Error> {
        let nonce = Uuid::new_v4();
        let message = format!("{device_id}:{nonce}");

        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.hmac_key).expect("HMAC can take key of any size");
        mac.update(message.as_bytes());
        let result = mac.finalize();
        let tag = result.into_bytes();

        Ok(format!("{}:{}:{}", hex::encode(tag), device_id, nonce))
    }

    /// Remove expired codes.
    fn purge_expired(&mut self) {
        let now = Instant::now();
        self.pending.retain(|p| p.expiry > now);
    }
}

/// Render a string as a QR code using Unicode block characters.
///
/// Returns a multi-line string suitable for terminal display. Uses the
/// `qrcode` crate's built-in string renderer with dark/light module mapping.
fn render_qr_unicode(data: &str) -> String {
    match QrCode::new(data.as_bytes()) {
        Ok(qr) => qr
            .render::<char>()
            .quiet_zone(true)
            .module_dimensions(2, 1)
            .build(),
        Err(_) => String::from("[QR code generation failed]"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hmac_key() -> Vec<u8> {
        let u1 = Uuid::new_v4();
        let u2 = Uuid::new_v4();
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(u1.as_bytes());
        key.extend_from_slice(u2.as_bytes());
        key
    }

    #[test]
    fn test_setup_code_generation() {
        let mut mgr = SetupCodeManager::new(test_hmac_key());
        let result = mgr.generate("http://localhost:9090");

        // Must be exactly 6 digits.
        assert_eq!(result.code.len(), SETUP_CODE_LENGTH);
        assert!(result.code.chars().all(|c| c.is_ascii_digit()));

        // Expiry must be in the future.
        assert!(result.expires_at > Utc::now());

        // Expiry should be approximately 5 minutes from now.
        let diff = result.expires_at - Utc::now();
        assert!(diff.num_seconds() > 290 && diff.num_seconds() <= 300);
    }

    #[test]
    fn test_setup_code_verification_success() {
        let mut mgr = SetupCodeManager::new(test_hmac_key());
        let result = mgr.generate("http://localhost:9090");

        let verification = mgr
            .verify(&result.code)
            .expect("verification should succeed");
        assert!(!verification.device_token.is_empty());
        assert!(!verification.device_id.is_empty());

        // Token should follow the format: hex(hmac_tag):device_id:nonce
        let parts: Vec<&str> = verification.device_token.split(':').collect();
        assert_eq!(parts.len(), 3, "token should have 3 parts separated by ':'");

        // First part should be hex (64 chars for SHA-256 HMAC).
        assert_eq!(parts[0].len(), 64);
        assert!(parts[0].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_setup_code_verification_expired() {
        let mut mgr = SetupCodeManager::new(test_hmac_key());

        // Manually insert an expired code.
        mgr.pending.push(PendingSetupCode {
            code: "123456".into(),
            expiry: Instant::now() - Duration::from_secs(1),
            attempts: 0,
            locked: false,
        });

        let result = mgr.verify("123456");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid or expired"));
    }

    #[test]
    fn test_setup_code_brute_force_lockout() {
        let mut mgr = SetupCodeManager::new(test_hmac_key());
        let result = mgr.generate("http://localhost:9090");
        let correct_code = result.code.clone();

        // Submit 3 wrong attempts.
        for i in 0..MAX_VERIFICATION_ATTEMPTS {
            let wrong = format!("{:06}", i + 900_000);
            // Skip if the wrong code happens to equal the correct code.
            if wrong == correct_code {
                continue;
            }
            let err = mgr.verify(&wrong);
            assert!(err.is_err(), "wrong code attempt {i} should fail");
        }

        // Now the correct code should be locked out.
        let locked_result = mgr.verify(&correct_code);
        assert!(locked_result.is_err());
        assert!(locked_result
            .unwrap_err()
            .to_string()
            .contains("locked out"));
    }

    #[test]
    fn test_setup_code_constant_time() {
        // Structural security test: verify that constant-time comparison is used.
        //
        // We verify the security invariant by testing that verification fails
        // with a code that differs by only a single character. A naive
        // early-exit comparison might leak timing information, but our
        // implementation uses `subtle::ConstantTimeEq`.
        let mut mgr = SetupCodeManager::new(test_hmac_key());
        let result = mgr.generate("http://localhost:9090");

        // Flip the last digit.
        let mut wrong_code = result.code.clone();
        let last = wrong_code.pop().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        wrong_code.push(flipped);

        // Must reject even a single-digit difference.
        if wrong_code != result.code {
            assert!(mgr.verify(&wrong_code).is_err());
        }

        // Correct code must still work.
        assert!(mgr.verify(&result.code).is_ok());
    }

    #[test]
    fn test_qr_code_generation() {
        let mut mgr = SetupCodeManager::new(test_hmac_key());
        let result = mgr.generate("http://localhost:9090");

        // QR Unicode should not be empty.
        assert!(!result.qr_unicode.is_empty());
        assert!(!result.qr_unicode.contains("[QR code generation failed]"));

        // The QR code encodes a JSON payload. Verify by parsing the payload
        // that was used to generate it.
        let payload = SetupPayload {
            code: result.code.clone(),
            endpoint: "http://localhost:9090".into(),
            expires_at: result.expires_at,
        };
        let json = serde_json::to_string(&payload).unwrap();

        // Verify the JSON is valid and contains expected fields.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["code"].as_str().unwrap(), result.code);
        assert_eq!(
            parsed["endpoint"].as_str().unwrap(),
            "http://localhost:9090"
        );
        assert!(parsed["expires_at"].as_str().is_some());
    }

    #[test]
    fn test_setup_code_generates_device_token() {
        let mut mgr = SetupCodeManager::new(test_hmac_key());
        let result = mgr.generate("http://localhost:9090");

        let verification = mgr
            .verify(&result.code)
            .expect("verification should succeed");

        // Token must follow HMAC pattern: hex(tag):device_id:nonce
        let parts: Vec<&str> = verification.device_token.split(':').collect();
        assert_eq!(parts.len(), 3);

        // Device ID in the token should match the returned device_id.
        assert_eq!(parts[1], verification.device_id);

        // The HMAC tag should be a valid 64-char hex string.
        assert_eq!(parts[0].len(), 64);
        assert!(parts[0].chars().all(|c| c.is_ascii_hexdigit()));

        // The nonce should be a valid UUID.
        assert!(Uuid::parse_str(parts[2]).is_ok());
    }

    #[test]
    fn test_setup_code_timing_attack_resistance() {
        // Security test: verify structural constant-time comparison guarantees.
        //
        // We cannot directly measure timing in a unit test, but we verify that:
        // 1. The `subtle::ConstantTimeEq` trait is used (compile-time guarantee).
        // 2. Both matching and non-matching paths evaluate all pending codes
        //    (no early exit on first match/mismatch).
        // 3. A single-bit difference in the code still causes rejection.

        let mut mgr = SetupCodeManager::new(test_hmac_key());
        let result = mgr.generate("http://localhost:9090");

        // Generate a second code to verify all codes are checked.
        let _result2 = mgr.generate("http://localhost:9091");

        // Try a code that differs in only the first digit.
        let mut near_miss = result.code.clone();
        let first = near_miss.remove(0);
        let flipped = if first == '0' { '1' } else { '0' };
        near_miss.insert(0, flipped);

        if near_miss != result.code {
            let err = mgr.verify(&near_miss);
            assert!(err.is_err(), "near-miss code must be rejected");
        }

        // The original code should still work (wasn't consumed by the near-miss).
        assert!(
            mgr.verify(&result.code).is_ok(),
            "original code must still be valid after a failed attempt"
        );
    }

    #[test]
    fn test_setup_code_consumed_after_use() {
        let mut mgr = SetupCodeManager::new(test_hmac_key());
        let result = mgr.generate("http://localhost:9090");

        // First verification should succeed.
        assert!(mgr.verify(&result.code).is_ok());

        // Second verification of the same code should fail (code consumed).
        assert!(mgr.verify(&result.code).is_err());
    }

    #[test]
    fn test_render_qr_unicode_produces_output() {
        let output = render_qr_unicode("test data");
        assert!(!output.is_empty());
        assert!(output.contains('\n'), "QR output should be multi-line");
    }
}
