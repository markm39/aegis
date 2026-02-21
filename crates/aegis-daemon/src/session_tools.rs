//! Session tool wrappers with policy checks and rate limiting.
//!
//! These functions wrap daemon operations with security controls:
//! - Rate limiting for subagent steering
//! - Depth-based spawn checks
//! - Audit logging hooks for cross-session interactions

use std::collections::HashMap;
use std::time::Instant;

/// Rate limiter for subagent steering.
///
/// Enforces a cooldown between steer messages to the same agent and a maximum
/// message length. Defaults match OpenClaw conventions: 2s cooldown, 4000 char max.
pub struct SteerRateLimiter {
    last_steer: HashMap<String, Instant>,
    cooldown_secs: u64,
    max_message_len: usize,
}

impl SteerRateLimiter {
    pub fn new() -> Self {
        Self {
            last_steer: HashMap::new(),
            cooldown_secs: 2,
            max_message_len: 4000,
        }
    }

    /// Check if a steer message is allowed for the given agent.
    ///
    /// Returns `Ok(())` and records the timestamp if allowed, or
    /// `Err(SteerError)` if the message is too long or rate-limited.
    pub fn check(&mut self, agent_name: &str, message: &str) -> Result<(), SteerError> {
        if message.len() > self.max_message_len {
            return Err(SteerError::MessageTooLong {
                len: message.len(),
                max: self.max_message_len,
            });
        }
        if let Some(last) = self.last_steer.get(agent_name) {
            let elapsed = last.elapsed().as_secs();
            if elapsed < self.cooldown_secs {
                return Err(SteerError::RateLimited {
                    wait_secs: self.cooldown_secs - elapsed,
                });
            }
        }
        self.last_steer
            .insert(agent_name.to_string(), Instant::now());
        Ok(())
    }
}

impl Default for SteerRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors from steer rate limiting.
#[derive(Debug)]
pub enum SteerError {
    /// The steer message exceeds the maximum allowed length.
    MessageTooLong { len: usize, max: usize },
    /// The agent was steered too recently; wait before sending again.
    RateLimited { wait_secs: u64 },
}

impl std::fmt::Display for SteerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SteerError::MessageTooLong { len, max } => {
                write!(f, "steer message too long ({len} bytes, max {max})")
            }
            SteerError::RateLimited { wait_secs } => {
                write!(f, "steer rate limited, wait {wait_secs}s")
            }
        }
    }
}

impl std::error::Error for SteerError {}

/// Depth-based spawn policy check.
///
/// Returns `Ok(())` if spawning a subagent is allowed at the current depth,
/// or `Err` with a reason string if denied.
pub fn check_spawn_depth(current_depth: u8, depth_limit: u8) -> Result<(), String> {
    if current_depth >= depth_limit {
        return Err(format!(
            "spawn denied: agent depth {current_depth} >= limit {depth_limit}"
        ));
    }
    Ok(())
}

/// Default subagent depth limit.
pub const DEFAULT_DEPTH_LIMIT: u8 = 3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steer_rate_limiter_allows_first_steer() {
        let mut limiter = SteerRateLimiter::new();
        assert!(limiter.check("agent-1", "hello").is_ok());
    }

    #[test]
    fn steer_rate_limiter_blocks_rapid_subsequent_steers() {
        let mut limiter = SteerRateLimiter::new();
        limiter.check("agent-1", "first").unwrap();
        let result = limiter.check("agent-1", "second");
        assert!(result.is_err());
        match result.unwrap_err() {
            SteerError::RateLimited { wait_secs } => {
                assert!(wait_secs > 0, "should report nonzero wait time");
            }
            other => panic!("expected RateLimited, got: {other}"),
        }
    }

    #[test]
    fn steer_rate_limiter_allows_different_agents() {
        let mut limiter = SteerRateLimiter::new();
        limiter.check("agent-1", "hello").unwrap();
        // Different agent should not be rate-limited
        assert!(limiter.check("agent-2", "hello").is_ok());
    }

    #[test]
    fn steer_rate_limiter_rejects_oversized_messages() {
        let mut limiter = SteerRateLimiter::new();
        let long_msg = "x".repeat(4001);
        let result = limiter.check("agent-1", &long_msg);
        assert!(result.is_err());
        match result.unwrap_err() {
            SteerError::MessageTooLong { len, max } => {
                assert_eq!(len, 4001);
                assert_eq!(max, 4000);
            }
            other => panic!("expected MessageTooLong, got: {other}"),
        }
    }

    #[test]
    fn steer_rate_limiter_allows_exact_max_length() {
        let mut limiter = SteerRateLimiter::new();
        let exact_msg = "x".repeat(4000);
        assert!(limiter.check("agent-1", &exact_msg).is_ok());
    }

    #[test]
    fn check_spawn_depth_allows_within_limit() {
        assert!(check_spawn_depth(0, DEFAULT_DEPTH_LIMIT).is_ok());
        assert!(check_spawn_depth(1, DEFAULT_DEPTH_LIMIT).is_ok());
        assert!(check_spawn_depth(2, DEFAULT_DEPTH_LIMIT).is_ok());
    }

    #[test]
    fn check_spawn_depth_denies_at_limit() {
        assert!(check_spawn_depth(3, DEFAULT_DEPTH_LIMIT).is_err());
        let err = check_spawn_depth(3, 3).unwrap_err();
        assert!(err.contains("depth 3 >= limit 3"), "got: {err}");
    }

    #[test]
    fn check_spawn_depth_denies_beyond_limit() {
        assert!(check_spawn_depth(4, DEFAULT_DEPTH_LIMIT).is_err());
        assert!(check_spawn_depth(255, DEFAULT_DEPTH_LIMIT).is_err());
    }

    #[test]
    fn steer_error_display() {
        let e = SteerError::MessageTooLong {
            len: 5000,
            max: 4000,
        };
        assert_eq!(
            e.to_string(),
            "steer message too long (5000 bytes, max 4000)"
        );

        let e = SteerError::RateLimited { wait_secs: 1 };
        assert_eq!(e.to_string(), "steer rate limited, wait 1s");
    }

    #[test]
    fn default_depth_limit_is_three() {
        assert_eq!(DEFAULT_DEPTH_LIMIT, 3);
    }
}
