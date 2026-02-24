//! Per-provider rate limiting with sliding-window tracking.
//!
//! Provides [`ProviderRateLimiter`] which enforces both requests-per-minute
//! (RPM) and tokens-per-minute (TPM) limits independently for each LLM
//! provider. Uses [`VecDeque`]-based sliding windows over [`Instant`]
//! timestamps for accurate, monotonic tracking.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

/// Duration of the sliding window for rate limiting.
const WINDOW: Duration = Duration::from_secs(60);

/// Error returned when a rate limit check fails.
#[derive(Debug, Clone, PartialEq)]
pub enum RateLimitError {
    /// The per-minute request limit has been reached.
    RequestsExceeded {
        /// Provider that is rate-limited.
        provider: String,
        /// Suggested wait time in milliseconds before retrying.
        retry_after_ms: u64,
    },
    /// The per-minute token limit has been reached.
    TokensExceeded {
        /// Provider that is rate-limited.
        provider: String,
        /// Suggested wait time in milliseconds before retrying.
        retry_after_ms: u64,
    },
}

impl fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RateLimitError::RequestsExceeded {
                provider,
                retry_after_ms,
            } => write!(
                f,
                "rate limit exceeded for provider '{provider}': too many requests, retry after {retry_after_ms}ms"
            ),
            RateLimitError::TokensExceeded {
                provider,
                retry_after_ms,
            } => write!(
                f,
                "rate limit exceeded for provider '{provider}': token budget exhausted, retry after {retry_after_ms}ms"
            ),
        }
    }
}

impl std::error::Error for RateLimitError {}

/// Per-provider sliding-window rate limit state.
#[derive(Debug)]
pub struct RateLimit {
    /// Maximum requests per minute. `0` means unlimited.
    pub requests_per_minute: u32,
    /// Maximum tokens per minute. `0` means unlimited.
    pub tokens_per_minute: u64,
    /// Timestamps of recent requests within the sliding window.
    request_times: VecDeque<Instant>,
    /// `(timestamp, token_count)` pairs for recent token usage.
    token_counts: VecDeque<(Instant, u64)>,
}

impl RateLimit {
    /// Create a new rate limit with the given RPM and TPM caps.
    ///
    /// Pass `0` for either value to leave it unlimited.
    pub fn new(requests_per_minute: u32, tokens_per_minute: u64) -> Self {
        Self {
            requests_per_minute,
            tokens_per_minute,
            request_times: VecDeque::new(),
            token_counts: VecDeque::new(),
        }
    }

    /// Evict entries older than `WINDOW` from the sliding windows.
    fn prune(&mut self, now: Instant) {
        let cutoff = now.checked_sub(WINDOW).unwrap_or(now);
        while self.request_times.front().is_some_and(|&t| t <= cutoff) {
            self.request_times.pop_front();
        }
        while self.token_counts.front().is_some_and(|(t, _)| *t <= cutoff) {
            self.token_counts.pop_front();
        }
    }

    /// Check whether a new request is allowed. If allowed, records the
    /// request timestamp and returns `Ok(())`. Otherwise returns the
    /// appropriate [`RateLimitError`].
    fn check_request(&mut self, provider: &str, now: Instant) -> Result<(), RateLimitError> {
        self.prune(now);

        // Check RPM
        if self.requests_per_minute > 0
            && self.request_times.len() as u32 >= self.requests_per_minute
        {
            let oldest = self.request_times.front().copied().unwrap_or(now);
            let retry_after = WINDOW
                .checked_sub(now.duration_since(oldest))
                .unwrap_or(Duration::ZERO);
            return Err(RateLimitError::RequestsExceeded {
                provider: provider.to_string(),
                retry_after_ms: retry_after.as_millis() as u64,
            });
        }

        // Check TPM
        if self.tokens_per_minute > 0 {
            let current_tokens: u64 = self.token_counts.iter().map(|(_, c)| c).sum();
            if current_tokens >= self.tokens_per_minute {
                let oldest = self.token_counts.front().map(|(t, _)| *t).unwrap_or(now);
                let retry_after = WINDOW
                    .checked_sub(now.duration_since(oldest))
                    .unwrap_or(Duration::ZERO);
                return Err(RateLimitError::TokensExceeded {
                    provider: provider.to_string(),
                    retry_after_ms: retry_after.as_millis() as u64,
                });
            }
        }

        // Allowed: record the request
        self.request_times.push_back(now);
        Ok(())
    }

    /// Record token usage for TPM tracking.
    fn record_tokens(&mut self, tokens: u64, now: Instant) {
        if tokens > 0 {
            self.token_counts.push_back((now, tokens));
        }
    }

    /// Number of requests still available in the current window.
    fn remaining_requests(&self, now: Instant) -> u32 {
        if self.requests_per_minute == 0 {
            return u32::MAX;
        }
        let mut clone = self.request_times.clone();
        let cutoff = now.checked_sub(WINDOW).unwrap_or(now);
        while clone.front().is_some_and(|&t| t <= cutoff) {
            clone.pop_front();
        }
        self.requests_per_minute.saturating_sub(clone.len() as u32)
    }

    /// Number of tokens still available in the current window.
    fn remaining_tokens(&self, now: Instant) -> u64 {
        if self.tokens_per_minute == 0 {
            return u64::MAX;
        }
        let cutoff = now.checked_sub(WINDOW).unwrap_or(now);
        let used: u64 = self
            .token_counts
            .iter()
            .filter(|(t, _)| *t > cutoff)
            .map(|(_, c)| c)
            .sum();
        self.tokens_per_minute.saturating_sub(used)
    }
}

/// Per-provider rate limiter managing multiple [`RateLimit`] instances.
///
/// Providers without explicit limits are treated as unlimited (always allowed).
#[derive(Debug)]
pub struct ProviderRateLimiter {
    limits: HashMap<String, RateLimit>,
}

impl ProviderRateLimiter {
    /// Create a new rate limiter with no configured providers.
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
        }
    }

    /// Create a rate limiter pre-populated with sensible defaults for
    /// common providers.
    ///
    /// Default limits:
    /// - **Anthropic:** 60 RPM, 100K TPM
    /// - **OpenAI:** 500 RPM, 200K TPM
    /// - **Google:** 60 RPM, 100K TPM
    /// - **Ollama:** unlimited (local)
    /// - **OpenRouter:** 200 RPM, 500K TPM
    pub fn with_defaults() -> Self {
        let mut limiter = Self::new();
        limiter.set_limit("anthropic", 60, 100_000);
        limiter.set_limit("openai", 500, 200_000);
        limiter.set_limit("google", 60, 100_000);
        limiter.set_limit("ollama", 0, 0); // unlimited
        limiter.set_limit("openrouter", 200, 500_000);
        limiter
    }

    /// Set (or override) the rate limit for a provider.
    ///
    /// Pass `0` for `rpm` or `tpm` to leave that dimension unlimited.
    pub fn set_limit(&mut self, provider: &str, rpm: u32, tpm: u64) {
        self.limits
            .insert(provider.to_string(), RateLimit::new(rpm, tpm));
    }

    /// Check whether a request to `provider` is allowed.
    ///
    /// If the provider has no configured limit, the request is always
    /// allowed. If allowed, the request is recorded in the sliding window.
    pub fn check_request(&mut self, provider: &str) -> Result<(), RateLimitError> {
        let now = Instant::now();
        self.check_request_at(provider, now)
    }

    /// Record token usage for a provider (for TPM tracking).
    ///
    /// Call this after receiving a response with token counts.
    pub fn record_tokens(&mut self, provider: &str, tokens: u64) {
        let now = Instant::now();
        self.record_tokens_at(provider, tokens, now);
    }

    /// Number of requests remaining for a provider in the current window.
    ///
    /// Returns `u32::MAX` if the provider is unlimited or unknown.
    pub fn remaining_requests(&self, provider: &str) -> u32 {
        let now = Instant::now();
        self.remaining_requests_at(provider, now)
    }

    /// Number of tokens remaining for a provider in the current window.
    ///
    /// Returns `u64::MAX` if the provider is unlimited or unknown.
    pub fn remaining_tokens(&self, provider: &str) -> u64 {
        let now = Instant::now();
        self.remaining_tokens_at(provider, now)
    }

    // -- Internal methods that accept an `Instant` for testability --

    fn check_request_at(&mut self, provider: &str, now: Instant) -> Result<(), RateLimitError> {
        match self.limits.get_mut(provider) {
            Some(limit) => limit.check_request(provider, now),
            None => Ok(()), // Unknown provider => unlimited
        }
    }

    fn record_tokens_at(&mut self, provider: &str, tokens: u64, now: Instant) {
        if let Some(limit) = self.limits.get_mut(provider) {
            limit.record_tokens(tokens, now);
        }
    }

    fn remaining_requests_at(&self, provider: &str, now: Instant) -> u32 {
        match self.limits.get(provider) {
            Some(limit) => limit.remaining_requests(now),
            None => u32::MAX,
        }
    }

    fn remaining_tokens_at(&self, provider: &str, now: Instant) -> u64 {
        match self.limits.get(provider) {
            Some(limit) => limit.remaining_tokens(now),
            None => u64::MAX,
        }
    }
}

impl Default for ProviderRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_allows_within_rpm() {
        let now = Instant::now();
        let mut limiter = ProviderRateLimiter::new();
        limiter.set_limit("test", 5, 0);

        for _ in 0..5 {
            assert!(limiter.check_request_at("test", now).is_ok());
        }
        // 6th request should be denied
        let err = limiter.check_request_at("test", now).unwrap_err();
        match err {
            RateLimitError::RequestsExceeded { provider, .. } => {
                assert_eq!(provider, "test");
            }
            other => panic!("expected RequestsExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_rate_limit_window_expiry() {
        let now = Instant::now();
        let mut limiter = ProviderRateLimiter::new();
        limiter.set_limit("test", 2, 0);

        // Use up both slots
        assert!(limiter.check_request_at("test", now).is_ok());
        assert!(limiter.check_request_at("test", now).is_ok());
        assert!(limiter.check_request_at("test", now).is_err());

        // Advance past the 60s window
        let later = now + Duration::from_secs(61);
        assert!(
            limiter.check_request_at("test", later).is_ok(),
            "should be allowed after window expires"
        );
    }

    #[test]
    fn test_rate_limit_token_tracking() {
        let now = Instant::now();
        let mut limiter = ProviderRateLimiter::new();
        limiter.set_limit("test", 0, 1000); // unlimited RPM, 1000 TPM

        // Record some tokens
        limiter.record_tokens_at("test", 500, now);
        assert_eq!(limiter.remaining_tokens_at("test", now), 500);

        // Record more, hitting the limit
        limiter.record_tokens_at("test", 500, now);
        assert_eq!(limiter.remaining_tokens_at("test", now), 0);

        // Next request should be denied due to TPM
        let err = limiter.check_request_at("test", now).unwrap_err();
        match err {
            RateLimitError::TokensExceeded { provider, .. } => {
                assert_eq!(provider, "test");
            }
            other => panic!("expected TokensExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_rate_limit_token_window_expiry() {
        let now = Instant::now();
        let mut limiter = ProviderRateLimiter::new();
        limiter.set_limit("test", 0, 1000);

        limiter.record_tokens_at("test", 1000, now);
        assert_eq!(limiter.remaining_tokens_at("test", now), 0);

        // After window expires, tokens should be available again
        let later = now + Duration::from_secs(61);
        assert_eq!(limiter.remaining_tokens_at("test", later), 1000);
        assert!(limiter.check_request_at("test", later).is_ok());
    }

    #[test]
    fn test_unknown_provider_unlimited() {
        let mut limiter = ProviderRateLimiter::new();

        // Unknown provider should always be allowed
        for _ in 0..1000 {
            assert!(limiter.check_request_at("unknown", Instant::now()).is_ok());
        }
        assert_eq!(limiter.remaining_requests("unknown"), u32::MAX);
        assert_eq!(limiter.remaining_tokens("unknown"), u64::MAX);
    }

    #[test]
    fn test_ollama_unlimited_with_defaults() {
        let mut limiter = ProviderRateLimiter::with_defaults();
        let now = Instant::now();

        // Ollama has 0/0 limits => unlimited
        for _ in 0..1000 {
            assert!(limiter.check_request_at("ollama", now).is_ok());
        }
    }

    #[test]
    fn test_default_limits_present() {
        let limiter = ProviderRateLimiter::with_defaults();

        // Verify defaults are set
        assert!(limiter.limits.contains_key("anthropic"));
        assert!(limiter.limits.contains_key("openai"));
        assert!(limiter.limits.contains_key("google"));
        assert!(limiter.limits.contains_key("ollama"));
        assert!(limiter.limits.contains_key("openrouter"));

        // Check specific values
        assert_eq!(limiter.limits["anthropic"].requests_per_minute, 60);
        assert_eq!(limiter.limits["anthropic"].tokens_per_minute, 100_000);
        assert_eq!(limiter.limits["openai"].requests_per_minute, 500);
        assert_eq!(limiter.limits["openai"].tokens_per_minute, 200_000);
        assert_eq!(limiter.limits["google"].requests_per_minute, 60);
        assert_eq!(limiter.limits["google"].tokens_per_minute, 100_000);
        assert_eq!(limiter.limits["ollama"].requests_per_minute, 0);
        assert_eq!(limiter.limits["ollama"].tokens_per_minute, 0);
        assert_eq!(limiter.limits["openrouter"].requests_per_minute, 200);
        assert_eq!(limiter.limits["openrouter"].tokens_per_minute, 500_000);
    }

    #[test]
    fn test_remaining_requests_decrements() {
        let now = Instant::now();
        let mut limiter = ProviderRateLimiter::new();
        limiter.set_limit("test", 10, 0);

        assert_eq!(limiter.remaining_requests_at("test", now), 10);

        limiter.check_request_at("test", now).unwrap();
        assert_eq!(limiter.remaining_requests_at("test", now), 9);

        for _ in 0..9 {
            limiter.check_request_at("test", now).unwrap();
        }
        assert_eq!(limiter.remaining_requests_at("test", now), 0);
    }

    #[test]
    fn test_set_limit_overrides() {
        let mut limiter = ProviderRateLimiter::with_defaults();
        assert_eq!(limiter.limits["anthropic"].requests_per_minute, 60);

        limiter.set_limit("anthropic", 120, 200_000);
        assert_eq!(limiter.limits["anthropic"].requests_per_minute, 120);
        assert_eq!(limiter.limits["anthropic"].tokens_per_minute, 200_000);
    }

    #[test]
    fn test_retry_after_ms_is_reasonable() {
        let now = Instant::now();
        let mut limiter = ProviderRateLimiter::new();
        limiter.set_limit("test", 1, 0);

        // Use the single allowed request
        limiter.check_request_at("test", now).unwrap();

        // Next request should fail with a retry_after close to 60s
        let err = limiter.check_request_at("test", now).unwrap_err();
        match err {
            RateLimitError::RequestsExceeded { retry_after_ms, .. } => {
                // Should be close to 60000ms (the full window)
                assert!(
                    retry_after_ms <= 60_000,
                    "retry_after_ms should be <= 60000, got {retry_after_ms}"
                );
                assert!(
                    retry_after_ms >= 59_000,
                    "retry_after_ms should be >= 59000, got {retry_after_ms}"
                );
            }
            other => panic!("expected RequestsExceeded, got {other:?}"),
        }
    }

    #[test]
    fn test_rate_limit_error_display() {
        let err = RateLimitError::RequestsExceeded {
            provider: "anthropic".into(),
            retry_after_ms: 5000,
        };
        let display = err.to_string();
        assert!(display.contains("anthropic"));
        assert!(display.contains("5000ms"));

        let err = RateLimitError::TokensExceeded {
            provider: "openai".into(),
            retry_after_ms: 10000,
        };
        let display = err.to_string();
        assert!(display.contains("openai"));
        assert!(display.contains("token budget"));
    }

    #[test]
    fn test_sliding_window_partial_expiry() {
        let now = Instant::now();
        let mut limiter = ProviderRateLimiter::new();
        limiter.set_limit("test", 3, 0);

        // Make 3 requests at different times
        limiter.check_request_at("test", now).unwrap();
        let t1 = now + Duration::from_secs(20);
        limiter.check_request_at("test", t1).unwrap();
        let t2 = now + Duration::from_secs(40);
        limiter.check_request_at("test", t2).unwrap();

        // At t=40, all 3 slots used
        assert!(limiter.check_request_at("test", t2).is_err());

        // At t=61, the first request (t=0) has expired, freeing one slot
        let t3 = now + Duration::from_secs(61);
        assert!(limiter.check_request_at("test", t3).is_ok());

        // But the second (t=20) and third (t=40) are still in window,
        // plus the new one we just added = 3, so no more
        assert!(limiter.check_request_at("test", t3).is_err());
    }

    #[test]
    fn test_record_tokens_zero_ignored() {
        let now = Instant::now();
        let mut limiter = ProviderRateLimiter::new();
        limiter.set_limit("test", 0, 100);

        limiter.record_tokens_at("test", 0, now);
        assert_eq!(limiter.remaining_tokens_at("test", now), 100);

        limiter.record_tokens_at("test", 50, now);
        assert_eq!(limiter.remaining_tokens_at("test", now), 50);
    }

    #[test]
    fn test_record_tokens_unknown_provider_noop() {
        let mut limiter = ProviderRateLimiter::new();
        // Should not panic or error
        limiter.record_tokens("nonexistent", 1000);
    }

    #[test]
    fn test_both_rpm_and_tpm_enforced() {
        let now = Instant::now();
        let mut limiter = ProviderRateLimiter::new();
        limiter.set_limit("test", 100, 500); // 100 RPM, 500 TPM

        // Record enough tokens to exceed TPM
        limiter.record_tokens_at("test", 500, now);

        // RPM has room (0 used out of 100), but TPM is full
        let err = limiter.check_request_at("test", now).unwrap_err();
        match err {
            RateLimitError::TokensExceeded { .. } => {} // expected
            other => panic!("expected TokensExceeded, got {other:?}"),
        }
    }
}
