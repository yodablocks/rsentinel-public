//! Rate limiting for API calls to prevent abuse and respect API limits.

use governor::{
    Quota, RateLimiter as GovRateLimiter,
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
};
use std::num::NonZeroU32;
use std::sync::Arc;

/// Rate limiter wrapper for controlling API request frequency.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<GovRateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl RateLimiter {
    /// Create a new rate limiter with specified requests per second.
    pub fn new(requests_per_second: u32) -> Self {
        let quota = Quota::per_second(
            NonZeroU32::new(requests_per_second).expect("requests_per_second must be > 0"),
        );
        Self {
            inner: Arc::new(GovRateLimiter::direct(quota)),
        }
    }

    /// Wait until a request can be made within rate limits.
    pub async fn acquire(&self) {
        self.inner.until_ready().await;
    }

    /// Try to acquire without waiting. Returns true if allowed.
    #[allow(dead_code)]
    pub fn try_acquire(&self) -> bool {
        self.inner.check().is_ok()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        // Default: 1 request per second (conservative for Shodan free tier)
        Self::new(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_creation() {
        let limiter = RateLimiter::new(5);
        assert!(limiter.try_acquire());
    }

    #[test]
    fn test_rate_limiter_default() {
        let limiter = RateLimiter::default();
        assert!(limiter.try_acquire());
    }
}
