// Adaptive rate limiting with burst mode for initial port discovery
use std::num::NonZeroU32;
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::Mutex;
use governor::{Quota, RateLimiter as GovernorLimiter, clock::DefaultClock, state::InMemoryState};

type GovLimiter = GovernorLimiter<governor::state::direct::NotKeyed, InMemoryState, DefaultClock>;

#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub current_rate: u32,
    pub is_bursting: bool,
    pub adjustments: u64,
}

/// Adaptive rate limiter that adjusts based on network conditions
pub struct AdaptiveRateLimiter {
    current_rate: Arc<Mutex<u32>>,
    min_rate: u32,
    max_rate: u32,
    limiter: Arc<Mutex<Arc<GovLimiter>>>,
    last_adjustment: Arc<Mutex<Instant>>,
    adjustment_interval: Duration,
    burst_rate: u32,
    is_bursting: Arc<Mutex<bool>>,
    burst_until: Arc<Mutex<Instant>>,
    adjustment_count: Arc<Mutex<u64>>,
}

impl AdaptiveRateLimiter {
    pub fn new(initial_rate: u32, min_rate: u32, max_rate: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(initial_rate.max(1)).unwrap());
        let limiter = Arc::new(GovernorLimiter::direct(quota));

        Self {
            current_rate: Arc::new(Mutex::new(initial_rate)),
            min_rate,
            max_rate,
            limiter: Arc::new(Mutex::new(limiter)),
            last_adjustment: Arc::new(Mutex::new(Instant::now())),
            adjustment_interval: Duration::from_secs(5),
            burst_rate: max_rate.min(initial_rate * 3),
            is_bursting: Arc::new(Mutex::new(false)),
            burst_until: Arc::new(Mutex::new(Instant::now())),
            adjustment_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Create with a burst mode that runs at higher rate for initial discovery
    pub fn with_burst(initial_rate: u32, min_rate: u32, max_rate: u32, burst_duration: Duration) -> Self {
        let burst_rate = max_rate.min(initial_rate * 3);
        let quota = Quota::per_second(NonZeroU32::new(burst_rate.max(1)).unwrap());
        let limiter = Arc::new(GovernorLimiter::direct(quota));

        Self {
            current_rate: Arc::new(Mutex::new(burst_rate)),
            min_rate,
            max_rate,
            limiter: Arc::new(Mutex::new(limiter)),
            last_adjustment: Arc::new(Mutex::new(Instant::now())),
            adjustment_interval: Duration::from_secs(5),
            burst_rate,
            is_bursting: Arc::new(Mutex::new(true)),
            burst_until: Arc::new(Mutex::new(Instant::now() + burst_duration)),
            adjustment_count: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn check(&self) -> Result<(), String> {
        self.maybe_end_burst().await;
        let limiter = self.limiter.lock().await;
        limiter.check().map_err(|_| "Rate limit exceeded".to_string())
    }

    pub async fn get_current_rate(&self) -> u32 {
        *self.current_rate.lock().await
    }

    async fn maybe_end_burst(&self) {
        let mut bursting = self.is_bursting.lock().await;
        if *bursting {
            let burst_until = self.burst_until.lock().await;
            if Instant::now() >= *burst_until {
                *bursting = false;
                drop(burst_until);
                drop(bursting);
                // Transition from burst rate to normal rate
                let current = *self.current_rate.lock().await;
                let normal_rate = (current / 3).max(self.min_rate);
                self.set_rate(normal_rate).await;
            }
        }
    }

    pub async fn is_bursting(&self) -> bool {
        *self.is_bursting.lock().await
    }

    pub async fn stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            current_rate: *self.current_rate.lock().await,
            is_bursting: *self.is_bursting.lock().await,
            adjustments: *self.adjustment_count.lock().await,
        }
    }

    async fn set_rate(&self, new_rate: u32) {
        let clamped = new_rate.clamp(self.min_rate, self.max_rate);
        let mut current = self.current_rate.lock().await;
        if *current != clamped {
            *current = clamped;
            let quota = Quota::per_second(NonZeroU32::new(clamped.max(1)).unwrap());
            let new_limiter = Arc::new(GovernorLimiter::direct(quota));
            let mut limiter = self.limiter.lock().await;
            *limiter = new_limiter;
        }
    }

    pub async fn increase_rate(&self, factor: f32) {
        let current = *self.current_rate.lock().await;
        let new_rate = (current as f32 * factor) as u32;
        self.set_rate(new_rate).await;
        let mut count = self.adjustment_count.lock().await;
        *count += 1;
    }

    pub async fn decrease_rate(&self, factor: f32) {
        let current = *self.current_rate.lock().await;
        let new_rate = (current as f32 * factor) as u32;
        self.set_rate(new_rate).await;
        let mut count = self.adjustment_count.lock().await;
        *count += 1;
    }

    /// Adjust rate based on response time with damped oscillation
    pub async fn adjust_based_on_response_time(&self, avg_response_ms: u64) {
        let mut last_adj = self.last_adjustment.lock().await;
        if last_adj.elapsed() < self.adjustment_interval {
            return;
        }

        // More nuanced adjustment: aggressive increase when fast, gentle decrease when slow
        if avg_response_ms < 50 {
            self.increase_rate(1.3).await;
        } else if avg_response_ms < 100 {
            self.increase_rate(1.15).await;
        } else if avg_response_ms > 500 {
            self.decrease_rate(0.7).await;
        } else if avg_response_ms > 300 {
            self.decrease_rate(0.85).await;
        }

        *last_adj = Instant::now();
    }

    /// Adjust rate based on packet loss with exponential backoff on high loss
    pub async fn adjust_based_on_packet_loss(&self, loss_percent: f32) {
        if loss_percent > 10.0 {
            // Severe loss: aggressive backoff
            self.decrease_rate(0.5).await;
        } else if loss_percent > 5.0 {
            self.decrease_rate(0.7).await;
        } else if loss_percent < 1.0 {
            self.increase_rate(1.1).await;
        }
    }

    /// Get the burst rate for initial discovery
    pub fn burst_rate(&self) -> u32 {
        self.burst_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_creation() {
        let limiter = AdaptiveRateLimiter::new(1000, 100, 10000);
        assert_eq!(limiter.get_current_rate().await, 1000);
    }

    #[tokio::test]
    async fn test_increase_rate() {
        let limiter = AdaptiveRateLimiter::new(1000, 100, 10000);
        limiter.increase_rate(1.5).await;
        assert_eq!(limiter.get_current_rate().await, 1500);
    }

    #[tokio::test]
    async fn test_decrease_rate() {
        let limiter = AdaptiveRateLimiter::new(1000, 100, 10000);
        limiter.decrease_rate(0.5).await;
        assert_eq!(limiter.get_current_rate().await, 500);
    }

    #[tokio::test]
    async fn test_rate_bounds() {
        let limiter = AdaptiveRateLimiter::new(1000, 100, 10000);

        limiter.increase_rate(100.0).await;
        assert_eq!(limiter.get_current_rate().await, 10000);

        limiter.decrease_rate(0.01).await;
        assert_eq!(limiter.get_current_rate().await, 100);
    }

    #[tokio::test]
    async fn test_adjust_based_on_response_time() {
        let limiter = AdaptiveRateLimiter::new(1000, 100, 10000);

        limiter.adjust_based_on_response_time(50).await;
        tokio::time::sleep(Duration::from_secs(6)).await;
        limiter.adjust_based_on_response_time(50).await;
        assert!(limiter.get_current_rate().await > 1000);
    }

    #[tokio::test]
    async fn test_limiter_enforces_new_rate() {
        let limiter = AdaptiveRateLimiter::new(1000, 100, 100000);

        // Increase rate
        limiter.increase_rate(2.0).await;
        assert_eq!(limiter.get_current_rate().await, 2000);

        // The new limiter should allow 2000/sec
        // Rapid checks should not all fail
        let mut successes = 0;
        for _ in 0..10 {
            if limiter.check().await.is_ok() {
                successes += 1;
            }
        }
        assert!(successes > 0, "Limiter should allow requests at new rate");
    }

    #[tokio::test]
    async fn test_burst_mode() {
        let limiter = AdaptiveRateLimiter::with_burst(1000, 100, 10000, Duration::from_secs(2));

        // Should start at burst rate (3x initial, capped at max)
        let rate = limiter.get_current_rate().await;
        assert_eq!(rate, 3000);
        assert!(limiter.is_bursting().await);

        // After burst duration, should transition to normal rate
        tokio::time::sleep(Duration::from_secs(3)).await;
        limiter.check().await.ok(); // Trigger burst check
        assert!(!limiter.is_bursting().await);
    }

    #[tokio::test]
    async fn test_stats() {
        let limiter = AdaptiveRateLimiter::new(1000, 100, 10000);
        limiter.increase_rate(1.5).await;

        let stats = limiter.stats().await;
        assert_eq!(stats.current_rate, 1500);
        assert_eq!(stats.adjustments, 1);
        assert!(!stats.is_bursting);
    }

    #[tokio::test]
    async fn test_adjustment_count() {
        let limiter = AdaptiveRateLimiter::new(1000, 100, 10000);
        limiter.increase_rate(1.1).await;
        limiter.increase_rate(1.1).await;
        limiter.decrease_rate(0.9).await;

        let stats = limiter.stats().await;
        assert_eq!(stats.adjustments, 3);
    }
}
