// Adaptive rate limiting based on network conditions
use std::num::NonZeroU32;
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::Mutex;
use governor::{Quota, RateLimiter as GovernorLimiter, clock::DefaultClock, state::InMemoryState};

type GovLimiter = GovernorLimiter<governor::state::direct::NotKeyed, InMemoryState, DefaultClock>;

/// Adaptive rate limiter that adjusts based on network conditions
pub struct AdaptiveRateLimiter {
    current_rate: Arc<Mutex<u32>>,
    min_rate: u32,
    max_rate: u32,
    limiter: Arc<Mutex<Arc<GovLimiter>>>,
    last_adjustment: Arc<Mutex<Instant>>,
    adjustment_interval: Duration,
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
        }
    }

    pub async fn check(&self) -> Result<(), String> {
        let limiter = self.limiter.lock().await;
        limiter.check().map_err(|_| "Rate limit exceeded".to_string())
    }

    pub async fn get_current_rate(&self) -> u32 {
        *self.current_rate.lock().await
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
    }

    pub async fn decrease_rate(&self, factor: f32) {
        let current = *self.current_rate.lock().await;
        let new_rate = (current as f32 * factor) as u32;
        self.set_rate(new_rate).await;
    }

    pub async fn adjust_based_on_response_time(&self, avg_response_ms: u64) {
        let mut last_adj = self.last_adjustment.lock().await;
        if last_adj.elapsed() < self.adjustment_interval {
            return;
        }

        if avg_response_ms < 100 {
            self.increase_rate(1.2).await;
        } else if avg_response_ms > 500 {
            self.decrease_rate(0.8).await;
        }

        *last_adj = Instant::now();
    }

    pub async fn adjust_based_on_packet_loss(&self, loss_percent: f32) {
        if loss_percent > 5.0 {
            self.decrease_rate(0.7).await;
        } else if loss_percent < 1.0 {
            self.increase_rate(1.1).await;
        }
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
}
