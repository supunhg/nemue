// Adaptive rate limiting based on network conditions
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::Mutex;
use governor::{Quota, RateLimiter as GovernorLimiter, clock::DefaultClock, state::InMemoryState};

/// Adaptive rate limiter that adjusts based on network conditions
pub struct AdaptiveRateLimiter {
    current_rate: Arc<Mutex<u32>>,
    min_rate: u32,
    max_rate: u32,
    limiter: Arc<GovernorLimiter<governor::state::direct::NotKeyed, InMemoryState, DefaultClock>>,
    last_adjustment: Arc<Mutex<Instant>>,
    adjustment_interval: Duration,
}

impl AdaptiveRateLimiter {
    pub fn new(initial_rate: u32, min_rate: u32, max_rate: u32) -> Self {
        let quota = Quota::per_second(std::num::NonZeroU32::new(initial_rate).unwrap());
        let limiter = Arc::new(GovernorLimiter::direct(quota));
        
        Self {
            current_rate: Arc::new(Mutex::new(initial_rate)),
            min_rate,
            max_rate,
            limiter,
            last_adjustment: Arc::new(Mutex::new(Instant::now())),
            adjustment_interval: Duration::from_secs(5),
        }
    }

    pub async fn check(&self) -> Result<(), String> {
        self.limiter.check().map_err(|_| "Rate limit exceeded".to_string())
    }

    pub async fn get_current_rate(&self) -> u32 {
        *self.current_rate.lock().await
    }

    pub async fn increase_rate(&self, factor: f32) {
        let mut current = self.current_rate.lock().await;
        let new_rate = ((*current as f32) * factor) as u32;
        *current = new_rate.min(self.max_rate);
    }

    pub async fn decrease_rate(&self, factor: f32) {
        let mut current = self.current_rate.lock().await;
        let new_rate = ((*current as f32) * factor) as u32;
        *current = new_rate.max(self.min_rate);
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
        
        // Test max bound
        limiter.increase_rate(100.0).await;
        assert_eq!(limiter.get_current_rate().await, 10000);
        
        // Test min bound
        limiter.decrease_rate(0.01).await;
        assert_eq!(limiter.get_current_rate().await, 100);
    }

    #[tokio::test]
    async fn test_adjust_based_on_response_time() {
        let limiter = AdaptiveRateLimiter::new(1000, 100, 10000);
        
        // Fast response should increase rate
        limiter.adjust_based_on_response_time(50).await;
        tokio::time::sleep(Duration::from_secs(6)).await;
        limiter.adjust_based_on_response_time(50).await;
        assert!(limiter.get_current_rate().await > 1000);
    }
}
