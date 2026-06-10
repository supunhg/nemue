// Adaptive rate limiting with burst mode for initial port discovery
use governor::{clock::DefaultClock, state::InMemoryState, Quota, RateLimiter as GovernorLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

type GovLimiter = GovernorLimiter<governor::state::direct::NotKeyed, InMemoryState, DefaultClock>;

#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub current_rate: u32,
    pub is_bursting: bool,
    pub adjustments: u64,
}

#[derive(Debug, Clone)]
pub struct GlobalRateLimiterStats {
    pub current_rate: u32,
    pub total_requests: u64,
    pub throttled_requests: u64,
}

#[derive(Debug, Clone)]
pub struct PerTargetRateLimiterStats {
    pub targets_tracked: usize,
    pub default_rate: u32,
}

#[derive(Debug, Clone)]
pub struct ApiRateLimiterStats {
    pub global_limit: u32,
    pub per_key_limit: u32,
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
    pub fn with_burst(
        initial_rate: u32,
        min_rate: u32,
        max_rate: u32,
        burst_duration: Duration,
    ) -> Self {
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
        limiter
            .check()
            .map_err(|_| "Rate limit exceeded".to_string())
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

/// Per-target rate limiter - limits scan rate per individual target
pub struct PerTargetRateLimiter {
    limiters: Arc<Mutex<std::collections::HashMap<String, Arc<GovLimiter>>>>,
    default_rate: u32,
}

impl PerTargetRateLimiter {
    pub fn new(default_rate: u32) -> Self {
        Self {
            limiters: Arc::new(Mutex::new(std::collections::HashMap::new())),
            default_rate,
        }
    }

    pub async fn check(&self, target: &str) -> Result<(), String> {
        let mut limiters = self.limiters.lock().await;
        let limiter = limiters
            .entry(target.to_string())
            .or_insert_with(|| {
                let quota = Quota::per_second(NonZeroU32::new(self.default_rate.max(1)).unwrap());
                Arc::new(GovernorLimiter::direct(quota))
            })
            .clone();
        drop(limiters);
        limiter
            .check()
            .map_err(|_| format!("Rate limit exceeded for target {}", target))
    }

    pub async fn set_target_rate(&self, target: &str, rate: u32) {
        let quota = Quota::per_second(NonZeroU32::new(rate.max(1)).unwrap());
        let limiter = Arc::new(GovernorLimiter::direct(quota));
        let mut limiters = self.limiters.lock().await;
        limiters.insert(target.to_string(), limiter);
    }

    pub async fn remove_target(&self, target: &str) {
        let mut limiters = self.limiters.lock().await;
        limiters.remove(target);
    }

    pub async fn stats(&self) -> PerTargetRateLimiterStats {
        let limiters = self.limiters.lock().await;
        PerTargetRateLimiterStats {
            targets_tracked: limiters.len(),
            default_rate: self.default_rate,
        }
    }
}

/// Global rate limiter - enforces a system-wide request cap
pub struct GlobalRateLimiter {
    limiter: Arc<GovLimiter>,
    total_requests: Arc<Mutex<u64>>,
    throttled_requests: Arc<Mutex<u64>>,
}

impl GlobalRateLimiter {
    pub fn new(max_rate: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(max_rate.max(1)).unwrap());
        Self {
            limiter: Arc::new(GovernorLimiter::direct(quota)),
            total_requests: Arc::new(Mutex::new(0)),
            throttled_requests: Arc::new(Mutex::new(0)),
        }
    }

    pub async fn check(&self) -> Result<(), String> {
        let mut total = self.total_requests.lock().await;
        *total += 1;
        drop(total);

        self.limiter.check().map_err(|_| {
            let throttled = self.throttled_requests.clone();
            tokio::spawn(async move {
                let mut t = throttled.lock().await;
                *t += 1;
            });
            "Global rate limit exceeded".to_string()
        })
    }

    pub async fn stats(&self) -> GlobalRateLimiterStats {
        let total = *self.total_requests.lock().await;
        let throttled = *self.throttled_requests.lock().await;
        GlobalRateLimiterStats {
            current_rate: 0,
            total_requests: total,
            throttled_requests: throttled,
        }
    }
}

/// API rate limiter - per-key and global limits for REST API
pub struct ApiRateLimiter {
    global: GlobalRateLimiter,
    per_key_limit: u32,
    window_secs: u64,
    key_timestamps: Arc<Mutex<std::collections::HashMap<String, Vec<Instant>>>>,
}

impl ApiRateLimiter {
    pub fn new(global_limit: u32, per_key_limit: u32, window_secs: u64) -> Self {
        Self {
            global: GlobalRateLimiter::new(global_limit),
            per_key_limit,
            window_secs,
            key_timestamps: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub async fn check(&self, api_key: &str) -> Result<(), String> {
        self.global.check().await?;

        let mut timestamps = self.key_timestamps.lock().await;
        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);
        let cutoff = now - window;

        let entries = timestamps.entry(api_key.to_string()).or_default();
        entries.retain(|t| *t > cutoff);

        if entries.len() as u32 >= self.per_key_limit {
            return Err("API key rate limit exceeded".to_string());
        }

        entries.push(now);
        Ok(())
    }

    pub async fn remaining(&self, api_key: &str) -> u32 {
        let timestamps = self.key_timestamps.lock().await;
        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);
        let cutoff = now - window;

        match timestamps.get(api_key) {
            Some(entries) => {
                let count = entries.iter().filter(|t| **t > cutoff).count() as u32;
                self.per_key_limit.saturating_sub(count)
            }
            None => self.per_key_limit,
        }
    }

    pub async fn stats(&self) -> ApiRateLimiterStats {
        ApiRateLimiterStats {
            global_limit: 0,
            per_key_limit: self.per_key_limit,
        }
    }
}

/// Combined rate limiter that enforces per-target, global, and adaptive limits
pub struct CombinedRateLimiter {
    adaptive: AdaptiveRateLimiter,
    per_target: PerTargetRateLimiter,
    global: GlobalRateLimiter,
}

impl CombinedRateLimiter {
    pub fn new(
        initial_rate: u32,
        min_rate: u32,
        max_rate: u32,
        global_max: u32,
        per_target_rate: u32,
    ) -> Self {
        Self {
            adaptive: AdaptiveRateLimiter::new(initial_rate, min_rate, max_rate),
            per_target: PerTargetRateLimiter::new(per_target_rate),
            global: GlobalRateLimiter::new(global_max),
        }
    }

    pub async fn check(&self, target: &str) -> Result<(), String> {
        self.global.check().await?;
        self.per_target.check(target).await?;
        self.adaptive.check().await?;
        Ok(())
    }

    pub async fn adjust_for_response_time(&self, avg_ms: u64) {
        self.adaptive.adjust_based_on_response_time(avg_ms).await;
    }

    pub async fn adjust_for_packet_loss(&self, loss_pct: f32) {
        self.adaptive.adjust_based_on_packet_loss(loss_pct).await;
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

        limiter.increase_rate(2.0).await;
        assert_eq!(limiter.get_current_rate().await, 2000);

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

        let rate = limiter.get_current_rate().await;
        assert_eq!(rate, 3000);
        assert!(limiter.is_bursting().await);

        tokio::time::sleep(Duration::from_secs(3)).await;
        limiter.check().await.ok();
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

    #[tokio::test]
    async fn test_per_target_limiter() {
        let limiter = PerTargetRateLimiter::new(10);
        assert!(limiter.check("192.168.1.1").await.is_ok());
        assert!(limiter.check("192.168.1.2").await.is_ok());

        let stats = limiter.stats().await;
        assert_eq!(stats.targets_tracked, 2);
    }

    #[tokio::test]
    async fn test_per_target_set_custom_rate() {
        let limiter = PerTargetRateLimiter::new(10);
        limiter.set_target_rate("fast-target", 100).await;

        let stats = limiter.stats().await;
        assert_eq!(stats.targets_tracked, 1);
    }

    #[tokio::test]
    async fn test_global_limiter() {
        let limiter = GlobalRateLimiter::new(1000);
        assert!(limiter.check().await.is_ok());

        let stats = limiter.stats().await;
        assert_eq!(stats.total_requests, 1);
    }

    #[tokio::test]
    async fn test_api_rate_limiter() {
        let limiter = ApiRateLimiter::new(1000, 5, 60);
        assert!(limiter.check("key1").await.is_ok());
        assert!(limiter.check("key1").await.is_ok());

        let remaining = limiter.remaining("key1").await;
        assert_eq!(remaining, 3);
    }

    #[tokio::test]
    async fn test_api_rate_limiter_independent_keys() {
        let limiter = ApiRateLimiter::new(1000, 2, 60);
        assert!(limiter.check("key1").await.is_ok());
        assert!(limiter.check("key1").await.is_ok());
        assert!(limiter.check("key1").await.is_err());

        assert!(limiter.check("key2").await.is_ok());
        assert_eq!(limiter.remaining("key2").await, 1);
    }

    #[tokio::test]
    async fn test_combined_limiter() {
        let limiter = CombinedRateLimiter::new(1000, 100, 10000, 5000, 100);
        assert!(limiter.check("192.168.1.1").await.is_ok());
    }
}
