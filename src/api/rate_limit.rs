use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Sliding window rate limit configuration per endpoint
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window: Duration,
}

impl RateLimitConfig {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            max_requests,
            window,
        }
    }

    pub fn per_second(max: u32) -> Self {
        Self::new(max, Duration::from_secs(1))
    }

    pub fn per_minute(max: u32) -> Self {
        Self::new(max, Duration::from_secs(60))
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self::per_minute(60)
    }
}

/// Rate limit info returned in response headers
#[derive(Debug, Clone)]
pub struct RateLimitHeaders {
    pub limit: u32,
    pub remaining: u32,
    pub reset_secs: u64,
    pub retry_after: Option<u64>,
}

/// Sliding window entry tracking request timestamps
struct SlidingWindow {
    timestamps: Vec<Instant>,
}

impl SlidingWindow {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
        }
    }

    fn prune(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.timestamps.retain(|t| *t > cutoff);
    }

    fn count(&mut self, window: Duration) -> u32 {
        self.prune(window);
        self.timestamps.len() as u32
    }

    fn record(&mut self) {
        self.timestamps.push(Instant::now());
    }

    fn oldest(&self) -> Option<Instant> {
        self.timestamps.first().copied()
    }
}

/// Per-client sliding window rate limiter for the REST API
pub struct RateLimiter {
    default_config: RateLimitConfig,
    endpoint_configs: HashMap<String, RateLimitConfig>,
    clients: Arc<RwLock<HashMap<String, SlidingWindow>>>,
}

impl RateLimiter {
    pub fn new(default_config: RateLimitConfig) -> Self {
        Self {
            default_config,
            endpoint_configs: HashMap::new(),
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set a custom rate limit for a specific endpoint path
    pub fn with_endpoint_limit(mut self, path: &str, config: RateLimitConfig) -> Self {
        self.endpoint_configs.insert(path.to_string(), config);
        self
    }

    fn config_for_endpoint(&self, endpoint: &str) -> &RateLimitConfig {
        self.endpoint_configs
            .get(endpoint)
            .unwrap_or(&self.default_config)
    }

    /// Check whether a request from `client_id` to `endpoint` is allowed.
    /// Returns the rate limit headers to include in the response.
    pub async fn check(
        &self,
        client_id: &str,
        endpoint: &str,
    ) -> Result<RateLimitHeaders, RateLimitHeaders> {
        let config = self.config_for_endpoint(endpoint);
        let key = format!("{}:{}", client_id, endpoint);

        let mut clients = self.clients.write().await;
        let window = clients.entry(key).or_insert_with(SlidingWindow::new);

        let current = window.count(config.window);
        let reset_secs = window
            .oldest()
            .map(|oldest| {
                let elapsed = oldest.elapsed();
                if elapsed < config.window {
                    (config.window - elapsed).as_secs().max(1)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        if current >= config.max_requests {
            Err(RateLimitHeaders {
                limit: config.max_requests,
                remaining: 0,
                reset_secs,
                retry_after: Some(reset_secs),
            })
        } else {
            window.record();
            let remaining = config.max_requests - current - 1;
            Ok(RateLimitHeaders {
                limit: config.max_requests,
                remaining,
                reset_secs,
                retry_after: None,
            })
        }
    }

    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }

    pub async fn reset_client(&self, client_id: &str) {
        let mut clients = self.clients.write().await;
        clients.retain(|k, _| !k.starts_with(client_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_allows_within_limit() {
        let limiter = RateLimiter::new(RateLimitConfig::new(3, Duration::from_secs(1)));
        assert!(limiter.check("c1", "/api/v1/scans").await.is_ok());
        assert!(limiter.check("c1", "/api/v1/scans").await.is_ok());
        assert!(limiter.check("c1", "/api/v1/scans").await.is_ok());
    }

    #[tokio::test]
    async fn test_blocks_over_limit() {
        let limiter = RateLimiter::new(RateLimitConfig::new(2, Duration::from_secs(60)));
        assert!(limiter.check("c1", "/api/v1/scans").await.is_ok());
        assert!(limiter.check("c1", "/api/v1/scans").await.is_ok());
        let result = limiter.check("c1", "/api/v1/scans").await;
        assert!(result.is_err());
        let headers = result.unwrap_err();
        assert_eq!(headers.remaining, 0);
        assert!(headers.retry_after.is_some());
    }

    #[tokio::test]
    async fn test_independent_clients() {
        let limiter = RateLimiter::new(RateLimitConfig::new(1, Duration::from_secs(60)));
        assert!(limiter.check("c1", "/api/v1/scans").await.is_ok());
        assert!(limiter.check("c2", "/api/v1/scans").await.is_ok());
        assert!(limiter.check("c1", "/api/v1/scans").await.is_err());
    }

    #[tokio::test]
    async fn test_independent_endpoints() {
        let limiter = RateLimiter::new(RateLimitConfig::new(1, Duration::from_secs(60)));
        assert!(limiter.check("c1", "/api/v1/scans").await.is_ok());
        assert!(limiter.check("c1", "/api/v1/webhooks").await.is_ok());
    }

    #[tokio::test]
    async fn test_custom_endpoint_limit() {
        let limiter = RateLimiter::new(RateLimitConfig::per_minute(100)).with_endpoint_limit(
            "/api/v1/scans",
            RateLimitConfig::new(1, Duration::from_secs(60)),
        );

        assert!(limiter.check("c1", "/api/v1/scans").await.is_ok());
        assert!(limiter.check("c1", "/api/v1/scans").await.is_err());
        assert!(limiter.check("c1", "/api/v1/webhooks").await.is_ok());
    }

    #[tokio::test]
    async fn test_sliding_window_recovery() {
        let limiter = RateLimiter::new(RateLimitConfig::new(2, Duration::from_millis(100)));
        assert!(limiter.check("c1", "/ep").await.is_ok());
        assert!(limiter.check("c1", "/ep").await.is_ok());
        assert!(limiter.check("c1", "/ep").await.is_err());

        tokio::time::sleep(Duration::from_millis(110)).await;
        assert!(limiter.check("c1", "/ep").await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limit_headers() {
        let limiter = RateLimiter::new(RateLimitConfig::new(5, Duration::from_secs(60)));
        let headers = limiter.check("c1", "/ep").await.unwrap();
        assert_eq!(headers.limit, 5);
        assert_eq!(headers.remaining, 4);
        assert!(headers.retry_after.is_none());
    }

    #[tokio::test]
    async fn test_reset_client() {
        let limiter = RateLimiter::new(RateLimitConfig::new(1, Duration::from_secs(60)));
        assert!(limiter.check("c1", "/ep").await.is_ok());
        assert!(limiter.check("c1", "/ep").await.is_err());
        limiter.reset_client("c1").await;
        assert!(limiter.check("c1", "/ep").await.is_ok());
    }
}
