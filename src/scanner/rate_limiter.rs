use governor::{Quota, RateLimiter as GovRateLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;

#[derive(Clone)]
pub struct RateLimiter {
    limiter: Arc<GovRateLimiter<governor::state::direct::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>,
}

impl RateLimiter {
    pub fn new(max_rate: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(max_rate).unwrap());
        let limiter = GovRateLimiter::direct(quota);
        
        Self {
            limiter: Arc::new(limiter),
        }
    }

    pub async fn wait(&self) {
        self.limiter.until_ready().await;
    }
}
