// CPU affinity and resource management
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[allow(dead_code)]
pub struct ResourceManager {
    total_workers: usize,
    active_workers: Arc<AtomicUsize>,
    max_workers: usize,
    min_workers: usize,
}

impl ResourceManager {
    pub fn new(min_workers: usize, max_workers: usize) -> Self {
        let initial = min_workers.max(1);
        Self {
            total_workers: initial,
            active_workers: Arc::new(AtomicUsize::new(initial)),
            max_workers,
            min_workers,
        }
    }

    pub fn scale_up(&self) -> usize {
        let current = self.active_workers.load(Ordering::Relaxed);
        if current < self.max_workers {
            let new_count = (current * 2).min(self.max_workers);
            self.active_workers.store(new_count, Ordering::Relaxed);
            new_count
        } else {
            current
        }
    }

    pub fn scale_down(&self) -> usize {
        let current = self.active_workers.load(Ordering::Relaxed);
        if current > self.min_workers {
            let new_count = (current / 2).max(self.min_workers);
            self.active_workers.store(new_count, Ordering::Relaxed);
            new_count
        } else {
            current
        }
    }

    pub fn active_workers(&self) -> usize {
        self.active_workers.load(Ordering::Relaxed)
    }

    pub fn set_workers(&self, count: usize) {
        let clamped = count.clamp(self.min_workers, self.max_workers);
        self.active_workers.store(clamped, Ordering::Relaxed);
    }

    pub fn min_workers(&self) -> usize {
        self.min_workers
    }

    pub fn max_workers(&self) -> usize {
        self.max_workers
    }

    pub fn auto_scale(&self, load_percent: f64) {
        if load_percent > 80.0 {
            self.scale_up();
        } else if load_percent < 20.0 {
            self.scale_down();
        }
    }
}

/// Retry strategy with exponential backoff
pub struct RetryStrategy {
    max_attempts: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
}

impl RetryStrategy {
    pub fn new(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            base_delay_ms: 100,
            max_delay_ms: 30_000,
        }
    }

    pub fn with_delays(max_attempts: u32, base_delay_ms: u64, max_delay_ms: u64) -> Self {
        Self {
            max_attempts,
            base_delay_ms,
            max_delay_ms,
        }
    }

    pub async fn execute<F, T, E>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> Result<T, E>,
    {
        let mut attempt = 0;
        loop {
            match operation() {
                Ok(result) => return Ok(result),
                Err(e) => {
                    attempt += 1;
                    if attempt >= self.max_attempts {
                        return Err(e);
                    }
                    
                    let delay = self.calculate_delay(attempt);
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    fn calculate_delay(&self, attempt: u32) -> std::time::Duration {
        let delay_ms = (self.base_delay_ms * 2u64.pow(attempt - 1))
            .min(self.max_delay_ms);
        std::time::Duration::from_millis(delay_ms)
    }

    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_manager_creation() {
        let manager = ResourceManager::new(2, 8);
        assert_eq!(manager.active_workers(), 2);
        assert_eq!(manager.min_workers(), 2);
        assert_eq!(manager.max_workers(), 8);
    }

    #[test]
    fn test_resource_manager_scale_up() {
        let manager = ResourceManager::new(2, 8);
        
        let count = manager.scale_up();
        assert_eq!(count, 4);
        
        let count = manager.scale_up();
        assert_eq!(count, 8);
        
        // Should not exceed max
        let count = manager.scale_up();
        assert_eq!(count, 8);
    }

    #[test]
    fn test_resource_manager_scale_down() {
        let manager = ResourceManager::new(2, 8);
        manager.set_workers(8);
        
        let count = manager.scale_down();
        assert_eq!(count, 4);
        
        let count = manager.scale_down();
        assert_eq!(count, 2);
        
        // Should not go below min
        let count = manager.scale_down();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_resource_manager_auto_scale() {
        let manager = ResourceManager::new(2, 8);
        
        // High load should scale up
        manager.auto_scale(85.0);
        assert_eq!(manager.active_workers(), 4);
        
        // Low load should scale down
        manager.auto_scale(15.0);
        assert_eq!(manager.active_workers(), 2);
    }

    #[test]
    fn test_retry_strategy_creation() {
        let strategy = RetryStrategy::new(5);
        assert_eq!(strategy.max_attempts(), 5);
        
        let strategy = RetryStrategy::with_delays(3, 50, 5000);
        assert_eq!(strategy.max_attempts(), 3);
    }

    #[tokio::test]
    async fn test_retry_strategy_success() {
        let strategy = RetryStrategy::new(3);
        let result = strategy.execute(|| Ok::<i32, String>(42)).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn test_retry_strategy_eventual_success() {
        let strategy = RetryStrategy::with_delays(3, 10, 100);
        let mut attempts = 0;
        
        let result = strategy.execute(|| {
            attempts += 1;
            if attempts < 3 {
                Err("not yet")
            } else {
                Ok(42)
            }
        }).await;
        
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn test_retry_strategy_max_attempts() {
        let strategy = RetryStrategy::with_delays(2, 10, 100);
        let mut attempts = 0;
        
        let result = strategy.execute(|| {
            attempts += 1;
            Err::<i32, &str>("always fails")
        }).await;
        
        assert!(result.is_err());
        assert_eq!(attempts, 2);
    }

    #[test]
    fn test_retry_delay_calculation() {
        let strategy = RetryStrategy::with_delays(5, 100, 5000);
        
        assert_eq!(strategy.calculate_delay(1), std::time::Duration::from_millis(100));
        assert_eq!(strategy.calculate_delay(2), std::time::Duration::from_millis(200));
        assert_eq!(strategy.calculate_delay(3), std::time::Duration::from_millis(400));
        assert_eq!(strategy.calculate_delay(10), std::time::Duration::from_millis(5000)); // Capped
    }
}
