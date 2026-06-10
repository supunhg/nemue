// Bandwidth throttling and QoS management
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::sleep;

pub struct BandwidthThrottle {
    max_bytes_per_sec: Arc<Mutex<u64>>,
    bytes_sent: Arc<Mutex<u64>>,
    window_start: Arc<Mutex<Instant>>,
}

impl BandwidthThrottle {
    pub fn new(max_bytes_per_sec: u64) -> Self {
        Self {
            max_bytes_per_sec: Arc::new(Mutex::new(max_bytes_per_sec)),
            bytes_sent: Arc::new(Mutex::new(0)),
            window_start: Arc::new(Mutex::new(Instant::now())),
        }
    }

    pub async fn acquire(&self, bytes: u64) {
        loop {
            let mut window_start = self.window_start.lock().await;
            let elapsed = window_start.elapsed();

            // Reset window every second
            if elapsed >= Duration::from_secs(1) {
                *window_start = Instant::now();
                let mut bytes_sent = self.bytes_sent.lock().await;
                *bytes_sent = 0;
            }
            drop(window_start);

            let mut bytes_sent = self.bytes_sent.lock().await;
            let max_bytes = *self.max_bytes_per_sec.lock().await;

            if *bytes_sent + bytes <= max_bytes {
                *bytes_sent += bytes;
                break;
            }

            // Wait before retrying
            drop(bytes_sent);
            sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn set_limit(&self, max_bytes_per_sec: u64) {
        let mut limit = self.max_bytes_per_sec.lock().await;
        *limit = max_bytes_per_sec;
    }

    pub async fn get_limit(&self) -> u64 {
        *self.max_bytes_per_sec.lock().await
    }

    pub async fn bytes_sent(&self) -> u64 {
        *self.bytes_sent.lock().await
    }
}

impl Clone for BandwidthThrottle {
    fn clone(&self) -> Self {
        Self {
            max_bytes_per_sec: Arc::clone(&self.max_bytes_per_sec),
            bytes_sent: Arc::clone(&self.bytes_sent),
            window_start: Arc::clone(&self.window_start),
        }
    }
}

/// QoS traffic shaper with priority queues
pub struct TrafficShaper {
    high_priority: Arc<Mutex<Vec<Vec<u8>>>>,
    normal_priority: Arc<Mutex<Vec<Vec<u8>>>>,
    low_priority: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    High,
    Normal,
    Low,
}

impl Default for TrafficShaper {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficShaper {
    pub fn new() -> Self {
        Self {
            high_priority: Arc::new(Mutex::new(Vec::new())),
            normal_priority: Arc::new(Mutex::new(Vec::new())),
            low_priority: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn enqueue(&self, data: Vec<u8>, priority: Priority) {
        match priority {
            Priority::High => {
                let mut queue = self.high_priority.lock().await;
                queue.push(data);
            }
            Priority::Normal => {
                let mut queue = self.normal_priority.lock().await;
                queue.push(data);
            }
            Priority::Low => {
                let mut queue = self.low_priority.lock().await;
                queue.push(data);
            }
        }
    }

    pub async fn dequeue(&self) -> Option<Vec<u8>> {
        // Check high priority first
        {
            let mut queue = self.high_priority.lock().await;
            if !queue.is_empty() {
                return Some(queue.remove(0));
            }
        }

        // Then normal priority
        {
            let mut queue = self.normal_priority.lock().await;
            if !queue.is_empty() {
                return Some(queue.remove(0));
            }
        }

        // Finally low priority
        {
            let mut queue = self.low_priority.lock().await;
            if !queue.is_empty() {
                return Some(queue.remove(0));
            }
        }

        None
    }

    pub async fn queue_lengths(&self) -> (usize, usize, usize) {
        let high = self.high_priority.lock().await.len();
        let normal = self.normal_priority.lock().await.len();
        let low = self.low_priority.lock().await.len();
        (high, normal, low)
    }

    pub async fn total_queued(&self) -> usize {
        let (high, normal, low) = self.queue_lengths().await;
        high + normal + low
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bandwidth_throttle_basic() {
        let throttle = BandwidthThrottle::new(1000);

        throttle.acquire(500).await;
        assert_eq!(throttle.bytes_sent().await, 500);

        throttle.acquire(400).await;
        assert_eq!(throttle.bytes_sent().await, 900);
    }

    #[tokio::test]
    async fn test_bandwidth_throttle_limit() {
        let throttle = BandwidthThrottle::new(1000);

        assert_eq!(throttle.get_limit().await, 1000);

        throttle.set_limit(2000).await;
        assert_eq!(throttle.get_limit().await, 2000);
    }

    #[tokio::test]
    async fn test_bandwidth_throttle_window_reset() {
        let throttle = BandwidthThrottle::new(1000);

        throttle.acquire(1000).await;
        assert_eq!(throttle.bytes_sent().await, 1000);

        tokio::time::sleep(Duration::from_millis(1100)).await;

        throttle.acquire(500).await;
        assert_eq!(throttle.bytes_sent().await, 500);
    }

    #[tokio::test]
    async fn test_traffic_shaper_priority() {
        let shaper = TrafficShaper::new();

        shaper.enqueue(vec![1], Priority::Low).await;
        shaper.enqueue(vec![2], Priority::High).await;
        shaper.enqueue(vec![3], Priority::Normal).await;

        // Should dequeue in priority order
        assert_eq!(shaper.dequeue().await, Some(vec![2])); // High
        assert_eq!(shaper.dequeue().await, Some(vec![3])); // Normal
        assert_eq!(shaper.dequeue().await, Some(vec![1])); // Low
        assert_eq!(shaper.dequeue().await, None);
    }

    #[tokio::test]
    async fn test_traffic_shaper_queue_lengths() {
        let shaper = TrafficShaper::new();

        shaper.enqueue(vec![1], Priority::High).await;
        shaper.enqueue(vec![2], Priority::High).await;
        shaper.enqueue(vec![3], Priority::Normal).await;
        shaper.enqueue(vec![4], Priority::Low).await;

        let (high, normal, low) = shaper.queue_lengths().await;
        assert_eq!(high, 2);
        assert_eq!(normal, 1);
        assert_eq!(low, 1);
        assert_eq!(shaper.total_queued().await, 4);
    }

    #[tokio::test]
    async fn test_traffic_shaper_empty() {
        let shaper = TrafficShaper::new();
        assert_eq!(shaper.dequeue().await, None);
        assert_eq!(shaper.total_queued().await, 0);
    }
}
