// Performance monitoring and metrics collection
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

/// Real-time performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub scan_rate: f64, // packets per second
    pub active_connections: usize,
    pub memory_usage_mb: usize,
    pub cpu_usage_percent: f32,
    pub uptime_seconds: u64,
    pub errors_count: u64,
}

/// Thread-safe metrics collector
pub struct MetricsCollector {
    packets_sent: Arc<AtomicU64>,
    packets_received: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    active_connections: Arc<AtomicUsize>,
    errors: Arc<AtomicU64>,
    start_time: Instant,
    last_snapshot: Arc<RwLock<PerformanceMetrics>>,
    // Windowed rate tracking
    window_packets: Arc<AtomicU64>,
    window_start: Arc<RwLock<Instant>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            errors: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
            last_snapshot: Arc::new(RwLock::new(PerformanceMetrics {
                packets_sent: 0,
                packets_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
                scan_rate: 0.0,
                active_connections: 0,
                memory_usage_mb: 0,
                cpu_usage_percent: 0.0,
                uptime_seconds: 0,
                errors_count: 0,
            })),
            window_packets: Arc::new(AtomicU64::new(0)),
            window_start: Arc::new(RwLock::new(Instant::now())),
        }
    }

    pub fn increment_packets_sent(&self, count: u64) {
        self.packets_sent.fetch_add(count, Ordering::Relaxed);
        self.window_packets.fetch_add(count, Ordering::Relaxed);
    }

    pub fn increment_packets_received(&self, count: u64) {
        self.packets_received.fetch_add(count, Ordering::Relaxed);
    }

    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn increment_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_active_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn increment_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get packets per second over a sliding 1-second window
    pub async fn packets_per_second(&self) -> f64 {
        let mut window_start = self.window_start.write().await;
        let elapsed = window_start.elapsed().as_secs_f64();

        if elapsed >= 1.0 {
            let packets = self.window_packets.swap(0, Ordering::Relaxed);
            let pps = packets as f64 / elapsed;
            *window_start = Instant::now();
            pps
        } else {
            // Estimate based on current window
            let packets = self.window_packets.load(Ordering::Relaxed);
            if elapsed > 0.01 {
                packets as f64 / elapsed
            } else {
                0.0
            }
        }
    }

    pub async fn snapshot(&self) -> PerformanceMetrics {
        let uptime = self.start_time.elapsed().as_secs();
        let packets = self.packets_sent.load(Ordering::Relaxed);
        let scan_rate = if uptime > 0 {
            packets as f64 / uptime as f64
        } else {
            0.0
        };

        let metrics = PerformanceMetrics {
            packets_sent: packets,
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            scan_rate,
            active_connections: self.active_connections.load(Ordering::Relaxed),
            memory_usage_mb: self.get_memory_usage(),
            cpu_usage_percent: self.get_cpu_usage(),
            uptime_seconds: uptime,
            errors_count: self.errors.load(Ordering::Relaxed),
        };

        *self.last_snapshot.write().await = metrics.clone();
        metrics
    }

    pub async fn get_last_snapshot(&self) -> PerformanceMetrics {
        self.last_snapshot.read().await.clone()
    }

    fn get_memory_usage(&self) -> usize {
        // Linux: read RSS from /proc/self/status
        #[cfg(target_os = "linux")]
        {
            if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("VmRSS:") {
                        if let Some(kb_str) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = kb_str.parse::<usize>() {
                                return kb / 1024; // Convert KB to MB
                            }
                        }
                    }
                }
            }
            0
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }

    fn get_cpu_usage(&self) -> f32 {
        // Simplified - would use procfs or similar in production
        0.0
    }

    pub fn reset(&self) {
        self.packets_sent.store(0, Ordering::Relaxed);
        self.packets_received.store(0, Ordering::Relaxed);
        self.bytes_sent.store(0, Ordering::Relaxed);
        self.bytes_received.store(0, Ordering::Relaxed);
        self.errors.store(0, Ordering::Relaxed);
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.packets_sent.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_increment_packets() {
        let collector = MetricsCollector::new();
        collector.increment_packets_sent(10);
        collector.increment_packets_sent(5);
        assert_eq!(collector.packets_sent.load(Ordering::Relaxed), 15);
    }

    #[test]
    fn test_bytes_tracking() {
        let collector = MetricsCollector::new();
        collector.add_bytes_sent(1024);
        collector.add_bytes_received(2048);
        assert_eq!(collector.bytes_sent.load(Ordering::Relaxed), 1024);
        assert_eq!(collector.bytes_received.load(Ordering::Relaxed), 2048);
    }

    #[test]
    fn test_connection_tracking() {
        let collector = MetricsCollector::new();
        collector.increment_active_connections();
        collector.increment_active_connections();
        assert_eq!(collector.active_connections.load(Ordering::Relaxed), 2);
        collector.decrement_active_connections();
        assert_eq!(collector.active_connections.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_snapshot() {
        let collector = MetricsCollector::new();
        collector.increment_packets_sent(100);
        collector.add_bytes_sent(4096);

        let metrics = collector.snapshot().await;
        assert_eq!(metrics.packets_sent, 100);
        assert_eq!(metrics.bytes_sent, 4096);
    }

    #[test]
    fn test_reset() {
        let collector = MetricsCollector::new();
        collector.increment_packets_sent(100);
        collector.increment_errors();
        collector.reset();
        assert_eq!(collector.packets_sent.load(Ordering::Relaxed), 0);
        assert_eq!(collector.errors.load(Ordering::Relaxed), 0);
    }
}
