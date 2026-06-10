use nemue::performance::{BoundedQueue, BufferPool, LockFreeQueue, MetricsCollector};
use nemue::scanner::cache::{CacheConfig, CacheKey, ScanCache};
use std::time::Duration;

#[tokio::test]
async fn test_buffer_pool_reuse() {
    let pool = BufferPool::new(1500, 10, 100);

    let mut buffers = Vec::new();
    for _ in 0..5 {
        let buf = BufferPool::acquire(pool.clone()).await;
        buffers.push(buf);
    }

    for buf in buffers {
        drop(buf);
    }

    let pool_guard = pool.lock().await;
    let stats = pool_guard.stats();
    assert!(
        stats.available_buffers > 0,
        "Buffers should be returned to pool"
    );
}

#[test]
fn test_lockfree_queue_memory_efficiency() {
    let queue = LockFreeQueue::new();

    for i in 0..10000u64 {
        queue.push(i);
    }

    assert_eq!(queue.len(), 10000);

    for _ in 0..10000 {
        queue.pop();
    }

    assert!(queue.is_empty());
}

#[test]
fn test_bounded_queue_memory_limit() {
    let capacity = 100;
    let queue = BoundedQueue::new(capacity);

    for i in 0..1000u64 {
        let _ = queue.push(i);
    }

    assert!(queue.len() <= capacity);
}

#[tokio::test]
async fn test_cache_memory_eviction() {
    let max_entries = 50;
    let cache = ScanCache::new(CacheConfig {
        max_entries,
        default_ttl: Duration::from_secs(3600),
        enable_stats: true,
    });

    for i in 0..100 {
        let key = CacheKey::new(&format!("host-{}", i), "80", "syn");
        let results = nemue::scanner::ScanResults {
            scan_start: chrono::Utc::now(),
            scan_end: chrono::Utc::now(),
            target_count: 1,
            port_count: 1,
            results: vec![nemue::scanner::ScanResult {
                target: "192.168.1.1".parse().unwrap(),
                port: 80,
                state: nemue::scanner::PortState::Open,
                protocol: nemue::scanner::Protocol::TCP,
                service: Some("http".to_string()),
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: chrono::Utc::now(),
            }],
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        };
        cache.put(key, results).await;
    }

    assert!(cache.len().await <= max_entries + 1);
}

#[tokio::test]
async fn test_metrics_collector_memory() {
    let metrics = MetricsCollector::new();

    for _ in 0..100000 {
        metrics.increment_packets_sent(1);
        metrics.add_bytes_sent(1500);
    }

    let snapshot = metrics.snapshot().await;
    assert_eq!(snapshot.packets_sent, 100000);
    assert_eq!(snapshot.bytes_sent, 150000000);
}

#[tokio::test]
async fn test_cache_stats_accuracy() {
    let cache = ScanCache::with_defaults();

    for i in 0..10 {
        let key = CacheKey::new(&format!("host-{}", i), "80", "syn");
        let results = nemue::scanner::ScanResults {
            scan_start: chrono::Utc::now(),
            scan_end: chrono::Utc::now(),
            target_count: 1,
            port_count: 1,
            results: vec![nemue::scanner::ScanResult {
                target: "192.168.1.1".parse().unwrap(),
                port: 80,
                state: nemue::scanner::PortState::Open,
                protocol: nemue::scanner::Protocol::TCP,
                service: Some("http".to_string()),
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: chrono::Utc::now(),
            }],
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        };
        cache.put(key, results).await;
    }

    for i in 0..10 {
        let key = CacheKey::new(&format!("host-{}", i), "80", "syn");
        cache.get(&key).await;
    }

    for i in 10..15 {
        let key = CacheKey::new(&format!("host-{}", i), "80", "syn");
        cache.get(&key).await;
    }

    let stats = cache.stats().await;
    assert_eq!(stats.hits, 10);
    assert_eq!(stats.misses, 5);
    assert_eq!(stats.insertions, 10);
}
