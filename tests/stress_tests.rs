use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use nemue::api::state::AppState;
use nemue::api::models::*;
use nemue::scanner::{PortParser, TargetParser};
use nemue::performance::{LockFreeQueue, BoundedQueue, AtomicFlag, MetricsCollector};

#[tokio::test]
async fn test_rapid_scan_creation_stress() {
    let state = Arc::new(RwLock::new(AppState::new()));
    let mut handles = Vec::new();

    let start = Instant::now();

    for i in 0..200 {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            let request = ScanRequest {
                targets: vec![format!("10.{}.{}.{}", (i / 65536) % 256, (i / 256) % 256, i % 256)],
                ports: vec![80],
                scan_type: ScanType::Tcp,
                timing: TimingTemplate::Normal,
                enable_service_detection: false,
                enable_os_detection: false,
                enable_vuln_check: false,
                enable_threat_intel: false,
            };
            let mut state = state.write().await;
            state.create_scan(request).await
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    let state = state.read().await;
    let stats = state.get_stats();

    assert_eq!(stats.total_scans, 200);
    assert!(elapsed < Duration::from_secs(10), "200 scans took {:?}", elapsed);
}

#[test]
fn test_port_parser_stress() {
    let start = Instant::now();

    for _ in 0..100000 {
        let _ = PortParser::parse("1-1024");
    }

    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(10), "100k port parses took {:?}", elapsed);
}

#[test]
fn test_target_parser_stress() {
    let start = Instant::now();

    for _ in 0..100000 {
        let _ = TargetParser::parse("192.168.1.1");
    }

    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(10), "100k target parses took {:?}", elapsed);
}

#[test]
fn test_lockfree_queue_stress() {
    let queue = Arc::new(LockFreeQueue::new());
    let start = Instant::now();

    for i in 0..100000u64 {
        queue.push(i);
    }

    for _ in 0..100000 {
        queue.pop();
    }

    let elapsed = start.elapsed();
    assert!(queue.is_empty());
    assert!(elapsed < Duration::from_secs(5), "Queue stress test took {:?}", elapsed);
}

#[test]
fn test_bounded_queue_stress() {
    let queue = BoundedQueue::new(1000);
    let start = Instant::now();

    for i in 0..100000u64 {
        let _ = queue.push(i);
    }

    let mut count = 0;
    while queue.pop().is_some() {
        count += 1;
    }

    let elapsed = start.elapsed();
    assert!(count <= 1000);
    assert!(elapsed < Duration::from_secs(5), "Bounded queue stress test took {:?}", elapsed);
}

#[test]
fn test_atomic_flag_stress() {
    let flag = AtomicFlag::new(false);
    let start = Instant::now();

    for i in 0..1000000 {
        flag.set(i % 2 == 0);
        let _ = flag.get();
    }

    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(5), "Atomic flag stress test took {:?}", elapsed);
}

#[tokio::test]
async fn test_metrics_collector_stress() {
    let metrics = MetricsCollector::new();
    let start = Instant::now();

    for _ in 0..1000000 {
        metrics.increment_packets_sent(1);
        metrics.add_bytes_sent(1500);
        metrics.increment_active_connections();
        metrics.decrement_active_connections();
    }

    let elapsed = start.elapsed();
    let snapshot = metrics.snapshot().await;
    assert_eq!(snapshot.packets_sent, 1000000);
    assert!(elapsed < Duration::from_secs(5), "Metrics stress test took {:?}", elapsed);
}

#[tokio::test]
async fn test_concurrent_state_stress() {
    let state = Arc::new(RwLock::new(AppState::new()));
    let mut handles = Vec::new();

    for i in 0..100 {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            if i % 3 == 0 {
                let request = ScanRequest {
                    targets: vec![format!("192.168.1.{}", i)],
                    ports: vec![80],
                    scan_type: ScanType::Tcp,
                    timing: TimingTemplate::Normal,
                    enable_service_detection: false,
                    enable_os_detection: false,
                    enable_vuln_check: false,
                    enable_threat_intel: false,
                };
                let mut state = state.write().await;
                state.create_scan(request).await;
            } else if i % 3 == 1 {
                let state = state.read().await;
                let _ = state.list_scans(1, 10);
            } else {
                let state = state.read().await;
                let _ = state.get_stats();
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}
