use nemue::api::models::*;
use nemue::api::state::AppState;
use nemue::scanner::{PortParser, TargetParser};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[tokio::test]
async fn test_concurrent_scan_creation_load() {
    let state = Arc::new(RwLock::new(AppState::new()));
    let mut handles = Vec::new();

    let start = Instant::now();

    for i in 0..50 {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            let request = ScanRequest {
                targets: vec![format!("192.168.1.{}", i)],
                ports: vec![80, 443],
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

    assert_eq!(stats.total_scans, 50);
    assert!(
        elapsed < Duration::from_secs(5),
        "Creating 50 scans took {:?}",
        elapsed
    );
}

#[tokio::test]
async fn test_concurrent_scan_list_load() {
    let state = Arc::new(RwLock::new(AppState::new()));

    {
        let mut state = state.write().await;
        for i in 0..100 {
            let request = ScanRequest {
                targets: vec![format!("10.0.0.{}", i % 255)],
                ports: vec![80],
                scan_type: ScanType::Tcp,
                timing: TimingTemplate::Normal,
                enable_service_detection: false,
                enable_os_detection: false,
                enable_vuln_check: false,
                enable_threat_intel: false,
            };
            state.create_scan(request).await;
        }
    }

    let mut handles = Vec::new();
    let start = Instant::now();

    for _ in 0..20 {
        let state = state.clone();
        handles.push(tokio::spawn(async move {
            let state = state.read().await;
            state.list_scans(1, 10)
        }));
    }

    for handle in handles {
        let result = handle.await.unwrap();
        assert_eq!(result.scans.len(), 10);
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "20 concurrent list operations took {:?}",
        elapsed
    );
}

#[test]
fn test_port_parser_throughput() {
    let start = Instant::now();
    let iterations = 10000;

    for _ in 0..iterations {
        let _ = PortParser::parse("22,80,443,8080,8443,3306,5432,6379,27017");
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    assert!(
        ops_per_sec > 1000.0,
        "Port parsing throughput: {:.0} ops/sec",
        ops_per_sec
    );
}

#[test]
fn test_target_parser_throughput() {
    let start = Instant::now();
    let iterations = 10000;

    for _ in 0..iterations {
        let _ = TargetParser::parse("192.168.1.1");
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    assert!(
        ops_per_sec > 1000.0,
        "Target parsing throughput: {:.0} ops/sec",
        ops_per_sec
    );
}

#[test]
fn test_cidr_parsing_throughput() {
    let start = Instant::now();
    let iterations = 1000;

    for _ in 0..iterations {
        let _ = TargetParser::parse("192.168.1.0/28");
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    assert!(
        ops_per_sec > 100.0,
        "CIDR parsing throughput: {:.0} ops/sec",
        ops_per_sec
    );
}

#[tokio::test]
async fn test_concurrent_cache_operations() {
    use nemue::scanner::cache::{CacheKey, ScanCache};

    let cache = Arc::new(ScanCache::with_defaults());
    let mut handles = Vec::new();

    let start = Instant::now();

    for i in 0..20 {
        let cache = cache.clone();
        handles.push(tokio::spawn(async move {
            let key = CacheKey::new(&format!("host-{}", i), "80", "syn");
            cache.get(&key).await
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "20 concurrent cache ops took {:?}",
        elapsed
    );
}
