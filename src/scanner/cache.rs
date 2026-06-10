use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::scanner::ScanResults;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub default_ttl: Duration,
    pub enable_stats: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 1000,
            default_ttl: Duration::from_secs(3600),
            enable_stats: true,
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    results: ScanResults,
    inserted_at: Instant,
    ttl: Duration,
    access_count: u64,
    last_accessed: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub insertions: u64,
    pub invalidations: u64,
    pub current_entries: usize,
    pub hit_rate: f64,
}

#[derive(Debug)]
struct AtomicStats {
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    insertions: AtomicU64,
    invalidations: AtomicU64,
}

impl AtomicStats {
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            insertions: AtomicU64::new(0),
            invalidations: AtomicU64::new(0),
        }
    }

    fn to_cache_stats(&self, current_entries: usize) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        CacheStats {
            hits,
            misses,
            evictions: self.evictions.load(Ordering::Relaxed),
            insertions: self.insertions.load(Ordering::Relaxed),
            invalidations: self.invalidations.load(Ordering::Relaxed),
            current_entries,
            hit_rate: if total > 0 {
                hits as f64 / total as f64
            } else {
                0.0
            },
        }
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct CacheKey {
    pub target: String,
    pub ports: String,
    pub scan_type: String,
}

impl CacheKey {
    pub fn new(target: &str, ports: &str, scan_type: &str) -> Self {
        Self {
            target: target.to_string(),
            ports: ports.to_string(),
            scan_type: scan_type.to_string(),
        }
    }
}

pub struct ScanCache {
    entries: Arc<RwLock<HashMap<CacheKey, CacheEntry>>>,
    config: CacheConfig,
    stats: AtomicStats,
}

impl ScanCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
            stats: AtomicStats::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(CacheConfig::default())
    }

    pub async fn get(&self, key: &CacheKey) -> Option<ScanResults> {
        let mut entries = self.entries.write().await;

        if let Some(entry) = entries.get_mut(key) {
            if entry.is_expired() {
                entries.remove(key);
                self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            entry.access_count += 1;
            entry.last_accessed = Instant::now();
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.results.clone())
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    pub async fn put(&self, key: CacheKey, results: ScanResults) {
        self.put_with_ttl(key, results, self.config.default_ttl)
            .await;
    }

    pub async fn put_with_ttl(&self, key: CacheKey, results: ScanResults, ttl: Duration) {
        let mut entries = self.entries.write().await;

        if entries.len() >= self.config.max_entries {
            self.evict_expired(&mut entries);

            if entries.len() >= self.config.max_entries {
                self.evict_lru(&mut entries);
            }
        }

        let now = Instant::now();
        entries.insert(
            key,
            CacheEntry {
                results,
                inserted_at: now,
                ttl,
                access_count: 0,
                last_accessed: now,
            },
        );

        self.stats.insertions.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn invalidate(&self, key: &CacheKey) -> bool {
        let mut entries = self.entries.write().await;
        if entries.remove(key).is_some() {
            self.stats.invalidations.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub async fn invalidate_all(&self) {
        let mut entries = self.entries.write().await;
        let count = entries.len() as u64;
        entries.clear();
        self.stats.invalidations.fetch_add(count, Ordering::Relaxed);
    }

    pub async fn invalidate_target(&self, target: &str) -> usize {
        let mut entries = self.entries.write().await;
        let keys_to_remove: Vec<CacheKey> = entries
            .keys()
            .filter(|k| k.target == target)
            .cloned()
            .collect();

        let count = keys_to_remove.len();
        for key in keys_to_remove {
            entries.remove(&key);
        }
        self.stats
            .invalidations
            .fetch_add(count as u64, Ordering::Relaxed);
        count
    }

    pub async fn stats(&self) -> CacheStats {
        let entries = self.entries.read().await;
        self.stats.to_cache_stats(entries.len())
    }

    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    pub async fn contains(&self, key: &CacheKey) -> bool {
        let entries = self.entries.read().await;
        entries.get(key).map(|e| !e.is_expired()).unwrap_or(false)
    }

    pub async fn cleanup(&self) -> usize {
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|_, entry| !entry.is_expired());
        let removed = before - entries.len();
        self.stats
            .evictions
            .fetch_add(removed as u64, Ordering::Relaxed);
        removed
    }

    fn evict_expired(&self, entries: &mut HashMap<CacheKey, CacheEntry>) {
        let before = entries.len();
        entries.retain(|_, entry| !entry.is_expired());
        let removed = before - entries.len();
        self.stats
            .evictions
            .fetch_add(removed as u64, Ordering::Relaxed);
    }

    fn evict_lru(&self, entries: &mut HashMap<CacheKey, CacheEntry>) {
        if let Some(oldest_key) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_accessed)
            .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest_key);
            self.stats.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl Default for ScanCache {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl Clone for ScanCache {
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
            config: self.config.clone(),
            stats: AtomicStats::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{PortState, Protocol, ScanResult, ScanResults};
    use chrono::Utc;
    use std::net::IpAddr;

    fn create_test_results(port: u16) -> ScanResults {
        ScanResults {
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1,
            port_count: 1,
            results: vec![ScanResult {
                target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                port,
                state: PortState::Open,
                protocol: Protocol::TCP,
                service: Some("http".to_string()),
                service_info: None,
                hostname: None,
                reason: None,
                timestamp: Utc::now(),
            }],
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_cache_put_and_get() {
        let cache = ScanCache::with_defaults();
        let key = CacheKey::new("192.168.1.1", "80,443", "syn");
        let results = create_test_results(80);

        cache.put(key.clone(), results.clone()).await;
        let cached = cache.get(&key).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().results.len(), 1);
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = ScanCache::with_defaults();
        let key = CacheKey::new("192.168.1.1", "80", "syn");

        assert!(cache.get(&key).await.is_none());
        let stats = cache.stats().await;
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let cache = ScanCache::new(CacheConfig {
            max_entries: 100,
            default_ttl: Duration::from_millis(50),
            enable_stats: true,
        });

        let key = CacheKey::new("192.168.1.1", "80", "syn");
        cache.put(key.clone(), create_test_results(80)).await;

        assert!(cache.get(&key).await.is_some());

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(cache.get(&key).await.is_none());
        let stats = cache.stats().await;
        assert_eq!(stats.evictions, 1);
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let cache = ScanCache::with_defaults();
        let key = CacheKey::new("192.168.1.1", "80", "syn");

        cache.put(key.clone(), create_test_results(80)).await;
        assert!(cache.invalidate(&key).await);
        assert!(cache.get(&key).await.is_none());
        assert!(!cache.invalidate(&key).await);
    }

    #[tokio::test]
    async fn test_cache_invalidate_target() {
        let cache = ScanCache::with_defaults();

        cache
            .put(
                CacheKey::new("192.168.1.1", "80", "syn"),
                create_test_results(80),
            )
            .await;
        cache
            .put(
                CacheKey::new("192.168.1.1", "443", "syn"),
                create_test_results(443),
            )
            .await;
        cache
            .put(
                CacheKey::new("192.168.1.2", "80", "syn"),
                create_test_results(80),
            )
            .await;

        let removed = cache.invalidate_target("192.168.1.1").await;
        assert_eq!(removed, 2);
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test]
    async fn test_cache_max_entries_eviction() {
        let cache = ScanCache::new(CacheConfig {
            max_entries: 2,
            default_ttl: Duration::from_secs(3600),
            enable_stats: true,
        });

        cache
            .put(CacheKey::new("host1", "80", "syn"), create_test_results(80))
            .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        cache
            .put(CacheKey::new("host2", "80", "syn"), create_test_results(80))
            .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        cache
            .put(CacheKey::new("host3", "80", "syn"), create_test_results(80))
            .await;

        assert!(cache.len().await <= 2);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = ScanCache::with_defaults();
        let key = CacheKey::new("192.168.1.1", "80", "syn");

        cache.put(key.clone(), create_test_results(80)).await;
        cache.get(&key).await;
        cache.get(&key).await;
        cache.get(&CacheKey::new("missing", "80", "syn")).await;

        let stats = cache.stats().await;
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.insertions, 1);
        assert!(stats.hit_rate > 0.6);
    }

    #[tokio::test]
    async fn test_cache_contains() {
        let cache = ScanCache::with_defaults();
        let key = CacheKey::new("192.168.1.1", "80", "syn");

        assert!(!cache.contains(&key).await);
        cache.put(key.clone(), create_test_results(80)).await;
        assert!(cache.contains(&key).await);
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let cache = ScanCache::new(CacheConfig {
            max_entries: 100,
            default_ttl: Duration::from_millis(50),
            enable_stats: true,
        });

        cache
            .put(CacheKey::new("host1", "80", "syn"), create_test_results(80))
            .await;
        cache
            .put(CacheKey::new("host2", "80", "syn"), create_test_results(80))
            .await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        let removed = cache.cleanup().await;
        assert_eq!(removed, 2);
        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn test_cache_key_differentiation() {
        let cache = ScanCache::with_defaults();

        cache
            .put(
                CacheKey::new("192.168.1.1", "80", "syn"),
                create_test_results(80),
            )
            .await;
        cache
            .put(
                CacheKey::new("192.168.1.1", "80", "connect"),
                create_test_results(80),
            )
            .await;

        assert_eq!(cache.len().await, 2);
    }
}
