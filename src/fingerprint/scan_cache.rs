use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct CacheKey {
    pub target: IpAddr,
    pub port: u16,
    pub scan_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResult<T: Clone> {
    pub data: T,
    pub timestamp: u64,
    pub ttl_seconds: u64,
    pub hit_count: u64,
}

pub struct ScanCache<T: Clone + Send + Sync> {
    data: Arc<RwLock<HashMap<CacheKey, CachedResult<T>>>>,
    max_entries: usize,
    default_ttl: Duration,
    stats: Arc<RwLock<CacheStats>>,
}

#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub inserts: u64,
}

impl<T: Clone + Send + Sync> ScanCache<T> {
    pub fn new(max_entries: usize, default_ttl: Duration) -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
            default_ttl,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        }
    }

    pub async fn get(&self, key: &CacheKey) -> Option<T> {
        let mut data = self.data.write().await;

        if let Some(entry) = data.get(key) {
            let elapsed = Duration::from_secs(entry.timestamp);
            if elapsed < Duration::from_secs(entry.ttl_seconds) {
                self.stats.write().await.hits += 1;
                return Some(entry.data.clone());
            } else {
                data.remove(key);
            }
        }

        self.stats.write().await.misses += 1;
        None
    }

    pub async fn insert(&self, key: CacheKey, value: T, ttl: Option<Duration>) {
        let mut data = self.data.write().await;

        if data.len() >= self.max_entries {
            self.evict_oldest(&mut data).await;
        }

        let entry = CachedResult {
            data: value,
            timestamp: 0,
            ttl_seconds: ttl.unwrap_or(self.default_ttl).as_secs(),
            hit_count: 0,
        };

        data.insert(key, entry);
        self.stats.write().await.inserts += 1;
    }

    pub async fn remove(&self, key: &CacheKey) -> Option<T> {
        let mut data = self.data.write().await;
        data.remove(key).map(|e| e.data)
    }

    pub async fn clear(&self) {
        let mut data = self.data.write().await;
        data.clear();
    }

    pub async fn len(&self) -> usize {
        let data = self.data.read().await;
        data.len()
    }

    pub async fn is_empty(&self) -> bool {
        let data = self.data.read().await;
        data.is_empty()
    }

    pub async fn stats(&self) -> CacheStats {
        let stats = self.stats.read().await;
        stats.clone()
    }

    async fn evict_oldest(&self, data: &mut HashMap<CacheKey, CachedResult<T>>) {
        if let Some(oldest_key) = data.keys().next().cloned() {
            data.remove(&oldest_key);
            self.stats.write().await.evictions += 1;
        }
    }
}

pub struct ScanResultCache {
    service_cache: ScanCache<crate::service::ServiceInfo>,
    port_cache: ScanCache<bool>,
    host_cache: ScanCache<bool>,
}

impl ScanResultCache {
    pub fn new() -> Self {
        Self {
            service_cache: ScanCache::new(10000, Duration::from_secs(3600)),
            port_cache: ScanCache::new(100000, Duration::from_secs(1800)),
            host_cache: ScanCache::new(1000, Duration::from_secs(7200)),
        }
    }

    pub async fn get_service(
        &self,
        target: IpAddr,
        port: u16,
    ) -> Option<crate::service::ServiceInfo> {
        let key = CacheKey {
            target,
            port,
            scan_type: "service".to_string(),
        };
        self.service_cache.get(&key).await
    }

    pub async fn cache_service(
        &self,
        target: IpAddr,
        port: u16,
        info: crate::service::ServiceInfo,
    ) {
        let key = CacheKey {
            target,
            port,
            scan_type: "service".to_string(),
        };
        self.service_cache.insert(key, info, None).await;
    }

    pub async fn is_port_open(&self, target: IpAddr, port: u16) -> Option<bool> {
        let key = CacheKey {
            target,
            port,
            scan_type: "port".to_string(),
        };
        self.port_cache.get(&key).await
    }

    pub async fn cache_port_state(&self, target: IpAddr, port: u16, is_open: bool) {
        let key = CacheKey {
            target,
            port,
            scan_type: "port".to_string(),
        };
        self.port_cache.insert(key, is_open, None).await;
    }

    pub async fn is_host_up(&self, target: IpAddr) -> Option<bool> {
        let key = CacheKey {
            target,
            port: 0,
            scan_type: "host".to_string(),
        };
        self.host_cache.get(&key).await
    }

    pub async fn cache_host_state(&self, target: IpAddr, is_up: bool) {
        let key = CacheKey {
            target,
            port: 0,
            scan_type: "host".to_string(),
        };
        self.host_cache.insert(key, is_up, None).await;
    }

    pub async fn clear_all(&self) {
        self.service_cache.clear().await;
        self.port_cache.clear().await;
        self.host_cache.clear().await;
    }
}

impl Default for ScanResultCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[tokio::test]
    async fn test_cache_basic() {
        let cache = ScanCache::new(10, Duration::from_secs(60));
        let key = CacheKey {
            target: "127.0.0.1".parse().unwrap(),
            port: 80,
            scan_type: "test".to_string(),
        };

        cache.insert(key.clone(), "value".to_string(), None).await;
        let result = cache.get(&key).await;
        assert_eq!(result, Some("value".to_string()));
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = ScanCache::<String>::new(10, Duration::from_secs(60));
        let key = CacheKey {
            target: "127.0.0.1".parse().unwrap(),
            port: 80,
            scan_type: "test".to_string(),
        };

        let result = cache.get(&key).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_cache_remove() {
        let cache = ScanCache::new(10, Duration::from_secs(60));
        let key = CacheKey {
            target: "127.0.0.1".parse().unwrap(),
            port: 80,
            scan_type: "test".to_string(),
        };

        cache.insert(key.clone(), "value".to_string(), None).await;
        let removed = cache.remove(&key).await;
        assert_eq!(removed, Some("value".to_string()));

        let result = cache.get(&key).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache = ScanCache::new(10, Duration::from_secs(60));
        let key1 = CacheKey {
            target: "127.0.0.1".parse().unwrap(),
            port: 80,
            scan_type: "test".to_string(),
        };
        let key2 = CacheKey {
            target: "127.0.0.1".parse().unwrap(),
            port: 443,
            scan_type: "test".to_string(),
        };

        cache.insert(key1, "value1".to_string(), None).await;
        cache.insert(key2, "value2".to_string(), None).await;
        assert_eq!(cache.len().await, 2);

        cache.clear().await;
        assert_eq!(cache.len().await, 0);
    }

    #[tokio::test]
    async fn test_scan_result_cache() {
        let cache = ScanResultCache::new();
        let target: IpAddr = "127.0.0.1".parse().unwrap();

        assert_eq!(cache.is_port_open(target, 80).await, None);

        cache.cache_port_state(target, 80, true).await;
        assert_eq!(cache.is_port_open(target, 80).await, Some(true));

        assert_eq!(cache.is_host_up(target).await, None);
        cache.cache_host_state(target, true).await;
        assert_eq!(cache.is_host_up(target).await, Some(true));
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = ScanCache::<String>::new(10, Duration::from_secs(60));
        let key = CacheKey {
            target: "127.0.0.1".parse().unwrap(),
            port: 80,
            scan_type: "test".to_string(),
        };

        cache.insert(key.clone(), "value".to_string(), None).await;
        cache.get(&key).await;
        cache.get(&key).await;

        let stats = cache.stats().await;
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.inserts, 1);
    }
}
