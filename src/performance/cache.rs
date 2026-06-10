// High-performance caching with LRU eviction
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct Cache<K, V> {
    data: Arc<RwLock<CacheData<K, V>>>,
    max_size: usize,
    ttl: Option<Duration>,
}

struct CacheData<K, V> {
    map: HashMap<K, CacheEntry<V>>,
    access_order: Vec<K>,
}

struct CacheEntry<V> {
    value: V,
    inserted_at: Instant,
    last_accessed: Instant,
}

impl<K: Clone + Eq + Hash, V: Clone> Cache<K, V> {
    pub fn new(max_size: usize) -> Self {
        Self {
            data: Arc::new(RwLock::new(CacheData {
                map: HashMap::new(),
                access_order: Vec::new(),
            })),
            max_size,
            ttl: None,
        }
    }

    pub fn with_ttl(max_size: usize, ttl: Duration) -> Self {
        Self {
            data: Arc::new(RwLock::new(CacheData {
                map: HashMap::new(),
                access_order: Vec::new(),
            })),
            max_size,
            ttl: Some(ttl),
        }
    }

    pub async fn get(&self, key: &K) -> Option<V> {
        let mut data = self.data.write().await;

        // Check if key exists and is valid
        let is_valid = if let Some(entry) = data.map.get(key) {
            if let Some(ttl) = self.ttl {
                entry.inserted_at.elapsed() <= ttl
            } else {
                true
            }
        } else {
            false
        };

        if !is_valid {
            data.map.remove(key);
            data.access_order.retain(|k| k != key);
            return None;
        }

        // Update access time and get value
        if let Some(entry) = data.map.get_mut(key) {
            entry.last_accessed = Instant::now();
            let value = entry.value.clone();

            // Update access order
            data.access_order.retain(|k| k != key);
            data.access_order.push(key.clone());

            Some(value)
        } else {
            None
        }
    }

    pub async fn insert(&self, key: K, value: V) {
        let mut data = self.data.write().await;

        // Remove old entry if exists
        if data.map.contains_key(&key) {
            data.access_order.retain(|k| k != &key);
        }

        // Evict if at capacity
        while data.map.len() >= self.max_size && !data.access_order.is_empty() {
            if let Some(oldest_key) = data.access_order.first().cloned() {
                data.map.remove(&oldest_key);
                data.access_order.remove(0);
            }
        }

        // Insert new entry
        let entry = CacheEntry {
            value,
            inserted_at: Instant::now(),
            last_accessed: Instant::now(),
        };

        data.map.insert(key.clone(), entry);
        data.access_order.push(key);
    }

    pub async fn remove(&self, key: &K) -> Option<V> {
        let mut data = self.data.write().await;
        data.access_order.retain(|k| k != key);
        data.map.remove(key).map(|e| e.value)
    }

    pub async fn clear(&self) {
        let mut data = self.data.write().await;
        data.map.clear();
        data.access_order.clear();
    }

    pub async fn len(&self) -> usize {
        let data = self.data.read().await;
        data.map.len()
    }

    pub async fn is_empty(&self) -> bool {
        let data = self.data.read().await;
        data.map.is_empty()
    }

    pub async fn cleanup_expired(&self) {
        if let Some(ttl) = self.ttl {
            let mut data = self.data.write().await;
            let now = Instant::now();

            let expired_keys: Vec<K> = data
                .map
                .iter()
                .filter(|(_, entry)| now.duration_since(entry.inserted_at) > ttl)
                .map(|(k, _)| k.clone())
                .collect();

            for key in expired_keys {
                data.map.remove(&key);
                data.access_order.retain(|k| k != &key);
            }
        }
    }

    pub async fn stats(&self) -> CacheStats {
        let data = self.data.read().await;
        CacheStats {
            size: data.map.len(),
            capacity: self.max_size,
            ttl: self.ttl,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub size: usize,
    pub capacity: usize,
    pub ttl: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_basic() {
        let cache = Cache::new(3);

        cache.insert("key1", "value1").await;
        cache.insert("key2", "value2").await;

        assert_eq!(cache.get(&"key1").await, Some("value1"));
        assert_eq!(cache.get(&"key2").await, Some("value2"));
        assert_eq!(cache.len().await, 2);
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let cache = Cache::new(2);

        cache.insert("key1", "value1").await;
        cache.insert("key2", "value2").await;
        cache.insert("key3", "value3").await;

        // key1 should be evicted
        assert_eq!(cache.get(&"key1").await, None);
        assert_eq!(cache.get(&"key2").await, Some("value2"));
        assert_eq!(cache.get(&"key3").await, Some("value3"));
        assert_eq!(cache.len().await, 2);
    }

    #[tokio::test]
    async fn test_cache_lru() {
        let cache = Cache::new(2);

        cache.insert("key1", "value1").await;
        cache.insert("key2", "value2").await;

        // Access key1 to make it recently used
        cache.get(&"key1").await;

        // Insert key3, should evict key2 (least recently used)
        cache.insert("key3", "value3").await;

        assert_eq!(cache.get(&"key1").await, Some("value1"));
        assert_eq!(cache.get(&"key2").await, None);
        assert_eq!(cache.get(&"key3").await, Some("value3"));
    }

    #[tokio::test]
    async fn test_cache_ttl() {
        let cache = Cache::with_ttl(10, Duration::from_millis(50));

        cache.insert("key1", "value1").await;
        assert_eq!(cache.get(&"key1").await, Some("value1"));

        tokio::time::sleep(Duration::from_millis(60)).await;

        // Should be expired
        assert_eq!(cache.get(&"key1").await, None);
    }

    #[tokio::test]
    async fn test_cache_remove() {
        let cache = Cache::new(3);

        cache.insert("key1", "value1").await;
        assert_eq!(cache.len().await, 1);

        let removed = cache.remove(&"key1").await;
        assert_eq!(removed, Some("value1"));
        assert_eq!(cache.len().await, 0);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache = Cache::new(3);

        cache.insert("key1", "value1").await;
        cache.insert("key2", "value2").await;
        assert_eq!(cache.len().await, 2);

        cache.clear().await;
        assert_eq!(cache.len().await, 0);
        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let cache = Cache::with_ttl(10, Duration::from_millis(50));

        cache.insert("key1", "value1").await;
        cache.insert("key2", "value2").await;

        tokio::time::sleep(Duration::from_millis(60)).await;

        cache.cleanup_expired().await;
        assert_eq!(cache.len().await, 0);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = Cache::with_ttl(5, Duration::from_secs(60));

        cache.insert("key1", "value1").await;
        cache.insert("key2", "value2").await;

        let stats = cache.stats().await;
        assert_eq!(stats.size, 2);
        assert_eq!(stats.capacity, 5);
        assert_eq!(stats.ttl, Some(Duration::from_secs(60)));
    }
}
