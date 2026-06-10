use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// A cached response entry
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub body: Vec<u8>,
    pub etag: String,
    pub content_type: String,
    pub cached_at: Instant,
    pub max_age: Duration,
}

impl CachedResponse {
    pub fn is_fresh(&self) -> bool {
        self.cached_at.elapsed() < self.max_age
    }

    pub fn age_secs(&self) -> u64 {
        self.cached_at.elapsed().as_secs()
    }
}

/// Cache-Control directive
#[derive(Debug, Clone)]
pub enum CacheDirective {
    Public,
    Private,
    NoCache,
    NoStore,
    MaxAge(u64),
    SMaxAge(u64),
    MustRevalidate,
}

impl CacheDirective {
    pub fn to_header_value(&self) -> String {
        match self {
            CacheDirective::Public => "public".to_string(),
            CacheDirective::Private => "private".to_string(),
            CacheDirective::NoCache => "no-cache".to_string(),
            CacheDirective::NoStore => "no-store".to_string(),
            CacheDirective::MaxAge(secs) => format!("max-age={}", secs),
            CacheDirective::SMaxAge(secs) => format!("s-maxage={}", secs),
            CacheDirective::MustRevalidate => "must-revalidate".to_string(),
        }
    }
}

/// Configuration for the response cache
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub default_max_age: Duration,
    pub respect_no_cache: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 1024,
            default_max_age: Duration::from_secs(60),
            respect_no_cache: true,
        }
    }
}

/// Response cache with ETag and Cache-Control support
pub struct ResponseCache {
    config: CacheConfig,
    entries: Arc<RwLock<HashMap<String, CachedResponse>>>,
}

impl ResponseCache {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn generate_etag(body: &[u8]) -> String {
        let mut hasher = DefaultHasher::new();
        body.hash(&mut hasher);
        format!("\"{:x}\"", hasher.finish())
    }

    /// Try to serve from cache. Returns `CacheResult::Hit` if a fresh entry
    /// exists, or `CacheResult::Stale` with the stale entry for conditional
    /// revalidation.
    pub async fn lookup(
        &self,
        cache_key: &str,
        if_none_match: Option<&str>,
    ) -> CacheResult {
        let entries = self.entries.read().await;
        match entries.get(cache_key) {
            Some(entry) => {
                if let Some(client_etag) = if_none_match {
                    if client_etag == entry.etag {
                        return CacheResult::NotModified {
                            etag: entry.etag.clone(),
                            age: entry.age_secs(),
                        };
                    }
                }

                if entry.is_fresh() {
                    CacheResult::Hit(entry.clone())
                } else {
                    CacheResult::Stale(entry.clone())
                }
            }
            None => CacheResult::Miss,
        }
    }

    /// Store a response in the cache
    pub async fn store(
        &self,
        cache_key: &str,
        body: Vec<u8>,
        content_type: &str,
        max_age: Option<Duration>,
    ) -> CachedResponse {
        let etag = Self::generate_etag(&body);
        let entry = CachedResponse {
            body,
            etag,
            content_type: content_type.to_string(),
            cached_at: Instant::now(),
            max_age: max_age.unwrap_or(self.config.default_max_age),
        };

        let mut entries = self.entries.write().await;

        if entries.len() >= self.config.max_entries {
            if let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, e)| e.cached_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            }
        }

        entries.insert(cache_key.to_string(), entry.clone());
        entry
    }

    /// Invalidate a specific cache entry
    pub async fn invalidate(&self, cache_key: &str) -> bool {
        self.entries.write().await.remove(cache_key).is_some()
    }

    /// Invalidate all entries whose key starts with the given prefix
    pub async fn invalidate_prefix(&self, prefix: &str) -> usize {
        let mut entries = self.entries.write().await;
        let keys: Vec<String> = entries
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        let count = keys.len();
        for key in keys {
            entries.remove(&key);
        }
        count
    }

    pub async fn clear(&self) {
        self.entries.write().await.clear();
    }

    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }
}

/// Result of a cache lookup
#[derive(Debug)]
pub enum CacheResult {
    /// Fresh cached response
    Hit(CachedResponse),
    /// Cache miss – must compute the response
    Miss,
    /// Cached entry is stale – caller may revalidate
    Stale(CachedResponse),
    /// Client ETag matched – respond 304 Not Modified
    NotModified { etag: String, age: u64 },
}

/// Build a Cache-Control header value from a list of directives
pub fn cache_control_header(directives: &[CacheDirective]) -> String {
    directives
        .iter()
        .map(|d| d.to_header_value())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CacheConfig {
        CacheConfig {
            max_entries: 10,
            default_max_age: Duration::from_secs(60),
            respect_no_cache: true,
        }
    }

    #[tokio::test]
    async fn test_store_and_hit() {
        let cache = ResponseCache::new(test_config());
        let entry = cache
            .store("key1", b"hello".to_vec(), "text/plain", None)
            .await;

        match cache.lookup("key1", None).await {
            CacheResult::Hit(cached) => {
                assert_eq!(cached.body, b"hello");
                assert_eq!(cached.etag, entry.etag);
            }
            _ => panic!("expected cache hit"),
        }
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = ResponseCache::new(test_config());
        assert!(matches!(cache.lookup("missing", None).await, CacheResult::Miss));
    }

    #[tokio::test]
    async fn test_etag_not_modified() {
        let cache = ResponseCache::new(test_config());
        let entry = cache
            .store("key1", b"data".to_vec(), "text/plain", None)
            .await;

        let result = cache.lookup("key1", Some(&entry.etag)).await;
        assert!(matches!(result, CacheResult::NotModified { .. }));
    }

    #[tokio::test]
    async fn test_etag_mismatch_returns_hit() {
        let cache = ResponseCache::new(test_config());
        cache
            .store("key1", b"data".to_vec(), "text/plain", None)
            .await;

        let result = cache.lookup("key1", Some("\"wrong-etag\"")).await;
        assert!(matches!(result, CacheResult::Hit(_)));
    }

    #[tokio::test]
    async fn test_stale_entry() {
        let cache = ResponseCache::new(CacheConfig {
            max_entries: 10,
            default_max_age: Duration::from_millis(50),
            respect_no_cache: true,
        });
        cache
            .store("key1", b"old".to_vec(), "text/plain", None)
            .await;

        tokio::time::sleep(Duration::from_millis(60)).await;

        match cache.lookup("key1", None).await {
            CacheResult::Stale(entry) => assert_eq!(entry.body, b"old"),
            _ => panic!("expected stale result"),
        }
    }

    #[tokio::test]
    async fn test_invalidate() {
        let cache = ResponseCache::new(test_config());
        cache
            .store("key1", b"v".to_vec(), "text/plain", None)
            .await;
        assert!(cache.invalidate("key1").await);
        assert!(matches!(cache.lookup("key1", None).await, CacheResult::Miss));
    }

    #[tokio::test]
    async fn test_invalidate_prefix() {
        let cache = ResponseCache::new(test_config());
        cache
            .store("scans:a", b"1".to_vec(), "text/plain", None)
            .await;
        cache
            .store("scans:b", b"2".to_vec(), "text/plain", None)
            .await;
        cache
            .store("webhooks:c", b"3".to_vec(), "text/plain", None)
            .await;

        let removed = cache.invalidate_prefix("scans:").await;
        assert_eq!(removed, 2);
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test]
    async fn test_eviction_on_max_entries() {
        let config = CacheConfig {
            max_entries: 2,
            default_max_age: Duration::from_secs(60),
            respect_no_cache: true,
        };
        let cache = ResponseCache::new(config);

        cache
            .store("a", b"1".to_vec(), "text/plain", None)
            .await;
        cache
            .store("b", b"2".to_vec(), "text/plain", None)
            .await;
        cache
            .store("c", b"3".to_vec(), "text/plain", None)
            .await;

        assert_eq!(cache.len().await, 2);
        assert!(matches!(cache.lookup("a", None).await, CacheResult::Miss));
    }

    #[tokio::test]
    async fn test_cache_control_header() {
        let header = cache_control_header(&[
            CacheDirective::Public,
            CacheDirective::MaxAge(300),
            CacheDirective::MustRevalidate,
        ]);
        assert_eq!(header, "public, max-age=300, must-revalidate");
    }

    #[tokio::test]
    async fn test_clear() {
        let cache = ResponseCache::new(test_config());
        cache
            .store("k", b"v".to_vec(), "text/plain", None)
            .await;
        cache.clear().await;
        assert!(cache.is_empty().await);
    }
}
