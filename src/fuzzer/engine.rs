// Web Fuzzing Engine - Directory and File Discovery
// Implements gobuster/feroxbuster/ffuf-like fuzzing capabilities

use anyhow::{anyhow, Result};
use std::sync::Arc;
use tokio::sync::{Semaphore, RwLock};
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};
use reqwest::{Client, Response, StatusCode};
use tracing::{debug, info, warn};
use serde::{Serialize, Deserialize};

/// Fuzzing mode determines what to enumerate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FuzzMode {
    /// Directory enumeration (append / to paths)
    Directory,
    /// File discovery (try exact paths)
    File,
    /// Extension fuzzing (append extensions to base paths)
    Extension,
    /// Virtual host discovery (fuzz Host header)
    VirtualHost,
    /// DNS subdomain enumeration
    Subdomain,
    /// AWS S3 bucket enumeration
    S3Bucket,
    /// Azure blob storage enumeration
    AzureBlob,
    /// GCP bucket enumeration
    GcpBucket,
}

/// Filter for matching responses
#[derive(Debug, Clone)]
pub struct ResponseFilter {
    /// Include only these status codes (empty = all)
    pub status_codes: Vec<u16>,
    /// Exclude these status codes
    pub exclude_status_codes: Vec<u16>,
    /// Minimum response size in bytes
    pub min_size: Option<usize>,
    /// Maximum response size in bytes
    pub max_size: Option<usize>,
    /// Exclude responses with these sizes (exact match)
    pub exclude_sizes: Vec<usize>,
    /// Include only responses matching this regex
    pub include_regex: Option<String>,
    /// Exclude responses matching this regex
    pub exclude_regex: Option<String>,
    /// Minimum response time in milliseconds
    pub min_time: Option<u64>,
    /// Maximum response time in milliseconds
    pub max_time: Option<u64>,
}

impl Default for ResponseFilter {
    fn default() -> Self {
        Self {
            status_codes: vec![200, 204, 301, 302, 307, 401, 403],
            exclude_status_codes: Vec::new(),
            min_size: None,
            max_size: None,
            exclude_sizes: Vec::new(),
            include_regex: None,
            exclude_regex: None,
            min_time: None,
            max_time: None,
        }
    }
}

/// Configuration for the fuzzing engine
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    /// Base URL to fuzz (e.g., "https://example.com")
    pub base_url: String,
    /// Fuzzing mode
    pub mode: FuzzMode,
    /// Maximum concurrent requests
    pub concurrency: usize,
    /// Requests per second limit (0 = unlimited)
    pub rate_limit: u32,
    /// Request timeout in seconds
    pub timeout: Duration,
    /// Follow redirects (up to N hops)
    pub follow_redirects: Option<u8>,
    /// User-Agent string
    pub user_agent: String,
    /// Custom headers
    pub headers: Vec<(String, String)>,
    /// Response filter
    pub filter: ResponseFilter,
    /// Enable recursive directory discovery
    pub recursive: bool,
    /// Maximum recursion depth
    pub max_depth: usize,
    /// Wordlist file path
    pub wordlist: String,
    /// File extensions to append (for Extension mode)
    pub extensions: Vec<String>,
    /// Detect and skip wildcard responses
    pub detect_wildcards: bool,
    /// Auto-calibrate (detect false positives)
    pub auto_calibrate: bool,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            mode: FuzzMode::Directory,
            concurrency: 50,
            rate_limit: 0,
            timeout: Duration::from_secs(10),
            follow_redirects: Some(3),
            user_agent: "Nemue/0.1.0".to_string(),
            headers: Vec::new(),
            filter: ResponseFilter::default(),
            recursive: false,
            max_depth: 3,
            wordlist: String::new(),
            extensions: Vec::new(),
            detect_wildcards: true,
            auto_calibrate: true,
        }
    }
}

/// Result of a single fuzz request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    /// Requested path
    pub path: String,
    /// HTTP status code
    pub status_code: u16,
    /// Response size in bytes
    pub size: usize,
    /// Response time in milliseconds
    pub response_time: u64,
    /// Whether this is a redirect
    pub is_redirect: bool,
    /// Redirect location (if any)
    pub redirect_location: Option<String>,
    /// Current recursion depth
    pub depth: usize,
}

/// Statistics for fuzzing session
#[derive(Debug, Clone, Default)]
pub struct FuzzStats {
    /// Total requests made
    pub total_requests: usize,
    /// Successful findings (matched filter)
    pub findings: usize,
    /// Failed requests (errors)
    pub errors: usize,
    /// Start time
    pub start_time: Option<Instant>,
    /// Current requests per second
    pub current_rate: f64,
}

/// Main fuzzing engine
pub struct FuzzEngine {
    /// Configuration
    config: FuzzConfig,
    /// HTTP client
    client: Client,
    /// Semaphore for concurrency control
    semaphore: Arc<Semaphore>,
    /// Discovered paths (to avoid duplicates)
    discovered: Arc<RwLock<HashSet<String>>>,
    /// Queue for recursive scanning
    queue: Arc<RwLock<VecDeque<(String, usize)>>>,
    /// Statistics
    stats: Arc<RwLock<FuzzStats>>,
    /// Wildcard response signature (for filtering false positives)
    wildcard_signature: Arc<RwLock<Option<(u16, usize)>>>,
}

impl FuzzEngine {
    /// Create a new fuzzing engine
    pub fn new(config: FuzzConfig) -> Result<Self> {
        // Build HTTP client with configuration
        let mut client_builder = Client::builder()
            .timeout(config.timeout)
            .user_agent(&config.user_agent);

        // Configure redirect policy
        if let Some(max_redirects) = config.follow_redirects {
            client_builder = client_builder
                .redirect(reqwest::redirect::Policy::limited(max_redirects as usize));
        } else {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
        }

        let client = client_builder.build()?;

        Ok(Self {
            config,
            client,
            semaphore: Arc::new(Semaphore::new(50)), // Will be updated
            discovered: Arc::new(RwLock::new(HashSet::new())),
            queue: Arc::new(RwLock::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(FuzzStats::default())),
            wildcard_signature: Arc::new(RwLock::new(None)),
        })
    }

    /// Start fuzzing with the configured wordlist
    pub async fn fuzz(&self, wordlist: Vec<String>) -> Result<Vec<FuzzResult>> {
        info!("Starting fuzzing engine with {} entries", wordlist.len());
        
        // Initialize stats
        {
            let mut stats = self.stats.write().await;
            stats.start_time = Some(Instant::now());
        }

        // Detect wildcard responses if enabled
        if self.config.detect_wildcards {
            self.detect_wildcard_response().await?;
        }

        // Auto-calibrate if enabled
        if self.config.auto_calibrate {
            self.calibrate(&wordlist).await?;
        }

        let mut results = Vec::new();
        let mut tasks = Vec::new();

        // Create tasks for each wordlist entry
        for word in wordlist {
            let permit = self.semaphore.clone().acquire_owned().await?;
            let engine = self.clone_for_task();
            
            let task = tokio::spawn(async move {
                let result = engine.fuzz_path(&word, 0).await;
                drop(permit);
                result
            });
            
            tasks.push(task);

            // Rate limiting
            if self.config.rate_limit > 0 {
                let delay = Duration::from_millis(1000 / self.config.rate_limit as u64);
                tokio::time::sleep(delay).await;
            }
        }

        // Collect results
        for task in tasks {
            if let Ok(Ok(Some(result))) = task.await {
                results.push(result);
            }
        }

        // Process recursive queue if enabled
        if self.config.recursive {
            results.extend(self.process_recursive_queue().await?);
        }

        Ok(results)
    }

    /// Fuzz a single path
    async fn fuzz_path(&self, word: &str, depth: usize) -> Result<Option<FuzzResult>> {
        // Build URL based on mode
        let url = self.build_url(word)?;
        
        debug!("Fuzzing: {}", url);

        // Send request
        let start = Instant::now();
        let response = match self.send_request(&url).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Request failed for {}: {}", url, e);
                let mut stats = self.stats.write().await;
                stats.errors += 1;
                return Ok(None);
            }
        };
        
        let elapsed = start.elapsed().as_millis() as u64;

        // Extract response details
        let status = response.status().as_u16();
        let is_redirect = response.status().is_redirection();
        let redirect_location = response.headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // Get response body to measure size
        let body = response.text().await?;
        let size = body.len();

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
        }

        // Check if this matches the wildcard signature
        if self.is_wildcard_response(status, size).await {
            debug!("Skipping wildcard response: {}", url);
            return Ok(None);
        }

        // Apply filter
        if !self.matches_filter(status, size, elapsed) {
            return Ok(None);
        }

        // Create result
        let result = FuzzResult {
            path: word.to_string(),
            status_code: status,
            size,
            response_time: elapsed,
            is_redirect,
            redirect_location,
            depth,
        };

        // Mark as discovered
        {
            let mut discovered = self.discovered.write().await;
            discovered.insert(word.to_string());
        }

        // Add to recursive queue if this is a directory
        if self.config.recursive && depth < self.config.max_depth {
            if status == 200 || status == 301 || status == 302 {
                let mut queue = self.queue.write().await;
                queue.push_back((word.to_string(), depth + 1));
            }
        }

        // Update findings count
        {
            let mut stats = self.stats.write().await;
            stats.findings += 1;
        }

        Ok(Some(result))
    }

    /// Build URL based on fuzzing mode
    fn build_url(&self, word: &str) -> Result<String> {
        let base = self.config.base_url.trim_end_matches('/');
        
        match self.config.mode {
            FuzzMode::Directory => {
                Ok(format!("{}/{}/", base, word.trim_start_matches('/')))
            }
            FuzzMode::File => {
                Ok(format!("{}/{}", base, word.trim_start_matches('/')))
            }
            FuzzMode::Extension => {
                // Will be implemented with extension fuzzing
                Ok(format!("{}/{}", base, word))
            }
            _ => Err(anyhow!("Unsupported fuzzing mode: {:?}", self.config.mode)),
        }
    }

    /// Send HTTP request with configured headers
    async fn send_request(&self, url: &str) -> Result<Response> {
        let mut request = self.client.get(url);
        
        // Add custom headers
        for (key, value) in &self.config.headers {
            request = request.header(key, value);
        }
        
        let response = request.send().await?;
        Ok(response)
    }

    /// Check if response matches the filter
    fn matches_filter(&self, status: u16, size: usize, time: u64) -> bool {
        let filter = &self.config.filter;

        // Check status codes
        if !filter.status_codes.is_empty() && !filter.status_codes.contains(&status) {
            return false;
        }

        if filter.exclude_status_codes.contains(&status) {
            return false;
        }

        // Check size
        if let Some(min) = filter.min_size {
            if size < min {
                return false;
            }
        }

        if let Some(max) = filter.max_size {
            if size > max {
                return false;
            }
        }

        if filter.exclude_sizes.contains(&size) {
            return false;
        }

        // Check time
        if let Some(min) = filter.min_time {
            if time < min {
                return false;
            }
        }

        if let Some(max) = filter.max_time {
            if time > max {
                return false;
            }
        }

        true
    }

    /// Detect wildcard responses by testing random non-existent paths
    async fn detect_wildcard_response(&self) -> Result<()> {
        info!("Detecting wildcard responses...");
        
        // Test with random non-existent path
        let random_path = format!("__nemue_test_{}", uuid::Uuid::new_v4());
        
        if let Ok(Some(result)) = self.fuzz_path(&random_path, 0).await {
            let mut signature = self.wildcard_signature.write().await;
            *signature = Some((result.status_code, result.size));
            info!("Wildcard detected: status={}, size={}", result.status_code, result.size);
        }

        Ok(())
    }

    /// Check if response matches wildcard signature
    async fn is_wildcard_response(&self, status: u16, size: usize) -> bool {
        let signature = self.wildcard_signature.read().await;
        
        if let Some((wildcard_status, wildcard_size)) = *signature {
            // Allow 5% variance in size for dynamic content
            let size_diff = if wildcard_size > 0 {
                ((size as i64 - wildcard_size as i64).abs() as f64 / wildcard_size as f64) < 0.05
            } else {
                size == wildcard_size
            };
            
            status == wildcard_status && size_diff
        } else {
            false
        }
    }

    /// Auto-calibrate by sampling wordlist to find common false positives
    async fn calibrate(&self, wordlist: &[String]) -> Result<()> {
        info!("Auto-calibrating...");
        
        // Sample a few entries from the wordlist
        let sample_size = std::cmp::min(5, wordlist.len());
        let samples: Vec<_> = wordlist.iter().take(sample_size).collect();
        
        // Test samples and look for patterns
        // This is a placeholder for more sophisticated calibration
        for sample in samples {
            let _ = self.fuzz_path(sample, 0).await;
        }

        Ok(())
    }

    /// Process recursive queue for directory discovery
    async fn process_recursive_queue(&self) -> Result<Vec<FuzzResult>> {
        let mut results = Vec::new();
        
        // This will be implemented in the recursive scanning feature
        // For now, return empty results
        
        Ok(results)
    }

    /// Clone engine for task spawning
    fn clone_for_task(&self) -> Self {
        Self {
            config: self.config.clone(),
            client: self.client.clone(),
            semaphore: self.semaphore.clone(),
            discovered: self.discovered.clone(),
            queue: self.queue.clone(),
            stats: self.stats.clone(),
            wildcard_signature: self.wildcard_signature.clone(),
        }
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> FuzzStats {
        self.stats.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzz_config_default() {
        let config = FuzzConfig::default();
        assert_eq!(config.mode, FuzzMode::Directory);
        assert_eq!(config.concurrency, 50);
        assert!(!config.recursive);
    }

    #[test]
    fn test_response_filter_default() {
        let filter = ResponseFilter::default();
        assert!(filter.status_codes.contains(&200));
        assert!(filter.status_codes.contains(&403));
    }

    #[test]
    fn test_build_url_directory_mode() {
        let config = FuzzConfig {
            base_url: "https://example.com".to_string(),
            mode: FuzzMode::Directory,
            ..Default::default()
        };
        
        let engine = FuzzEngine::new(config).unwrap();
        let url = engine.build_url("admin").unwrap();
        assert_eq!(url, "https://example.com/admin/");
    }

    #[test]
    fn test_build_url_file_mode() {
        let config = FuzzConfig {
            base_url: "https://example.com".to_string(),
            mode: FuzzMode::File,
            ..Default::default()
        };
        
        let engine = FuzzEngine::new(config).unwrap();
        let url = engine.build_url("robots.txt").unwrap();
        assert_eq!(url, "https://example.com/robots.txt");
    }

    #[test]
    fn test_matches_filter_status_code() {
        let config = FuzzConfig::default();
        let engine = FuzzEngine::new(config).unwrap();
        
        // Should match (200 is in default filter)
        assert!(engine.matches_filter(200, 1000, 100));
        
        // Should not match (404 is not in default filter)
        assert!(!engine.matches_filter(404, 1000, 100));
    }

    #[test]
    fn test_matches_filter_size() {
        let mut config = FuzzConfig::default();
        config.filter.min_size = Some(500);
        config.filter.max_size = Some(2000);
        
        let engine = FuzzEngine::new(config).unwrap();
        
        // Should match
        assert!(engine.matches_filter(200, 1000, 100));
        
        // Too small
        assert!(!engine.matches_filter(200, 100, 100));
        
        // Too large
        assert!(!engine.matches_filter(200, 5000, 100));
    }

    #[test]
    fn test_matches_filter_exclude_size() {
        let mut config = FuzzConfig::default();
        config.filter.exclude_sizes = vec![1234, 5678];
        
        let engine = FuzzEngine::new(config).unwrap();
        
        // Should match
        assert!(engine.matches_filter(200, 1000, 100));
        
        // Should not match (excluded size)
        assert!(!engine.matches_filter(200, 1234, 100));
    }
}
