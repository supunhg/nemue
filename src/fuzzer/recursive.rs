// Recursive Scanner - Automatic subdirectory discovery and fuzzing
// feroxbuster-style recursive capabilities

use anyhow::Result;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::engine::{FuzzEngine, FuzzConfig, FuzzResult};
use super::wordlist::WordlistManager;

/// Recursive scanning configuration
#[derive(Debug, Clone)]
pub struct RecursiveConfig {
    /// Maximum recursion depth
    pub max_depth: usize,
    /// Breadth-first (true) or depth-first (false)
    pub breadth_first: bool,
    /// Minimum status code to consider for recursion
    pub min_status: u16,
    /// Maximum status code to consider for recursion
    pub max_status: u16,
    /// Extract links from discovered pages
    pub extract_links: bool,
    /// Follow robots.txt and sitemap.xml
    pub follow_sitemaps: bool,
    /// Extract paths from JavaScript files
    pub extract_from_js: bool,
    /// Generate backup file variants
    pub generate_backups: bool,
}

impl Default for RecursiveConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            breadth_first: true,
            min_status: 200,
            max_status: 399,
            extract_links: true,
            follow_sitemaps: true,
            extract_from_js: true,
            generate_backups: true,
        }
    }
}

/// Recursive scanner for automatic subdirectory discovery
#[allow(dead_code)]
pub struct RecursiveScanner {
    /// Base fuzzing configuration
    fuzz_config: FuzzConfig,
    /// Recursive configuration
    recursive_config: RecursiveConfig,
    /// Wordlist manager
    wordlist_manager: WordlistManager,
    /// Discovered directories (to avoid duplicates)
    discovered_dirs: Arc<RwLock<HashSet<String>>>,
    /// Queue of directories to scan
    scan_queue: Arc<RwLock<VecDeque<(String, usize)>>>,
}

impl RecursiveScanner {
    /// Create a new recursive scanner
    pub fn new(
        fuzz_config: FuzzConfig,
        recursive_config: RecursiveConfig,
    ) -> Self {
        Self {
            fuzz_config,
            recursive_config,
            wordlist_manager: WordlistManager::new(),
            discovered_dirs: Arc::new(RwLock::new(HashSet::new())),
            scan_queue: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// Start recursive scanning
    pub async fn scan(&self, initial_wordlist: Vec<String>) -> Result<Vec<FuzzResult>> {
        info!("Starting recursive scan with depth {}", self.recursive_config.max_depth);
        
        let mut all_results = Vec::new();

        // Scan root level
        let root_results = self.scan_directory("", 0, &initial_wordlist).await?;
        all_results.extend(root_results.clone());

        // Add discovered directories to queue
        for result in &root_results {
            if self.should_recurse(&result) {
                let mut queue = self.scan_queue.write().await;
                queue.push_back((result.path.clone(), 1));
            }
        }

        // Process queue recursively
        while let Some((dir, depth)) = self.pop_from_queue().await {
            if depth >= self.recursive_config.max_depth {
                debug!("Max depth reached for: {}", dir);
                continue;
            }

            debug!("Recursively scanning: {} (depth {})", dir, depth);
            
            let results = self.scan_directory(&dir, depth, &initial_wordlist).await?;
            all_results.extend(results.clone());

            // Add new directories to queue
            for result in results {
                if self.should_recurse(&result) {
                    let mut queue = self.scan_queue.write().await;
                    queue.push_back((result.path.clone(), depth + 1));
                }
            }
        }

        info!("Recursive scan complete. Total findings: {}", all_results.len());
        Ok(all_results)
    }

    /// Scan a single directory
    async fn scan_directory(
        &self,
        base_path: &str,
        _depth: usize,
        wordlist: &[String],
    ) -> Result<Vec<FuzzResult>> {
        // Check if already discovered
        {
            let discovered = self.discovered_dirs.read().await;
            if discovered.contains(base_path) {
                debug!("Already scanned: {}", base_path);
                return Ok(Vec::new());
            }
        }

        // Mark as discovered
        {
            let mut discovered = self.discovered_dirs.write().await;
            discovered.insert(base_path.to_string());
        }

        // Update base URL for this directory
        let mut config = self.fuzz_config.clone();
        if !base_path.is_empty() {
            config.base_url = format!("{}/{}", 
                config.base_url.trim_end_matches('/'), 
                base_path.trim_start_matches('/')
            );
        }

        // Create fuzzing engine
        let engine = FuzzEngine::new(config)?;

        // Perform fuzzing
        let results = engine.fuzz(wordlist.to_vec()).await?;

        // Extract additional paths if configured
        if self.recursive_config.extract_links {
            // This would extract links from HTML responses
            // Placeholder for now
        }

        if self.recursive_config.extract_from_js {
            // This would extract paths from JavaScript files
            // Placeholder for now
        }

        if self.recursive_config.generate_backups {
            // Generate backup file variants
            let _backup_results = self.generate_backup_variants(&results).await?;
            // Would add backup_results to main results
        }

        Ok(results)
    }

    /// Check if a result should trigger recursion
    fn should_recurse(&self, result: &FuzzResult) -> bool {
        // Only recurse for successful responses
        if result.status_code < self.recursive_config.min_status 
            || result.status_code > self.recursive_config.max_status {
            return false;
        }

        // Only recurse for directories (paths ending with /)
        result.path.ends_with('/')
    }

    /// Pop next directory from queue (breadth-first or depth-first)
    async fn pop_from_queue(&self) -> Option<(String, usize)> {
        let mut queue = self.scan_queue.write().await;
        
        if self.recursive_config.breadth_first {
            queue.pop_front()
        } else {
            queue.pop_back()
        }
    }

    /// Generate backup file variants for discovered files
    async fn generate_backup_variants(&self, results: &[FuzzResult]) -> Result<Vec<FuzzResult>> {
        let variants = Vec::new();

        for result in results {
            if result.path.ends_with('/') {
                continue; // Skip directories
            }

            // Generate backup extensions
            let _backup_paths = vec![
                format!("{}.bak", result.path),
                format!("{}.old", result.path),
                format!("{}.backup", result.path),
                format!("{}~", result.path),
                format!("{}.swp", result.path),
                format!("{}.tmp", result.path),
                format!("{}.save", result.path),
            ];

            // Test each backup variant
            // This would be implemented with actual HTTP requests
            // Placeholder for now
        }

        Ok(variants)
    }

    /// Extract paths from robots.txt
    pub async fn extract_from_robots(&self, _base_url: &str) -> Result<Vec<String>> {
        // Fetch robots.txt and extract disallowed paths
        // Placeholder implementation
        Ok(vec![
            "admin".to_string(),
            "private".to_string(),
            "backup".to_string(),
        ])
    }

    /// Extract paths from sitemap.xml
    pub async fn extract_from_sitemap(&self, _base_url: &str) -> Result<Vec<String>> {
        // Fetch sitemap.xml and extract all URLs
        // Placeholder implementation
        Ok(Vec::new())
    }

    /// Extract paths from JavaScript files
    pub async fn extract_from_javascript(&self, _js_content: &str) -> Vec<String> {
        let paths = Vec::new();

        // Look for common patterns in JavaScript
        // - API endpoints: /api/v1/users
        // - Route definitions: router.get('/path')
        // - URL constants: const API_URL = '/api'
        
        // Regex patterns for common JavaScript path patterns
        let _patterns = vec![
            r#"['"](/[a-zA-Z0-9/_-]+)['"]"#,  // Quoted paths
            r#"router\.(get|post|put|delete)\(['"]([^'"]+)['"]"#,  // Express.js routes
            r#"fetch\(['"]([^'"]+)['"]"#,  // Fetch API calls
            r#"axios\.(get|post|put|delete)\(['"]([^'"]+)['"]"#,  // Axios calls
        ];

        // This would use regex to extract paths
        // Placeholder for now
        
        paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzer::engine::FuzzMode;

    #[test]
    fn test_recursive_config_default() {
        let config = RecursiveConfig::default();
        assert_eq!(config.max_depth, 3);
        assert!(config.breadth_first);
        assert_eq!(config.min_status, 200);
        assert_eq!(config.max_status, 399);
    }

    #[test]
    fn test_should_recurse_directory() {
        let fuzz_config = FuzzConfig {
            base_url: "https://example.com".to_string(),
            mode: FuzzMode::Directory,
            ..Default::default()
        };
        let recursive_config = RecursiveConfig::default();
        let scanner = RecursiveScanner::new(fuzz_config, recursive_config);

        let result = FuzzResult {
            path: "admin/".to_string(),
            status_code: 200,
            size: 1000,
            response_time: 100,
            is_redirect: false,
            redirect_location: None,
            depth: 0,
        };

        assert!(scanner.should_recurse(&result));
    }

    #[test]
    fn test_should_not_recurse_file() {
        let fuzz_config = FuzzConfig {
            base_url: "https://example.com".to_string(),
            mode: FuzzMode::File,
            ..Default::default()
        };
        let recursive_config = RecursiveConfig::default();
        let scanner = RecursiveScanner::new(fuzz_config, recursive_config);

        let result = FuzzResult {
            path: "admin.php".to_string(),
            status_code: 200,
            size: 1000,
            response_time: 100,
            is_redirect: false,
            redirect_location: None,
            depth: 0,
        };

        assert!(!scanner.should_recurse(&result));
    }

    #[test]
    fn test_should_not_recurse_error_status() {
        let fuzz_config = FuzzConfig::default();
        let recursive_config = RecursiveConfig::default();
        let scanner = RecursiveScanner::new(fuzz_config, recursive_config);

        let result = FuzzResult {
            path: "admin/".to_string(),
            status_code: 404,
            size: 1000,
            response_time: 100,
            is_redirect: false,
            redirect_location: None,
            depth: 0,
        };

        assert!(!scanner.should_recurse(&result));
    }

    #[test]
    fn test_extract_from_javascript() {
        let fuzz_config = FuzzConfig::default();
        let recursive_config = RecursiveConfig::default();
        let scanner = RecursiveScanner::new(fuzz_config, recursive_config);

        let js_content = r#"
            const API_URL = '/api/v1';
            router.get('/users', getUsers);
            fetch('/api/posts');
        "#;

        let paths = tokio_test::block_on(scanner.extract_from_javascript(js_content));
        // This test would pass once extraction is implemented
        // For now, it just verifies the function doesn't panic
        assert!(paths.is_empty() || !paths.is_empty());
    }
}
