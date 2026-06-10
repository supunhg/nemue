// Parameter Fuzzing - GET/POST/Header parameter injection and discovery
// ffuf-style parameter fuzzing with multiple injection modes

use anyhow::Result;
use reqwest::{Client, Method};
use std::collections::HashMap;
use std::time::Instant;

use super::engine::{FuzzResult, ResponseFilter};

/// Parameter injection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionMode {
    /// Test one parameter at a time (fast)
    Sniper,
    /// Test all combinations (thorough but slow)
    Clusterbomb,
    /// Iterate through wordlists together (synchronized)
    Pitchfork,
    /// Replace all FUZZ keywords with same value
    Replace,
}

/// Parameter injection location
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectionLocation {
    /// URL query parameters (?param=value)
    QueryString,
    /// POST body parameters
    PostBody,
    /// HTTP headers
    Headers,
    /// Cookies
    Cookies,
    /// URL path segments
    Path,
    /// JSON body fields
    JsonBody,
}

/// Parameter fuzzing configuration
#[derive(Debug, Clone)]
pub struct ParamFuzzConfig {
    /// Base URL template (use FUZZ for injection points)
    pub url_template: String,
    /// HTTP method
    pub method: Method,
    /// Injection mode
    pub mode: InjectionMode,
    /// Injection locations
    pub locations: Vec<InjectionLocation>,
    /// HTTP headers
    pub headers: HashMap<String, String>,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// Response filter
    pub filter: Option<ResponseFilter>,
    /// POST body template (for POST requests)
    pub body_template: Option<String>,
    /// Follow redirects
    pub follow_redirects: bool,
}

impl Default for ParamFuzzConfig {
    fn default() -> Self {
        Self {
            url_template: String::new(),
            method: Method::GET,
            mode: InjectionMode::Sniper,
            locations: vec![InjectionLocation::QueryString],
            headers: HashMap::new(),
            timeout_ms: 10000,
            filter: None,
            body_template: None,
            follow_redirects: false,
        }
    }
}

/// Parameter fuzzer for testing injection points
pub struct ParamFuzzer {
    config: ParamFuzzConfig,
    client: Client,
}

impl ParamFuzzer {
    /// Create a new parameter fuzzer
    pub fn new(config: ParamFuzzConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .build()?;

        Ok(Self { config, client })
    }

    /// Fuzz with single wordlist (Sniper/Replace mode)
    pub async fn fuzz_single(&self, wordlist: Vec<String>) -> Result<Vec<FuzzResult>> {
        let mut results = Vec::new();

        for word in wordlist {
            let result = self.fuzz_with_value(&word).await?;
            if let Some(filter) = &self.config.filter {
                if self.matches_filter(&result, filter) {
                    results.push(result);
                }
            } else {
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Fuzz with multiple wordlists (Clusterbomb/Pitchfork mode)
    pub async fn fuzz_multi(&self, wordlists: Vec<Vec<String>>) -> Result<Vec<FuzzResult>> {
        let mut results = Vec::new();

        match self.config.mode {
            InjectionMode::Clusterbomb => {
                // Test all combinations
                results = self.fuzz_clusterbomb(wordlists).await?;
            }
            InjectionMode::Pitchfork => {
                // Iterate together
                results = self.fuzz_pitchfork(wordlists).await?;
            }
            _ => {
                // Unsupported for multi-wordlist
            }
        }

        Ok(results)
    }

    /// Fuzz a single parameter value
    async fn fuzz_with_value(&self, value: &str) -> Result<FuzzResult> {
        let url = self.inject_value(&self.config.url_template, value);
        let body = self
            .config
            .body_template
            .as_ref()
            .map(|t| self.inject_value(t, value));

        let start = Instant::now();

        let mut request = self.client.request(self.config.method.clone(), &url);

        // Add headers
        for (key, val) in &self.config.headers {
            request = request.header(key, self.inject_value(val, value));
        }

        // Add body if present
        if let Some(body_content) = body {
            request = request.body(body_content);
        }

        let response = request.send().await?;
        let elapsed = start.elapsed().as_millis() as u64;

        let status_code = response.status().as_u16();
        let size = response.content_length().unwrap_or(0) as usize;
        let is_redirect = (300..400).contains(&status_code);
        let redirect_location = if is_redirect {
            response
                .headers()
                .get("Location")
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        } else {
            None
        };

        Ok(FuzzResult {
            path: value.to_string(),
            status_code,
            size,
            response_time: elapsed,
            is_redirect,
            redirect_location,
            depth: 0,
        })
    }

    /// Clusterbomb mode - test all combinations
    async fn fuzz_clusterbomb(&self, wordlists: Vec<Vec<String>>) -> Result<Vec<FuzzResult>> {
        let mut results = Vec::new();

        if wordlists.len() != 2 {
            return Ok(results);
        }

        for word1 in &wordlists[0] {
            for word2 in &wordlists[1] {
                let url = self.inject_multi_values(&self.config.url_template, &[word1, word2]);
                let result = self.fuzz_url(&url, &format!("{}×{}", word1, word2)).await?;

                if let Some(filter) = &self.config.filter {
                    if self.matches_filter(&result, filter) {
                        results.push(result);
                    }
                } else {
                    results.push(result);
                }
            }
        }

        Ok(results)
    }

    /// Pitchfork mode - iterate wordlists together
    async fn fuzz_pitchfork(&self, wordlists: Vec<Vec<String>>) -> Result<Vec<FuzzResult>> {
        let mut results = Vec::new();

        if wordlists.is_empty() {
            return Ok(results);
        }

        let min_len = wordlists.iter().map(|w| w.len()).min().unwrap_or(0);

        for i in 0..min_len {
            let values: Vec<&str> = wordlists.iter().map(|w| w[i].as_str()).collect();

            let url = self.inject_multi_values(&self.config.url_template, &values);
            let result = self.fuzz_url(&url, &values.join(",")).await?;

            if let Some(filter) = &self.config.filter {
                if self.matches_filter(&result, filter) {
                    results.push(result);
                }
            } else {
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Fuzz a specific URL
    async fn fuzz_url(&self, url: &str, label: &str) -> Result<FuzzResult> {
        let start = Instant::now();

        let response = self
            .client
            .request(self.config.method.clone(), url)
            .send()
            .await?;

        let elapsed = start.elapsed().as_millis() as u64;

        let status_code = response.status().as_u16();
        let size = response.content_length().unwrap_or(0) as usize;
        let is_redirect = (300..400).contains(&status_code);

        Ok(FuzzResult {
            path: label.to_string(),
            status_code,
            size,
            response_time: elapsed,
            is_redirect,
            redirect_location: None,
            depth: 0,
        })
    }

    /// Inject a single value into template (replaces FUZZ keyword)
    fn inject_value(&self, template: &str, value: &str) -> String {
        match self.config.mode {
            InjectionMode::Replace => template.replace("FUZZ", value),
            _ => template.replace("FUZZ", value),
        }
    }

    /// Inject multiple values into template (replaces FUZZ1, FUZZ2, etc.)
    fn inject_multi_values(&self, template: &str, values: &[&str]) -> String {
        let mut result = template.to_string();

        for (i, value) in values.iter().enumerate() {
            let keyword = format!("FUZZ{}", i + 1);
            result = result.replace(&keyword, value);
        }

        // Also replace plain FUZZ with first value
        if !values.is_empty() {
            result = result.replace("FUZZ", values[0]);
        }

        result
    }

    /// Check if result matches filter
    fn matches_filter(&self, result: &FuzzResult, filter: &ResponseFilter) -> bool {
        // Status code filter
        if !filter.status_codes.is_empty() && !filter.status_codes.contains(&result.status_code) {
            return false;
        }

        // Size filter
        if let Some(min_size) = filter.min_size {
            if result.size < min_size {
                return false;
            }
        }

        if let Some(max_size) = filter.max_size {
            if result.size > max_size {
                return false;
            }
        }

        // Response time filter would go here if needed

        true
    }
}

/// Parameter discovery - find which parameters exist
pub struct ParamDiscovery {
    base_url: String,
    client: Client,
}

impl ParamDiscovery {
    /// Create a new parameter discovery instance
    pub fn new(base_url: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        Ok(Self { base_url, client })
    }

    /// Discover GET parameters
    pub async fn discover_get_params(&self, param_wordlist: Vec<String>) -> Result<Vec<String>> {
        let mut discovered = Vec::new();

        for param in param_wordlist {
            let url = format!("{}?{}=test", self.base_url, param);

            if let Ok(response) = self.client.get(&url).send().await {
                if response.status().is_success() {
                    discovered.push(param);
                }
            }
        }

        Ok(discovered)
    }

    /// Discover POST parameters
    pub async fn discover_post_params(&self, param_wordlist: Vec<String>) -> Result<Vec<String>> {
        let mut discovered = Vec::new();

        for param in param_wordlist {
            let body = format!("{}=test", param);

            if let Ok(response) = self
                .client
                .post(&self.base_url)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body)
                .send()
                .await
            {
                if response.status().is_success() {
                    discovered.push(param);
                }
            }
        }

        Ok(discovered)
    }

    /// Discover JSON parameters
    pub async fn discover_json_params(&self, param_wordlist: Vec<String>) -> Result<Vec<String>> {
        let mut discovered = Vec::new();

        for param in param_wordlist {
            let json = format!("{{\"{}\": \"test\"}}", param);

            if let Ok(response) = self
                .client
                .post(&self.base_url)
                .header("Content-Type", "application/json")
                .body(json)
                .send()
                .await
            {
                if response.status().is_success() {
                    discovered.push(param);
                }
            }
        }

        Ok(discovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_injection_mode() {
        assert_ne!(InjectionMode::Sniper, InjectionMode::Clusterbomb);
        assert_eq!(InjectionMode::Sniper, InjectionMode::Sniper);
    }

    #[test]
    fn test_injection_location() {
        assert_ne!(InjectionLocation::QueryString, InjectionLocation::PostBody);
        assert_eq!(InjectionLocation::Headers, InjectionLocation::Headers);
    }

    #[test]
    fn test_inject_single_value() {
        let config = ParamFuzzConfig {
            url_template: "https://example.com/page?id=FUZZ".to_string(),
            mode: InjectionMode::Replace,
            ..Default::default()
        };

        let fuzzer = ParamFuzzer::new(config).unwrap();
        let result = fuzzer.inject_value("https://example.com/page?id=FUZZ", "123");
        assert_eq!(result, "https://example.com/page?id=123");
    }

    #[test]
    fn test_inject_multi_values() {
        let config = ParamFuzzConfig {
            url_template: "https://example.com/FUZZ1/FUZZ2".to_string(),
            mode: InjectionMode::Clusterbomb,
            ..Default::default()
        };

        let fuzzer = ParamFuzzer::new(config).unwrap();
        let result =
            fuzzer.inject_multi_values("https://example.com/FUZZ1/FUZZ2", &["admin", "users"]);
        assert_eq!(result, "https://example.com/admin/users");
    }

    #[test]
    fn test_matches_filter_status() {
        let config = ParamFuzzConfig::default();
        let fuzzer = ParamFuzzer::new(config).unwrap();

        let result = FuzzResult {
            path: "test".to_string(),
            status_code: 200,
            size: 1000,
            response_time: 100,
            is_redirect: false,
            redirect_location: None,
            depth: 0,
        };

        let filter = ResponseFilter {
            status_codes: vec![200, 201],
            exclude_status_codes: Vec::new(),
            min_size: None,
            max_size: None,
            exclude_sizes: Vec::new(),
            include_regex: None,
            exclude_regex: None,
            min_time: None,
            max_time: None,
        };

        assert!(fuzzer.matches_filter(&result, &filter));
    }

    #[test]
    fn test_matches_filter_size() {
        let config = ParamFuzzConfig::default();
        let fuzzer = ParamFuzzer::new(config).unwrap();

        let result = FuzzResult {
            path: "test".to_string(),
            status_code: 200,
            size: 500,
            response_time: 100,
            is_redirect: false,
            redirect_location: None,
            depth: 0,
        };

        let filter = ResponseFilter {
            status_codes: Vec::new(),
            exclude_status_codes: Vec::new(),
            min_size: Some(100),
            max_size: Some(1000),
            exclude_sizes: Vec::new(),
            include_regex: None,
            exclude_regex: None,
            min_time: None,
            max_time: None,
        };

        assert!(fuzzer.matches_filter(&result, &filter));
    }
}
