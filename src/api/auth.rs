use actix_web::dev::ServiceRequest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use chrono::{DateTime, Utc};

/// API key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Map of API key -> key metadata
    pub keys: HashMap<String, ApiKeyInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

impl ApiKeyConfig {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub fn add_key(&mut self, key: String, name: String, scopes: Vec<String>) {
        self.keys.insert(key, ApiKeyInfo {
            name,
            enabled: true,
            scopes,
            created_at: Some(Utc::now().to_rfc3339()),
        });
    }

    pub fn validate(&self, key: &str) -> Option<&ApiKeyInfo> {
        self.keys.get(key).filter(|info| info.enabled)
    }
}

/// Rate limiter state per API key or IP
#[derive(Debug)]
pub struct RateLimiterState {
    requests: HashMap<String, Vec<DateTime<Utc>>>,
    max_requests: u64,
    window_secs: u64,
}

impl RateLimiterState {
    pub fn new(max_requests: u64, window_secs: u64) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests,
            window_secs,
        }
    }

    pub fn check_and_record(&mut self, key: &str) -> bool {
        let now = Utc::now();
        let window = chrono::Duration::seconds(self.window_secs as i64);
        let cutoff = now - window;

        let entries = self.requests.entry(key.to_string()).or_default();
        entries.retain(|t| *t > cutoff);

        if entries.len() as u64 >= self.max_requests {
            return false;
        }

        entries.push(now);
        true
    }

    pub fn remaining(&self, key: &str) -> u64 {
        let now = Utc::now();
        let window = chrono::Duration::seconds(self.window_secs as i64);
        let cutoff = now - window;

        match self.requests.get(key) {
            Some(entries) => {
                let count = entries.iter().filter(|t| **t > cutoff).count() as u64;
                self.max_requests.saturating_sub(count)
            }
            None => self.max_requests,
        }
    }
}

/// Extract bearer token or X-API-Key header from request
pub fn extract_api_key(req: &ServiceRequest) -> Option<String> {
    // Check Authorization: Bearer <key>
    if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Some(auth_str[7..].to_string());
            }
        }
    }

    // Check X-API-Key header
    if let Some(api_key) = req.headers().get("X-API-Key") {
        if let Ok(key) = api_key.to_str() {
            return Some(key.to_string());
        }
    }

    // Check query parameter
    if let Some(query) = req.uri().query() {
        for param in query.split('&') {
            if let Some((k, v)) = param.split_once('=') {
                if k == "api_key" {
                    return Some(v.to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_config_validation() {
        let mut config = ApiKeyConfig::new();
        config.add_key(
            "test-key-123".to_string(),
            "Test Key".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );

        assert!(config.validate("test-key-123").is_some());
        assert!(config.validate("invalid-key").is_none());
    }

    #[test]
    fn test_api_key_disabled() {
        let mut config = ApiKeyConfig::new();
        config.add_key(
            "disabled-key".to_string(),
            "Disabled".to_string(),
            vec![],
        );
        config.keys.get_mut("disabled-key").unwrap().enabled = false;

        assert!(config.validate("disabled-key").is_none());
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiterState::new(5, 60);
        assert!(limiter.check_and_record("user1"));
        assert!(limiter.check_and_record("user1"));
        assert!(limiter.check_and_record("user1"));
        assert_eq!(limiter.remaining("user1"), 2);
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiterState::new(3, 60);
        assert!(limiter.check_and_record("user2"));
        assert!(limiter.check_and_record("user2"));
        assert!(limiter.check_and_record("user2"));
        assert!(!limiter.check_and_record("user2"));
        assert_eq!(limiter.remaining("user2"), 0);
    }

    #[test]
    fn test_rate_limiter_independent_keys() {
        let mut limiter = RateLimiterState::new(2, 60);
        assert!(limiter.check_and_record("userA"));
        assert!(limiter.check_and_record("userA"));
        assert!(!limiter.check_and_record("userA"));

        assert!(limiter.check_and_record("userB"));
        assert_eq!(limiter.remaining("userB"), 1);
    }

    #[test]
    fn test_rate_limiter_unknown_key_has_full_quota() {
        let limiter = RateLimiterState::new(100, 60);
        assert_eq!(limiter.remaining("unknown"), 100);
    }
}
