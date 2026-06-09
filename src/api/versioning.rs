use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ApiVersion {
    V1,
    V2,
}

impl ApiVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiVersion::V1 => "v1",
            ApiVersion::V2 => "v2",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "v1" | "1" => Some(ApiVersion::V1),
            "v2" | "2" => Some(ApiVersion::V2),
            _ => None,
        }
    }

    pub fn is_supported(&self) -> bool {
        let config = VersionConfig::default();
        config.is_version_supported(self)
    }
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionConfig {
    pub current: ApiVersion,
    pub supported: Vec<ApiVersion>,
    pub deprecated: Vec<DeprecatedVersion>,
    pub default_version: ApiVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecatedVersion {
    pub version: ApiVersion,
    pub deprecated_at: DateTime<Utc>,
    pub sunset_at: Option<DateTime<Utc>>,
    pub message: String,
    pub migration_guide: Option<String>,
}

impl Default for VersionConfig {
    fn default() -> Self {
        Self {
            current: ApiVersion::V2,
            supported: vec![ApiVersion::V1, ApiVersion::V2],
            deprecated: vec![DeprecatedVersion {
                version: ApiVersion::V1,
                deprecated_at: Utc::now(),
                sunset_at: None,
                message: "API v1 is deprecated. Please migrate to v2.".to_string(),
                migration_guide: Some("https://docs.nemue.dev/api/migration-v1-v2".to_string()),
            }],
            default_version: ApiVersion::V2,
        }
    }
}

impl VersionConfig {
    pub fn is_version_supported(&self, version: &ApiVersion) -> bool {
        self.supported.contains(version)
    }

    pub fn is_deprecated(&self, version: &ApiVersion) -> bool {
        self.deprecated.iter().any(|d| d.version == *version)
    }

    pub fn get_deprecation_info(&self, version: &ApiVersion) -> Option<&DeprecatedVersion> {
        self.deprecated.iter().find(|d| d.version == *version)
    }

    pub fn is_sunset(&self, version: &ApiVersion) -> bool {
        if let Some(info) = self.get_deprecation_info(version) {
            if let Some(sunset) = info.sunset_at {
                return Utc::now() > sunset;
            }
        }
        false
    }
}

#[derive(Debug, Clone)]
pub struct VersionNegotiator {
    config: VersionConfig,
}

impl VersionNegotiator {
    pub fn new(config: VersionConfig) -> Self {
        Self { config }
    }

    pub fn negotiate_from_path(&self, path: &str) -> Result<ApiVersion, VersionError> {
        if path.starts_with("/api/v1/") || path == "/api/v1" {
            return self.validate_version(ApiVersion::V1);
        }
        if path.starts_with("/api/v2/") || path == "/api/v2" {
            return self.validate_version(ApiVersion::V2);
        }
        Ok(self.config.default_version.clone())
    }

    pub fn negotiate_from_header(&self, header_value: &str) -> Result<ApiVersion, VersionError> {
        let version_str = header_value.trim();
        match ApiVersion::from_str(version_str) {
            Some(version) => self.validate_version(version),
            None => Err(VersionError::InvalidVersion(format!(
                "Unknown API version: '{}'. Supported: v1, v2",
                version_str
            ))),
        }
    }

    pub fn negotiate_from_query(&self, query: &str) -> Result<ApiVersion, VersionError> {
        for param in query.split('&') {
            if let Some((key, value)) = param.split_once('=') {
                if key == "api_version" || key == "version" {
                    return self.negotiate_from_header(value);
                }
            }
        }
        Ok(self.config.default_version.clone())
    }

    fn validate_version(&self, version: ApiVersion) -> Result<ApiVersion, VersionError> {
        if !self.config.is_version_supported(&version) {
            return Err(VersionError::UnsupportedVersion(format!(
                "API version {} is no longer supported",
                version
            )));
        }

        if self.config.is_sunset(&version) {
            return Err(VersionError::SunsetVersion(format!(
                "API version {} has been sunset and is no longer available",
                version
            )));
        }

        Ok(version)
    }

    pub fn get_response_headers(&self, version: &ApiVersion) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("X-API-Version".to_string(), version.as_str().to_string());
        headers.insert("X-API-Current-Version".to_string(), self.config.current.as_str().to_string());

        if let Some(info) = self.config.get_deprecation_info(version) {
            headers.insert("X-API-Deprecated".to_string(), "true".to_string());
            headers.insert("X-API-Deprecation-Message".to_string(), info.message.clone());
            if let Some(sunset) = info.sunset_at {
                headers.insert("X-API-Sunset-Date".to_string(), sunset.to_rfc3339());
            }
            if let Some(guide) = &info.migration_guide {
                headers.insert("X-API-Migration-Guide".to_string(), guide.clone());
            }
        }

        headers
    }
}

impl Default for VersionNegotiator {
    fn default() -> Self {
        Self::new(VersionConfig::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub current: String,
    pub supported: Vec<String>,
    pub deprecated: Vec<DeprecatedVersionInfo>,
    pub default_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeprecatedVersionInfo {
    pub version: String,
    pub deprecated_at: String,
    pub sunset_at: Option<String>,
    pub message: String,
    pub migration_guide: Option<String>,
}

impl VersionInfo {
    pub fn from_config(config: &VersionConfig) -> Self {
        Self {
            current: config.current.as_str().to_string(),
            supported: config.supported.iter().map(|v| v.as_str().to_string()).collect(),
            deprecated: config.deprecated.iter().map(|d| DeprecatedVersionInfo {
                version: d.version.as_str().to_string(),
                deprecated_at: d.deprecated_at.to_rfc3339(),
                sunset_at: d.sunset_at.map(|dt| dt.to_rfc3339()),
                message: d.message.clone(),
                migration_guide: d.migration_guide.clone(),
            }).collect(),
            default_version: config.default_version.as_str().to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionResponse {
    pub api_version: VersionInfo,
    pub server_version: String,
}

#[derive(Debug, Clone)]
pub enum VersionError {
    InvalidVersion(String),
    UnsupportedVersion(String),
    SunsetVersion(String),
}

impl std::fmt::Display for VersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionError::InvalidVersion(msg) => write!(f, "Invalid version: {}", msg),
            VersionError::UnsupportedVersion(msg) => write!(f, "Unsupported version: {}", msg),
            VersionError::SunsetVersion(msg) => write!(f, "Sunset version: {}", msg),
        }
    }
}

impl std::error::Error for VersionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_version_from_str() {
        assert_eq!(ApiVersion::from_str("v1"), Some(ApiVersion::V1));
        assert_eq!(ApiVersion::from_str("v2"), Some(ApiVersion::V2));
        assert_eq!(ApiVersion::from_str("1"), Some(ApiVersion::V1));
        assert_eq!(ApiVersion::from_str("2"), Some(ApiVersion::V2));
        assert_eq!(ApiVersion::from_str("V1"), Some(ApiVersion::V1));
        assert_eq!(ApiVersion::from_str("v3"), None);
    }

    #[test]
    fn test_api_version_as_str() {
        assert_eq!(ApiVersion::V1.as_str(), "v1");
        assert_eq!(ApiVersion::V2.as_str(), "v2");
    }

    #[test]
    fn test_api_version_display() {
        assert_eq!(format!("{}", ApiVersion::V1), "v1");
        assert_eq!(format!("{}", ApiVersion::V2), "v2");
    }

    #[test]
    fn test_api_version_is_supported() {
        assert!(ApiVersion::V1.is_supported());
        assert!(ApiVersion::V2.is_supported());
    }

    #[test]
    fn test_version_config_default() {
        let config = VersionConfig::default();
        assert_eq!(config.current, ApiVersion::V2);
        assert_eq!(config.default_version, ApiVersion::V2);
        assert!(config.supported.contains(&ApiVersion::V1));
        assert!(config.supported.contains(&ApiVersion::V2));
    }

    #[test]
    fn test_version_config_is_deprecated() {
        let config = VersionConfig::default();
        assert!(config.is_deprecated(&ApiVersion::V1));
        assert!(!config.is_deprecated(&ApiVersion::V2));
    }

    #[test]
    fn test_version_config_is_sunset() {
        let config = VersionConfig::default();
        assert!(!config.is_sunset(&ApiVersion::V1));
    }

    #[test]
    fn test_version_config_with_sunset() {
        let config = VersionConfig {
            current: ApiVersion::V2,
            supported: vec![ApiVersion::V1, ApiVersion::V2],
            deprecated: vec![DeprecatedVersion {
                version: ApiVersion::V1,
                deprecated_at: Utc::now(),
                sunset_at: Some(Utc::now() - chrono::Duration::days(1)),
                message: "V1 sunset".to_string(),
                migration_guide: None,
            }],
            default_version: ApiVersion::V2,
        };
        assert!(config.is_sunset(&ApiVersion::V1));
        assert!(!config.is_sunset(&ApiVersion::V2));
    }

    #[test]
    fn test_negotiate_from_path_v1() {
        let negotiator = VersionNegotiator::default();
        let version = negotiator.negotiate_from_path("/api/v1/scans").unwrap();
        assert_eq!(version, ApiVersion::V1);
    }

    #[test]
    fn test_negotiate_from_path_v2() {
        let negotiator = VersionNegotiator::default();
        let version = negotiator.negotiate_from_path("/api/v2/scans").unwrap();
        assert_eq!(version, ApiVersion::V2);
    }

    #[test]
    fn test_negotiate_from_path_default() {
        let negotiator = VersionNegotiator::default();
        let version = negotiator.negotiate_from_path("/health").unwrap();
        assert_eq!(version, ApiVersion::V2);
    }

    #[test]
    fn test_negotiate_from_header() {
        let negotiator = VersionNegotiator::default();
        assert_eq!(negotiator.negotiate_from_header("v1").unwrap(), ApiVersion::V1);
        assert_eq!(negotiator.negotiate_from_header("v2").unwrap(), ApiVersion::V2);
        assert!(negotiator.negotiate_from_header("v3").is_err());
    }

    #[test]
    fn test_negotiate_from_query() {
        let negotiator = VersionNegotiator::default();
        let version = negotiator.negotiate_from_query("api_version=v1&other=123").unwrap();
        assert_eq!(version, ApiVersion::V1);
    }

    #[test]
    fn test_negotiate_from_query_default() {
        let negotiator = VersionNegotiator::default();
        let version = negotiator.negotiate_from_query("other=123").unwrap();
        assert_eq!(version, ApiVersion::V2);
    }

    #[test]
    fn test_response_headers_no_deprecation() {
        let negotiator = VersionNegotiator::default();
        let headers = negotiator.get_response_headers(&ApiVersion::V2);
        assert_eq!(headers.get("X-API-Version").unwrap(), "v2");
        assert!(!headers.contains_key("X-API-Deprecated"));
    }

    #[test]
    fn test_response_headers_with_deprecation() {
        let negotiator = VersionNegotiator::default();
        let headers = negotiator.get_response_headers(&ApiVersion::V1);
        assert_eq!(headers.get("X-API-Version").unwrap(), "v1");
        assert_eq!(headers.get("X-API-Deprecated").unwrap(), "true");
        assert!(headers.contains_key("X-API-Deprecation-Message"));
    }

    #[test]
    fn test_version_info_from_config() {
        let config = VersionConfig::default();
        let info = VersionInfo::from_config(&config);
        assert_eq!(info.current, "v2");
        assert_eq!(info.default_version, "v2");
        assert_eq!(info.supported.len(), 2);
        assert_eq!(info.deprecated.len(), 1);
    }

    #[test]
    fn test_version_response_serialize() {
        let config = VersionConfig::default();
        let resp = VersionResponse {
            api_version: VersionInfo::from_config(&config),
            server_version: "1.0.0".to_string(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("v2"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    fn test_version_error_display() {
        let err = VersionError::InvalidVersion("bad".to_string());
        assert!(format!("{}", err).contains("Invalid version"));

        let err = VersionError::UnsupportedVersion("v0".to_string());
        assert!(format!("{}", err).contains("Unsupported version"));

        let err = VersionError::SunsetVersion("v1".to_string());
        assert!(format!("{}", err).contains("Sunset version"));
    }

    #[test]
    fn test_version_error_is_error() {
        let err: Box<dyn std::error::Error> = Box::new(VersionError::InvalidVersion("test".to_string()));
        assert!(err.to_string().contains("Invalid version"));
    }

    #[test]
    fn test_negotiate_from_path_exact_v1() {
        let negotiator = VersionNegotiator::default();
        assert_eq!(negotiator.negotiate_from_path("/api/v1").unwrap(), ApiVersion::V1);
    }

    #[test]
    fn test_negotiate_from_path_exact_v2() {
        let negotiator = VersionNegotiator::default();
        assert_eq!(negotiator.negotiate_from_path("/api/v2").unwrap(), ApiVersion::V2);
    }

    #[test]
    fn test_deprecated_version_serialize() {
        let dep = DeprecatedVersion {
            version: ApiVersion::V1,
            deprecated_at: Utc::now(),
            sunset_at: Some(Utc::now()),
            message: "test".to_string(),
            migration_guide: Some("https://example.com".to_string()),
        };
        let json = serde_json::to_string(&dep).unwrap();
        assert!(json.contains("v1"));
        assert!(json.contains("test"));
    }

    #[test]
    fn test_version_negotiator_default() {
        let negotiator = VersionNegotiator::default();
        assert_eq!(negotiator.config.current, ApiVersion::V2);
    }
}
