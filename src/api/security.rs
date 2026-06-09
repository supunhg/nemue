use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeadersConfig {
    pub x_content_type_options: bool,
    pub x_frame_options: XFrameOptions,
    pub x_xss_protection: bool,
    pub strict_transport_security: Option<HstsConfig>,
    pub content_security_policy: Option<String>,
    pub referrer_policy: ReferrerPolicy,
    pub permissions_policy: Option<String>,
    pub cross_origin_opener_policy: Option<CoopPolicy>,
    pub cross_origin_resource_policy: Option<CorpPolicy>,
    pub cross_origin_embedder_policy: Option<CoepPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum XFrameOptions {
    Deny,
    SameOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HstsConfig {
    pub max_age: u64,
    pub include_subdomains: bool,
    pub preload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoopPolicy {
    UnsafeNone,
    SameOriginAllowPopups,
    SameOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorpPolicy {
    SameSite,
    SameOrigin,
    CrossOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoepPolicy {
    UnsafeNone,
    RequireCorp,
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            x_content_type_options: true,
            x_frame_options: XFrameOptions::Deny,
            x_xss_protection: true,
            strict_transport_security: Some(HstsConfig::default()),
            content_security_policy: Some("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".to_string()),
            referrer_policy: ReferrerPolicy::StrictOriginWhenCrossOrigin,
            permissions_policy: Some("accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()".to_string()),
            cross_origin_opener_policy: Some(CoopPolicy::SameOrigin),
            cross_origin_resource_policy: Some(CorpPolicy::SameOrigin),
            cross_origin_embedder_policy: Some(CoepPolicy::RequireCorp),
        }
    }
}

impl SecurityHeadersConfig {
    pub fn development() -> Self {
        Self {
            x_content_type_options: true,
            x_frame_options: XFrameOptions::SameOrigin,
            x_xss_protection: true,
            strict_transport_security: None,
            content_security_policy: None,
            referrer_policy: ReferrerPolicy::NoReferrerWhenDowngrade,
            permissions_policy: None,
            cross_origin_opener_policy: None,
            cross_origin_resource_policy: None,
            cross_origin_embedder_policy: None,
        }
    }

    pub fn minimal() -> Self {
        Self {
            x_content_type_options: true,
            x_frame_options: XFrameOptions::Deny,
            x_xss_protection: false,
            strict_transport_security: None,
            content_security_policy: None,
            referrer_policy: ReferrerPolicy::NoReferrer,
            permissions_policy: None,
            cross_origin_opener_policy: None,
            cross_origin_resource_policy: None,
            cross_origin_embedder_policy: None,
        }
    }

    pub fn to_header_pairs(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        if self.x_content_type_options {
            headers.push(("X-Content-Type-Options".to_string(), "nosniff".to_string()));
        }

        let xfo = match &self.x_frame_options {
            XFrameOptions::Deny => "DENY",
            XFrameOptions::SameOrigin => "SAMEORIGIN",
        };
        headers.push(("X-Frame-Options".to_string(), xfo.to_string()));

        if self.x_xss_protection {
            headers.push(("X-XSS-Protection".to_string(), "1; mode=block".to_string()));
        }

        if let Some(hsts) = &self.strict_transport_security {
            let mut value = format!("max-age={}", hsts.max_age);
            if hsts.include_subdomains {
                value.push_str("; includeSubDomains");
            }
            if hsts.preload {
                value.push_str("; preload");
            }
            headers.push(("Strict-Transport-Security".to_string(), value));
        }

        if let Some(csp) = &self.content_security_policy {
            headers.push(("Content-Security-Policy".to_string(), csp.clone()));
        }

        let rp = match &self.referrer_policy {
            ReferrerPolicy::NoReferrer => "no-referrer",
            ReferrerPolicy::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            ReferrerPolicy::Origin => "origin",
            ReferrerPolicy::OriginWhenCrossOrigin => "origin-when-cross-origin",
            ReferrerPolicy::SameOrigin => "same-origin",
            ReferrerPolicy::StrictOrigin => "strict-origin",
            ReferrerPolicy::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            ReferrerPolicy::UnsafeUrl => "unsafe-url",
        };
        headers.push(("Referrer-Policy".to_string(), rp.to_string()));

        if let Some(pp) = &self.permissions_policy {
            headers.push(("Permissions-Policy".to_string(), pp.clone()));
        }

        if let Some(coop) = &self.cross_origin_opener_policy {
            let value = match coop {
                CoopPolicy::UnsafeNone => "unsafe-none",
                CoopPolicy::SameOriginAllowPopups => "same-origin-allow-popups",
                CoopPolicy::SameOrigin => "same-origin",
            };
            headers.push(("Cross-Origin-Opener-Policy".to_string(), value.to_string()));
        }

        if let Some(corp) = &self.cross_origin_resource_policy {
            let value = match corp {
                CorpPolicy::SameSite => "same-site",
                CorpPolicy::SameOrigin => "same-origin",
                CorpPolicy::CrossOrigin => "cross-origin",
            };
            headers.push(("Cross-Origin-Resource-Policy".to_string(), value.to_string()));
        }

        if let Some(coep) = &self.cross_origin_embedder_policy {
            let value = match coep {
                CoepPolicy::UnsafeNone => "unsafe-none",
                CoepPolicy::RequireCorp => "require-corp",
            };
            headers.push(("Cross-Origin-Embedder-Policy".to_string(), value.to_string()));
        }

        headers
    }
}

impl Default for HstsConfig {
    fn default() -> Self {
        Self {
            max_age: 31536000,
            include_subdomains: true,
            preload: true,
        }
    }
}

/// CORS configuration for API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub exposed_headers: Vec<String>,
    pub max_age: u32,
    pub allow_credentials: bool,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".to_string()],
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Authorization".to_string(),
                "Content-Type".to_string(),
                "X-API-Key".to_string(),
                "X-Request-ID".to_string(),
            ],
            exposed_headers: vec![
                "X-RateLimit-Limit".to_string(),
                "X-RateLimit-Remaining".to_string(),
                "X-RateLimit-Reset".to_string(),
            ],
            max_age: 3600,
            allow_credentials: false,
        }
    }
}

impl CorsConfig {
    pub fn strict(allowed_origins: Vec<String>) -> Self {
        Self {
            allowed_origins,
            allow_credentials: true,
            ..Self::default()
        }
    }

    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.contains(&"*".to_string())
            || self.allowed_origins.iter().any(|o| o == origin)
    }
}

/// Security middleware configuration
pub struct SecurityConfig {
    pub headers: SecurityHeadersConfig,
    pub cors: CorsConfig,
    pub rate_limit_enabled: bool,
    pub request_id_enabled: bool,
    pub audit_logging_enabled: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            headers: SecurityHeadersConfig::default(),
            cors: CorsConfig::default(),
            rate_limit_enabled: true,
            request_id_enabled: true,
            audit_logging_enabled: true,
        }
    }
}

impl SecurityConfig {
    pub fn production() -> Self {
        Self {
            headers: SecurityHeadersConfig::default(),
            cors: CorsConfig::strict(vec!["https://app.example.com".to_string()]),
            rate_limit_enabled: true,
            request_id_enabled: true,
            audit_logging_enabled: true,
        }
    }

    pub fn development() -> Self {
        Self {
            headers: SecurityHeadersConfig::development(),
            cors: CorsConfig {
                allowed_origins: vec!["*".to_string()],
                allow_credentials: false,
                ..CorsConfig::default()
            },
            rate_limit_enabled: false,
            request_id_enabled: true,
            audit_logging_enabled: true,
        }
    }
}

/// Validate that a CSP header is well-formed
pub fn validate_csp(csp: &str) -> Result<(), String> {
    if csp.is_empty() {
        return Err("CSP cannot be empty".to_string());
    }

    let valid_directives = [
        "default-src", "script-src", "style-src", "img-src", "connect-src",
        "font-src", "object-src", "media-src", "frame-src", "sandbox",
        "report-uri", "child-src", "form-action", "frame-ancestors",
        "plugin-types", "base-uri", "report-to", "worker-src",
        "manifest-src", "prefetch-src", "navigate-to",
    ];

    for directive in csp.split(';') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }

        let name = directive.split_whitespace().next().unwrap_or("");
        if !valid_directives.contains(&name) && !name.starts_with("nonce-") {
            return Err(format!("Unknown CSP directive: {}", name));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_security_headers() {
        let config = SecurityHeadersConfig::default();
        let headers = config.to_header_pairs();

        assert!(headers.iter().any(|(k, _)| k == "X-Content-Type-Options"));
        assert!(headers.iter().any(|(k, _)| k == "X-Frame-Options"));
        assert!(headers.iter().any(|(k, _)| k == "Strict-Transport-Security"));
        assert!(headers.iter().any(|(k, _)| k == "Content-Security-Policy"));
        assert!(headers.iter().any(|(k, _)| k == "Referrer-Policy"));
        assert!(headers.iter().any(|(k, _)| k == "Permissions-Policy"));
    }

    #[test]
    fn test_hsts_header_format() {
        let config = SecurityHeadersConfig::default();
        let headers = config.to_header_pairs();

        let hsts = headers.iter().find(|(k, _)| k == "Strict-Transport-Security").unwrap();
        assert!(hsts.1.contains("max-age="));
        assert!(hsts.1.contains("includeSubDomains"));
        assert!(hsts.1.contains("preload"));
    }

    #[test]
    fn test_csp_header_present() {
        let config = SecurityHeadersConfig::default();
        let headers = config.to_header_pairs();

        let csp = headers.iter().find(|(k, _)| k == "Content-Security-Policy").unwrap();
        assert!(csp.1.contains("default-src 'self'"));
        assert!(csp.1.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn test_development_config_relaxed() {
        let config = SecurityHeadersConfig::development();
        let headers = config.to_header_pairs();

        assert!(!headers.iter().any(|(k, _)| k == "Strict-Transport-Security"));
        assert!(!headers.iter().any(|(k, _)| k == "Content-Security-Policy"));
    }

    #[test]
    fn test_minimal_config() {
        let config = SecurityHeadersConfig::minimal();
        let headers = config.to_header_pairs();

        assert!(headers.iter().any(|(k, _)| k == "X-Content-Type-Options"));
        assert!(!headers.iter().any(|(k, _)| k == "Strict-Transport-Security"));
    }

    #[test]
    fn test_x_frame_options_deny() {
        let config = SecurityHeadersConfig::default();
        let headers = config.to_header_pairs();
        let xfo = headers.iter().find(|(k, _)| k == "X-Frame-Options").unwrap();
        assert_eq!(xfo.1, "DENY");
    }

    #[test]
    fn test_cors_default_allows_all() {
        let cors = CorsConfig::default();
        assert!(cors.is_origin_allowed("https://anything.com"));
        assert!(cors.is_origin_allowed("http://localhost:3000"));
    }

    #[test]
    fn test_cors_strict_origin() {
        let cors = CorsConfig::strict(vec!["https://app.example.com".to_string()]);
        assert!(cors.is_origin_allowed("https://app.example.com"));
        assert!(!cors.is_origin_allowed("https://evil.com"));
    }

    #[test]
    fn test_validate_csp_valid() {
        assert!(validate_csp("default-src 'self'; script-src 'self'").is_ok());
        assert!(validate_csp("frame-ancestors 'none'").is_ok());
    }

    #[test]
    fn test_validate_csp_empty() {
        assert!(validate_csp("").is_err());
    }

    #[test]
    fn test_validate_csp_unknown_directive() {
        assert!(validate_csp("invalid-directive 'self'").is_err());
    }

    #[test]
    fn test_coop_header() {
        let config = SecurityHeadersConfig::default();
        let headers = config.to_header_pairs();
        let coop = headers.iter().find(|(k, _)| k == "Cross-Origin-Opener-Policy").unwrap();
        assert_eq!(coop.1, "same-origin");
    }

    #[test]
    fn test_corp_header() {
        let config = SecurityHeadersConfig::default();
        let headers = config.to_header_pairs();
        let corp = headers.iter().find(|(k, _)| k == "Cross-Origin-Resource-Policy").unwrap();
        assert_eq!(corp.1, "same-origin");
    }

    #[test]
    fn test_coep_header() {
        let config = SecurityHeadersConfig::default();
        let headers = config.to_header_pairs();
        let coep = headers.iter().find(|(k, _)| k == "Cross-Origin-Embedder-Policy").unwrap();
        assert_eq!(coep.1, "require-corp");
    }

    #[test]
    fn test_security_config_production() {
        let config = SecurityConfig::production();
        assert!(config.rate_limit_enabled);
        assert!(config.audit_logging_enabled);
        assert!(config.request_id_enabled);
    }

    #[test]
    fn test_security_config_development() {
        let config = SecurityConfig::development();
        assert!(!config.rate_limit_enabled);
    }

    #[test]
    fn test_referrer_policy_variants() {
        for variant in [
            ReferrerPolicy::NoReferrer,
            ReferrerPolicy::StrictOriginWhenCrossOrigin,
            ReferrerPolicy::UnsafeUrl,
        ] {
            let config = SecurityHeadersConfig {
                referrer_policy: variant,
                ..SecurityHeadersConfig::minimal()
            };
            let headers = config.to_header_pairs();
            assert!(headers.iter().any(|(k, _)| k == "Referrer-Policy"));
        }
    }
}
