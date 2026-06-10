// Security Headers Analysis
// Checks for missing or misconfigured security headers

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Security header check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaderResult {
    pub header: String,
    pub present: bool,
    pub value: Option<String>,
    pub severity: Severity,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Security header analyzer
pub struct SecurityHeaderAnalyzer;

impl SecurityHeaderAnalyzer {
    /// Analyze HTTP response headers for security issues
    pub fn analyze(headers: &HashMap<String, String>) -> Vec<SecurityHeaderResult> {
        let mut results = Vec::new();

        // Check critical security headers
        results.push(Self::check_strict_transport_security(headers));
        results.push(Self::check_content_security_policy(headers));
        results.push(Self::check_x_frame_options(headers));
        results.push(Self::check_x_content_type_options(headers));
        results.push(Self::check_x_xss_protection(headers));
        results.push(Self::check_referrer_policy(headers));
        results.push(Self::check_permissions_policy(headers));

        // Check for information disclosure
        results.extend(Self::check_information_disclosure(headers));

        results
    }

    /// Check for Strict-Transport-Security header
    fn check_strict_transport_security(headers: &HashMap<String, String>) -> SecurityHeaderResult {
        let header_name = "strict-transport-security";

        if let Some(value) = Self::get_header_case_insensitive(headers, header_name) {
            // Check if max-age is sufficient
            let has_good_max_age = value.contains("max-age=")
                && Self::extract_max_age(&value).unwrap_or(0) >= 31536000; // 1 year

            let severity = if !has_good_max_age {
                Severity::Medium
            } else {
                Severity::Info
            };

            SecurityHeaderResult {
                header: "Strict-Transport-Security".to_string(),
                present: true,
                value: Some(value.clone()),
                severity,
                recommendation: if !has_good_max_age {
                    "Increase max-age to at least 31536000 (1 year)".to_string()
                } else {
                    "Header properly configured".to_string()
                },
            }
        } else {
            SecurityHeaderResult {
                header: "Strict-Transport-Security".to_string(),
                present: false,
                value: None,
                severity: Severity::High,
                recommendation:
                    "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header"
                        .to_string(),
            }
        }
    }

    /// Check for Content-Security-Policy header
    fn check_content_security_policy(headers: &HashMap<String, String>) -> SecurityHeaderResult {
        let header_name = "content-security-policy";

        if let Some(value) = Self::get_header_case_insensitive(headers, header_name) {
            // Check for unsafe directives
            let has_unsafe = value.contains("unsafe-inline") || value.contains("unsafe-eval");

            let severity = if has_unsafe {
                Severity::Medium
            } else {
                Severity::Info
            };

            SecurityHeaderResult {
                header: "Content-Security-Policy".to_string(),
                present: true,
                value: Some(value.clone()),
                severity,
                recommendation: if has_unsafe {
                    "Remove 'unsafe-inline' and 'unsafe-eval' directives".to_string()
                } else {
                    "Header properly configured".to_string()
                },
            }
        } else {
            SecurityHeaderResult {
                header: "Content-Security-Policy".to_string(),
                present: false,
                value: None,
                severity: Severity::High,
                recommendation: "Add CSP header to prevent XSS attacks".to_string(),
            }
        }
    }

    /// Check for X-Frame-Options header
    fn check_x_frame_options(headers: &HashMap<String, String>) -> SecurityHeaderResult {
        let header_name = "x-frame-options";

        if let Some(value) = Self::get_header_case_insensitive(headers, header_name) {
            let value_upper = value.to_uppercase();
            let is_valid = value_upper == "DENY" || value_upper == "SAMEORIGIN";

            SecurityHeaderResult {
                header: "X-Frame-Options".to_string(),
                present: true,
                value: Some(value.clone()),
                severity: if is_valid {
                    Severity::Info
                } else {
                    Severity::Medium
                },
                recommendation: if is_valid {
                    "Header properly configured".to_string()
                } else {
                    "Set to 'DENY' or 'SAMEORIGIN'".to_string()
                },
            }
        } else {
            SecurityHeaderResult {
                header: "X-Frame-Options".to_string(),
                present: false,
                value: None,
                severity: Severity::Medium,
                recommendation: "Add 'X-Frame-Options: DENY' to prevent clickjacking".to_string(),
            }
        }
    }

    /// Check for X-Content-Type-Options header
    fn check_x_content_type_options(headers: &HashMap<String, String>) -> SecurityHeaderResult {
        let header_name = "x-content-type-options";

        if let Some(value) = Self::get_header_case_insensitive(headers, header_name) {
            let is_nosniff = value.to_lowercase() == "nosniff";

            SecurityHeaderResult {
                header: "X-Content-Type-Options".to_string(),
                present: true,
                value: Some(value.clone()),
                severity: if is_nosniff {
                    Severity::Info
                } else {
                    Severity::Low
                },
                recommendation: if is_nosniff {
                    "Header properly configured".to_string()
                } else {
                    "Set to 'nosniff'".to_string()
                },
            }
        } else {
            SecurityHeaderResult {
                header: "X-Content-Type-Options".to_string(),
                present: false,
                value: None,
                severity: Severity::Medium,
                recommendation: "Add 'X-Content-Type-Options: nosniff'".to_string(),
            }
        }
    }

    /// Check for X-XSS-Protection header
    fn check_x_xss_protection(headers: &HashMap<String, String>) -> SecurityHeaderResult {
        let header_name = "x-xss-protection";

        if let Some(value) = Self::get_header_case_insensitive(headers, header_name) {
            SecurityHeaderResult {
                header: "X-XSS-Protection".to_string(),
                present: true,
                value: Some(value.clone()),
                severity: Severity::Info,
                recommendation: "Header present (Note: CSP is preferred over X-XSS-Protection)"
                    .to_string(),
            }
        } else {
            SecurityHeaderResult {
                header: "X-XSS-Protection".to_string(),
                present: false,
                value: None,
                severity: Severity::Low,
                recommendation: "Add 'X-XSS-Protection: 1; mode=block' (though CSP is preferred)"
                    .to_string(),
            }
        }
    }

    /// Check for Referrer-Policy header
    fn check_referrer_policy(headers: &HashMap<String, String>) -> SecurityHeaderResult {
        let header_name = "referrer-policy";

        if let Some(value) = Self::get_header_case_insensitive(headers, header_name) {
            let secure_policies = [
                "no-referrer",
                "no-referrer-when-downgrade",
                "strict-origin",
                "strict-origin-when-cross-origin",
            ];

            let is_secure = secure_policies
                .iter()
                .any(|p| value.to_lowercase().contains(p));

            SecurityHeaderResult {
                header: "Referrer-Policy".to_string(),
                present: true,
                value: Some(value.clone()),
                severity: if is_secure {
                    Severity::Info
                } else {
                    Severity::Low
                },
                recommendation: if is_secure {
                    "Header properly configured".to_string()
                } else {
                    "Use a more restrictive policy like 'strict-origin-when-cross-origin'"
                        .to_string()
                },
            }
        } else {
            SecurityHeaderResult {
                header: "Referrer-Policy".to_string(),
                present: false,
                value: None,
                severity: Severity::Low,
                recommendation: "Add 'Referrer-Policy: strict-origin-when-cross-origin'"
                    .to_string(),
            }
        }
    }

    /// Check for Permissions-Policy header
    fn check_permissions_policy(headers: &HashMap<String, String>) -> SecurityHeaderResult {
        let header_name = "permissions-policy";

        if let Some(value) = Self::get_header_case_insensitive(headers, header_name) {
            SecurityHeaderResult {
                header: "Permissions-Policy".to_string(),
                present: true,
                value: Some(value.clone()),
                severity: Severity::Info,
                recommendation: "Header properly configured".to_string(),
            }
        } else {
            SecurityHeaderResult {
                header: "Permissions-Policy".to_string(),
                present: false,
                value: None,
                severity: Severity::Low,
                recommendation: "Add Permissions-Policy to control browser features".to_string(),
            }
        }
    }

    /// Check for information disclosure in headers
    fn check_information_disclosure(
        headers: &HashMap<String, String>,
    ) -> Vec<SecurityHeaderResult> {
        let mut results = Vec::new();

        // Check Server header
        if let Some(server) = Self::get_header_case_insensitive(headers, "server") {
            if server.contains('/') || server.len() > 20 {
                results.push(SecurityHeaderResult {
                    header: "Server".to_string(),
                    present: true,
                    value: Some(server.clone()),
                    severity: Severity::Low,
                    recommendation: "Remove version information from Server header".to_string(),
                });
            }
        }

        // Check X-Powered-By header
        if let Some(powered_by) = Self::get_header_case_insensitive(headers, "x-powered-by") {
            results.push(SecurityHeaderResult {
                header: "X-Powered-By".to_string(),
                present: true,
                value: Some(powered_by.clone()),
                severity: Severity::Low,
                recommendation: "Remove X-Powered-By header to prevent information disclosure"
                    .to_string(),
            });
        }

        results
    }

    /// Get header value case-insensitively
    fn get_header_case_insensitive(
        headers: &HashMap<String, String>,
        name: &str,
    ) -> Option<String> {
        let name_lower = name.to_lowercase();

        for (key, value) in headers {
            if key.to_lowercase() == name_lower {
                return Some(value.clone());
            }
        }

        None
    }

    /// Extract max-age value from HSTS header
    fn extract_max_age(value: &str) -> Option<u64> {
        if let Some(pos) = value.find("max-age=") {
            let after = &value[pos + 8..];
            let age_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            age_str.parse().ok()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_hsts() {
        let headers = HashMap::new();
        let result = SecurityHeaderAnalyzer::check_strict_transport_security(&headers);

        assert!(!result.present);
        assert_eq!(result.severity, Severity::High);
    }

    #[test]
    fn test_present_hsts() {
        let mut headers = HashMap::new();
        headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000; includeSubDomains".to_string(),
        );

        let result = SecurityHeaderAnalyzer::check_strict_transport_security(&headers);

        assert!(result.present);
        assert_eq!(result.severity, Severity::Info);
    }

    #[test]
    fn test_weak_hsts() {
        let mut headers = HashMap::new();
        headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=300".to_string(),
        );

        let result = SecurityHeaderAnalyzer::check_strict_transport_security(&headers);

        assert!(result.present);
        assert_eq!(result.severity, Severity::Medium);
    }

    #[test]
    fn test_missing_csp() {
        let headers = HashMap::new();
        let result = SecurityHeaderAnalyzer::check_content_security_policy(&headers);

        assert!(!result.present);
        assert_eq!(result.severity, Severity::High);
    }

    #[test]
    fn test_unsafe_csp() {
        let mut headers = HashMap::new();
        headers.insert(
            "Content-Security-Policy".to_string(),
            "default-src 'self' 'unsafe-inline'".to_string(),
        );

        let result = SecurityHeaderAnalyzer::check_content_security_policy(&headers);

        assert!(result.present);
        assert_eq!(result.severity, Severity::Medium);
    }

    #[test]
    fn test_x_powered_by_disclosure() {
        let mut headers = HashMap::new();
        headers.insert("X-Powered-By".to_string(), "PHP/7.4.3".to_string());

        let results = SecurityHeaderAnalyzer::check_information_disclosure(&headers);

        assert!(!results.is_empty());
        assert_eq!(results[0].header, "X-Powered-By");
        assert_eq!(results[0].severity, Severity::Low);
    }

    #[test]
    fn test_analyze_all_headers() {
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "nginx".to_string());

        let results = SecurityHeaderAnalyzer::analyze(&headers);

        // Should check multiple headers
        assert!(results.len() > 5);
    }
}
