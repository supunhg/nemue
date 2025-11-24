use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// CVE vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    pub cve_id: String,
    pub description: String,
    pub severity: CveSeverity,
    pub cvss_score: f32,
    pub published_date: String,
    pub references: Vec<String>,
}

/// CVE severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CveSeverity {
    Critical,
    High,
    Medium,
    Low,
    None,
}

impl CveSeverity {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s >= 9.0 => CveSeverity::Critical,
            s if s >= 7.0 => CveSeverity::High,
            s if s >= 4.0 => CveSeverity::Medium,
            s if s >= 0.1 => CveSeverity::Low,
            _ => CveSeverity::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CveSeverity::Critical => "CRITICAL",
            CveSeverity::High => "HIGH",
            CveSeverity::Medium => "MEDIUM",
            CveSeverity::Low => "LOW",
            CveSeverity::None => "NONE",
        }
    }
}

/// CVE database for vulnerability lookups
pub struct CveDatabase {
    cache: HashMap<String, Vec<CveInfo>>,
    use_cache: bool,
}

impl CveDatabase {
    pub fn new(use_cache: bool) -> Self {
        Self {
            cache: HashMap::new(),
            use_cache,
        }
    }

    /// Lookup vulnerabilities for a specific service and version
    pub async fn lookup_vulnerabilities(
        &mut self,
        service: &str,
        version: &str,
    ) -> Result<Vec<CveInfo>> {
        let cache_key = format!("{}:{}", service, version);

        // Check cache first
        if self.use_cache {
            if let Some(cached) = self.cache.get(&cache_key) {
                return Ok(cached.clone());
            }
        }

        // In a real implementation, this would query NVD API or local database
        // For now, we'll use a simplified pattern matching system
        let vulnerabilities = self.search_known_vulnerabilities(service, version);

        // Cache the results
        if self.use_cache {
            self.cache.insert(cache_key, vulnerabilities.clone());
        }

        Ok(vulnerabilities)
    }

    /// Search known vulnerabilities using pattern matching
    /// In production, this would query the NVD API: https://nvd.nist.gov/developers/vulnerabilities
    fn search_known_vulnerabilities(&self, service: &str, version: &str) -> Vec<CveInfo> {
        let mut results = Vec::new();

        // Apache HTTP Server vulnerabilities
        if service.to_lowercase().contains("apache") {
            if let Some(ver) = self.parse_version(version) {
                if ver.major == 2 && ver.minor <= 4 && ver.patch < 50 {
                    results.push(CveInfo {
                        cve_id: "CVE-2021-44790".to_string(),
                        description: "Apache HTTP Server 2.4.x < 2.4.51 buffer overflow in mod_lua".to_string(),
                        severity: CveSeverity::Critical,
                        cvss_score: 9.8,
                        published_date: "2021-12-20".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-44790".to_string(),
                        ],
                    });
                }
            }
        }

        // OpenSSH vulnerabilities
        if service.to_lowercase().contains("openssh") || service.to_lowercase().contains("ssh") {
            if let Some(ver) = self.parse_version(version) {
                if ver.major <= 8 && ver.minor < 8 {
                    results.push(CveInfo {
                        cve_id: "CVE-2021-41617".to_string(),
                        description: "OpenSSH < 8.8 privilege escalation via supplemental groups".to_string(),
                        severity: CveSeverity::High,
                        cvss_score: 7.0,
                        published_date: "2021-09-26".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-41617".to_string(),
                        ],
                    });
                }
            }
        }

        // OpenSSL vulnerabilities
        if service.to_lowercase().contains("openssl") || service.to_lowercase().contains("ssl") {
            if version.contains("1.1.1") {
                results.push(CveInfo {
                    cve_id: "CVE-2022-0778".to_string(),
                    description: "OpenSSL 1.1.1 infinite loop vulnerability (denial of service)".to_string(),
                    severity: CveSeverity::High,
                    cvss_score: 7.5,
                    published_date: "2022-03-15".to_string(),
                    references: vec![
                        "https://nvd.nist.gov/vuln/detail/CVE-2022-0778".to_string(),
                    ],
                });
            }
        }

        // MySQL vulnerabilities
        if service.to_lowercase().contains("mysql") {
            if let Some(ver) = self.parse_version(version) {
                if ver.major == 5 || (ver.major == 8 && ver.minor == 0 && ver.patch < 28) {
                    results.push(CveInfo {
                        cve_id: "CVE-2021-2471".to_string(),
                        description: "MySQL Server vulnerability in replication component".to_string(),
                        severity: CveSeverity::Medium,
                        cvss_score: 4.9,
                        published_date: "2021-10-20".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-2471".to_string(),
                        ],
                    });
                }
            }
        }

        // PostgreSQL vulnerabilities
        if service.to_lowercase().contains("postgresql") || service.to_lowercase().contains("postgres") {
            if let Some(ver) = self.parse_version(version) {
                if ver.major <= 13 {
                    results.push(CveInfo {
                        cve_id: "CVE-2021-32027".to_string(),
                        description: "PostgreSQL buffer overflow in array subscripting calculations".to_string(),
                        severity: CveSeverity::High,
                        cvss_score: 8.8,
                        published_date: "2021-05-14".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-32027".to_string(),
                        ],
                    });
                }
            }
        }

        // nginx vulnerabilities
        if service.to_lowercase().contains("nginx") {
            if let Some(ver) = self.parse_version(version) {
                if ver.major == 1 && ver.minor <= 20 {
                    results.push(CveInfo {
                        cve_id: "CVE-2021-23017".to_string(),
                        description: "nginx resolver off-by-one buffer overflow".to_string(),
                        severity: CveSeverity::High,
                        cvss_score: 8.1,
                        published_date: "2021-05-25".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-23017".to_string(),
                        ],
                    });
                }
            }
        }

        results
    }

    /// Parse version string into major.minor.patch
    fn parse_version(&self, version: &str) -> Option<Version> {
        let parts: Vec<&str> = version
            .trim()
            .split(|c: char| c == '.' || c == '-' || c.is_whitespace())
            .collect();

        if parts.is_empty() {
            return None;
        }

        let major = parts.get(0)?.parse().ok()?;
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

        Some(Version {
            major,
            minor,
            patch,
        })
    }

    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let entries = self.cache.len();
        let total_vulns = self.cache.values().map(|v| v.len()).sum();
        (entries, total_vulns)
    }
}

#[derive(Debug)]
struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_apache_vulnerability_detection() {
        let mut db = CveDatabase::new(true);
        let vulns = db
            .lookup_vulnerabilities("Apache httpd", "2.4.49")
            .await
            .unwrap();
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.severity == CveSeverity::Critical));
    }

    #[tokio::test]
    async fn test_openssh_vulnerability_detection() {
        let mut db = CveDatabase::new(true);
        let vulns = db.lookup_vulnerabilities("OpenSSH", "8.0").await.unwrap();
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.cve_id.contains("CVE")));
    }

    #[tokio::test]
    async fn test_version_parsing() {
        let db = CveDatabase::new(false);
        assert!(db.parse_version("2.4.49").is_some());
        assert!(db.parse_version("8.0p1").is_some());
        assert!(db.parse_version("1.1.1k").is_some());
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let mut db = CveDatabase::new(true);
        
        // First lookup
        let _ = db.lookup_vulnerabilities("Apache", "2.4.49").await.unwrap();
        let (entries, _) = db.cache_stats();
        assert_eq!(entries, 1);

        // Second lookup should use cache
        let _ = db.lookup_vulnerabilities("Apache", "2.4.49").await.unwrap();
        let (entries, _) = db.cache_stats();
        assert_eq!(entries, 1);

        // Clear cache
        db.clear_cache();
        let (entries, _) = db.cache_stats();
        assert_eq!(entries, 0);
    }

    #[test]
    fn test_severity_from_score() {
        assert_eq!(CveSeverity::from_score(9.5), CveSeverity::Critical);
        assert_eq!(CveSeverity::from_score(7.5), CveSeverity::High);
        assert_eq!(CveSeverity::from_score(5.0), CveSeverity::Medium);
        assert_eq!(CveSeverity::from_score(2.0), CveSeverity::Low);
        assert_eq!(CveSeverity::from_score(0.0), CveSeverity::None);
    }
}
