// NVD (National Vulnerability Database) integration
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// CVSS v3.1 severity ratings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CvssV3Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl CvssV3Severity {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s == 0.0 => CvssV3Severity::None,
            s if s < 4.0 => CvssV3Severity::Low,
            s if s < 7.0 => CvssV3Severity::Medium,
            s if s < 9.0 => CvssV3Severity::High,
            _ => CvssV3Severity::Critical,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            CvssV3Severity::None => "NONE",
            CvssV3Severity::Low => "LOW",
            CvssV3Severity::Medium => "MEDIUM",
            CvssV3Severity::High => "HIGH",
            CvssV3Severity::Critical => "CRITICAL",
        }
    }
}

/// CVSS v3.1 metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssV3Metrics {
    /// Base score (0.0 - 10.0)
    pub base_score: f32,
    /// Severity rating
    pub severity: CvssV3Severity,
    /// Vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    pub vector_string: String,
    /// Attack Vector (Network, Adjacent, Local, Physical)
    pub attack_vector: String,
    /// Attack Complexity (Low, High)
    pub attack_complexity: String,
    /// Privileges Required (None, Low, High)
    pub privileges_required: String,
    /// User Interaction (None, Required)
    pub user_interaction: String,
    /// Scope (Unchanged, Changed)
    pub scope: String,
    /// Confidentiality Impact (None, Low, High)
    pub confidentiality_impact: String,
    /// Integrity Impact (None, Low, High)
    pub integrity_impact: String,
    /// Availability Impact (None, Low, High)
    pub availability_impact: String,
}

impl CvssV3Metrics {
    /// Create metrics from base score
    pub fn from_score(score: f32) -> Self {
        Self {
            base_score: score,
            severity: CvssV3Severity::from_score(score),
            vector_string: format!("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            attack_vector: "NETWORK".to_string(),
            attack_complexity: "LOW".to_string(),
            privileges_required: "NONE".to_string(),
            user_interaction: "NONE".to_string(),
            scope: "UNCHANGED".to_string(),
            confidentiality_impact: "HIGH".to_string(),
            integrity_impact: "HIGH".to_string(),
            availability_impact: "HIGH".to_string(),
        }
    }

    /// Parse CVSS vector string
    pub fn from_vector(vector: &str) -> Option<Self> {
        // Simplified parser - real implementation would parse full vector
        if !vector.starts_with("CVSS:3.") {
            return None;
        }

        // Extract components
        let mut metrics = CvssV3Metrics::from_score(0.0);
        metrics.vector_string = vector.to_string();

        for part in vector.split('/') {
            let kv: Vec<&str> = part.split(':').collect();
            if kv.len() != 2 {
                continue;
            }

            match kv[0] {
                "AV" => metrics.attack_vector = Self::expand_av(kv[1]),
                "AC" => metrics.attack_complexity = Self::expand_ac(kv[1]),
                "PR" => metrics.privileges_required = Self::expand_pr(kv[1]),
                "UI" => metrics.user_interaction = Self::expand_ui(kv[1]),
                "S" => metrics.scope = Self::expand_s(kv[1]),
                "C" => metrics.confidentiality_impact = Self::expand_impact(kv[1]),
                "I" => metrics.integrity_impact = Self::expand_impact(kv[1]),
                "A" => metrics.availability_impact = Self::expand_impact(kv[1]),
                _ => {}
            }
        }

        Some(metrics)
    }

    fn expand_av(v: &str) -> String {
        match v {
            "N" => "NETWORK",
            "A" => "ADJACENT",
            "L" => "LOCAL",
            "P" => "PHYSICAL",
            _ => "UNKNOWN",
        }
        .to_string()
    }

    fn expand_ac(v: &str) -> String {
        match v {
            "L" => "LOW",
            "H" => "HIGH",
            _ => "UNKNOWN",
        }
        .to_string()
    }

    fn expand_pr(v: &str) -> String {
        match v {
            "N" => "NONE",
            "L" => "LOW",
            "H" => "HIGH",
            _ => "UNKNOWN",
        }
        .to_string()
    }

    fn expand_ui(v: &str) -> String {
        match v {
            "N" => "NONE",
            "R" => "REQUIRED",
            _ => "UNKNOWN",
        }
        .to_string()
    }

    fn expand_s(v: &str) -> String {
        match v {
            "U" => "UNCHANGED",
            "C" => "CHANGED",
            _ => "UNKNOWN",
        }
        .to_string()
    }

    fn expand_impact(v: &str) -> String {
        match v {
            "N" => "NONE",
            "L" => "LOW",
            "H" => "HIGH",
            _ => "UNKNOWN",
        }
        .to_string()
    }

    /// Check if vulnerability is easily exploitable
    pub fn is_easily_exploitable(&self) -> bool {
        self.attack_vector == "NETWORK"
            && self.attack_complexity == "LOW"
            && self.privileges_required == "NONE"
            && self.user_interaction == "NONE"
    }
}

/// NVD CVE entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdCveEntry {
    /// CVE identifier
    pub cve_id: String,
    /// Description
    pub description: String,
    /// Published date
    pub published_date: String,
    /// Last modified date
    pub last_modified_date: String,
    /// CVSS v3.1 metrics
    pub cvss_v3: Option<CvssV3Metrics>,
    /// CVSS v2 score (for older CVEs)
    pub cvss_v2_score: Option<f32>,
    /// Affected products (CPE URIs)
    pub affected_products: Vec<String>,
    /// References
    pub references: Vec<String>,
    /// CWE (Common Weakness Enumeration)
    pub cwe: Vec<String>,
}

/// NVD database with CVSS v3.1 support
pub struct NvdDatabase {
    entries: HashMap<String, NvdCveEntry>,
}

impl NvdDatabase {
    /// Create a new NVD database
    pub fn new() -> Self {
        let mut db = Self {
            entries: HashMap::new(),
        };
        db.populate_known_cves();
        db
    }

    /// Populate database with known critical CVEs
    fn populate_known_cves(&mut self) {
        // Log4Shell
        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2021-44228".to_string(),
            description: "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.".to_string(),
            published_date: "2021-12-10".to_string(),
            last_modified_date: "2023-11-07".to_string(),
            cvss_v3: Some(CvssV3Metrics {
                base_score: 10.0,
                severity: CvssV3Severity::Critical,
                vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string(),
                attack_vector: "NETWORK".to_string(),
                attack_complexity: "LOW".to_string(),
                privileges_required: "NONE".to_string(),
                user_interaction: "NONE".to_string(),
                scope: "CHANGED".to_string(),
                confidentiality_impact: "HIGH".to_string(),
                integrity_impact: "HIGH".to_string(),
                availability_impact: "HIGH".to_string(),
            }),
            cvss_v2_score: Some(9.3),
            affected_products: vec![
                "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*".to_string(),
            ],
            references: vec![
                "https://logging.apache.org/log4j/2.x/security.html".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string(),
            ],
            cwe: vec!["CWE-502".to_string(), "CWE-400".to_string()],
        });

        // EternalBlue
        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2017-0144".to_string(),
            description: "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka 'Windows SMB Remote Code Execution Vulnerability.'".to_string(),
            published_date: "2017-03-17".to_string(),
            last_modified_date: "2020-09-28".to_string(),
            cvss_v3: Some(CvssV3Metrics {
                base_score: 8.1,
                severity: CvssV3Severity::High,
                vector_string: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                attack_vector: "NETWORK".to_string(),
                attack_complexity: "HIGH".to_string(),
                privileges_required: "NONE".to_string(),
                user_interaction: "NONE".to_string(),
                scope: "UNCHANGED".to_string(),
                confidentiality_impact: "HIGH".to_string(),
                integrity_impact: "HIGH".to_string(),
                availability_impact: "HIGH".to_string(),
            }),
            cvss_v2_score: Some(9.3),
            affected_products: vec![
                "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*".to_string(),
            ],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2017-0144".to_string(),
                "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0144".to_string(),
            ],
            cwe: vec!["CWE-119".to_string()],
        });

        // Heartbleed
        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2014-0160".to_string(),
            description: "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read.".to_string(),
            published_date: "2014-04-07".to_string(),
            last_modified_date: "2020-10-15".to_string(),
            cvss_v3: Some(CvssV3Metrics {
                base_score: 7.5,
                severity: CvssV3Severity::High,
                vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(),
                attack_vector: "NETWORK".to_string(),
                attack_complexity: "LOW".to_string(),
                privileges_required: "NONE".to_string(),
                user_interaction: "NONE".to_string(),
                scope: "UNCHANGED".to_string(),
                confidentiality_impact: "HIGH".to_string(),
                integrity_impact: "NONE".to_string(),
                availability_impact: "NONE".to_string(),
            }),
            cvss_v2_score: Some(5.0),
            affected_products: vec![
                "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*".to_string(),
            ],
            references: vec![
                "https://heartbleed.com/".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2014-0160".to_string(),
            ],
            cwe: vec!["CWE-125".to_string()],
        });

        // BlueKeep
        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2019-0708".to_string(),
            description: "A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests.".to_string(),
            published_date: "2019-05-16".to_string(),
            last_modified_date: "2020-08-24".to_string(),
            cvss_v3: Some(CvssV3Metrics {
                base_score: 9.8,
                severity: CvssV3Severity::Critical,
                vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                attack_vector: "NETWORK".to_string(),
                attack_complexity: "LOW".to_string(),
                privileges_required: "NONE".to_string(),
                user_interaction: "NONE".to_string(),
                scope: "UNCHANGED".to_string(),
                confidentiality_impact: "HIGH".to_string(),
                integrity_impact: "HIGH".to_string(),
                availability_impact: "HIGH".to_string(),
            }),
            cvss_v2_score: Some(10.0),
            affected_products: vec![
                "cpe:2.3:o:microsoft:windows_7:*:*:*:*:*:*:*:*".to_string(),
                "cpe:2.3:o:microsoft:windows_server_2008:*:*:*:*:*:*:*:*".to_string(),
            ],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2019-0708".to_string(),
                "https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708".to_string(),
            ],
            cwe: vec!["CWE-416".to_string()],
        });

        // Ghostcat
        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2020-1938".to_string(),
            description: "When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection.".to_string(),
            published_date: "2020-02-24".to_string(),
            last_modified_date: "2021-07-21".to_string(),
            cvss_v3: Some(CvssV3Metrics {
                base_score: 9.8,
                severity: CvssV3Severity::Critical,
                vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                attack_vector: "NETWORK".to_string(),
                attack_complexity: "LOW".to_string(),
                privileges_required: "NONE".to_string(),
                user_interaction: "NONE".to_string(),
                scope: "UNCHANGED".to_string(),
                confidentiality_impact: "HIGH".to_string(),
                integrity_impact: "HIGH".to_string(),
                availability_impact: "HIGH".to_string(),
            }),
            cvss_v2_score: Some(7.5),
            affected_products: vec![
                "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*".to_string(),
            ],
            references: vec![
                "https://www.chaitin.cn/en/ghostcat".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2020-1938".to_string(),
            ],
            cwe: vec!["CWE-285".to_string()],
        });

        // Shellshock
        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2014-6271".to_string(),
            description: "GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment.".to_string(),
            published_date: "2014-09-24".to_string(),
            last_modified_date: "2021-02-01".to_string(),
            cvss_v3: Some(CvssV3Metrics {
                base_score: 9.8,
                severity: CvssV3Severity::Critical,
                vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
                attack_vector: "NETWORK".to_string(),
                attack_complexity: "LOW".to_string(),
                privileges_required: "NONE".to_string(),
                user_interaction: "NONE".to_string(),
                scope: "UNCHANGED".to_string(),
                confidentiality_impact: "HIGH".to_string(),
                integrity_impact: "HIGH".to_string(),
                availability_impact: "HIGH".to_string(),
            }),
            cvss_v2_score: Some(10.0),
            affected_products: vec![
                "cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*".to_string(),
            ],
            references: vec![
                "https://nvd.nist.gov/vuln/detail/CVE-2014-6271".to_string(),
            ],
            cwe: vec!["CWE-78".to_string()],
        });
    }

    /// Add CVE entry
    fn add_entry(&mut self, entry: NvdCveEntry) {
        self.entries.insert(entry.cve_id.clone(), entry);
    }

    /// Get CVE entry
    pub fn get_cve(&self, cve_id: &str) -> Option<&NvdCveEntry> {
        self.entries.get(cve_id)
    }

    /// Get CVSS v3.1 score for CVE
    pub fn get_cvss_score(&self, cve_id: &str) -> Option<f32> {
        self.entries
            .get(cve_id)
            .and_then(|e| e.cvss_v3.as_ref())
            .map(|m| m.base_score)
    }

    /// Get severity for CVE
    pub fn get_severity(&self, cve_id: &str) -> Option<&CvssV3Severity> {
        self.entries
            .get(cve_id)
            .and_then(|e| e.cvss_v3.as_ref())
            .map(|m| &m.severity)
    }

    /// Check if CVE is critical
    pub fn is_critical(&self, cve_id: &str) -> bool {
        matches!(self.get_severity(cve_id), Some(CvssV3Severity::Critical))
    }

    /// Get all critical CVEs
    pub fn get_critical_cves(&self) -> Vec<&NvdCveEntry> {
        self.entries
            .values()
            .filter(|e| {
                e.cvss_v3
                    .as_ref()
                    .map(|m| m.severity == CvssV3Severity::Critical)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Get CVE count
    pub fn count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for NvdDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_severity_from_score() {
        assert_eq!(CvssV3Severity::from_score(0.0), CvssV3Severity::None);
        assert_eq!(CvssV3Severity::from_score(3.9), CvssV3Severity::Low);
        assert_eq!(CvssV3Severity::from_score(6.9), CvssV3Severity::Medium);
        assert_eq!(CvssV3Severity::from_score(8.9), CvssV3Severity::High);
        assert_eq!(CvssV3Severity::from_score(10.0), CvssV3Severity::Critical);
    }

    #[test]
    fn test_nvd_database() {
        let db = NvdDatabase::new();
        
        assert!(db.count() >= 6, "Should have 6+ CVE entries");
        
        // Test Log4Shell
        let log4shell = db.get_cve("CVE-2021-44228").unwrap();
        assert_eq!(log4shell.cve_id, "CVE-2021-44228");
        assert_eq!(log4shell.cvss_v3.as_ref().unwrap().base_score, 10.0);
        assert_eq!(log4shell.cvss_v3.as_ref().unwrap().severity, CvssV3Severity::Critical);
    }

    #[test]
    fn test_get_cvss_score() {
        let db = NvdDatabase::new();
        
        assert_eq!(db.get_cvss_score("CVE-2021-44228"), Some(10.0));
        assert_eq!(db.get_cvss_score("CVE-2014-0160"), Some(7.5));
        assert_eq!(db.get_cvss_score("CVE-NONEXISTENT"), None);
    }

    #[test]
    fn test_is_critical() {
        let db = NvdDatabase::new();
        
        assert!(db.is_critical("CVE-2021-44228")); // Log4Shell
        assert!(db.is_critical("CVE-2019-0708")); // BlueKeep
        assert!(!db.is_critical("CVE-2014-0160")); // Heartbleed (High, not Critical)
    }

    #[test]
    fn test_get_critical_cves() {
        let db = NvdDatabase::new();
        let critical = db.get_critical_cves();
        
        assert!(critical.len() >= 3, "Should have 3+ critical CVEs");
        assert!(critical.iter().all(|c| c.cvss_v3.as_ref().unwrap().severity == CvssV3Severity::Critical));
    }

    #[test]
    fn test_cvss_metrics() {
        let metrics = CvssV3Metrics::from_score(9.8);
        assert_eq!(metrics.base_score, 9.8);
        assert_eq!(metrics.severity, CvssV3Severity::Critical);
        assert!(metrics.is_easily_exploitable());
    }
}
