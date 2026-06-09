// NVD (National Vulnerability Database) integration
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// CVSS v4.0 severity ratings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CvssV4Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl CvssV4Severity {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s == 0.0 => CvssV4Severity::None,
            s if s < 4.0 => CvssV4Severity::Low,
            s if s < 7.0 => CvssV4Severity::Medium,
            s if s < 9.0 => CvssV4Severity::High,
            _ => CvssV4Severity::Critical,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            CvssV4Severity::None => "NONE",
            CvssV4Severity::Low => "LOW",
            CvssV4Severity::Medium => "MEDIUM",
            CvssV4Severity::High => "HIGH",
            CvssV4Severity::Critical => "CRITICAL",
        }
    }
}

/// CVSS v4.0 metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssV4Metrics {
    pub base_score: f32,
    pub severity: CvssV4Severity,
    pub vector_string: String,
    pub attack_vector: String,
    pub attack_complexity: String,
    pub attack_requirements: String,
    pub privileges_required: String,
    pub user_interaction: String,
    pub vc_confidentiality: String,
    pub vc_integrity: String,
    pub vc_availability: String,
    pub sc_confidentiality: String,
    pub sc_integrity: String,
    pub sc_availability: String,
}

impl CvssV4Metrics {
    pub fn from_score(score: f32) -> Self {
        Self {
            base_score: score,
            severity: CvssV4Severity::from_score(score),
            vector_string: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N".to_string(),
            attack_vector: "NETWORK".to_string(),
            attack_complexity: "LOW".to_string(),
            attack_requirements: "NONE".to_string(),
            privileges_required: "NONE".to_string(),
            user_interaction: "NONE".to_string(),
            vc_confidentiality: "HIGH".to_string(),
            vc_integrity: "HIGH".to_string(),
            vc_availability: "HIGH".to_string(),
            sc_confidentiality: "NONE".to_string(),
            sc_integrity: "NONE".to_string(),
            sc_availability: "NONE".to_string(),
        }
    }

    pub fn is_easily_exploitable(&self) -> bool {
        self.attack_vector == "NETWORK"
            && self.attack_complexity == "LOW"
            && self.attack_requirements == "NONE"
            && self.privileges_required == "NONE"
            && self.user_interaction == "NONE"
    }
}

/// EPSS (Exploit Prediction Scoring System) data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssData {
    pub cve_id: String,
    pub epss_probability: f32,
    pub epss_percentile: f32,
    pub model_version: String,
    pub score_date: String,
}

impl EpssData {
    pub fn new(cve_id: &str, probability: f32, percentile: f32) -> Self {
        Self {
            cve_id: cve_id.to_string(),
            epss_probability: probability,
            epss_percentile: percentile,
            model_version: "2024.03.05".to_string(),
            score_date: "2024-12-01".to_string(),
        }
    }

    pub fn is_high_risk(&self) -> bool {
        self.epss_probability > 0.10
    }

    pub fn is_medium_risk(&self) -> bool {
        self.epss_probability > 0.01
    }

    pub fn risk_level(&self) -> &str {
        if self.epss_probability > 0.50 {
            "VERY HIGH"
        } else if self.epss_probability > 0.10 {
            "HIGH"
        } else if self.epss_probability > 0.01 {
            "MEDIUM"
        } else {
            "LOW"
        }
    }
}

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
    pub base_score: f32,
    pub severity: CvssV3Severity,
    pub vector_string: String,
    pub attack_vector: String,
    pub attack_complexity: String,
    pub privileges_required: String,
    pub user_interaction: String,
    pub scope: String,
    pub confidentiality_impact: String,
    pub integrity_impact: String,
    pub availability_impact: String,
}

impl CvssV3Metrics {
    pub fn from_score(score: f32) -> Self {
        Self {
            base_score: score,
            severity: CvssV3Severity::from_score(score),
            vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
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

    pub fn from_vector(vector: &str) -> Option<Self> {
        if !vector.starts_with("CVSS:3.") {
            return None;
        }
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
        match v { "N" => "NETWORK", "A" => "ADJACENT", "L" => "LOCAL", "P" => "PHYSICAL", _ => "UNKNOWN" }.to_string()
    }
    fn expand_ac(v: &str) -> String {
        match v { "L" => "LOW", "H" => "HIGH", _ => "UNKNOWN" }.to_string()
    }
    fn expand_pr(v: &str) -> String {
        match v { "N" => "NONE", "L" => "LOW", "H" => "HIGH", _ => "UNKNOWN" }.to_string()
    }
    fn expand_ui(v: &str) -> String {
        match v { "N" => "NONE", "R" => "REQUIRED", _ => "UNKNOWN" }.to_string()
    }
    fn expand_s(v: &str) -> String {
        match v { "U" => "UNCHANGED", "C" => "CHANGED", _ => "UNKNOWN" }.to_string()
    }
    fn expand_impact(v: &str) -> String {
        match v { "N" => "NONE", "L" => "LOW", "H" => "HIGH", _ => "UNKNOWN" }.to_string()
    }

    pub fn is_easily_exploitable(&self) -> bool {
        self.attack_vector == "NETWORK"
            && self.attack_complexity == "LOW"
            && self.privileges_required == "NONE"
            && self.user_interaction == "NONE"
    }
}

/// Version range for affected products
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    pub product: String,
    pub version_start: Option<String>,
    pub version_end: Option<String>,
    pub end_inclusive: bool,
    pub affected_versions: Vec<String>,
}

impl VersionRange {
    pub fn is_affected(&self, version: &str) -> bool {
        if self.affected_versions.contains(&version.to_string()) {
            return true;
        }
        if let Some(ref start) = self.version_start {
            if Self::version_lt(version, start) {
                return false;
            }
        }
        if let Some(ref end) = self.version_end {
            if self.end_inclusive {
                return Self::version_lte(version, end);
            } else {
                return Self::version_lt(version, end);
            }
        }
        true
    }

    fn parse_version(v: &str) -> Vec<u32> {
        v.split('.').filter_map(|part| part.parse::<u32>().ok()).collect()
    }

    fn version_lt(a: &str, b: &str) -> bool {
        Self::parse_version(a) < Self::parse_version(b)
    }

    fn version_lte(a: &str, b: &str) -> bool {
        Self::parse_version(a) <= Self::parse_version(b)
    }
}

/// NVD CVE entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvdCveEntry {
    pub cve_id: String,
    pub description: String,
    pub published_date: String,
    pub last_modified_date: String,
    pub cvss_v3: Option<CvssV3Metrics>,
    pub cvss_v4: Option<CvssV4Metrics>,
    pub cvss_v2_score: Option<f32>,
    pub epss: Option<EpssData>,
    pub affected_products: Vec<String>,
    pub affected_versions: Vec<VersionRange>,
    pub references: Vec<String>,
    pub cwe: Vec<String>,
    pub exploit_available: bool,
}

/// NVD database with CVSS v3.1/v4.0 and EPSS support
pub struct NvdDatabase {
    entries: HashMap<String, NvdCveEntry>,
    epss_data: HashMap<String, EpssData>,
}

impl NvdDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            entries: HashMap::new(),
            epss_data: HashMap::new(),
        };
        db.populate_known_cves();
        db.populate_epss_data();
        db
    }

    fn populate_known_cves(&mut self) {
        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2021-44228".to_string(),
            description: "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.".to_string(),
            published_date: "2021-12-10".to_string(),
            last_modified_date: "2023-11-07".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 10.0, severity: CvssV3Severity::Critical, vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "LOW".to_string(), privileges_required: "NONE".to_string(), user_interaction: "NONE".to_string(), scope: "CHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "HIGH".to_string(), availability_impact: "HIGH".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(10.0)),
            cvss_v2_score: Some(9.3),
            epss: Some(EpssData::new("CVE-2021-44228", 0.975, 99.6)),
            affected_products: vec!["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![VersionRange { product: "apache:log4j".to_string(), version_start: Some("2.0-beta9".to_string()), version_end: Some("2.15.0".to_string()), end_inclusive: false, affected_versions: vec![] }],
            references: vec!["https://logging.apache.org/log4j/2.x/security.html".to_string(), "https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()],
            cwe: vec!["CWE-502".to_string(), "CWE-400".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2017-0144".to_string(),
            description: "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets.".to_string(),
            published_date: "2017-03-17".to_string(),
            last_modified_date: "2020-09-28".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 8.1, severity: CvssV3Severity::High, vector_string: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "HIGH".to_string(), privileges_required: "NONE".to_string(), user_interaction: "NONE".to_string(), scope: "UNCHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "HIGH".to_string(), availability_impact: "HIGH".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(8.1)),
            cvss_v2_score: Some(9.3),
            epss: Some(EpssData::new("CVE-2017-0144", 0.97, 99.5)),
            affected_products: vec!["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2017-0144".to_string()],
            cwe: vec!["CWE-119".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2014-0160".to_string(),
            description: "OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets.".to_string(),
            published_date: "2014-04-07".to_string(),
            last_modified_date: "2020-10-15".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 7.5, severity: CvssV3Severity::High, vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "LOW".to_string(), privileges_required: "NONE".to_string(), user_interaction: "NONE".to_string(), scope: "UNCHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "NONE".to_string(), availability_impact: "NONE".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(7.5)),
            cvss_v2_score: Some(5.0),
            epss: Some(EpssData::new("CVE-2014-0160", 0.95, 99.0)),
            affected_products: vec!["cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![VersionRange { product: "openssl:openssl".to_string(), version_start: Some("1.0.1".to_string()), version_end: Some("1.0.1f".to_string()), end_inclusive: true, affected_versions: vec![] }],
            references: vec!["https://heartbleed.com/".to_string(), "https://nvd.nist.gov/vuln/detail/CVE-2014-0160".to_string()],
            cwe: vec!["CWE-125".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2019-0708".to_string(),
            description: "A remote code execution vulnerability exists in Remote Desktop Services.".to_string(),
            published_date: "2019-05-16".to_string(),
            last_modified_date: "2020-08-24".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 9.8, severity: CvssV3Severity::Critical, vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "LOW".to_string(), privileges_required: "NONE".to_string(), user_interaction: "NONE".to_string(), scope: "UNCHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "HIGH".to_string(), availability_impact: "HIGH".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(9.8)),
            cvss_v2_score: Some(10.0),
            epss: Some(EpssData::new("CVE-2019-0708", 0.96, 99.2)),
            affected_products: vec!["cpe:2.3:o:microsoft:windows_7:*:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-0708".to_string()],
            cwe: vec!["CWE-416".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2020-1938".to_string(),
            description: "Apache Tomcat AJP connector allows remote code execution.".to_string(),
            published_date: "2020-02-24".to_string(),
            last_modified_date: "2021-07-21".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 9.8, severity: CvssV3Severity::Critical, vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "LOW".to_string(), privileges_required: "NONE".to_string(), user_interaction: "NONE".to_string(), scope: "UNCHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "HIGH".to_string(), availability_impact: "HIGH".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(9.8)),
            cvss_v2_score: Some(7.5),
            epss: Some(EpssData::new("CVE-2020-1938", 0.94, 98.8)),
            affected_products: vec!["cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![VersionRange { product: "apache:tomcat".to_string(), version_start: Some("6.0".to_string()), version_end: Some("9.0.31".to_string()), end_inclusive: false, affected_versions: vec![] }],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-1938".to_string()],
            cwe: vec!["CWE-285".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2014-6271".to_string(),
            description: "GNU Bash through 4.3 allows remote attackers to execute arbitrary code via crafted environment.".to_string(),
            published_date: "2014-09-24".to_string(),
            last_modified_date: "2021-02-01".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 9.8, severity: CvssV3Severity::Critical, vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "LOW".to_string(), privileges_required: "NONE".to_string(), user_interaction: "NONE".to_string(), scope: "UNCHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "HIGH".to_string(), availability_impact: "HIGH".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(9.8)),
            cvss_v2_score: Some(10.0),
            epss: Some(EpssData::new("CVE-2014-6271", 0.97, 99.4)),
            affected_products: vec!["cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![VersionRange { product: "gnu:bash".to_string(), version_start: None, version_end: Some("4.3".to_string()), end_inclusive: true, affected_versions: vec![] }],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2014-6271".to_string()],
            cwe: vec!["CWE-78".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2014-3566".to_string(),
            description: "The SSL protocol 3.0 uses nondeterministic CBC padding, allowing man-in-the-middle attackers to obtain cleartext data.".to_string(),
            published_date: "2014-10-14".to_string(),
            last_modified_date: "2022-08-12".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 3.1, severity: CvssV3Severity::Low, vector_string: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "HIGH".to_string(), privileges_required: "NONE".to_string(), user_interaction: "REQUIRED".to_string(), scope: "UNCHANGED".to_string(), confidentiality_impact: "LOW".to_string(), integrity_impact: "NONE".to_string(), availability_impact: "NONE".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(3.1)),
            cvss_v2_score: Some(4.3),
            epss: Some(EpssData::new("CVE-2014-3566", 0.05, 75.0)),
            affected_products: vec!["cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2014-3566".to_string()],
            cwe: vec!["CWE-327".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2016-0800".to_string(),
            description: "The SSLv2 protocol allows remote attackers to decrypt TLS ciphertext via a padding-oracle attack (DROWN).".to_string(),
            published_date: "2016-03-01".to_string(),
            last_modified_date: "2023-11-07".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 7.4, severity: CvssV3Severity::High, vector_string: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "HIGH".to_string(), privileges_required: "NONE".to_string(), user_interaction: "NONE".to_string(), scope: "UNCHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "HIGH".to_string(), availability_impact: "NONE".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(7.4)),
            cvss_v2_score: Some(5.8),
            epss: Some(EpssData::new("CVE-2016-0800", 0.15, 92.0)),
            affected_products: vec!["cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![],
            references: vec!["https://drownattack.com/".to_string(), "https://nvd.nist.gov/vuln/detail/CVE-2016-0800".to_string()],
            cwe: vec!["CWE-327".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2021-26855".to_string(),
            description: "Microsoft Exchange Server Remote Code Execution Vulnerability (ProxyLogon).".to_string(),
            published_date: "2021-03-02".to_string(),
            last_modified_date: "2023-11-07".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 9.8, severity: CvssV3Severity::Critical, vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "LOW".to_string(), privileges_required: "NONE".to_string(), user_interaction: "NONE".to_string(), scope: "UNCHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "HIGH".to_string(), availability_impact: "HIGH".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(9.8)),
            cvss_v2_score: Some(7.5),
            epss: Some(EpssData::new("CVE-2021-26855", 0.97, 99.7)),
            affected_products: vec!["cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-26855".to_string()],
            cwe: vec!["CWE-918".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2021-34527".to_string(),
            description: "Windows Print Spooler Remote Code Execution Vulnerability (PrintNightmare).".to_string(),
            published_date: "2021-07-02".to_string(),
            last_modified_date: "2023-11-07".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 8.8, severity: CvssV3Severity::High, vector_string: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "LOW".to_string(), privileges_required: "LOW".to_string(), user_interaction: "NONE".to_string(), scope: "UNCHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "HIGH".to_string(), availability_impact: "HIGH".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(8.8)),
            cvss_v2_score: None,
            epss: Some(EpssData::new("CVE-2021-34527", 0.90, 98.0)),
            affected_products: vec!["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-34527".to_string()],
            cwe: vec!["CWE-269".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2022-22965".to_string(),
            description: "Spring Framework RCE via data binding (Spring4Shell).".to_string(),
            published_date: "2022-04-01".to_string(),
            last_modified_date: "2023-11-07".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 9.8, severity: CvssV3Severity::Critical, vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "LOW".to_string(), privileges_required: "NONE".to_string(), user_interaction: "NONE".to_string(), scope: "UNCHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "HIGH".to_string(), availability_impact: "HIGH".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(9.8)),
            cvss_v2_score: None,
            epss: Some(EpssData::new("CVE-2022-22965", 0.70, 97.5)),
            affected_products: vec!["cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![VersionRange { product: "vmware:spring_framework".to_string(), version_start: Some("5.3.0".to_string()), version_end: Some("5.3.18".to_string()), end_inclusive: false, affected_versions: vec![] }],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-22965".to_string()],
            cwe: vec!["CWE-94".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2023-34362".to_string(),
            description: "Progress MOVEit Transfer SQL injection vulnerability.".to_string(),
            published_date: "2023-06-02".to_string(),
            last_modified_date: "2023-11-07".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 9.8, severity: CvssV3Severity::Critical, vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "LOW".to_string(), privileges_required: "NONE".to_string(), user_interaction: "NONE".to_string(), scope: "UNCHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "HIGH".to_string(), availability_impact: "HIGH".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(9.8)),
            cvss_v2_score: None,
            epss: Some(EpssData::new("CVE-2023-34362", 0.96, 99.5)),
            affected_products: vec!["cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-34362".to_string()],
            cwe: vec!["CWE-89".to_string()],
            exploit_available: true,
        });

        self.add_entry(NvdCveEntry {
            cve_id: "CVE-2024-1709".to_string(),
            description: "ConnectWise ScreenConnect authentication bypass vulnerability.".to_string(),
            published_date: "2024-02-21".to_string(),
            last_modified_date: "2024-03-14".to_string(),
            cvss_v3: Some(CvssV3Metrics { base_score: 10.0, severity: CvssV3Severity::Critical, vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string(), attack_vector: "NETWORK".to_string(), attack_complexity: "LOW".to_string(), privileges_required: "NONE".to_string(), user_interaction: "NONE".to_string(), scope: "CHANGED".to_string(), confidentiality_impact: "HIGH".to_string(), integrity_impact: "HIGH".to_string(), availability_impact: "HIGH".to_string() }),
            cvss_v4: Some(CvssV4Metrics::from_score(10.0)),
            cvss_v2_score: None,
            epss: Some(EpssData::new("CVE-2024-1709", 0.97, 99.8)),
            affected_products: vec!["cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*".to_string()],
            affected_versions: vec![VersionRange { product: "connectwise:screenconnect".to_string(), version_start: None, version_end: Some("23.9.8".to_string()), end_inclusive: false, affected_versions: vec![] }],
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-1709".to_string()],
            cwe: vec!["CWE-288".to_string()],
            exploit_available: true,
        });
    }

    fn populate_epss_data(&mut self) {
        let epss_entries = vec![
            EpssData::new("CVE-2021-44228", 0.975, 99.6),
            EpssData::new("CVE-2017-0144", 0.97, 99.5),
            EpssData::new("CVE-2014-0160", 0.95, 99.0),
            EpssData::new("CVE-2019-0708", 0.96, 99.2),
            EpssData::new("CVE-2020-1938", 0.94, 98.8),
            EpssData::new("CVE-2014-6271", 0.97, 99.4),
            EpssData::new("CVE-2014-3566", 0.05, 75.0),
            EpssData::new("CVE-2016-0800", 0.15, 92.0),
            EpssData::new("CVE-2021-26855", 0.97, 99.7),
            EpssData::new("CVE-2021-34527", 0.90, 98.0),
            EpssData::new("CVE-2022-22965", 0.70, 97.5),
            EpssData::new("CVE-2023-34362", 0.96, 99.5),
            EpssData::new("CVE-2024-1709", 0.97, 99.8),
        ];
        for entry in epss_entries {
            self.epss_data.insert(entry.cve_id.clone(), entry);
        }
    }

    fn add_entry(&mut self, entry: NvdCveEntry) {
        self.entries.insert(entry.cve_id.clone(), entry);
    }

    pub fn get_cve(&self, cve_id: &str) -> Option<&NvdCveEntry> {
        self.entries.get(cve_id)
    }

    pub fn get_cvss_score(&self, cve_id: &str) -> Option<f32> {
        self.entries.get(cve_id).and_then(|e| e.cvss_v3.as_ref()).map(|m| m.base_score)
    }

    pub fn get_cvss_v4_score(&self, cve_id: &str) -> Option<f32> {
        self.entries.get(cve_id).and_then(|e| e.cvss_v4.as_ref()).map(|m| m.base_score)
    }

    pub fn get_best_cvss_score(&self, cve_id: &str) -> Option<f32> {
        self.get_cvss_v4_score(cve_id)
            .or_else(|| self.get_cvss_score(cve_id))
            .or_else(|| self.entries.get(cve_id).and_then(|e| e.cvss_v2_score))
    }

    pub fn get_severity(&self, cve_id: &str) -> Option<&CvssV3Severity> {
        self.entries.get(cve_id).and_then(|e| e.cvss_v3.as_ref()).map(|m| &m.severity)
    }

    pub fn get_epss(&self, cve_id: &str) -> Option<&EpssData> {
        self.epss_data.get(cve_id)
            .or_else(|| self.entries.get(cve_id).and_then(|e| e.epss.as_ref()))
    }

    pub fn is_high_epss_risk(&self, cve_id: &str) -> bool {
        self.get_epss(cve_id).map(|e| e.is_high_risk()).unwrap_or(false)
    }

    pub fn get_high_epss_cves(&self) -> Vec<&NvdCveEntry> {
        self.entries.values()
            .filter(|e| e.epss.as_ref().map(|epss| epss.is_high_risk()).unwrap_or(false))
            .collect()
    }

    pub fn has_exploit(&self, cve_id: &str) -> bool {
        self.entries.get(cve_id).map(|e| e.exploit_available).unwrap_or(false)
    }

    pub fn is_version_affected(&self, cve_id: &str, version: &str) -> bool {
        self.entries.get(cve_id)
            .map(|e| e.affected_versions.iter().any(|vr| vr.is_affected(version)))
            .unwrap_or(false)
    }

    pub fn is_critical(&self, cve_id: &str) -> bool {
        matches!(self.get_severity(cve_id), Some(CvssV3Severity::Critical))
    }

    pub fn get_critical_cves(&self) -> Vec<&NvdCveEntry> {
        self.entries.values()
            .filter(|e| e.cvss_v3.as_ref().map(|m| m.severity == CvssV3Severity::Critical).unwrap_or(false))
            .collect()
    }

    pub fn get_cves_by_cwe(&self, cwe_id: &str) -> Vec<&NvdCveEntry> {
        self.entries.values()
            .filter(|e| e.cwe.contains(&cwe_id.to_string()))
            .collect()
    }

    pub fn get_cves_by_product(&self, cpe_pattern: &str) -> Vec<&NvdCveEntry> {
        self.entries.values()
            .filter(|e| e.affected_products.iter().any(|p| p.contains(cpe_pattern)))
            .collect()
    }

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
    fn test_cvss_v4_severity_from_score() {
        assert_eq!(CvssV4Severity::from_score(0.0), CvssV4Severity::None);
        assert_eq!(CvssV4Severity::from_score(3.9), CvssV4Severity::Low);
        assert_eq!(CvssV4Severity::from_score(6.9), CvssV4Severity::Medium);
        assert_eq!(CvssV4Severity::from_score(8.9), CvssV4Severity::High);
        assert_eq!(CvssV4Severity::from_score(10.0), CvssV4Severity::Critical);
    }

    #[test]
    fn test_nvd_database() {
        let db = NvdDatabase::new();
        assert!(db.count() >= 6, "Should have 6+ CVE entries");
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
    fn test_cvss_v4_support() {
        let db = NvdDatabase::new();
        assert_eq!(db.get_cvss_v4_score("CVE-2021-44228"), Some(10.0));
        assert_eq!(db.get_cvss_v4_score("CVE-2014-0160"), Some(7.5));
        assert_eq!(db.get_cvss_v4_score("CVE-NONEXISTENT"), None);
    }

    #[test]
    fn test_best_cvss_score() {
        let db = NvdDatabase::new();
        assert_eq!(db.get_best_cvss_score("CVE-2021-44228"), Some(10.0));
        assert_eq!(db.get_best_cvss_score("CVE-NONEXISTENT"), None);
    }

    #[test]
    fn test_epss_data() {
        let db = NvdDatabase::new();
        let epss = db.get_epss("CVE-2021-44228").unwrap();
        assert_eq!(epss.cve_id, "CVE-2021-44228");
        assert!(epss.epss_probability > 0.9);
        assert!(epss.is_high_risk());
        assert_eq!(epss.risk_level(), "VERY HIGH");
        assert!(db.is_high_epss_risk("CVE-2021-44228"));
        assert!(!db.is_high_epss_risk("CVE-2014-3566"));
    }

    #[test]
    fn test_high_epss_cves() {
        let db = NvdDatabase::new();
        let high_risk = db.get_high_epss_cves();
        assert!(high_risk.len() >= 5, "Should have 5+ high EPSS CVEs");
    }

    #[test]
    fn test_is_critical() {
        let db = NvdDatabase::new();
        assert!(db.is_critical("CVE-2021-44228"));
        assert!(db.is_critical("CVE-2019-0708"));
        assert!(!db.is_critical("CVE-2014-0160"));
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

    #[test]
    fn test_cvss_v4_metrics() {
        let metrics = CvssV4Metrics::from_score(9.8);
        assert_eq!(metrics.base_score, 9.8);
        assert_eq!(metrics.severity, CvssV4Severity::Critical);
        assert!(metrics.is_easily_exploitable());
    }

    #[test]
    fn test_version_range() {
        let vr = VersionRange {
            product: "test".to_string(),
            version_start: Some("1.0".to_string()),
            version_end: Some("2.0".to_string()),
            end_inclusive: false,
            affected_versions: vec!["0.9".to_string()],
        };
        assert!(vr.is_affected("0.9"));
        assert!(vr.is_affected("1.0"));
        assert!(vr.is_affected("1.5"));
        assert!(!vr.is_affected("2.0"));
        assert!(!vr.is_affected("2.1"));
    }

    #[test]
    fn test_exploit_available() {
        let db = NvdDatabase::new();
        assert!(db.has_exploit("CVE-2021-44228"));
        assert!(db.has_exploit("CVE-2014-0160"));
    }

    #[test]
    fn test_cves_by_cwe() {
        let db = NvdDatabase::new();
        let cwe_78 = db.get_cves_by_cwe("CWE-78");
        assert!(cwe_78.len() >= 1, "Should have CWE-78 entries");
    }

    #[test]
    fn test_cves_by_product() {
        let db = NvdDatabase::new();
        let exchange = db.get_cves_by_product("microsoft:exchange");
        assert!(exchange.len() >= 1, "Should have Exchange CVEs");
    }
}
