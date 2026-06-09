use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Prediction for likely vulnerabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnPrediction {
    /// Service or component
    pub target: String,
    /// Predicted vulnerability type
    pub vuln_type: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// CVE identifiers (if known)
    pub potential_cves: Vec<String>,
    /// Reasoning for prediction
    pub reasoning: String,
    /// Recommended checks
    pub recommended_checks: Vec<String>,
}

/// Prediction for attack vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackVector {
    /// Vector name
    pub name: String,
    /// Target service or host
    pub target: String,
    /// Likelihood score (0.0 - 1.0)
    pub likelihood: f64,
    /// Impact score (0.0 - 1.0)
    pub impact: f64,
    /// Required conditions
    pub conditions: Vec<String>,
    /// Mitigation strategies
    pub mitigations: Vec<String>,
}

/// Version prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionPrediction {
    /// Target service or OS
    pub target: String,
    /// Predicted version
    pub predicted_version: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Evidence supporting prediction
    pub evidence: Vec<String>,
    /// Alternative versions
    pub alternatives: Vec<String>,
}

/// Predictive analytics engine
pub struct PredictiveEngine {
    /// Service vulnerability patterns
    vuln_patterns: HashMap<String, Vec<VulnPattern>>,
    /// Attack vector database
    attack_vectors: Vec<AttackVectorTemplate>,
    /// Version fingerprints
    version_fingerprints: HashMap<String, Vec<VersionFingerprint>>,
}

#[derive(Debug, Clone)]
struct VulnPattern {
    pattern: String,
    vuln_type: String,
    cve_prefix: String,
    confidence_base: f64,
}

#[derive(Debug, Clone)]
struct AttackVectorTemplate {
    name: String,
    target_services: Vec<String>,
    conditions: Vec<String>,
    mitigations: Vec<String>,
    base_likelihood: f64,
    base_impact: f64,
}

#[derive(Debug, Clone)]
struct VersionFingerprint {
    version: String,
    indicators: Vec<String>,
    weight: f64,
}

impl PredictiveEngine {
    /// Create a new predictive engine
    pub fn new() -> Self {
        let mut vuln_patterns = HashMap::new();

        // SSH vulnerability patterns
        vuln_patterns.insert("ssh".to_string(), vec![
            VulnPattern {
                pattern: "OpenSSH".to_string(),
                vuln_type: "Authentication bypass".to_string(),
                cve_prefix: "CVE-2023-".to_string(),
                confidence_base: 0.3,
            },
            VulnPattern {
                pattern: "SSH-1".to_string(),
                vuln_type: "Protocol weakness".to_string(),
                cve_prefix: "CVE-1999-".to_string(),
                confidence_base: 0.8,
            },
        ]);

        // HTTP vulnerability patterns
        vuln_patterns.insert("http".to_string(), vec![
            VulnPattern {
                pattern: "Apache/2.2".to_string(),
                vuln_type: "Multiple vulnerabilities".to_string(),
                cve_prefix: "CVE-2021-".to_string(),
                confidence_base: 0.7,
            },
            VulnPattern {
                pattern: "nginx/1.0".to_string(),
                vuln_type: "Buffer overflow".to_string(),
                cve_prefix: "CVE-2022-".to_string(),
                confidence_base: 0.6,
            },
        ]);

        // SMB vulnerability patterns
        vuln_patterns.insert("smb".to_string(), vec![
            VulnPattern {
                pattern: "SMBv1".to_string(),
                vuln_type: "Remote code execution".to_string(),
                cve_prefix: "CVE-2017-".to_string(),
                confidence_base: 0.9,
            },
        ]);

        let attack_vectors = vec![
            AttackVectorTemplate {
                name: "Brute force".to_string(),
                target_services: vec!["ssh".to_string(), "ftp".to_string(), "rdp".to_string()],
                conditions: vec!["Weak passwords".to_string(), "No rate limiting".to_string()],
                mitigations: vec![
                    "Implement account lockout".to_string(),
                    "Use MFA".to_string(),
                    "Rate limit connections".to_string(),
                ],
                base_likelihood: 0.7,
                base_impact: 0.6,
            },
            AttackVectorTemplate {
                name: "SQL Injection".to_string(),
                target_services: vec!["http".to_string(), "https".to_string(), "mysql".to_string()],
                conditions: vec![
                    "Dynamic SQL queries".to_string(),
                    "Insufficient input validation".to_string(),
                ],
                mitigations: vec![
                    "Use parameterized queries".to_string(),
                    "Input validation".to_string(),
                    "WAF deployment".to_string(),
                ],
                base_likelihood: 0.5,
                base_impact: 0.9,
            },
            AttackVectorTemplate {
                name: "Remote code execution".to_string(),
                target_services: vec!["smb".to_string(), "rdp".to_string(), "http".to_string()],
                conditions: vec![
                    "Vulnerable service version".to_string(),
                    "Public-facing service".to_string(),
                ],
                mitigations: vec![
                    "Patch management".to_string(),
                    "Network segmentation".to_string(),
                    "Disable unnecessary services".to_string(),
                ],
                base_likelihood: 0.3,
                base_impact: 1.0,
            },
            AttackVectorTemplate {
                name: "Man-in-the-middle".to_string(),
                target_services: vec!["http".to_string(), "ftp".to_string(), "telnet".to_string()],
                conditions: vec![
                    "Cleartext protocol".to_string(),
                    "Network access".to_string(),
                ],
                mitigations: vec![
                    "Use encrypted protocols".to_string(),
                    "Certificate pinning".to_string(),
                    "VPN usage".to_string(),
                ],
                base_likelihood: 0.4,
                base_impact: 0.7,
            },
        ];

        let mut version_fingerprints = HashMap::new();

        // SSH version fingerprints
        version_fingerprints.insert("ssh".to_string(), vec![
            VersionFingerprint {
                version: "OpenSSH_8.9".to_string(),
                indicators: vec!["SSH-2.0-OpenSSH_8.9".to_string()],
                weight: 0.9,
            },
            VersionFingerprint {
                version: "OpenSSH_7.4".to_string(),
                indicators: vec!["SSH-2.0-OpenSSH_7.4".to_string()],
                weight: 0.8,
            },
        ]);

        // HTTP version fingerprints
        version_fingerprints.insert("http".to_string(), vec![
            VersionFingerprint {
                version: "Apache/2.4.54".to_string(),
                indicators: vec!["Apache/2.4.54".to_string(), "Server: Apache/2.4.54".to_string()],
                weight: 0.85,
            },
            VersionFingerprint {
                version: "nginx/1.22.1".to_string(),
                indicators: vec!["nginx/1.22.1".to_string(), "Server: nginx/1.22.1".to_string()],
                weight: 0.85,
            },
        ]);

        Self {
            vuln_patterns,
            attack_vectors,
            version_fingerprints,
        }
    }

    /// Predict likely vulnerabilities for a service
    pub fn predict_vulnerabilities(&self, service: &str, banner: Option<&str>) -> Vec<VulnPrediction> {
        let service_lower = service.to_lowercase();
        let mut predictions = Vec::new();

        if let Some(patterns) = self.vuln_patterns.get(&service_lower) {
            for pattern in patterns {
                let mut confidence = pattern.confidence_base;

                // Check if banner matches pattern
                if let Some(b) = banner {
                    if b.to_lowercase().contains(&pattern.pattern.to_lowercase()) {
                        confidence = (confidence + 0.3).min(1.0);
                    }
                }

                predictions.push(VulnPrediction {
                    target: service.to_string(),
                    vuln_type: pattern.vuln_type.clone(),
                    confidence,
                    potential_cves: vec![format!("{}*", pattern.cve_prefix)],
                    reasoning: format!(
                        "Service '{}' matches vulnerability pattern '{}'",
                        service, pattern.pattern
                    ),
                    recommended_checks: vec![
                        format!("Check for {} vulnerabilities", pattern.vuln_type),
                        "Verify service version".to_string(),
                        "Test for known CVEs".to_string(),
                    ],
                });
            }
        }

        // Generic prediction for any service
        if predictions.is_empty() {
            predictions.push(VulnPrediction {
                target: service.to_string(),
                vuln_type: "Configuration weakness".to_string(),
                confidence: 0.3,
                potential_cves: vec![],
                reasoning: "Default configuration may have security issues".to_string(),
                recommended_checks: vec![
                    "Review default credentials".to_string(),
                    "Check for unnecessary features".to_string(),
                    "Verify access controls".to_string(),
                ],
            });
        }

        predictions
    }

    /// Predict attack vectors for a set of services
    pub fn predict_attack_vectors(&self, services: &[String]) -> Vec<AttackVector> {
        let mut vectors = Vec::new();

        for template in &self.attack_vectors {
            // Check if any service matches target services
            let matching_services: Vec<&String> = services
                .iter()
                .filter(|s| template.target_services.contains(s))
                .collect();

            if !matching_services.is_empty() {
                let likelihood = template.base_likelihood * (matching_services.len() as f64 / services.len() as f64).min(1.0);

                vectors.push(AttackVector {
                    name: template.name.clone(),
                    target: matching_services
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    likelihood,
                    impact: template.base_impact,
                    conditions: template.conditions.clone(),
                    mitigations: template.mitigations.clone(),
                });
            }
        }

        // Sort by risk (likelihood * impact)
        vectors.sort_by(|a, b| {
            let risk_a = a.likelihood * a.impact;
            let risk_b = b.likelihood * b.impact;
            risk_b.partial_cmp(&risk_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        vectors
    }

    /// Predict service version from banner
    pub fn predict_service_version(&self, service: &str, banner: &str) -> Option<VersionPrediction> {
        let service_lower = service.to_lowercase();

        if let Some(fingerprints) = self.version_fingerprints.get(&service_lower) {
            let mut best_match: Option<(&VersionFingerprint, f64)> = None;

            for fp in fingerprints {
                let mut match_score = 0.0;
                let mut matched_indicators = Vec::new();

                for indicator in &fp.indicators {
                    if banner.contains(indicator) {
                        match_score += fp.weight;
                        matched_indicators.push(indicator.clone());
                    }
                }

                if match_score > 0.0 {
                    if let Some((_, best_score)) = best_match {
                        if match_score > best_score {
                            best_match = Some((fp, match_score));
                        }
                    } else {
                        best_match = Some((fp, match_score));
                    }
                }
            }

            if let Some((fp, score)) = best_match {
                return Some(VersionPrediction {
                    target: service.to_string(),
                    predicted_version: fp.version.clone(),
                    confidence: score.min(1.0),
                    evidence: fp.indicators.clone(),
                    alternatives: fingerprints
                        .iter()
                        .filter(|f| f.version != fp.version)
                        .map(|f| f.version.clone())
                        .collect(),
                });
            }
        }

        None
    }

    /// Predict OS version from fingerprints
    pub fn predict_os_version(&self, fingerprints: &[String]) -> Option<VersionPrediction> {
        let mut os_scores: HashMap<String, f64> = HashMap::new();
        let mut os_evidence: HashMap<String, Vec<String>> = HashMap::new();

        // Simple OS detection based on common patterns
        for fp in fingerprints {
            let fp_lower = fp.to_lowercase();

            if fp_lower.contains("windows") || fp_lower.contains("microsoft") {
                let entry = os_scores.entry("Windows".to_string()).or_insert(0.0);
                *entry += 0.6;
                os_evidence
                    .entry("Windows".to_string())
                    .or_default()
                    .push(fp.clone());
            }

            if fp_lower.contains("linux") || fp_lower.contains("ubuntu") || fp_lower.contains("debian") {
                let entry = os_scores.entry("Linux".to_string()).or_insert(0.0);
                *entry += 0.6;
                os_evidence
                    .entry("Linux".to_string())
                    .or_default()
                    .push(fp.clone());
            }

            if fp_lower.contains("macos") || fp_lower.contains("darwin") {
                let entry = os_scores.entry("macOS".to_string()).or_insert(0.0);
                *entry += 0.7;
                os_evidence
                    .entry("macOS".to_string())
                    .or_default()
                    .push(fp.clone());
            }

            if fp_lower.contains("freebsd") || fp_lower.contains("openbsd") {
                let entry = os_scores.entry("BSD".to_string()).or_insert(0.0);
                *entry += 0.7;
                os_evidence
                    .entry("BSD".to_string())
                    .or_default()
                    .push(fp.clone());
            }
        }

        // Find best match
        os_scores
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(os, &score)| VersionPrediction {
                target: "Operating System".to_string(),
                predicted_version: os.clone(),
                confidence: score.min(1.0),
                evidence: os_evidence.get(os).cloned().unwrap_or_default(),
                alternatives: os_scores
                    .keys()
                    .filter(|k| *k != os)
                    .cloned()
                    .collect(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predict_vulnerabilities_ssh() {
        let engine = PredictiveEngine::new();
        let predictions = engine.predict_vulnerabilities("ssh", Some("SSH-2.0-OpenSSH_8.9"));

        assert!(!predictions.is_empty());
        assert!(predictions.iter().any(|p| p.vuln_type.contains("Authentication")));
    }

    #[test]
    fn test_predict_vulnerabilities_http() {
        let engine = PredictiveEngine::new();
        let predictions = engine.predict_vulnerabilities("http", Some("Apache/2.2.34"));

        assert!(!predictions.is_empty());
        assert!(predictions.iter().any(|p| p.confidence > 0.5));
    }

    #[test]
    fn test_predict_vulnerabilities_unknown_service() {
        let engine = PredictiveEngine::new();
        let predictions = engine.predict_vulnerabilities("custom_service", None);

        assert!(!predictions.is_empty());
        assert!(predictions[0].vuln_type.contains("Configuration"));
    }

    #[test]
    fn test_predict_attack_vectors() {
        let engine = PredictiveEngine::new();
        let services = vec![
            "ssh".to_string(),
            "http".to_string(),
            "ftp".to_string(),
        ];

        let vectors = engine.predict_attack_vectors(&services);
        assert!(!vectors.is_empty());

        // Should have brute force for ssh and ftp
        assert!(vectors.iter().any(|v| v.name == "Brute force"));

        // Should have SQL injection for http
        assert!(vectors.iter().any(|v| v.name == "SQL Injection"));
    }

    #[test]
    fn test_predict_attack_vectors_empty_services() {
        let engine = PredictiveEngine::new();
        let vectors = engine.predict_attack_vectors(&[]);

        assert!(vectors.is_empty());
    }

    #[test]
    fn test_predict_service_version_ssh() {
        let engine = PredictiveEngine::new();
        let prediction = engine.predict_service_version("ssh", "SSH-2.0-OpenSSH_8.9");

        assert!(prediction.is_some());
        let pred = prediction.unwrap();
        assert_eq!(pred.predicted_version, "OpenSSH_8.9");
        assert!(pred.confidence > 0.0);
    }

    #[test]
    fn test_predict_service_version_no_match() {
        let engine = PredictiveEngine::new();
        let prediction = engine.predict_service_version("ssh", "Unknown banner");

        assert!(prediction.is_none());
    }

    #[test]
    fn test_predict_os_version_linux() {
        let engine = PredictiveEngine::new();
        let fingerprints = vec![
            "Linux 5.15.0".to_string(),
            "Ubuntu 22.04".to_string(),
        ];

        let prediction = engine.predict_os_version(&fingerprints);
        assert!(prediction.is_some());
        assert_eq!(prediction.unwrap().predicted_version, "Linux");
    }

    #[test]
    fn test_predict_os_version_windows() {
        let engine = PredictiveEngine::new();
        let fingerprints = vec![
            "Windows Server 2022".to_string(),
            "Microsoft IIS/10.0".to_string(),
        ];

        let prediction = engine.predict_os_version(&fingerprints);
        assert!(prediction.is_some());
        assert_eq!(prediction.unwrap().predicted_version, "Windows");
    }

    #[test]
    fn test_predict_os_version_empty() {
        let engine = PredictiveEngine::new();
        let prediction = engine.predict_os_version(&[]);

        assert!(prediction.is_none());
    }
}
