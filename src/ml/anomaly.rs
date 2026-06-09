use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Types of anomalies that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Unusual open port detected
    UnusualPort,
    /// Unusual service detected
    UnusualService,
    /// Unusual OS fingerprint
    UnusualOsFingerprint,
    /// Scan anomaly (timing, pattern, etc.)
    ScanAnomaly,
}

/// Result of anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    /// Type of anomaly detected
    pub anomaly_type: AnomalyType,
    /// Severity score (0.0 - 1.0)
    pub severity: f64,
    /// Description of the anomaly
    pub description: String,
    /// Related port (if applicable)
    pub port: Option<u16>,
    /// Related service (if applicable)
    pub service: Option<String>,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
}

/// Baseline statistics for a network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBaseline {
    /// Commonly open ports with frequency
    pub common_ports: HashMap<u16, f64>,
    /// Commonly seen services with frequency
    pub common_services: HashMap<String, f64>,
    /// Common OS fingerprints
    pub common_os_fingerprints: HashMap<String, f64>,
    /// Total hosts scanned
    pub total_hosts: u64,
    /// Average number of open ports per host
    pub avg_open_ports: f64,
}

/// Anomaly detector for scan results
pub struct AnomalyDetector {
    baseline: NetworkBaseline,
    /// Threshold for anomaly detection (0.0 - 1.0)
    threshold: f64,
    /// Known high-risk ports
    high_risk_ports: HashSet<u16>,
    /// Known suspicious services
    suspicious_services: HashSet<String>,
}

impl AnomalyDetector {
    /// Create a new anomaly detector with default baseline
    pub fn new(threshold: f64) -> Self {
        let mut high_risk_ports = HashSet::new();
        // Common high-risk ports
        for port in [21, 23, 25, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017] {
            high_risk_ports.insert(port);
        }

        let mut suspicious_services = HashSet::new();
        for svc in ["telnet", "ftp", "rsh", "rlogin", "rexec", "vnc", "x11", "rdp", "smb"] {
            suspicious_services.insert(svc.to_string());
        }

        Self {
            baseline: NetworkBaseline {
                common_ports: HashMap::new(),
                common_services: HashMap::new(),
                common_os_fingerprints: HashMap::new(),
                total_hosts: 0,
                avg_open_ports: 0.0,
            },
            threshold,
            high_risk_ports,
            suspicious_services,
        }
    }

    /// Create detector with custom baseline
    pub fn with_baseline(baseline: NetworkBaseline, threshold: f64) -> Self {
        let mut detector = Self::new(threshold);
        detector.baseline = baseline;
        detector
    }

    /// Update the baseline with new scan data
    pub fn update_baseline(&mut self, hosts: &[HostScanResult]) {
        let total = hosts.len() as u64;
        if total == 0 {
            return;
        }

        let mut port_counts: HashMap<u16, u64> = HashMap::new();
        let mut service_counts: HashMap<String, u64> = HashMap::new();
        let mut os_counts: HashMap<String, u64> = HashMap::new();
        let mut total_ports = 0u64;

        for host in hosts {
            for port in &host.open_ports {
                *port_counts.entry(*port).or_insert(0) += 1;
                total_ports += 1;
            }
            if let Some(svc) = &host.service {
                *service_counts.entry(svc.clone()).or_insert(0) += 1;
            }
            if let Some(os) = &host.os_fingerprint {
                *os_counts.entry(os.clone()).or_insert(0) += 1;
            }
        }

        self.baseline.total_hosts = total;
        self.baseline.avg_open_ports = total_ports as f64 / total as f64;

        for (port, count) in port_counts {
            self.baseline.common_ports.insert(port, count as f64 / total as f64);
        }

        for (svc, count) in service_counts {
            self.baseline.common_services.insert(svc, count as f64 / total as f64);
        }

        for (os, count) in os_counts {
            self.baseline.common_os_fingerprints.insert(os, count as f64 / total as f64);
        }
    }

    /// Detect anomalies in a host scan result
    pub fn detect(&self, host: &HostScanResult) -> Vec<AnomalyResult> {
        let mut anomalies = Vec::new();

        // Check for unusual open ports
        anomalies.extend(self.detect_unusual_ports(host));

        // Check for unusual services
        anomalies.extend(self.detect_unusual_services(host));

        // Check for unusual OS fingerprints
        anomalies.extend(self.detect_unusual_os(host));

        // Check for scan anomalies
        anomalies.extend(self.detect_scan_anomalies(host));

        anomalies
    }

    /// Detect unusual open ports
    fn detect_unusual_ports(&self, host: &HostScanResult) -> Vec<AnomalyResult> {
        let mut anomalies = Vec::new();

        for &port in &host.open_ports {
            let mut is_anomaly = false;
            let mut severity = 0.0;
            let mut description = String::new();

            // Port not in baseline at all
            if !self.baseline.common_ports.contains_key(&port) && self.baseline.total_hosts > 10 {
                is_anomaly = true;
                severity = 0.7;
                description = format!("Port {} is not commonly seen in network baseline", port);
            }
            // Port is very rare in baseline
            else if let Some(&freq) = self.baseline.common_ports.get(&port) {
                if freq < 0.05 && self.baseline.total_hosts > 10 {
                    is_anomaly = true;
                    severity = 0.5 + (0.05 - freq) * 10.0;
                    description = format!(
                        "Port {} is rarely seen (frequency: {:.1}%)",
                        port,
                        freq * 100.0
                    );
                }
            }

            // High-risk port detection
            if self.high_risk_ports.contains(&port) {
                severity = severity.max(0.6);
                if !is_anomaly {
                    is_anomaly = true;
                    description = format!("High-risk port {} is open", port);
                } else {
                    description.push_str(&format!(" and is a high-risk port"));
                }
            }

            if is_anomaly {
                anomalies.push(AnomalyResult {
                    anomaly_type: AnomalyType::UnusualPort,
                    severity: severity.min(1.0),
                    description,
                    port: Some(port),
                    service: None,
                    confidence: 0.8,
                });
            }
        }

        anomalies
    }

    /// Detect unusual services
    fn detect_unusual_services(&self, host: &HostScanResult) -> Vec<AnomalyResult> {
        let mut anomalies = Vec::new();

        if let Some(ref service) = host.service {
            // Check if service is suspicious
            if self.suspicious_services.contains(&service.to_lowercase()) {
                anomalies.push(AnomalyResult {
                    anomaly_type: AnomalyType::UnusualService,
                    severity: 0.7,
                    description: format!("Suspicious service detected: {}", service),
                    port: host.open_ports.first().copied(),
                    service: Some(service.clone()),
                    confidence: 0.9,
                });
            }

            // Check if service is not in baseline
            if !self.baseline.common_services.contains_key(service) && self.baseline.total_hosts > 10 {
                anomalies.push(AnomalyResult {
                    anomaly_type: AnomalyType::UnusualService,
                    severity: 0.5,
                    description: format!("Service '{}' is not in network baseline", service),
                    port: host.open_ports.first().copied(),
                    service: Some(service.clone()),
                    confidence: 0.7,
                });
            }
            // Check if service is rare
            else if let Some(&freq) = self.baseline.common_services.get(service) {
                if freq < 0.1 && self.baseline.total_hosts > 10 {
                    anomalies.push(AnomalyResult {
                        anomaly_type: AnomalyType::UnusualService,
                        severity: 0.4 + (0.1 - freq) * 5.0,
                        description: format!(
                            "Service '{}' is rarely seen (frequency: {:.1}%)",
                            service,
                            freq * 100.0
                        ),
                        port: host.open_ports.first().copied(),
                        service: Some(service.clone()),
                        confidence: 0.75,
                    });
                }
            }
        }

        anomalies
    }

    /// Detect unusual OS fingerprints
    fn detect_unusual_os(&self, host: &HostScanResult) -> Vec<AnomalyResult> {
        let mut anomalies = Vec::new();

        if let Some(ref os) = host.os_fingerprint {
            // OS not in baseline
            if !self.baseline.common_os_fingerprints.contains_key(os) && self.baseline.total_hosts > 10 {
                anomalies.push(AnomalyResult {
                    anomaly_type: AnomalyType::UnusualOsFingerprint,
                    severity: 0.6,
                    description: format!("OS '{}' is not in network baseline", os),
                    port: None,
                    service: None,
                    confidence: 0.65,
                });
            }
            // OS is rare
            else if let Some(&freq) = self.baseline.common_os_fingerprints.get(os) {
                if freq < 0.05 && self.baseline.total_hosts > 10 {
                    anomalies.push(AnomalyResult {
                        anomaly_type: AnomalyType::UnusualOsFingerprint,
                        severity: 0.4 + (0.05 - freq) * 8.0,
                        description: format!(
                            "OS '{}' is rarely seen (frequency: {:.1}%)",
                            os,
                            freq * 100.0
                        ),
                        port: None,
                        service: None,
                        confidence: 0.7,
                    });
                }
            }
        }

        anomalies
    }

    /// Detect scan anomalies (unusual patterns)
    fn detect_scan_anomalies(&self, host: &HostScanResult) -> Vec<AnomalyResult> {
        let mut anomalies = Vec::new();

        // Check for unusually high number of open ports
        let port_count = host.open_ports.len() as f64;
        if self.baseline.avg_open_ports > 0.0 && port_count > self.baseline.avg_open_ports * 3.0 {
            anomalies.push(AnomalyResult {
                anomaly_type: AnomalyType::ScanAnomaly,
                severity: 0.6,
                description: format!(
                    "Host has {} open ports (baseline average: {:.1})",
                    port_count, self.baseline.avg_open_ports
                ),
                port: None,
                service: None,
                confidence: 0.75,
            });
        }

        // Check for consecutive port ranges (potential scan or service)
        let mut sorted_ports: Vec<u16> = host.open_ports.clone();
        sorted_ports.sort();
        let mut consecutive_count = 1;
        let mut range_start = 0;
        for i in 1..sorted_ports.len() {
            if sorted_ports[i] == sorted_ports[i-1] + 1 {
                consecutive_count += 1;
                if consecutive_count >= 10 {
                    anomalies.push(AnomalyResult {
                        anomaly_type: AnomalyType::ScanAnomaly,
                        severity: 0.8,
                        description: format!(
                            "Consecutive port range detected: {}-{} ({} ports)",
                            sorted_ports[range_start],
                            sorted_ports[i],
                            consecutive_count
                        ),
                        port: None,
                        service: None,
                        confidence: 0.85,
                    });
                    break;
                }
            } else {
                consecutive_count = 1;
                range_start = i;
            }
        }

        anomalies
    }

    /// Get the current baseline
    pub fn baseline(&self) -> &NetworkBaseline {
        &self.baseline
    }
}

/// Host scan result for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostScanResult {
    /// IP address of the host
    pub ip: String,
    /// Open ports
    pub open_ports: Vec<u16>,
    /// Primary service detected
    pub service: Option<String>,
    /// OS fingerprint
    pub os_fingerprint: Option<String>,
    /// Scan duration in milliseconds
    pub scan_duration_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_host() -> HostScanResult {
        HostScanResult {
            ip: "192.168.1.1".to_string(),
            open_ports: vec![22, 80, 443],
            service: Some("ssh".to_string()),
            os_fingerprint: Some("Linux".to_string()),
            scan_duration_ms: Some(1000),
        }
    }

    fn create_baseline() -> NetworkBaseline {
        let mut common_ports = HashMap::new();
        common_ports.insert(22, 0.9);
        common_ports.insert(80, 0.8);
        common_ports.insert(443, 0.85);

        let mut common_services = HashMap::new();
        common_services.insert("ssh".to_string(), 0.9);
        common_services.insert("http".to_string(), 0.8);

        let mut common_os = HashMap::new();
        common_os.insert("Linux".to_string(), 0.7);
        common_os.insert("Windows".to_string(), 0.3);

        NetworkBaseline {
            common_ports,
            common_services,
            common_os_fingerprints: common_os,
            total_hosts: 100,
            avg_open_ports: 5.0,
        }
    }

    #[test]
    fn test_no_anomalies_for_normal_host() {
        let baseline = create_baseline();
        let detector = AnomalyDetector::with_baseline(baseline, 0.5);
        let host = create_test_host();

        let anomalies = detector.detect(&host);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_detect_unusual_port() {
        let baseline = create_baseline();
        let detector = AnomalyDetector::with_baseline(baseline, 0.5);
        let mut host = create_test_host();
        host.open_ports.push(31337); // Unusual port

        let anomalies = detector.detect(&host);
        assert!(anomalies.iter().any(|a| a.anomaly_type == AnomalyType::UnusualPort && a.port == Some(31337)));
    }

    #[test]
    fn test_detect_high_risk_port() {
        let baseline = create_baseline();
        let detector = AnomalyDetector::with_baseline(baseline, 0.5);
        let mut host = create_test_host();
        host.open_ports.push(3389); // RDP - high risk

        let anomalies = detector.detect(&host);
        assert!(anomalies.iter().any(|a| a.anomaly_type == AnomalyType::UnusualPort && a.port == Some(3389)));
    }

    #[test]
    fn test_detect_suspicious_service() {
        let baseline = create_baseline();
        let detector = AnomalyDetector::with_baseline(baseline, 0.5);
        let mut host = create_test_host();
        host.service = Some("telnet".to_string());

        let anomalies = detector.detect(&host);
        assert!(anomalies.iter().any(|a| a.anomaly_type == AnomalyType::UnusualService));
    }

    #[test]
    fn test_detect_unusual_os() {
        let baseline = create_baseline();
        let detector = AnomalyDetector::with_baseline(baseline, 0.5);
        let mut host = create_test_host();
        host.os_fingerprint = Some("FreeBSD".to_string());

        let anomalies = detector.detect(&host);
        assert!(anomalies.iter().any(|a| a.anomaly_type == AnomalyType::UnusualOsFingerprint));
    }

    #[test]
    fn test_detect_scan_anomaly_high_port_count() {
        let baseline = create_baseline();
        let detector = AnomalyDetector::with_baseline(baseline, 0.5);
        let mut host = create_test_host();
        host.open_ports = (1..=20).collect(); // 20 ports, baseline avg is 5

        let anomalies = detector.detect(&host);
        assert!(anomalies.iter().any(|a| a.anomaly_type == AnomalyType::ScanAnomaly));
    }

    #[test]
    fn test_detect_consecutive_ports() {
        let baseline = create_baseline();
        let detector = AnomalyDetector::with_baseline(baseline, 0.5);
        let mut host = create_test_host();
        host.open_ports = (1000..1020).collect(); // 20 consecutive ports

        let anomalies = detector.detect(&host);
        assert!(anomalies.iter().any(|a| a.anomaly_type == AnomalyType::ScanAnomaly && a.description.contains("Consecutive")));
    }

    #[test]
    fn test_update_baseline() {
        let mut detector = AnomalyDetector::new(0.5);
        let hosts = vec![
            HostScanResult {
                ip: "192.168.1.1".to_string(),
                open_ports: vec![22, 80],
                service: Some("ssh".to_string()),
                os_fingerprint: Some("Linux".to_string()),
                scan_duration_ms: None,
            },
            HostScanResult {
                ip: "192.168.1.2".to_string(),
                open_ports: vec![22, 443],
                service: Some("ssh".to_string()),
                os_fingerprint: Some("Linux".to_string()),
                scan_duration_ms: None,
            },
        ];

        detector.update_baseline(&hosts);
        assert_eq!(detector.baseline().total_hosts, 2);
        assert!(detector.baseline().common_ports.contains_key(&22));
    }
}
