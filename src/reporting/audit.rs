// Audit trail and evidence collection
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTrail {
    entries: Vec<AuditEntry>,
    metadata: AuditMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditMetadata {
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub operator: String,
    pub purpose: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub description: String,
    pub actor: String,
    pub target: Option<String>,
    pub evidence: Vec<Evidence>,
    pub metadata: HashMap<String, String>,
    pub severity: AuditSeverity,
    pub source_ip: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    ScanStarted,
    ScanCompleted,
    ScanCancelled,
    TargetDiscovered,
    PortScanned,
    ServiceDetected,
    VulnerabilityFound,
    ComplianceCheck,
    ConfigurationChange,
    ErrorOccurred,
    ApiAccess,
    AuthenticationSuccess,
    AuthenticationFailure,
    AuthorizationDenied,
    RateLimitExceeded,
    KeyRotated,
    SessionCreated,
    SessionDestroyed,
    ScanExported,
    ReportGenerated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_id: String,
    pub evidence_type: EvidenceType,
    pub description: String,
    pub data: String,
    pub collected_at: DateTime<Utc>,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceType {
    NetworkPacket,
    ServiceBanner,
    HttpResponse,
    Certificate,
    Configuration,
    Screenshot,
    LogEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExport {
    pub version: String,
    pub exported_at: DateTime<Utc>,
    pub entries: Vec<AuditEntry>,
    pub metadata: AuditMetadata,
    pub total_entries: usize,
    pub checksum: String,
}

impl AuditTrail {
    pub fn new(scan_id: String, operator: String, purpose: String) -> Self {
        Self {
            entries: Vec::new(),
            metadata: AuditMetadata {
                scan_id,
                started_at: Utc::now(),
                completed_at: None,
                operator,
                purpose,
            },
        }
    }

    pub fn add_entry(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }

    pub fn log_scan_event(&mut self, event_type: EventType, description: String, actor: String, target: Option<String>) {
        self.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type,
            description,
            actor,
            target,
            evidence: Vec::new(),
            metadata: HashMap::new(),
            severity: AuditSeverity::Info,
            source_ip: None,
            request_id: None,
        });
    }

    pub fn log_api_access(&mut self, method: &str, path: &str, status: u16, actor: String, source_ip: Option<String>, request_id: Option<String>) {
        let severity = if status >= 500 {
            AuditSeverity::Error
        } else if status >= 400 {
            AuditSeverity::Warning
        } else {
            AuditSeverity::Info
        };

        self.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::ApiAccess,
            description: format!("{} {} -> {}", method, path, status),
            actor,
            target: Some(path.to_string()),
            evidence: Vec::new(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("method".to_string(), method.to_string());
                m.insert("path".to_string(), path.to_string());
                m.insert("status".to_string(), status.to_string());
                m
            },
            severity,
            source_ip,
            request_id,
        });
    }

    pub fn log_auth_event(&mut self, success: bool, actor: String, source_ip: Option<String>, method: &str) {
        self.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: if success { EventType::AuthenticationSuccess } else { EventType::AuthenticationFailure },
            description: format!("Authentication {} via {}", if success { "succeeded" } else { "failed" }, method),
            actor,
            target: None,
            evidence: Vec::new(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("method".to_string(), method.to_string());
                m.insert("success".to_string(), success.to_string());
                m
            },
            severity: if success { AuditSeverity::Info } else { AuditSeverity::Warning },
            source_ip,
            request_id: None,
        });
    }

    pub fn log_config_change(&mut self, description: String, actor: String, key: &str, old_value: &str, new_value: &str) {
        self.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::ConfigurationChange,
            description,
            actor,
            target: None,
            evidence: Vec::new(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("key".to_string(), key.to_string());
                m.insert("old_value".to_string(), old_value.to_string());
                m.insert("new_value".to_string(), new_value.to_string());
                m
            },
            severity: AuditSeverity::Warning,
            source_ip: None,
            request_id: None,
        });
    }

    pub fn log_rate_limit_exceeded(&mut self, actor: String, source_ip: Option<String>, limit: u32) {
        self.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::RateLimitExceeded,
            description: format!("Rate limit exceeded (limit: {})", limit),
            actor,
            target: None,
            evidence: Vec::new(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("limit".to_string(), limit.to_string());
                m
            },
            severity: AuditSeverity::Warning,
            source_ip,
            request_id: None,
        });
    }

    pub fn log_key_rotation(&mut self, actor: String, key_name: &str) {
        self.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::KeyRotated,
            description: format!("API key '{}' rotated", key_name),
            actor,
            target: None,
            evidence: Vec::new(),
            metadata: {
                let mut m = HashMap::new();
                m.insert("key_name".to_string(), key_name.to_string());
                m
            },
            severity: AuditSeverity::Info,
            source_ip: None,
            request_id: None,
        });
    }

    pub fn complete(&mut self) {
        self.metadata.completed_at = Some(Utc::now());
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn entries_by_type(&self, event_type: EventType) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.event_type == event_type)
            .collect()
    }

    pub fn entries_for_target(&self, target: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.target.as_deref() == Some(target))
            .collect()
    }

    pub fn entries_by_severity(&self, severity: AuditSeverity) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.severity == severity)
            .collect()
    }

    pub fn entries_in_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    pub fn entries_for_actor(&self, actor: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.actor == actor)
            .collect()
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn export(&self) -> AuditExport {
        let json_entries = serde_json::to_string(&self.entries).unwrap_or_default();
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        json_entries.hash(&mut hasher);

        AuditExport {
            version: "1.0".to_string(),
            exported_at: Utc::now(),
            entries: self.entries.clone(),
            metadata: self.metadata.clone(),
            total_entries: self.entries.len(),
            checksum: format!("{:x}", hasher.finish()),
        }
    }

    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.export())
    }

    pub fn export_csv(&self) -> String {
        let mut csv = String::from("timestamp,event_type,severity,actor,target,description\n");
        for entry in &self.entries {
            csv.push_str(&format!(
                "{},{:?},{:?},{},{},{}\n",
                entry.timestamp.to_rfc3339(),
                entry.event_type,
                entry.severity,
                entry.actor,
                entry.target.as_deref().unwrap_or(""),
                entry.description.replace(',', ";").replace('\n', " ")
            ));
        }
        csv
    }

    pub fn chain_of_custody_report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== CHAIN OF CUSTODY ===\n\n");
        report.push_str(&format!("Scan ID: {}\n", self.metadata.scan_id));
        report.push_str(&format!("Operator: {}\n", self.metadata.operator));
        report.push_str(&format!("Purpose: {}\n", self.metadata.purpose));
        report.push_str(&format!("Started: {}\n", self.metadata.started_at));
        if let Some(completed) = self.metadata.completed_at {
            report.push_str(&format!("Completed: {}\n", completed));
        }
        report.push_str(&format!("Total Events: {}\n\n", self.entries.len()));

        report.push_str("=== EVENT LOG ===\n");
        for (i, entry) in self.entries.iter().enumerate() {
            report.push_str(&format!("\n[{}] {} - {:?} ({:?})\n",
                i + 1,
                entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                entry.event_type,
                entry.severity
            ));
            report.push_str(&format!("  Actor: {}\n", entry.actor));
            if let Some(target) = &entry.target {
                report.push_str(&format!("  Target: {}\n", target));
            }
            if let Some(source_ip) = &entry.source_ip {
                report.push_str(&format!("  Source IP: {}\n", source_ip));
            }
            report.push_str(&format!("  Description: {}\n", entry.description));
            if !entry.evidence.is_empty() {
                report.push_str(&format!("  Evidence Items: {}\n", entry.evidence.len()));
                for evidence in &entry.evidence {
                    report.push_str(&format!("    - {} (Hash: {})\n",
                        evidence.evidence_id,
                        &evidence.hash[..8]
                    ));
                }
            }
        }

        report
    }

    pub fn summary(&self) -> AuditSummary {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_severity: HashMap<String, usize> = HashMap::new();
        let mut by_actor: HashMap<String, usize> = HashMap::new();

        for entry in &self.entries {
            *by_type.entry(format!("{:?}", entry.event_type)).or_insert(0) += 1;
            *by_severity.entry(format!("{:?}", entry.severity)).or_insert(0) += 1;
            *by_actor.entry(entry.actor.clone()).or_insert(0) += 1;
        }

        AuditSummary {
            total_entries: self.entries.len(),
            by_type,
            by_severity,
            by_actor,
            time_span: if self.entries.len() >= 2 {
                Some((
                    self.entries.first().unwrap().timestamp,
                    self.entries.last().unwrap().timestamp,
                ))
            } else {
                None
            },
        }
    }

    pub fn generate_signature(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.metadata.scan_id.hash(&mut hasher);
        self.metadata.started_at.timestamp().hash(&mut hasher);
        self.entries.len().hash(&mut hasher);

        format!("{:x}", hasher.finish())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    pub total_entries: usize,
    pub by_type: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
    pub by_actor: HashMap<String, usize>,
    pub time_span: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

impl Evidence {
    pub fn new(
        evidence_id: String,
        evidence_type: EvidenceType,
        description: String,
        data: String,
    ) -> Self {
        let hash = Self::calculate_hash(&data);
        Self {
            evidence_id,
            evidence_type,
            description,
            data,
            collected_at: Utc::now(),
            hash,
        }
    }

    fn calculate_hash(data: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    pub fn verify(&self) -> bool {
        Self::calculate_hash(&self.data) == self.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_trail_creation() {
        let trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Security assessment".to_string(),
        );

        assert_eq!(trail.metadata.scan_id, "scan-001");
        assert_eq!(trail.metadata.operator, "admin");
        assert_eq!(trail.entries.len(), 0);
    }

    #[test]
    fn test_add_entry() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        let entry = AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::ScanStarted,
            description: "Scan initiated".to_string(),
            actor: "admin".to_string(),
            target: None,
            evidence: vec![],
            metadata: HashMap::new(),
            severity: AuditSeverity::Info,
            source_ip: None,
            request_id: None,
        };

        trail.add_entry(entry);
        assert_eq!(trail.entries.len(), 1);
    }

    #[test]
    fn test_complete_audit() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        assert!(trail.metadata.completed_at.is_none());
        trail.complete();
        assert!(trail.metadata.completed_at.is_some());
    }

    #[test]
    fn test_entries_by_type() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        trail.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::ScanStarted,
            description: "Start".to_string(),
            actor: "admin".to_string(),
            target: None,
            evidence: vec![],
            metadata: HashMap::new(),
            severity: AuditSeverity::Info,
            source_ip: None,
            request_id: None,
        });

        trail.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::VulnerabilityFound,
            description: "Vuln".to_string(),
            actor: "admin".to_string(),
            target: None,
            evidence: vec![],
            metadata: HashMap::new(),
            severity: AuditSeverity::Critical,
            source_ip: None,
            request_id: None,
        });

        let vuln_entries = trail.entries_by_type(EventType::VulnerabilityFound);
        assert_eq!(vuln_entries.len(), 1);
    }

    #[test]
    fn test_entries_for_target() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        trail.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::PortScanned,
            description: "Scanned".to_string(),
            actor: "admin".to_string(),
            target: Some("192.168.1.1".to_string()),
            evidence: vec![],
            metadata: HashMap::new(),
            severity: AuditSeverity::Info,
            source_ip: None,
            request_id: None,
        });

        let target_entries = trail.entries_for_target("192.168.1.1");
        assert_eq!(target_entries.len(), 1);
    }

    #[test]
    fn test_entries_by_severity() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        trail.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::ErrorOccurred,
            description: "Error".to_string(),
            actor: "system".to_string(),
            target: None,
            evidence: vec![],
            metadata: HashMap::new(),
            severity: AuditSeverity::Critical,
            source_ip: None,
            request_id: None,
        });

        trail.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::ScanStarted,
            description: "Start".to_string(),
            actor: "admin".to_string(),
            target: None,
            evidence: vec![],
            metadata: HashMap::new(),
            severity: AuditSeverity::Info,
            source_ip: None,
            request_id: None,
        });

        assert_eq!(trail.entries_by_severity(AuditSeverity::Critical).len(), 1);
        assert_eq!(trail.entries_by_severity(AuditSeverity::Info).len(), 1);
    }

    #[test]
    fn test_entries_for_actor() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        trail.log_scan_event(EventType::ScanStarted, "Start".to_string(), "admin".to_string(), None);
        trail.log_scan_event(EventType::ScanStarted, "Start".to_string(), "user2".to_string(), None);

        assert_eq!(trail.entries_for_actor("admin").len(), 1);
    }

    #[test]
    fn test_log_api_access() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "system".to_string(),
            "Test".to_string(),
        );

        trail.log_api_access("GET", "/api/v1/scans", 200, "user1".to_string(), Some("127.0.0.1".to_string()), Some("req-123".to_string()));

        assert_eq!(trail.entries.len(), 1);
        assert_eq!(trail.entries[0].event_type, EventType::ApiAccess);
    }

    #[test]
    fn test_log_auth_event() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "system".to_string(),
            "Test".to_string(),
        );

        trail.log_auth_event(true, "user1".to_string(), Some("127.0.0.1".to_string()), "jwt");
        trail.log_auth_event(false, "user2".to_string(), Some("10.0.0.1".to_string()), "api_key");

        assert_eq!(trail.entries.len(), 2);
        assert_eq!(trail.entries[0].event_type, EventType::AuthenticationSuccess);
        assert_eq!(trail.entries[1].event_type, EventType::AuthenticationFailure);
    }

    #[test]
    fn test_log_config_change() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        trail.log_config_change(
            "Rate limit changed".to_string(),
            "admin".to_string(),
            "max_rate",
            "1000",
            "2000",
        );

        assert_eq!(trail.entries.len(), 1);
        assert_eq!(trail.entries[0].event_type, EventType::ConfigurationChange);
        assert_eq!(trail.entries[0].severity, AuditSeverity::Warning);
    }

    #[test]
    fn test_log_rate_limit_exceeded() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "system".to_string(),
            "Test".to_string(),
        );

        trail.log_rate_limit_exceeded("user1".to_string(), Some("10.0.0.1".to_string()), 100);

        assert_eq!(trail.entries.len(), 1);
        assert_eq!(trail.entries[0].event_type, EventType::RateLimitExceeded);
    }

    #[test]
    fn test_log_key_rotation() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        trail.log_key_rotation("admin".to_string(), "primary-key");

        assert_eq!(trail.entries.len(), 1);
        assert_eq!(trail.entries[0].event_type, EventType::KeyRotated);
    }

    #[test]
    fn test_evidence_creation() {
        let evidence = Evidence::new(
            "ev-001".to_string(),
            EvidenceType::ServiceBanner,
            "SSH banner".to_string(),
            "SSH-2.0-OpenSSH_8.2".to_string(),
        );

        assert_eq!(evidence.evidence_id, "ev-001");
        assert_eq!(evidence.evidence_type, EvidenceType::ServiceBanner);
        assert!(!evidence.hash.is_empty());
    }

    #[test]
    fn test_evidence_verification() {
        let evidence = Evidence::new(
            "ev-001".to_string(),
            EvidenceType::ServiceBanner,
            "SSH banner".to_string(),
            "SSH-2.0-OpenSSH_8.2".to_string(),
        );

        assert!(evidence.verify());
    }

    #[test]
    fn test_chain_of_custody_report() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Security assessment".to_string(),
        );

        trail.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::ScanStarted,
            description: "Scan started".to_string(),
            actor: "admin".to_string(),
            target: None,
            evidence: vec![],
            metadata: HashMap::new(),
            severity: AuditSeverity::Info,
            source_ip: Some("127.0.0.1".to_string()),
            request_id: None,
        });

        let report = trail.chain_of_custody_report();
        assert!(report.contains("CHAIN OF CUSTODY"));
        assert!(report.contains("scan-001"));
        assert!(report.contains("admin"));
        assert!(report.contains("Source IP: 127.0.0.1"));
    }

    #[test]
    fn test_generate_signature() {
        let trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        let signature = trail.generate_signature();
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 16);
    }

    #[test]
    fn test_to_json() {
        let trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        let json = trail.to_json();
        assert!(json.is_ok());
        assert!(json.unwrap().contains("scan-001"));
    }

    #[test]
    fn test_export() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        trail.log_scan_event(EventType::ScanStarted, "Start".to_string(), "admin".to_string(), None);

        let export = trail.export();
        assert_eq!(export.version, "1.0");
        assert_eq!(export.total_entries, 1);
        assert!(!export.checksum.is_empty());
    }

    #[test]
    fn test_export_csv() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        trail.log_scan_event(EventType::ScanStarted, "Start".to_string(), "admin".to_string(), None);

        let csv = trail.export_csv();
        assert!(csv.contains("timestamp,event_type"));
        assert!(csv.contains("ScanStarted"));
    }

    #[test]
    fn test_summary() {
        let mut trail = AuditTrail::new(
            "scan-001".to_string(),
            "admin".to_string(),
            "Test".to_string(),
        );

        trail.log_scan_event(EventType::ScanStarted, "Start".to_string(), "admin".to_string(), None);
        trail.log_scan_event(EventType::ScanCompleted, "Done".to_string(), "admin".to_string(), None);
        trail.log_auth_event(false, "user2".to_string(), None, "api_key");

        let summary = trail.summary();
        assert_eq!(summary.total_entries, 3);
        assert!(summary.by_type.contains_key("ScanStarted"));
        assert!(summary.by_severity.contains_key("Warning"));
        assert!(summary.by_actor.contains_key("admin"));
    }
}
