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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    ScanStarted,
    ScanCompleted,
    TargetDiscovered,
    PortScanned,
    ServiceDetected,
    VulnerabilityFound,
    ComplianceCheck,
    ConfigurationChange,
    ErrorOccurred,
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

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
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
            report.push_str(&format!("\n[{}] {} - {:?}\n", 
                i + 1, 
                entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                entry.event_type
            ));
            report.push_str(&format!("  Actor: {}\n", entry.actor));
            if let Some(target) = &entry.target {
                report.push_str(&format!("  Target: {}\n", target));
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
        });

        trail.add_entry(AuditEntry {
            timestamp: Utc::now(),
            event_type: EventType::VulnerabilityFound,
            description: "Vuln".to_string(),
            actor: "admin".to_string(),
            target: None,
            evidence: vec![],
            metadata: HashMap::new(),
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
        });

        let target_entries = trail.entries_for_target("192.168.1.1");
        assert_eq!(target_entries.len(), 1);
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
        });

        let report = trail.chain_of_custody_report();
        assert!(report.contains("CHAIN OF CUSTODY"));
        assert!(report.contains("scan-001"));
        assert!(report.contains("admin"));
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
        assert_eq!(signature.len(), 16); // Hex string of u64
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
}
