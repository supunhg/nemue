use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    #[serde(default)]
    pub scan_type: ScanType,
    #[serde(default)]
    pub timing: TimingTemplate,
    #[serde(default)]
    pub enable_service_detection: bool,
    #[serde(default)]
    pub enable_os_detection: bool,
    #[serde(default)]
    pub enable_vuln_check: bool,
    #[serde(default)]
    pub enable_threat_intel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum ScanType {
    #[default]
    Tcp,
    Udp,
    Syn,
    Connect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TimingTemplate {
    Paranoid,
    Sneaky,
    Polite,
    #[default]
    Normal,
    Aggressive,
    Insane,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    pub scan_id: Uuid,
    pub status: ScanState,
    pub progress: f32,
    pub targets_total: usize,
    pub targets_completed: usize,
    pub ports_total: usize,
    pub ports_scanned: usize,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub scan_id: Uuid,
    pub targets: Vec<TargetResult>,
    pub total_open_ports: usize,
    pub total_vulnerabilities: usize,
    pub overall_risk_score: u8,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetResult {
    pub target: String,
    pub ip: IpAddr,
    pub status: HostStatus,
    pub open_ports: Vec<PortResult>,
    pub os_detection: Option<OsInfo>,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub threat_info: Option<ThreatInfo>,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostStatus {
    Up,
    Down,
    Filtered,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub version: Option<String>,
    pub product: Option<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub os_family: String,
    pub os_generation: Option<String>,
    pub confidence: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub cve_id: String,
    pub severity: String,
    pub cvss_score: f32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub is_malicious: bool,
    pub threat_level: String,
    pub categories: Vec<String>,
    pub confidence_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
    pub status_code: u16,
}

impl ApiError {
    pub fn new(error: &str, message: &str, status_code: u16) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
            status_code,
        }
    }

    pub fn bad_request(message: &str) -> Self {
        Self::new("bad_request", message, 400)
    }

    pub fn not_found(message: &str) -> Self {
        Self::new("not_found", message, 404)
    }

    #[allow(dead_code)]
    pub fn internal_error(message: &str) -> Self {
        Self::new("internal_error", message, 500)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub active_scans: usize,
    pub completed_scans: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanListResponse {
    pub scans: Vec<ScanSummary>,
    pub total: usize,
    pub page: usize,
    pub per_page: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: Uuid,
    pub status: ScanState,
    pub targets_count: usize,
    pub ports_count: usize,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Aggregated scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub total_scans: usize,
    pub active_scans: usize,
    pub completed_scans: usize,
    pub failed_scans: usize,
    pub cancelled_scans: usize,
    pub total_targets_scanned: usize,
    pub total_ports_scanned: usize,
    pub uptime_seconds: u64,
}

/// Request to register a webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterWebhookRequest {
    pub url: String,
    pub provider: super::webhooks::WebhookProvider,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default)]
    pub events: Vec<String>,
}

fn default_max_retries() -> u32 {
    3
}

/// Registered webhook info (without secrets)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookInfo {
    pub webhook_id: Uuid,
    pub url: String,
    pub provider: super::webhooks::WebhookProvider,
    pub events: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Request to evaluate CI/CD results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdEvaluateRequest {
    pub scan_id: String,
    #[serde(default)]
    pub targets_scanned: usize,
    #[serde(default)]
    pub total_open_ports: usize,
    #[serde(default)]
    pub total_vulnerabilities: usize,
    #[serde(default)]
    pub risk_score: u8,
}
