mod engine;
mod target;
mod port;
mod rate_limiter;
mod stealth;

pub use engine::ScanEngine;
pub use target::{Target, TargetParser};
pub use port::{Port, PortParser};
pub use rate_limiter::RateLimiter;
pub use stealth::{StealthOptions, TimingTemplate};

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub state: PortState,
    pub protocol: Protocol,
    pub service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_info: Option<crate::service::ServiceInfo>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::TCP => write!(f, "tcp"),
            Protocol::UDP => write!(f, "udp"),
            Protocol::ICMP => write!(f, "icmp"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub scan_start: chrono::DateTime<chrono::Utc>,
    pub scan_end: chrono::DateTime<chrono::Utc>,
    pub target_count: usize,
    pub port_count: usize,
    pub results: Vec<ScanResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub os_fingerprints: Vec<crate::fingerprint::OsFingerprint>,
}
