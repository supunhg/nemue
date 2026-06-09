mod engine;
mod target;
mod port;
mod rate_limiter;
mod stealth;
mod timing;
mod discovery;
mod dns;
mod scan_types;
mod fragmentation;
mod decoy;
mod spoofing;
mod payload;
mod proxy;
pub mod packet_io;
pub mod config;
pub mod diff;
pub mod idle;
pub mod ftp_bounce;
pub mod history;
pub mod trends;

pub use engine::ScanEngine;
pub use target::{Target, TargetParser, TargetConfig};
pub use port::{Port, PortParser, PortProtocol, PortRange, PortSelectionMode, PortSpec, ProtocolPort};
pub use rate_limiter::RateLimiter;
pub use stealth::StealthOptions;
pub use timing::{
    TimingTemplate, TimingConfig, TimingConfigBuilder,
    parse_duration, parse_parallelism, parse_rate, parse_retries, parse_hostgroup,
};
pub use discovery::{HostDiscovery, DiscoveryMethod, DiscoveryConfig, DiscoveryResult};
pub use dns::{DnsResolver, DnsConfig};
pub use scan_types::{
    ScanType, 
    TcpFlags, 
    AdvancedScanner, 
    PortState as ScanPortState, 
    PortStateReason, 
    ScanResult as AdvancedScanResult
};
pub use fragmentation::{
    FragmentationConfig, IpFragment, PacketFragmenter, FragmentReassembler,
};
pub use decoy::{
    DecoyConfig, DecoyScanner, RealSourcePosition, DecoyListBuilder,
};
pub use spoofing::{
    MacAddress, SourceConfig, SourceSpoofer, SourceSpooferBuilder, 
    SourcePortStrategy, NetworkInterface,
};
pub use payload::{
    PayloadConfig, PayloadBuilder, CustomPacketBuilder, IpOption, TtlPresets,
};
pub use proxy::{
    ProxyProtocol, ProxyConfig, ProxyChain, ProxyClient, ProxyConnection, ProxyChainBuilder,
};
pub use history::{ScanHistory, HistoryEntry, ScanSummary};
pub use trends::{TrendReport, PortTrend, ServiceTrend, TrendSummary, TrendAnalyzer};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub os_fingerprints: Vec<crate::fingerprint::OsFingerprint>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub script_results: Vec<ScriptOutputResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptOutputResult {
    pub target: IpAddr,
    pub port: u16,
    pub script_name: String,
    pub output: String,
}
