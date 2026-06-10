pub mod cache;
pub mod compression;
pub mod config;
mod decoy;
pub mod dedup;
pub mod diff;
mod discovery;
mod dns;
pub mod encryption;
mod engine;
mod fragmentation;
pub mod ftp_bounce;
pub mod groups;
pub mod history;
pub mod idle;
pub mod notifications;
pub mod packet_io;
pub mod passive;
mod payload;
mod port;
mod proxy;
mod rate_limiter;
mod scan_types;
pub mod scheduler;
mod spoofing;
mod stealth;
mod target;
pub mod templates;
mod timing;
pub mod trends;
pub mod validation;

pub use cache::{CacheConfig, CacheKey, CacheStats, ScanCache};
pub use compression::{CompressionAlgorithm, CompressionConfig, CompressionStats, ScanCompressor};
pub use decoy::{DecoyConfig, DecoyListBuilder, DecoyScanner, RealSourcePosition};
pub use dedup::{DedupStats, DuplicateGroup, ScanDeduplicator};
pub use discovery::{
    ArpDiscovery, DiscoveryConfig, DiscoveryMethod, DiscoveryResult, HostDiscovery,
};
pub use dns::{DnsConfig, DnsResolver};
pub use encryption::{
    EncryptedData, EncryptionConfig, EncryptionKey, EncryptionStats, ScanEncryptor,
};
pub use engine::ScanEngine;
pub use fragmentation::{FragmentReassembler, FragmentationConfig, IpFragment, PacketFragmenter};
pub use groups::{GroupManager, GroupResult, GroupStats, GroupTarget, ScanGroup, TargetStats};
pub use history::{HistoryEntry, ScanHistory, ScanSummary};
pub use notifications::{
    NotificationChannel, NotificationConfig, NotificationEvent, NotificationManager,
    NotificationMessage, NotificationMessageBuilder, NotificationRecord,
};
pub use passive::{
    ArpObservation, DhcpObservation, DnsObservation, PassiveConfig, PassiveDiscovery,
    PassiveDiscoveryBuilder, PassiveHost, PassiveResult, PassiveService, TrafficStats,
};
pub use payload::{CustomPacketBuilder, IpOption, PayloadBuilder, PayloadConfig, TtlPresets};
pub use port::{
    Port, PortParser, PortProtocol, PortRange, PortSelectionMode, PortSpec, ProtocolPort,
};
pub use proxy::{
    ProxyChain, ProxyChainBuilder, ProxyClient, ProxyConfig, ProxyConnection, ProxyProtocol,
};
pub use rate_limiter::RateLimiter;
pub use scan_types::{
    AdvancedScanner, FilteringState, FirewallAnalysis, FirewallType, PortState as ScanPortState,
    PortStateReason, ScanResult as AdvancedScanResult, ScanType, TcpFlags, WindowAnalysis,
};
pub use scheduler::{Recurrence, ScanScheduler, ScheduleStatus, ScheduledScan};
pub use spoofing::{
    MacAddress, NetworkInterface, SourceConfig, SourcePortStrategy, SourceSpoofer,
    SourceSpooferBuilder,
};
pub use stealth::StealthOptions;
pub use target::{Target, TargetConfig, TargetParser};
pub use templates::{ScanTemplate, TemplateBuilder, TemplateCategory, TemplateLibrary};
pub use timing::{
    parse_duration, parse_hostgroup, parse_parallelism, parse_rate, parse_retries, TimingConfig,
    TimingConfigBuilder, TimingTemplate,
};
pub use trends::{PortTrend, ServiceTrend, TrendAnalyzer, TrendReport, TrendSummary};
pub use validation::InputValidator;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
