use anyhow::{anyhow, Result};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Advanced TCP scan types beyond basic SYN/Connect/UDP
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanType {
    /// TCP SYN scan (default, requires root)
    Syn,
    /// TCP Connect scan (full handshake)
    Connect,
    /// UDP scan
    Udp,
    /// ACK scan - for firewall rule mapping (-sA)
    Ack,
    /// Window scan - examines TCP window field (-sW)
    Window,
    /// Maimon scan - FIN/ACK probe (-sM)
    Maimon,
    /// NULL scan - no flags set (-sN)
    Null,
    /// FIN scan - only FIN flag (-sF)
    Fin,
    /// Xmas scan - FIN+PSH+URG flags (-sX)
    Xmas,
    /// Custom scan with specific flags (--scanflags)
    Custom(TcpFlags),
}

impl fmt::Display for ScanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanType::Syn => write!(f, "SYN"),
            ScanType::Connect => write!(f, "CONNECT"),
            ScanType::Udp => write!(f, "UDP"),
            ScanType::Ack => write!(f, "ACK"),
            ScanType::Window => write!(f, "WINDOW"),
            ScanType::Maimon => write!(f, "MAIMON"),
            ScanType::Null => write!(f, "NULL"),
            ScanType::Fin => write!(f, "FIN"),
            ScanType::Xmas => write!(f, "XMAS"),
            ScanType::Custom(flags) => write!(f, "CUSTOM({})", flags),
        }
    }
}

impl ScanType {
    /// Get nmap equivalent flag
    pub fn nmap_flag(&self) -> &str {
        match self {
            ScanType::Syn => "-sS",
            ScanType::Connect => "-sT",
            ScanType::Udp => "-sU",
            ScanType::Ack => "-sA",
            ScanType::Window => "-sW",
            ScanType::Maimon => "-sM",
            ScanType::Null => "-sN",
            ScanType::Fin => "-sF",
            ScanType::Xmas => "-sX",
            ScanType::Custom(_) => "--scanflags",
        }
    }

    /// Parse from nmap flag
    pub fn from_nmap_flag(flag: &str) -> Option<Self> {
        match flag {
            "-sS" | "syn" | "SYN" => Some(ScanType::Syn),
            "-sT" | "connect" | "CONNECT" => Some(ScanType::Connect),
            "-sU" | "udp" | "UDP" => Some(ScanType::Udp),
            "-sA" | "ack" | "ACK" => Some(ScanType::Ack),
            "-sW" | "window" | "WINDOW" => Some(ScanType::Window),
            "-sM" | "maimon" | "MAIMON" => Some(ScanType::Maimon),
            "-sN" | "null" | "NULL" => Some(ScanType::Null),
            "-sF" | "fin" | "FIN" => Some(ScanType::Fin),
            "-sX" | "xmas" | "XMAS" => Some(ScanType::Xmas),
            _ => None,
        }
    }

    /// Check if scan type requires root/raw sockets
    pub fn requires_raw_sockets(&self) -> bool {
        !matches!(self, ScanType::Connect)
    }

    /// Get description of scan type
    pub fn description(&self) -> &str {
        match self {
            ScanType::Syn => "TCP SYN stealth scan (half-open)",
            ScanType::Connect => "TCP connect scan (full handshake)",
            ScanType::Udp => "UDP port scan",
            ScanType::Ack => "TCP ACK scan (firewall rule mapping)",
            ScanType::Window => "TCP Window scan (examines window field)",
            ScanType::Maimon => "Maimon scan (FIN/ACK probe)",
            ScanType::Null => "NULL scan (no TCP flags set)",
            ScanType::Fin => "FIN scan (only FIN flag set)",
            ScanType::Xmas => "Xmas scan (FIN+PSH+URG flags)",
            ScanType::Custom(_) => "Custom scan with specific TCP flags",
        }
    }

    /// Get TCP flags for this scan type
    pub fn tcp_flags(&self) -> TcpFlags {
        match self {
            ScanType::Syn => TcpFlags::new().with_syn(),
            ScanType::Connect => TcpFlags::new().with_syn(), // Connect uses SYN initially
            ScanType::Ack => TcpFlags::new().with_ack(),
            ScanType::Window => TcpFlags::new().with_ack(), // Window scan uses ACK
            ScanType::Maimon => TcpFlags::new().with_fin().with_ack(),
            ScanType::Null => TcpFlags::new(), // No flags
            ScanType::Fin => TcpFlags::new().with_fin(),
            ScanType::Xmas => TcpFlags::new().with_fin().with_psh().with_urg(),
            ScanType::Custom(flags) => *flags,
            ScanType::Udp => TcpFlags::new(), // N/A for UDP
        }
    }
}

/// TCP flag configuration for custom scans
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn new() -> Self {
        Self {
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: false,
            urg: false,
            ece: false,
            cwr: false,
        }
    }

    pub fn with_fin(mut self) -> Self {
        self.fin = true;
        self
    }

    pub fn with_syn(mut self) -> Self {
        self.syn = true;
        self
    }

    pub fn with_rst(mut self) -> Self {
        self.rst = true;
        self
    }

    pub fn with_psh(mut self) -> Self {
        self.psh = true;
        self
    }

    pub fn with_ack(mut self) -> Self {
        self.ack = true;
        self
    }

    pub fn with_urg(mut self) -> Self {
        self.urg = true;
        self
    }

    pub fn with_ece(mut self) -> Self {
        self.ece = true;
        self
    }

    pub fn with_cwr(mut self) -> Self {
        self.cwr = true;
        self
    }

    /// Parse from nmap --scanflags format (e.g., "SYNFIN", "URGACKPSHRSTSYNFIN")
    pub fn from_string(s: &str) -> Result<Self> {
        let mut flags = TcpFlags::new();
        let upper = s.to_uppercase();

        if upper.contains("FIN") {
            flags.fin = true;
        }
        if upper.contains("SYN") {
            flags.syn = true;
        }
        if upper.contains("RST") {
            flags.rst = true;
        }
        if upper.contains("PSH") || upper.contains("PUSH") {
            flags.psh = true;
        }
        if upper.contains("ACK") {
            flags.ack = true;
        }
        if upper.contains("URG") {
            flags.urg = true;
        }
        if upper.contains("ECE") {
            flags.ece = true;
        }
        if upper.contains("CWR") {
            flags.cwr = true;
        }

        // Validate at least one flag is set or explicitly allow none
        if !flags.any_set() && !upper.is_empty() && upper != "NONE" {
            return Err(anyhow!("Invalid TCP flags: {}", s));
        }

        Ok(flags)
    }

    /// Convert to byte representation
    pub fn to_u8(&self) -> u8 {
        let mut byte = 0u8;
        if self.fin { byte |= 0x01; }
        if self.syn { byte |= 0x02; }
        if self.rst { byte |= 0x04; }
        if self.psh { byte |= 0x08; }
        if self.ack { byte |= 0x10; }
        if self.urg { byte |= 0x20; }
        if self.ece { byte |= 0x40; }
        if self.cwr { byte |= 0x80; }
        byte
    }

    /// Check if any flag is set
    pub fn any_set(&self) -> bool {
        self.fin || self.syn || self.rst || self.psh || 
        self.ack || self.urg || self.ece || self.cwr
    }

    /// Get flag names as string (for display)
    pub fn to_string_list(&self) -> Vec<&str> {
        let mut flags = Vec::new();
        if self.fin { flags.push("FIN"); }
        if self.syn { flags.push("SYN"); }
        if self.rst { flags.push("RST"); }
        if self.psh { flags.push("PSH"); }
        if self.ack { flags.push("ACK"); }
        if self.urg { flags.push("URG"); }
        if self.ece { flags.push("ECE"); }
        if self.cwr { flags.push("CWR"); }
        flags
    }
}

impl Default for TcpFlags {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flags = self.to_string_list();
        if flags.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", flags.join("+"))
        }
    }
}

/// Result of a port scan with detailed information
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub port: u16,
    pub state: PortState,
    pub reason: PortStateReason,
    pub ttl: Option<u8>,
    pub window_size: Option<u16>,
}

/// Port state determination
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::Unfiltered => write!(f, "unfiltered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
            PortState::ClosedFiltered => write!(f, "closed|filtered"),
        }
    }
}

/// Reason why port is in a particular state (for --reason flag)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortStateReason {
    SynAck,
    Rst,
    IcmpUnreach,
    NoResponse,
    TcpResponse,
    UdpResponse,
    EchoReply,
    WindowUpdate,
    Custom(String),
}

impl fmt::Display for PortStateReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortStateReason::SynAck => write!(f, "syn-ack"),
            PortStateReason::Rst => write!(f, "reset"),
            PortStateReason::IcmpUnreach => write!(f, "port-unreach"),
            PortStateReason::NoResponse => write!(f, "no-response"),
            PortStateReason::TcpResponse => write!(f, "tcp-response"),
            PortStateReason::UdpResponse => write!(f, "udp-response"),
            PortStateReason::EchoReply => write!(f, "echo-reply"),
            PortStateReason::WindowUpdate => write!(f, "window-update"),
            PortStateReason::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Advanced scanner for TCP scans with various techniques
pub struct AdvancedScanner {
    scan_type: ScanType,
    timeout: Duration,
}

impl AdvancedScanner {
    pub fn new(scan_type: ScanType) -> Self {
        Self {
            scan_type,
            timeout: Duration::from_secs(3),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Scan a single port with the configured scan type
    pub async fn scan_port(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        match self.scan_type {
            ScanType::Connect => self.connect_scan(target, port).await,
            ScanType::Ack => self.ack_scan(target, port).await,
            ScanType::Window => self.window_scan(target, port).await,
            ScanType::Maimon => self.maimon_scan(target, port).await,
            ScanType::Null => self.null_scan(target, port).await,
            ScanType::Fin => self.fin_scan(target, port).await,
            ScanType::Xmas => self.xmas_scan(target, port).await,
            ScanType::Syn => self.syn_scan(target, port).await,
            ScanType::Custom(flags) => self.custom_scan(target, port, flags).await,
            ScanType::Udp => Err(anyhow!("UDP scanning not implemented in AdvancedScanner")),
        }
    }

    /// TCP Connect scan (full three-way handshake)
    async fn connect_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        let addr = SocketAddr::new(target, port);
        
        match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => {
                Ok(ScanResult {
                    port,
                    state: PortState::Open,
                    reason: PortStateReason::SynAck,
                    ttl: None,
                    window_size: None,
                })
            }
            Ok(Err(_)) => {
                Ok(ScanResult {
                    port,
                    state: PortState::Closed,
                    reason: PortStateReason::Rst,
                    ttl: None,
                    window_size: None,
                })
            }
            Err(_) => {
                Ok(ScanResult {
                    port,
                    state: PortState::Filtered,
                    reason: PortStateReason::NoResponse,
                    ttl: None,
                    window_size: None,
                })
            }
        }
    }

    /// ACK scan (firewall rule detection)
    /// Note: Requires raw sockets in production
    async fn ack_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        // Placeholder: In production, this would send ACK packets and analyze responses
        // RST = unfiltered, No response = filtered
        
        // For now, use connect as fallback
        let addr = SocketAddr::new(target, port);
        match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_)) | Ok(Err(_)) => {
                Ok(ScanResult {
                    port,
                    state: PortState::Unfiltered,
                    reason: PortStateReason::Rst,
                    ttl: None,
                    window_size: None,
                })
            }
            Err(_) => {
                Ok(ScanResult {
                    port,
                    state: PortState::Filtered,
                    reason: PortStateReason::NoResponse,
                    ttl: None,
                    window_size: None,
                })
            }
        }
    }

    /// Window scan (examines TCP window size in RST)
    async fn window_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        // Placeholder: Requires raw socket implementation
        // Positive window size in RST = open, Zero = closed
        
        let addr = SocketAddr::new(target, port);
        match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                Ok(ScanResult {
                    port,
                    state: PortState::Open,
                    reason: PortStateReason::WindowUpdate,
                    ttl: None,
                    window_size: Some(1024), // Placeholder
                })
            }
            Ok(Err(_)) => {
                Ok(ScanResult {
                    port,
                    state: PortState::Closed,
                    reason: PortStateReason::Rst,
                    ttl: None,
                    window_size: Some(0),
                })
            }
            Err(_) => {
                Ok(ScanResult {
                    port,
                    state: PortState::Filtered,
                    reason: PortStateReason::NoResponse,
                    ttl: None,
                    window_size: None,
                })
            }
        }
    }

    /// Maimon scan (FIN/ACK probe)
    async fn maimon_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        // Placeholder: Most systems drop FIN/ACK if port open, RST if closed
        self.stealth_scan(target, port, "maimon").await
    }

    /// NULL scan (no flags set)
    async fn null_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        // Placeholder: No response = open|filtered, RST = closed
        self.stealth_scan(target, port, "null").await
    }

    /// FIN scan (only FIN flag)
    async fn fin_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        // Placeholder: No response = open|filtered, RST = closed
        self.stealth_scan(target, port, "fin").await
    }

    /// Xmas scan (FIN+PSH+URG)
    async fn xmas_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        // Placeholder: No response = open|filtered, RST = closed
        self.stealth_scan(target, port, "xmas").await
    }

    /// SYN scan (half-open)
    async fn syn_scan(&self, target: IpAddr, port: u16) -> Result<ScanResult> {
        // Placeholder: Should use raw sockets
        // For now, use connect scan as fallback
        self.connect_scan(target, port).await
    }

    /// Custom scan with specific flags
    async fn custom_scan(&self, target: IpAddr, port: u16, _flags: TcpFlags) -> Result<ScanResult> {
        // Placeholder: Requires raw socket implementation
        self.stealth_scan(target, port, "custom").await
    }

    /// Helper for stealth scans (NULL, FIN, Xmas)
    async fn stealth_scan(&self, target: IpAddr, port: u16, scan_name: &str) -> Result<ScanResult> {
        // Placeholder: These scans require raw sockets
        // Fallback to connect for now
        
        let addr = SocketAddr::new(target, port);
        match timeout(self.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                Ok(ScanResult {
                    port,
                    state: PortState::OpenFiltered,
                    reason: PortStateReason::NoResponse,
                    ttl: None,
                    window_size: None,
                })
            }
            Ok(Err(_)) => {
                Ok(ScanResult {
                    port,
                    state: PortState::Closed,
                    reason: PortStateReason::Rst,
                    ttl: None,
                    window_size: None,
                })
            }
            Err(_) => {
                Ok(ScanResult {
                    port,
                    state: PortState::OpenFiltered,
                    reason: PortStateReason::NoResponse,
                    ttl: None,
                    window_size: None,
                })
            }
        }
    }

    /// Get scan type
    pub fn scan_type(&self) -> ScanType {
        self.scan_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_type_display() {
        assert_eq!(ScanType::Syn.to_string(), "SYN");
        assert_eq!(ScanType::Ack.to_string(), "ACK");
        assert_eq!(ScanType::Xmas.to_string(), "XMAS");
    }

    #[test]
    fn test_scan_type_nmap_flag() {
        assert_eq!(ScanType::Syn.nmap_flag(), "-sS");
        assert_eq!(ScanType::Ack.nmap_flag(), "-sA");
        assert_eq!(ScanType::Null.nmap_flag(), "-sN");
        assert_eq!(ScanType::Fin.nmap_flag(), "-sF");
        assert_eq!(ScanType::Xmas.nmap_flag(), "-sX");
    }

    #[test]
    fn test_scan_type_from_flag() {
        assert_eq!(ScanType::from_nmap_flag("-sS"), Some(ScanType::Syn));
        assert_eq!(ScanType::from_nmap_flag("-sA"), Some(ScanType::Ack));
        assert_eq!(ScanType::from_nmap_flag("-sN"), Some(ScanType::Null));
        assert_eq!(ScanType::from_nmap_flag("xmas"), Some(ScanType::Xmas));
        assert_eq!(ScanType::from_nmap_flag("invalid"), None);
    }

    #[test]
    fn test_scan_type_requires_raw() {
        assert!(ScanType::Syn.requires_raw_sockets());
        assert!(ScanType::Ack.requires_raw_sockets());
        assert!(!ScanType::Connect.requires_raw_sockets());
    }

    #[test]
    fn test_tcp_flags_basic() {
        let flags = TcpFlags::new().with_syn().with_ack();
        assert!(flags.syn);
        assert!(flags.ack);
        assert!(!flags.fin);
        assert_eq!(flags.to_u8(), 0x12); // SYN=0x02, ACK=0x10
    }

    #[test]
    fn test_tcp_flags_from_string() {
        let flags = TcpFlags::from_string("SYNFIN").unwrap();
        assert!(flags.syn);
        assert!(flags.fin);
        assert!(!flags.ack);

        let xmas = TcpFlags::from_string("FINPSHURG").unwrap();
        assert!(xmas.fin);
        assert!(xmas.psh);
        assert!(xmas.urg);
    }

    #[test]
    fn test_tcp_flags_display() {
        let flags = TcpFlags::new().with_syn().with_ack();
        assert_eq!(flags.to_string(), "SYN+ACK");

        let empty = TcpFlags::new();
        assert_eq!(empty.to_string(), "NONE");
    }

    #[test]
    fn test_scan_type_tcp_flags() {
        let syn_flags = ScanType::Syn.tcp_flags();
        assert!(syn_flags.syn);
        assert!(!syn_flags.ack);

        let xmas_flags = ScanType::Xmas.tcp_flags();
        assert!(xmas_flags.fin);
        assert!(xmas_flags.psh);
        assert!(xmas_flags.urg);

        let null_flags = ScanType::Null.tcp_flags();
        assert!(!null_flags.any_set());
    }

    #[test]
    fn test_port_state_display() {
        assert_eq!(PortState::Open.to_string(), "open");
        assert_eq!(PortState::Filtered.to_string(), "filtered");
        assert_eq!(PortState::OpenFiltered.to_string(), "open|filtered");
    }

    #[test]
    fn test_port_state_reason_display() {
        assert_eq!(PortStateReason::SynAck.to_string(), "syn-ack");
        assert_eq!(PortStateReason::Rst.to_string(), "reset");
        assert_eq!(PortStateReason::NoResponse.to_string(), "no-response");
    }

    #[tokio::test]
    async fn test_connect_scan_localhost() {
        let scanner = AdvancedScanner::new(ScanType::Connect);
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        
        // Scan a port that's likely closed
        let result = scanner.scan_port(target, 12345).await;
        assert!(result.is_ok());
        
        // State should be closed or filtered
        let scan_result = result.unwrap();
        assert!(matches!(
            scan_result.state,
            PortState::Closed | PortState::Filtered
        ));
    }

    #[test]
    fn test_advanced_scanner_creation() {
        let scanner = AdvancedScanner::new(ScanType::Ack)
            .with_timeout(Duration::from_secs(5));
        
        assert_eq!(scanner.scan_type(), ScanType::Ack);
        assert_eq!(scanner.timeout, Duration::from_secs(5));
    }
}
