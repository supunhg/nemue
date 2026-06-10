use anyhow::Result;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

/// SNMP versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    V1,
    V2c,
    V3,
}

impl SnmpVersion {
    pub fn description(&self) -> &str {
        match self {
            SnmpVersion::V1 => "SNMPv1",
            SnmpVersion::V2c => "SNMPv2c",
            SnmpVersion::V3 => "SNMPv3",
        }
    }
}

/// SNMP v3 security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpV3SecurityLevel {
    NoAuthNoPriv,
    AuthNoPriv,
    AuthPriv,
}

impl SnmpV3SecurityLevel {
    pub fn description(&self) -> &str {
        match self {
            SnmpV3SecurityLevel::NoAuthNoPriv => "No Authentication, No Privacy",
            SnmpV3SecurityLevel::AuthNoPriv => "Authentication, No Privacy",
            SnmpV3SecurityLevel::AuthPriv => "Authentication and Privacy",
        }
    }
}

/// SNMP v3 authentication protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpAuthProtocol {
    None,
    MD5,
    SHA,
}

/// SNMP PDU types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    GetRequest = 0xA0,
    GetNextRequest = 0xA1,
    GetResponse = 0xA2,
    SetRequest = 0xA3,
    GetBulkRequest = 0xA5,
}

/// SNMP OID for common MIB objects
#[derive(Debug, Clone)]
pub struct OidEntry {
    pub oid: String,
    pub name: String,
    pub value: Option<String>,
}

/// Security findings for SNMP
#[derive(Debug, Clone)]
pub enum SnmpSecurityFinding {
    DefaultCommunityAccepted,
    VersionDowngrade,
    NoAuthentication,
    WeakAuthentication,
    WriteAccessAvailable,
    VersionInfoExposed,
    CommunityStringGuessable,
}

impl SnmpSecurityFinding {
    pub fn severity(&self) -> &str {
        match self {
            SnmpSecurityFinding::DefaultCommunityAccepted => "CRITICAL",
            SnmpSecurityFinding::VersionDowngrade => "HIGH",
            SnmpSecurityFinding::NoAuthentication => "HIGH",
            SnmpSecurityFinding::WeakAuthentication => "MEDIUM",
            SnmpSecurityFinding::WriteAccessAvailable => "CRITICAL",
            SnmpSecurityFinding::VersionInfoExposed => "LOW",
            SnmpSecurityFinding::CommunityStringGuessable => "HIGH",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            SnmpSecurityFinding::DefaultCommunityAccepted => {
                "Default community string (public/private) accepted"
            }
            SnmpSecurityFinding::VersionDowngrade => {
                "Agent supports SNMPv1/v2c which lack encryption"
            }
            SnmpSecurityFinding::NoAuthentication => {
                "SNMPv1/v2c community strings sent in cleartext"
            }
            SnmpSecurityFinding::WeakAuthentication => "SNMPv3 uses weak authentication protocol",
            SnmpSecurityFinding::WriteAccessAvailable => {
                "Write access confirmed with community string"
            }
            SnmpSecurityFinding::VersionInfoExposed => "SNMP agent version information exposed",
            SnmpSecurityFinding::CommunityStringGuessable => "Common community string accepted",
        }
    }
}

/// SNMP scan result
#[derive(Debug, Clone)]
pub struct SnmpScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub is_snmp: bool,
    pub detected_version: Option<SnmpVersion>,
    pub valid_communities: Vec<String>,
    pub sys_descr: Option<String>,
    pub sys_name: Option<String>,
    pub sys_object_id: Option<String>,
    pub sys_uptime: Option<String>,
    pub sys_contact: Option<String>,
    pub sys_location: Option<String>,
    pub mib_entries: Vec<OidEntry>,
    pub interface_entries: Vec<OidEntry>,
    pub v3_users: Vec<String>,
    pub write_access_communities: Vec<String>,
    pub security_findings: Vec<SnmpSecurityFinding>,
}

/// SNMP scanner
#[derive(Clone)]
pub struct SnmpScanner {
    timeout_duration: Duration,
    community_strings: Vec<String>,
}

impl SnmpScanner {
    pub const DEFAULT_PORT: u16 = 161;

    const DEFAULT_COMMUNITIES: &'static [&'static str] = &[
        "public",
        "private",
        "community",
        "manager",
        "admin",
        "secret",
        "snmp",
        "monitor",
        "agent",
        "switch",
        "router",
        "cisco",
        "default",
        "read",
        "write",
        "all",
        "system",
        "test",
        "guest",
        "root",
        "backup",
        "operator",
        "security",
        "network",
        "device",
        "equipment",
        "infrastructure",
        "server",
        "workstation",
        "printer",
        "camera",
    ];

    const SYSTEM_MIB_OIDS: &'static [(&'static str, &'static str)] = &[
        ("1.3.6.1.2.1.1.1.0", "sysDescr"),
        ("1.3.6.1.2.1.1.2.0", "sysObjectID"),
        ("1.3.6.1.2.1.1.3.0", "sysUpTime"),
        ("1.3.6.1.2.1.1.4.0", "sysContact"),
        ("1.3.6.1.2.1.1.5.0", "sysName"),
        ("1.3.6.1.2.1.1.6.0", "sysLocation"),
        ("1.3.6.1.2.1.1.7.0", "sysServices"),
        ("1.3.6.1.2.1.1.8.0", "sysORLastChange"),
        ("1.3.6.1.2.1.1.9.0", "sysOREntries"),
    ];

    const INTERFACE_MIB_OIDS: &'static [(&'static str, &'static str)] = &[
        ("1.3.6.1.2.1.2.1.0", "ifNumber"),
        ("1.3.6.1.2.1.2.2.1.1.1", "ifIndex.1"),
        ("1.3.6.1.2.1.2.2.1.2.1", "ifDescr.1"),
        ("1.3.6.1.2.1.2.2.1.3.1", "ifType.1"),
        ("1.3.6.1.2.1.2.2.1.5.1", "ifSpeed.1"),
        ("1.3.6.1.2.1.2.2.1.6.1", "ifPhysAddress.1"),
        ("1.3.6.1.2.1.2.2.1.7.1", "ifAdminStatus.1"),
        ("1.3.6.1.2.1.2.2.1.8.1", "ifOperStatus.1"),
    ];

    const SNMP_V3_USERS: &'static [&'static str] = &[
        "admin",
        "root",
        "user",
        "monitor",
        "manager",
        "operator",
        "readonly",
        "readwrite",
        "trapuser",
        "v3user",
        "snmpuser",
    ];

    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            community_strings: Self::DEFAULT_COMMUNITIES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    pub fn with_communities(timeout_ms: u64, communities: Vec<String>) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
            community_strings: communities,
        }
    }

    pub async fn scan(&self, target: IpAddr, port: u16) -> Result<SnmpScanResult> {
        let is_snmp = self.detect_snmp(target, port, "public").await?;

        if !is_snmp {
            return Ok(SnmpScanResult {
                target,
                port,
                is_snmp: false,
                detected_version: None,
                valid_communities: Vec::new(),
                sys_descr: None,
                sys_name: None,
                sys_object_id: None,
                sys_uptime: None,
                sys_contact: None,
                sys_location: None,
                mib_entries: Vec::new(),
                interface_entries: Vec::new(),
                v3_users: Vec::new(),
                write_access_communities: Vec::new(),
                security_findings: Vec::new(),
            });
        }

        let valid_communities = self.brute_force_communities(target, port).await;
        let community = valid_communities
            .first()
            .cloned()
            .unwrap_or_else(|| "public".to_string());

        let mib_entries = self.enumerate_mib(target, port, &community).await;
        let interface_entries = self.enumerate_interface_mib(target, port, &community).await;
        let sys_descr = self.get_mib_value(&mib_entries, "sysDescr");
        let sys_name = self.get_mib_value(&mib_entries, "sysName");
        let sys_object_id = self.get_mib_value(&mib_entries, "sysObjectID");
        let sys_uptime = self.get_mib_value(&mib_entries, "sysUpTime");
        let sys_contact = self.get_mib_value(&mib_entries, "sysContact");
        let sys_location = self.get_mib_value(&mib_entries, "sysLocation");

        let detected_version = self.detect_version(target, port, &community).await;

        // Test write access for valid communities
        let mut write_access_communities = Vec::new();
        for comm in &valid_communities {
            if self.test_write_access(target, port, comm).await {
                write_access_communities.push(comm.clone());
            }
        }

        // Enumerate SNMPv3 users if version 3 is detected
        let v3_users = if detected_version == Some(SnmpVersion::V3) {
            self.enumerate_snmp_v3_users(target, port).await
        } else {
            Vec::new()
        };

        let security_findings = self.assess_security(
            &valid_communities,
            &detected_version,
            &write_access_communities,
        );

        Ok(SnmpScanResult {
            target,
            port,
            is_snmp: true,
            detected_version,
            valid_communities,
            sys_descr,
            sys_name,
            sys_object_id,
            sys_uptime,
            sys_contact,
            sys_location,
            mib_entries,
            interface_entries,
            v3_users,
            write_access_communities,
            security_findings,
        })
    }

    pub async fn detect_snmp(&self, target: IpAddr, port: u16, community: &str) -> Result<bool> {
        let addr = SocketAddr::new(target, port);
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(self.timeout_duration))?;

        let request = self.build_get_request(community, "1.3.6.1.2.1.1.1.0");
        socket.send_to(&request, addr)?;

        let mut response = [0u8; 1500];
        match socket.recv_from(&mut response) {
            Ok((n, _)) if n > 4 => {
                // Check SNMP response tag (0x30 = SEQUENCE)
                Ok(response[0] == 0x30)
            }
            _ => Ok(false),
        }
    }

    async fn detect_version(
        &self,
        target: IpAddr,
        port: u16,
        community: &str,
    ) -> Option<SnmpVersion> {
        let addr = SocketAddr::new(target, port);
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return None,
        };
        let _ = socket.set_read_timeout(Some(self.timeout_duration));

        // Try v2c first (most common)
        let request = self.build_get_request_v2c(community, "1.3.6.1.2.1.1.1.0");
        if socket.send_to(&request, addr).is_err() {
            return None;
        }

        let mut response = [0u8; 1500];
        if let Ok((n, _)) = socket.recv_from(&mut response) {
            if n > 10 {
                // Parse version from response
                // SNMP version is in the first SEQUENCE -> version INTEGER
                if let Some(version) = self.parse_snmp_version(&response[..n]) {
                    return Some(version);
                }
            }
        }

        Some(SnmpVersion::V2c)
    }

    fn parse_snmp_version(&self, data: &[u8]) -> Option<SnmpVersion> {
        // SEQUENCE tag (0x30), length, then INTEGER tag (0x02), length, version byte
        if data.len() < 6 || data[0] != 0x30 {
            return None;
        }
        if data[2] != 0x02 {
            return None;
        }
        let version_len = data[3] as usize;
        if 4 + version_len > data.len() {
            return None;
        }
        match data[4] {
            0 => Some(SnmpVersion::V1),
            1 => Some(SnmpVersion::V2c),
            3 => Some(SnmpVersion::V3),
            _ => None,
        }
    }

    pub async fn brute_force_communities(&self, target: IpAddr, port: u16) -> Vec<String> {
        let mut found = Vec::new();
        let addr = SocketAddr::new(target, port);

        for community in &self.community_strings {
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = socket.set_read_timeout(Some(self.timeout_duration));

            let request = self.build_get_request(community, "1.3.6.1.2.1.1.1.0");
            if socket.send_to(&request, addr).is_err() {
                continue;
            }

            let mut response = [0u8; 1500];
            if let Ok((n, _)) = socket.recv_from(&mut response) {
                if n > 4 && response[0] == 0x30 {
                    // Verify it's a valid GetResponse (not an error)
                    if self.is_valid_response(&response[..n]) {
                        found.push(community.clone());
                    }
                }
            }
        }

        found
    }

    fn is_valid_response(&self, data: &[u8]) -> bool {
        // Look for GetResponse PDU tag (0xA2)
        for i in 0..data.len().min(20) {
            if data[i] == 0xA2 {
                return true;
            }
        }
        false
    }

    pub async fn enumerate_mib(&self, target: IpAddr, port: u16, community: &str) -> Vec<OidEntry> {
        let mut entries = Vec::new();
        let addr = SocketAddr::new(target, port);

        for &(oid, name) in Self::SYSTEM_MIB_OIDS {
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = socket.set_read_timeout(Some(self.timeout_duration));

            let request = self.build_get_request(community, oid);
            if socket.send_to(&request, addr).is_err() {
                continue;
            }

            let mut response = [0u8; 1500];
            if let Ok((n, _)) = socket.recv_from(&mut response) {
                if n > 4 {
                    let value = self.extract_string_value(&response[..n]);
                    entries.push(OidEntry {
                        oid: oid.to_string(),
                        name: name.to_string(),
                        value,
                    });
                }
            }
        }

        entries
    }

    fn extract_string_value(&self, data: &[u8]) -> Option<String> {
        // Look for OCTET STRING tag (0x04) in the response
        for i in 0..data.len().saturating_sub(3) {
            if data[i] == 0x04 {
                let len = data[i + 1] as usize;
                if i + 2 + len <= data.len() && len > 0 {
                    if let Ok(s) = std::str::from_utf8(&data[i + 2..i + 2 + len]) {
                        return Some(s.to_string());
                    }
                }
            }
        }
        None
    }

    fn get_mib_value(&self, entries: &[OidEntry], name: &str) -> Option<String> {
        entries
            .iter()
            .find(|e| e.name == name)
            .and_then(|e| e.value.clone())
    }

    pub async fn enumerate_interface_mib(
        &self,
        target: IpAddr,
        port: u16,
        community: &str,
    ) -> Vec<OidEntry> {
        let mut entries = Vec::new();
        let addr = SocketAddr::new(target, port);

        for &(oid, name) in Self::INTERFACE_MIB_OIDS {
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = socket.set_read_timeout(Some(self.timeout_duration));

            let request = self.build_get_request(community, oid);
            if socket.send_to(&request, addr).is_err() {
                continue;
            }

            let mut response = [0u8; 1500];
            if let Ok((n, _)) = socket.recv_from(&mut response) {
                if n > 4 {
                    let value = self.extract_string_value(&response[..n]);
                    entries.push(OidEntry {
                        oid: oid.to_string(),
                        name: name.to_string(),
                        value,
                    });
                }
            }
        }

        entries
    }

    pub async fn enumerate_snmp_v3_users(&self, target: IpAddr, port: u16) -> Vec<String> {
        let mut found_users = Vec::new();
        let addr = SocketAddr::new(target, port);

        // SNMPv3 User-Based Security Model (USM) users OID
        let _usm_users_oid = "1.3.6.1.6.3.15.1.2.2.1";

        for user in Self::SNMP_V3_USERS {
            let socket = match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(_) => continue,
            };
            let _ = socket.set_read_timeout(Some(self.timeout_duration));

            // Build SNMPv3 discovery message
            let request = self.build_snmpv3_discovery(user);
            if socket.send_to(&request, addr).is_err() {
                continue;
            }

            let mut response = [0u8; 1500];
            if let Ok((n, _)) = socket.recv_from(&mut response) {
                if n > 10 && response[0] == 0x30 {
                    // Check if we got a report PDU (0xA8) which indicates user exists
                    if self.is_snmpv3_report(&response[..n]) {
                        found_users.push(user.to_string());
                    }
                }
            }
        }

        found_users
    }

    fn build_snmpv3_discovery(&self, user: &str) -> Vec<u8> {
        let user_bytes = user.as_bytes();

        // Build USM security parameters
        let mut usm_params = Vec::new();
        usm_params.extend_from_slice(&self.encode_tlv(0x04, &[])); // Engine ID (empty for discovery)
        usm_params.extend_from_slice(&self.encode_integer(0x02, 0)); // Engine boots
        usm_params.extend_from_slice(&self.encode_integer(0x02, 0)); // Engine time
        usm_params.extend_from_slice(&self.encode_tlv(0x04, user_bytes)); // User name
        usm_params.extend_from_slice(&self.encode_tlv(0x04, &[])); // Authentication parameters
        usm_params.extend_from_slice(&self.encode_tlv(0x04, &[])); // Privacy parameters
        let usm_encoded = self.encode_tlv(0x30, &usm_params);

        // Build Scoped PDU
        let mut scoped_pdu = Vec::new();
        scoped_pdu.extend_from_slice(&self.encode_tlv(0x04, &[])); // Context engine ID
        scoped_pdu.extend_from_slice(&self.encode_tlv(0x04, &[])); // Context name

        // Build GetRequest PDU
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&self.encode_integer(0x02, 0)); // request-id
        pdu.extend_from_slice(&self.encode_integer(0x02, 0)); // error-status
        pdu.extend_from_slice(&self.encode_integer(0x02, 0)); // error-index

        // VarBindList with sysDescr
        let oid_bytes = self.encode_oid("1.3.6.1.2.1.1.1.0");
        let mut varbind = Vec::new();
        varbind.extend_from_slice(&self.encode_tlv(0x06, &oid_bytes));
        varbind.push(0x05); // NULL
        varbind.push(0x00);
        pdu.extend_from_slice(&self.encode_tlv(0x30, &varbind));

        scoped_pdu.extend_from_slice(&self.encode_tlv(0xA0, &pdu)); // GetRequest
        let scoped_encoded = self.encode_tlv(0x30, &scoped_pdu);

        // Build SNMPv3 message
        let mut message = Vec::new();
        message.extend_from_slice(&self.encode_integer(0x02, 3)); // Version: SNMPv3
        message.extend_from_slice(&self.encode_integer(0x02, 0x7FFFFFFF)); // Max message size
        message.extend_from_slice(&self.encode_tlv(0x04, &[0x03])); // Message flags: AuthPriv
        message.extend_from_slice(&self.encode_integer(0x02, 3)); // Security model: USM
        message.extend_from_slice(&usm_encoded);
        message.extend_from_slice(&scoped_encoded);

        self.encode_tlv(0x30, &message)
    }

    fn is_snmpv3_report(&self, data: &[u8]) -> bool {
        // Look for Report PDU tag (0xA8)
        for i in 0..data.len().min(50) {
            if data[i] == 0xA8 {
                return true;
            }
        }
        false
    }

    pub async fn test_write_access(&self, target: IpAddr, port: u16, community: &str) -> bool {
        let addr = SocketAddr::new(target, port);

        // Try to set sysContact to test write access
        let test_value = "Nemue Security Test";
        let oid = "1.3.6.1.2.1.1.4.0";

        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return false,
        };
        let _ = socket.set_read_timeout(Some(self.timeout_duration));

        let request = self.build_set_request(community, oid, test_value);
        if socket.send_to(&request, addr).is_err() {
            return false;
        }

        let mut response = [0u8; 1500];
        if let Ok((n, _)) = socket.recv_from(&mut response) {
            if n > 4 && response[0] == 0x30 {
                // Check for SetResponse (0xA3)
                for i in 0..n.min(20) {
                    if response[i] == 0xA3 {
                        return true;
                    }
                }
            }
        }

        false
    }

    fn build_set_request(&self, community: &str, oid: &str, value: &str) -> Vec<u8> {
        let oid_bytes = self.encode_oid(oid);
        let community_bytes = community.as_bytes();

        // Build VarBind: OID + OCTET STRING value
        let mut varbind = Vec::new();
        varbind.extend_from_slice(&self.encode_tlv(0x06, &oid_bytes)); // OID
        varbind.extend_from_slice(&self.encode_tlv(0x04, value.as_bytes())); // Value

        // Build VarBindList
        let varbind_list = self.encode_tlv(0x30, &varbind);

        // Build SetRequest PDU
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&self.encode_integer(0x02, 0)); // request-id
        pdu.extend_from_slice(&self.encode_integer(0x02, 0)); // error-status
        pdu.extend_from_slice(&self.encode_integer(0x02, 0)); // error-index
        pdu.extend_from_slice(&varbind_list);
        let pdu_encoded = self.encode_tlv(0xA3, &pdu); // SetRequest tag

        // Build message
        let mut message = Vec::new();
        message.extend_from_slice(&self.encode_integer(0x02, 0)); // version (v1)
        message.extend_from_slice(&self.encode_tlv(0x04, community_bytes)); // community
        message.extend_from_slice(&pdu_encoded);

        self.encode_tlv(0x30, &message) // SEQUENCE
    }

    fn assess_security(
        &self,
        valid_communities: &[String],
        detected_version: &Option<SnmpVersion>,
        write_access_communities: &[String],
    ) -> Vec<SnmpSecurityFinding> {
        let mut findings = Vec::new();

        // Check for default community strings
        let defaults = ["public", "private", "community"];
        for community in valid_communities {
            if defaults.contains(&community.as_str()) {
                findings.push(SnmpSecurityFinding::DefaultCommunityAccepted);
                break;
            }
        }

        // Check for guessable community strings
        if valid_communities.len() > 2 {
            findings.push(SnmpSecurityFinding::CommunityStringGuessable);
        }

        // Check version security
        match detected_version {
            Some(SnmpVersion::V1) | Some(SnmpVersion::V2c) => {
                findings.push(SnmpSecurityFinding::NoAuthentication);
                findings.push(SnmpSecurityFinding::VersionDowngrade);
            }
            Some(SnmpVersion::V3) => {
                // v3 is more secure, but still check for weak configs
            }
            None => {}
        }

        // Check for write access
        if !write_access_communities.is_empty() {
            findings.push(SnmpSecurityFinding::WriteAccessAvailable);
        }

        // Check for version info exposure
        if detected_version.is_some() {
            findings.push(SnmpSecurityFinding::VersionInfoExposed);
        }

        findings
    }

    /// Build an SNMPv1 GetRequest packet
    fn build_get_request(&self, community: &str, oid: &str) -> Vec<u8> {
        self.build_get_request_generic(community, oid, 0) // v1 = version 0
    }

    /// Build an SNMPv2c GetRequest packet
    fn build_get_request_v2c(&self, community: &str, oid: &str) -> Vec<u8> {
        self.build_get_request_generic(community, oid, 1) // v2c = version 1
    }

    fn build_get_request_generic(&self, community: &str, oid: &str, version: u8) -> Vec<u8> {
        let oid_bytes = self.encode_oid(oid);
        let community_bytes = community.as_bytes();

        // Build VarBind: OID + NULL
        let mut varbind = Vec::new();
        varbind.extend_from_slice(&self.encode_tlv(0x06, &oid_bytes)); // OID
        varbind.push(0x05); // NULL tag
        varbind.push(0x00); // NULL length

        // Build VarBindList
        let varbind_list = self.encode_tlv(0x30, &varbind);

        // Build GetRequest PDU
        let mut pdu = Vec::new();
        pdu.extend_from_slice(&self.encode_integer(0x02, 0)); // request-id
        pdu.extend_from_slice(&self.encode_integer(0x02, 0)); // error-status
        pdu.extend_from_slice(&self.encode_integer(0x02, 0)); // error-index
        pdu.extend_from_slice(&varbind_list);
        let pdu_encoded = self.encode_tlv(0xA0, &pdu); // GetRequest tag

        // Build message
        let mut message = Vec::new();
        message.extend_from_slice(&self.encode_integer(0x02, version as i64)); // version
        message.extend_from_slice(&self.encode_tlv(0x04, community_bytes)); // community
        message.extend_from_slice(&pdu_encoded);

        self.encode_tlv(0x30, &message) // SEQUENCE
    }

    fn encode_oid(&self, oid: &str) -> Vec<u8> {
        let parts: Vec<u32> = oid.split('.').filter_map(|s| s.parse().ok()).collect();
        if parts.len() < 2 {
            return vec![0x00];
        }

        let mut bytes = Vec::new();
        // First two sub-identifiers are encoded as: first * 40 + second
        bytes.push((parts[0] * 40 + parts[1]) as u8);

        for &part in &parts[2..] {
            if part < 128 {
                bytes.push(part as u8);
            } else {
                // Multi-byte encoding
                let mut encoded = Vec::new();
                let mut val = part;
                encoded.push((val & 0x7F) as u8);
                val >>= 7;
                while val > 0 {
                    encoded.push(((val & 0x7F) | 0x80) as u8);
                    val >>= 7;
                }
                encoded.reverse();
                bytes.extend_from_slice(&encoded);
            }
        }

        bytes
    }

    fn encode_tlv(&self, tag: u8, value: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(tag);
        if value.len() < 128 {
            result.push(value.len() as u8);
        } else if value.len() < 256 {
            result.push(0x81);
            result.push(value.len() as u8);
        } else {
            result.push(0x82);
            result.push((value.len() >> 8) as u8);
            result.push((value.len() & 0xFF) as u8);
        }
        result.extend_from_slice(value);
        result
    }

    fn encode_integer(&self, tag: u8, value: i64) -> Vec<u8> {
        let bytes = if value == 0 {
            vec![0x00]
        } else if value > 0 {
            let mut b = Vec::new();
            let mut v = value as u64;
            while v > 0 {
                b.push((v & 0xFF) as u8);
                v >>= 8;
            }
            b.reverse();
            if b[0] & 0x80 != 0 {
                b.insert(0, 0x00);
            }
            b
        } else {
            let mut b = Vec::new();
            let mut v = value;
            while v < -1 {
                b.push((v & 0xFF) as u8);
                v >>= 8;
            }
            b.push((v & 0xFF) as u8);
            b.reverse();
            b
        };
        self.encode_tlv(tag, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snmp_version_description() {
        assert_eq!(SnmpVersion::V1.description(), "SNMPv1");
        assert_eq!(SnmpVersion::V2c.description(), "SNMPv2c");
        assert_eq!(SnmpVersion::V3.description(), "SNMPv3");
    }

    #[test]
    fn test_snmp_v3_security_level_description() {
        assert_eq!(
            SnmpV3SecurityLevel::NoAuthNoPriv.description(),
            "No Authentication, No Privacy"
        );
        assert_eq!(
            SnmpV3SecurityLevel::AuthPriv.description(),
            "Authentication and Privacy"
        );
    }

    #[test]
    fn test_snmp_security_finding_severity() {
        assert_eq!(
            SnmpSecurityFinding::DefaultCommunityAccepted.severity(),
            "CRITICAL"
        );
        assert_eq!(SnmpSecurityFinding::NoAuthentication.severity(), "HIGH");
        assert_eq!(
            SnmpSecurityFinding::WriteAccessAvailable.severity(),
            "CRITICAL"
        );
        assert_eq!(SnmpSecurityFinding::VersionInfoExposed.severity(), "LOW");
    }

    #[test]
    fn test_snmp_security_finding_description() {
        assert!(!SnmpSecurityFinding::DefaultCommunityAccepted
            .description()
            .is_empty());
        assert!(!SnmpSecurityFinding::VersionDowngrade
            .description()
            .is_empty());
    }

    #[test]
    fn test_snmp_scanner_creation() {
        let scanner = SnmpScanner::new(2000);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(2000));
        assert!(!scanner.community_strings.is_empty());
    }

    #[test]
    fn test_snmp_scanner_with_communities() {
        let communities = vec!["test1".to_string(), "test2".to_string()];
        let scanner = SnmpScanner::with_communities(1000, communities.clone());
        assert_eq!(scanner.community_strings, communities);
    }

    #[test]
    fn test_snmp_default_port() {
        assert_eq!(SnmpScanner::DEFAULT_PORT, 161);
    }

    #[test]
    fn test_encode_oid() {
        let scanner = SnmpScanner::new(1000);
        // 1.3.6.1.2.1.1.1.0 = sysDescr
        let encoded = scanner.encode_oid("1.3.6.1.2.1.1.1.0");
        assert!(!encoded.is_empty());
        // First byte: 1*40 + 3 = 43 = 0x2B
        assert_eq!(encoded[0], 0x2B);
    }

    #[test]
    fn test_build_get_request() {
        let scanner = SnmpScanner::new(1000);
        let packet = scanner.build_get_request("public", "1.3.6.1.2.1.1.1.0");
        assert!(!packet.is_empty());
        // Should start with SEQUENCE tag
        assert_eq!(packet[0], 0x30);
    }

    #[test]
    fn test_build_get_request_v2c() {
        let scanner = SnmpScanner::new(1000);
        let packet = scanner.build_get_request_v2c("public", "1.3.6.1.2.1.1.1.0");
        assert!(!packet.is_empty());
        assert_eq!(packet[0], 0x30);
    }

    #[test]
    fn test_encode_tlv() {
        let scanner = SnmpScanner::new(1000);
        let encoded = scanner.encode_tlv(0x04, b"hello");
        assert_eq!(encoded[0], 0x04); // OCTET STRING tag
        assert_eq!(encoded[1], 5); // length
        assert_eq!(&encoded[2..], b"hello");
    }

    #[test]
    fn test_encode_integer() {
        let scanner = SnmpScanner::new(1000);
        let encoded = scanner.encode_integer(0x02, 0);
        assert_eq!(encoded, vec![0x02, 0x01, 0x00]);

        let encoded = scanner.encode_integer(0x02, 1);
        assert_eq!(encoded, vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn test_parse_snmp_version() {
        let scanner = SnmpScanner::new(1000);
        // v2c response: SEQUENCE { INTEGER(1), ... }
        let data = [0x30, 0x05, 0x02, 0x01, 0x01, 0x00, 0x00];
        let version = scanner.parse_snmp_version(&data);
        assert_eq!(version, Some(SnmpVersion::V2c));
    }

    #[test]
    fn test_assess_security_default_community() {
        let scanner = SnmpScanner::new(1000);
        let communities = vec!["public".to_string()];
        let version = Some(SnmpVersion::V2c);
        let write_communities = vec![];
        let findings = scanner.assess_security(&communities, &version, &write_communities);
        assert!(findings
            .iter()
            .any(|f| matches!(f, SnmpSecurityFinding::DefaultCommunityAccepted)));
        assert!(findings
            .iter()
            .any(|f| matches!(f, SnmpSecurityFinding::NoAuthentication)));
    }

    #[test]
    fn test_assess_security_private_community() {
        let scanner = SnmpScanner::new(1000);
        let communities = vec!["private".to_string()];
        let version = Some(SnmpVersion::V2c);
        let write_communities = vec!["private".to_string()];
        let findings = scanner.assess_security(&communities, &version, &write_communities);
        assert!(findings
            .iter()
            .any(|f| matches!(f, SnmpSecurityFinding::WriteAccessAvailable)));
    }

    #[test]
    fn test_assess_security_v3() {
        let scanner = SnmpScanner::new(1000);
        let communities = vec!["test".to_string()];
        let version = Some(SnmpVersion::V3);
        let write_communities = vec![];
        let findings = scanner.assess_security(&communities, &version, &write_communities);
        // v3 should not have cleartext auth findings
        assert!(!findings
            .iter()
            .any(|f| matches!(f, SnmpSecurityFinding::NoAuthentication)));
    }

    #[test]
    fn test_assess_security_multiple_guessable() {
        let scanner = SnmpScanner::new(1000);
        let communities = vec!["abc".to_string(), "def".to_string(), "ghi".to_string()];
        let version = Some(SnmpVersion::V1);
        let write_communities = vec![];
        let findings = scanner.assess_security(&communities, &version, &write_communities);
        assert!(findings
            .iter()
            .any(|f| matches!(f, SnmpSecurityFinding::CommunityStringGuessable)));
    }

    #[test]
    fn test_oid_entry_fields() {
        let entry = OidEntry {
            oid: "1.3.6.1.2.1.1.1.0".to_string(),
            name: "sysDescr".to_string(),
            value: Some("Linux".to_string()),
        };
        assert_eq!(entry.name, "sysDescr");
        assert!(entry.value.is_some());
    }

    #[test]
    fn test_build_set_request() {
        let scanner = SnmpScanner::new(1000);
        let packet = scanner.build_set_request("private", "1.3.6.1.2.1.1.4.0", "test");
        assert!(!packet.is_empty());
        assert_eq!(packet[0], 0x30);
    }

    #[test]
    fn test_build_snmpv3_discovery() {
        let scanner = SnmpScanner::new(1000);
        let packet = scanner.build_snmpv3_discovery("admin");
        assert!(!packet.is_empty());
        assert_eq!(packet[0], 0x30);
    }

    #[test]
    fn test_is_snmpv3_report() {
        let scanner = SnmpScanner::new(1000);
        // Report PDU tag is 0xA8
        let data = [0x00, 0x00, 0xA8, 0x00];
        assert!(scanner.is_snmpv3_report(&data));
        let data2 = [0x00, 0x00, 0x00];
        assert!(!scanner.is_snmpv3_report(&data2));
    }

    #[test]
    fn test_interface_mib_oids() {
        assert!(!SnmpScanner::INTERFACE_MIB_OIDS.is_empty());
        assert_eq!(SnmpScanner::INTERFACE_MIB_OIDS[0].1, "ifNumber");
    }

    #[test]
    fn test_snmp_v3_users() {
        assert!(!SnmpScanner::SNMP_V3_USERS.is_empty());
        assert!(SnmpScanner::SNMP_V3_USERS.contains(&"admin"));
    }

    #[test]
    fn test_default_communities_count() {
        assert!(SnmpScanner::DEFAULT_COMMUNITIES.len() >= 20);
    }

    #[test]
    fn test_assess_security_version_info_exposed() {
        let scanner = SnmpScanner::new(1000);
        let communities = vec!["public".to_string()];
        let version = Some(SnmpVersion::V2c);
        let write_communities = vec![];
        let findings = scanner.assess_security(&communities, &version, &write_communities);
        assert!(findings
            .iter()
            .any(|f| matches!(f, SnmpSecurityFinding::VersionInfoExposed)));
    }

    #[test]
    fn test_assess_security_no_version() {
        let scanner = SnmpScanner::new(1000);
        let communities = vec![];
        let version = None;
        let write_communities = vec![];
        let findings = scanner.assess_security(&communities, &version, &write_communities);
        assert!(!findings
            .iter()
            .any(|f| matches!(f, SnmpSecurityFinding::VersionInfoExposed)));
    }
}
