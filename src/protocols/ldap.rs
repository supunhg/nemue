use anyhow::{anyhow, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// LDAP result codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum LdapResultCode {
    Success = 0,
    OperationsError = 1,
    ProtocolError = 2,
    TimeLimitExceeded = 3,
    SizeLimitExceeded = 4,
    CompareFalse = 5,
    CompareTrue = 6,
    AuthMethodNotSupported = 7,
    StrongerAuthRequired = 8,
    Referral = 10,
    AdminLimitExceeded = 11,
    UnavailableCriticalExtension = 12,
    ConfidentialityRequired = 13,
    SaslBindInProgress = 14,
    NoSuchAttribute = 16,
    UndefinedAttributeType = 17,
    InappropriateMatching = 18,
    ConstraintViolation = 19,
    AttributeOrValueExists = 20,
    InvalidAttributeSyntax = 21,
    NoSuchObject = 32,
    AliasProblem = 33,
    InvalidDNSyntax = 34,
    AliasDereferencingProblem = 36,
    InappropriateAuthentication = 48,
    InvalidCredentials = 49,
    InsufficientAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    LoopDetect = 54,
    NamingViolation = 64,
    ObjectClassViolation = 65,
    NotAllowedOnNonLeaf = 66,
    NotAllowedOnRDN = 67,
    EntryAlreadyExists = 68,
    ObjectClassModsProhibited = 69,
    Other = 80,
}

impl LdapResultCode {
    pub fn from_u32(val: u32) -> Self {
        match val {
            0 => LdapResultCode::Success,
            1 => LdapResultCode::OperationsError,
            2 => LdapResultCode::ProtocolError,
            7 => LdapResultCode::AuthMethodNotSupported,
            8 => LdapResultCode::StrongerAuthRequired,
            48 => LdapResultCode::InappropriateAuthentication,
            49 => LdapResultCode::InvalidCredentials,
            50 => LdapResultCode::InsufficientAccessRights,
            _ => LdapResultCode::Other,
        }
    }

    pub fn description(&self) -> &str {
        match self {
            LdapResultCode::Success => "Success",
            LdapResultCode::OperationsError => "Operations Error",
            LdapResultCode::ProtocolError => "Protocol Error",
            LdapResultCode::AuthMethodNotSupported => "Auth Method Not Supported",
            LdapResultCode::StrongerAuthRequired => "Stronger Auth Required",
            LdapResultCode::InappropriateAuthentication => "Inappropriate Authentication",
            LdapResultCode::InvalidCredentials => "Invalid Credentials",
            LdapResultCode::InsufficientAccessRights => "Insufficient Access Rights",
            _ => "Other",
        }
    }
}

/// LDAP security findings
#[derive(Debug, Clone)]
pub enum LdapSecurityFinding {
    AnonymousBindAllowed,
    CleartextTransport,
    NoSizeLimit,
    NoTimeLimit,
    BaseDnExposed,
    NullBindSuccess,
    WeakAuthentication,
    SchemaExposed,
    NoAccessControl,
    DefaultConfig,
}

impl LdapSecurityFinding {
    pub fn severity(&self) -> &str {
        match self {
            LdapSecurityFinding::AnonymousBindAllowed => "CRITICAL",
            LdapSecurityFinding::CleartextTransport => "HIGH",
            LdapSecurityFinding::NoSizeLimit => "MEDIUM",
            LdapSecurityFinding::NoTimeLimit => "MEDIUM",
            LdapSecurityFinding::BaseDnExposed => "LOW",
            LdapSecurityFinding::NullBindSuccess => "CRITICAL",
            LdapSecurityFinding::WeakAuthentication => "MEDIUM",
            LdapSecurityFinding::SchemaExposed => "LOW",
            LdapSecurityFinding::NoAccessControl => "MEDIUM",
            LdapSecurityFinding::DefaultConfig => "MEDIUM",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            LdapSecurityFinding::AnonymousBindAllowed => "Anonymous LDAP bind is permitted",
            LdapSecurityFinding::CleartextTransport => "LDAP traffic is not encrypted (no LDAPS/StartTLS)",
            LdapSecurityFinding::NoSizeLimit => "Server does not enforce size limits on search results",
            LdapSecurityFinding::NoTimeLimit => "Server does not enforce time limits on search results",
            LdapSecurityFinding::BaseDnExposed => "Base DN can be discovered via Root DSE",
            LdapSecurityFinding::NullBindSuccess => "Null (empty) bind credentials accepted",
            LdapSecurityFinding::WeakAuthentication => "Server allows simple authentication without TLS",
            LdapSecurityFinding::SchemaExposed => "LDAP schema is exposed via subschemaSubentry",
            LdapSecurityFinding::NoAccessControl => "Server does not enforce access control on anonymous queries",
            LdapSecurityFinding::DefaultConfig => "Server appears to use default configuration",
        }
    }
}

/// LDAP entry from search result
#[derive(Debug, Clone)]
pub struct LdapEntry {
    pub dn: String,
    pub attributes: Vec<(String, Vec<String>)>,
}

/// LDAP scan result
#[derive(Debug, Clone)]
pub struct LdapScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub is_ldap: bool,
    pub naming_contexts: Vec<String>,
    pub base_dn: Option<String>,
    pub supported_controls: Vec<String>,
    pub supported_sasl_mechanisms: Vec<String>,
    pub supported_extensions: Vec<String>,
    pub supported_features: Vec<String>,
    pub vendor_name: Option<String>,
    pub vendor_version: Option<String>,
    pub subschema_subentry: Option<String>,
    pub default_naming_context: Option<String>,
    pub is_anonymous_bind_allowed: bool,
    pub is_null_bind_allowed: bool,
    pub supports_starttls: bool,
    pub ldap_version: Option<u8>,
    pub security_findings: Vec<LdapSecurityFinding>,
}

/// LDAP scanner
#[derive(Clone)]
pub struct LdapScanner {
    timeout_duration: Duration,
}

impl LdapScanner {
    pub const DEFAULT_PORT: u16 = 389;
    pub const LDAPS_PORT: u16 = 636;

    // ASN.1 BER tag constants
    const TAG_SEQUENCE: u8 = 0x30;
    const TAG_INTEGER: u8 = 0x02;
    const TAG_OCTET_STRING: u8 = 0x04;
    const TAG_ENUMERATED: u8 = 0x0A;
    const TAG_BOOLEAN: u8 = 0x01;

    // LDAP operation tags
    const TAG_BIND_REQUEST: u8 = 0x60;
    const TAG_BIND_RESPONSE: u8 = 0x61;
    const TAG_SEARCH_REQUEST: u8 = 0x63;
    const TAG_SEARCH_RESULT_ENTRY: u8 = 0x64;
    const TAG_SEARCH_RESULT_DONE: u8 = 0x65;
    const TAG_SEARCH_REFERRAL: u8 = 0x73;

    // Search scope values
    const SCOPE_BASE: u8 = 0x00;
    const SCOPE_ONE_LEVEL: u8 = 0x01;
    const SCOPE_SUBTREE: u8 = 0x02;

    // Deref aliases
    const DEREF_NEVER: u8 = 0x00;

    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
        }
    }

    pub async fn scan(&self, target: IpAddr, port: u16) -> Result<LdapScanResult> {
        let is_ldap = self.detect_ldap(target, port).await?;

        if !is_ldap {
            return Ok(LdapScanResult {
                target,
                port,
                is_ldap: false,
                naming_contexts: Vec::new(),
                base_dn: None,
                supported_controls: Vec::new(),
                supported_sasl_mechanisms: Vec::new(),
                supported_extensions: Vec::new(),
                supported_features: Vec::new(),
                vendor_name: None,
                vendor_version: None,
                subschema_subentry: None,
                default_naming_context: None,
                is_anonymous_bind_allowed: false,
                is_null_bind_allowed: false,
                supports_starttls: false,
                ldap_version: None,
                security_findings: Vec::new(),
            });
        }

        let is_anonymous_bind_allowed = self.test_anonymous_bind(target, port).await.unwrap_or(false);
        let is_null_bind_allowed = self.test_null_bind(target, port).await.unwrap_or(false);
        let ldap_version = self.detect_ldap_version(target, port).await;

        let root_dse = self.query_root_dse(target, port).await.unwrap_or_default();
        let naming_contexts = self.extract_naming_contexts(&root_dse);
        let base_dn = naming_contexts.first().cloned();
        let supported_controls = self.extract_attribute_values(&root_dse, "supportedControl");
        let supported_sasl_mechanisms = self.extract_attribute_values(&root_dse, "supportedSASLMechanisms");
        let supported_extensions = self.extract_attribute_values(&root_dse, "supportedExtension");
        let supported_features = self.extract_attribute_values(&root_dse, "supportedFeatures");
        let vendor_name = self.extract_attribute_values(&root_dse, "vendorName").into_iter().next();
        let vendor_version = self.extract_attribute_values(&root_dse, "vendorVersion").into_iter().next();
        let subschema_subentry = self.extract_attribute_values(&root_dse, "subschemaSubentry").into_iter().next();
        let default_naming_context = self.extract_attribute_values(&root_dse, "defaultNamingContext").into_iter().next();

        let security_findings = self.assess_security(
            is_anonymous_bind_allowed,
            is_null_bind_allowed,
            port,
            &naming_contexts,
            &subschema_subentry,
        );

        Ok(LdapScanResult {
            target,
            port,
            is_ldap: true,
            naming_contexts,
            base_dn,
            supported_controls,
            supported_sasl_mechanisms,
            supported_extensions,
            supported_features,
            vendor_name,
            vendor_version,
            subschema_subentry,
            default_naming_context,
            is_anonymous_bind_allowed,
            is_null_bind_allowed,
            supports_starttls: false, // Would need separate TLS negotiation test
            ldap_version,
            security_findings,
        })
    }

    pub async fn detect_ldap(&self, target: IpAddr, port: u16) -> Result<bool> {
        let addr = SocketAddr::new(target, port);
        let stream = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return Ok(false),
        };

        let (mut reader, mut writer) = stream.into_split();

        // Send anonymous bind request
        let bind_request = self.build_bind_request(3, "", "");
        if writer.write_all(&bind_request).await.is_err() {
            return Ok(false);
        }

        let mut response = [0u8; 4096];
        match timeout(self.timeout_duration, reader.read(&mut response)).await {
            Ok(Ok(n)) if n > 2 => {
                // Check for LDAP message envelope (SEQUENCE tag)
                Ok(response[0] == Self::TAG_SEQUENCE)
            }
            _ => Ok(false),
        }
    }

    async fn test_anonymous_bind(&self, target: IpAddr, port: u16) -> Result<bool> {
        let addr = SocketAddr::new(target, port);
        let stream = timeout(self.timeout_duration, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("Connection timeout"))?
            .map_err(|e| anyhow!("Connection failed: {}", e))?;

        let (mut reader, mut writer) = stream.into_split();

        // Anonymous bind: empty DN and empty password
        let bind_request = self.build_bind_request(3, "", "");
        writer.write_all(&bind_request).await?;

        let mut response = [0u8; 4096];
        let n = timeout(self.timeout_duration, reader.read(&mut response))
            .await
            .map_err(|_| anyhow!("Read timeout"))?
            .map_err(|e| anyhow!("Read failed: {}", e))?;

        if n < 10 {
            return Ok(false);
        }

        // Parse bind response for result code
        if let Some(result_code) = self.parse_bind_result(&response[..n]) {
            Ok(result_code == LdapResultCode::Success)
        } else {
            Ok(false)
        }
    }

    async fn test_null_bind(&self, target: IpAddr, port: u16) -> Result<bool> {
        let addr = SocketAddr::new(target, port);
        let stream = timeout(self.timeout_duration, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("Connection timeout"))?
            .map_err(|e| anyhow!("Connection failed: {}", e))?;

        let (mut reader, mut writer) = stream.into_split();

        // Null bind: version 2, empty DN, no password field
        let bind_request = self.build_simple_bind_v2("", "");
        writer.write_all(&bind_request).await?;

        let mut response = [0u8; 4096];
        let n = timeout(self.timeout_duration, reader.read(&mut response))
            .await
            .map_err(|_| anyhow!("Read timeout"))?
            .map_err(|e| anyhow!("Read failed: {}", e))?;

        if n < 10 {
            return Ok(false);
        }

        if let Some(result_code) = self.parse_bind_result(&response[..n]) {
            Ok(result_code == LdapResultCode::Success)
        } else {
            Ok(false)
        }
    }

    async fn query_root_dse(&self, target: IpAddr, port: u16) -> Result<Vec<LdapEntry>> {
        let addr = SocketAddr::new(target, port);
        let stream = timeout(self.timeout_duration, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("Connection timeout"))?
            .map_err(|e| anyhow!("Connection failed: {}", e))?;

        let (mut reader, mut writer) = stream.into_split();

        // First bind anonymously
        let bind_request = self.build_bind_request(3, "", "");
        writer.write_all(&bind_request).await?;

        let mut response = [0u8; 4096];
        let _ = timeout(self.timeout_duration, reader.read(&mut response)).await;

        // Search for root DSE (empty base DN, base scope, objectClass=*)
        let search_request = self.build_search_request(
            "",
            Self::SCOPE_BASE,
            Self::DEREF_NEVER,
            0, // size limit
            0, // time limit
            false, // types only
            "(objectClass=*)",
            &["namingContexts", "supportedControl", "supportedSASLMechanisms",
              "supportedExtension", "supportedFeatures", "vendorName", "vendorVersion",
              "subschemaSubentry", "defaultNamingContext"],
        );
        writer.write_all(&search_request).await?;

        let mut entries = Vec::new();
        let mut buffer = vec![0u8; 65536];
        let mut total_read = 0;

        loop {
            match timeout(self.timeout_duration, reader.read(&mut buffer[total_read..])).await {
                Ok(Ok(n)) if n > 0 => {
                    total_read += n;
                    if total_read > buffer.len() - 1024 {
                        break;
                    }
                    // Check if we've received SearchResultDone
                    if self.contains_search_done(&buffer[..total_read]) {
                        break;
                    }
                }
                _ => break,
            }
        }

        // Parse search results
        entries = self.parse_search_results(&buffer[..total_read]);

        Ok(entries)
    }

    fn extract_naming_contexts(&self, entries: &[LdapEntry]) -> Vec<String> {
        self.extract_attribute_values(entries, "namingContexts")
    }

    fn extract_attribute_values(&self, entries: &[LdapEntry], attr_name: &str) -> Vec<String> {
        let mut values = Vec::new();
        for entry in entries {
            for (name, vals) in &entry.attributes {
                if name.eq_ignore_ascii_case(attr_name) {
                    values.extend(vals.clone());
                }
            }
        }
        values
    }

    fn assess_security(
        &self,
        anonymous_bind: bool,
        null_bind: bool,
        port: u16,
        naming_contexts: &[String],
        subschema_subentry: &Option<String>,
    ) -> Vec<LdapSecurityFinding> {
        let mut findings = Vec::new();

        if anonymous_bind {
            findings.push(LdapSecurityFinding::AnonymousBindAllowed);
        }

        if null_bind {
            findings.push(LdapSecurityFinding::NullBindSuccess);
        }

        if port != Self::LDAPS_PORT {
            findings.push(LdapSecurityFinding::CleartextTransport);
        }

        if !naming_contexts.is_empty() {
            findings.push(LdapSecurityFinding::BaseDnExposed);
        }

        if subschema_subentry.is_some() {
            findings.push(LdapSecurityFinding::SchemaExposed);
        }

        if anonymous_bind && !naming_contexts.is_empty() {
            findings.push(LdapSecurityFinding::NoAccessControl);
        }

        findings
    }

    pub async fn detect_ldap_version(&self, target: IpAddr, port: u16) -> Option<u8> {
        let addr = SocketAddr::new(target, port);
        let stream = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        let (mut reader, mut writer) = stream.into_split();

        // Try LDAPv3 bind first
        let bind_request = self.build_bind_request(3, "", "");
        if writer.write_all(&bind_request).await.is_err() {
            return None;
        }

        let mut response = [0u8; 4096];
        match timeout(self.timeout_duration, reader.read(&mut response)).await {
            Ok(Ok(n)) if n > 10 => {
                if let Some(result_code) = self.parse_bind_result(&response[..n]) {
                    if result_code == LdapResultCode::Success {
                        return Some(3);
                    }
                }
            }
            _ => {}
        }

        // Try LDAPv2 bind
        let stream2 = match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => return None,
        };

        let (mut reader2, mut writer2) = stream2.into_split();
        let bind_request2 = self.build_simple_bind_v2("", "");
        if writer2.write_all(&bind_request2).await.is_err() {
            return None;
        }

        let mut response2 = [0u8; 4096];
        match timeout(self.timeout_duration, reader2.read(&mut response2)).await {
            Ok(Ok(n)) if n > 10 => {
                if let Some(result_code) = self.parse_bind_result(&response2[..n]) {
                    if result_code == LdapResultCode::Success {
                        return Some(2);
                    }
                }
            }
            _ => {}
        }

        Some(3) // Default to v3 if we can't determine
    }

    fn build_bind_request(&self, version: u8, dn: &str, password: &str) -> Vec<u8> {
        let mut message = Vec::new();

        // Version
        message.extend_from_slice(&self.encode_tlv(Self::TAG_INTEGER, &[version]));

        // DN
        message.extend_from_slice(&self.encode_tlv(Self::TAG_OCTET_STRING, dn.as_bytes()));

        // Simple authentication (tag 0x80)
        let auth = self.encode_tlv(0x80, password.as_bytes());
        message.extend_from_slice(&auth);

        // Wrap in Bind Request (0x60)
        let bind_req = self.encode_tlv(Self::TAG_BIND_REQUEST, &message);

        // LDAP Message: messageID (1) + protocol op
        let mut ldap_msg = Vec::new();
        ldap_msg.extend_from_slice(&self.encode_tlv(Self::TAG_INTEGER, &[0x01]));
        ldap_msg.extend_from_slice(&bind_req);

        self.encode_tlv(Self::TAG_SEQUENCE, &ldap_msg)
    }

    fn build_simple_bind_v2(&self, dn: &str, password: &str) -> Vec<u8> {
        let mut message = Vec::new();

        // Version 2
        message.extend_from_slice(&self.encode_tlv(Self::TAG_INTEGER, &[0x02]));

        // DN
        message.extend_from_slice(&self.encode_tlv(Self::TAG_OCTET_STRING, dn.as_bytes()));

        // Simple authentication (tag 0x80)
        let auth = self.encode_tlv(0x80, password.as_bytes());
        message.extend_from_slice(&auth);

        let bind_req = self.encode_tlv(Self::TAG_BIND_REQUEST, &message);

        let mut ldap_msg = Vec::new();
        ldap_msg.extend_from_slice(&self.encode_tlv(Self::TAG_INTEGER, &[0x01]));
        ldap_msg.extend_from_slice(&bind_req);

        self.encode_tlv(Self::TAG_SEQUENCE, &ldap_msg)
    }

    fn build_search_request(
        &self,
        base_dn: &str,
        scope: u8,
        deref: u8,
        size_limit: u32,
        time_limit: u32,
        types_only: bool,
        filter: &str,
        attributes: &[&str],
    ) -> Vec<u8> {
        let mut message: Vec<u8> = Vec::new();

        // messageID = 2
        let mut ldap_msg = Vec::new();
        ldap_msg.extend_from_slice(&self.encode_tlv(Self::TAG_INTEGER, &[0x02]));

        // Search Request fields
        let mut search = Vec::new();
        search.extend_from_slice(&self.encode_tlv(Self::TAG_OCTET_STRING, base_dn.as_bytes()));
        search.push(Self::TAG_ENUMERATED);
        search.push(0x01);
        search.push(scope);
        search.push(Self::TAG_ENUMERATED);
        search.push(0x01);
        search.push(deref);

        // Size limit
        let size_bytes = self.encode_ber_integer(size_limit as i64);
        search.extend_from_slice(&self.encode_tlv(Self::TAG_INTEGER, &size_bytes));

        // Time limit
        let time_bytes = self.encode_ber_integer(time_limit as i64);
        search.extend_from_slice(&self.encode_tlv(Self::TAG_INTEGER, &time_bytes));

        // Types only
        search.extend_from_slice(&self.encode_tlv(Self::TAG_BOOLEAN, &[types_only as u8]));

        // Filter: (objectClass=*)
        let filter_bytes = self.encode_search_filter(filter);
        search.extend_from_slice(&filter_bytes);

        // Attributes
        let mut attr_list = Vec::new();
        for attr in attributes {
            attr_list.extend_from_slice(&self.encode_tlv(Self::TAG_OCTET_STRING, attr.as_bytes()));
        }
        search.extend_from_slice(&self.encode_tlv(Self::TAG_SEQUENCE, &attr_list));

        // Wrap in Search Request tag
        ldap_msg.extend_from_slice(&self.encode_tlv(Self::TAG_SEARCH_REQUEST, &search));

        self.encode_tlv(Self::TAG_SEQUENCE, &ldap_msg)
    }

    fn encode_search_filter(&self, filter: &str) -> Vec<u8> {
        // Simplified: encode (objectClass=*) as present filter
        // Tag 0x87 = present (attribute description)
        let attr = if filter.starts_with('(') && filter.ends_with(')') {
            // Extract attribute name from simple filter like (objectClass=*)
            let inner = &filter[1..filter.len() - 1];
            if let Some(eq_pos) = inner.find('=') {
                &inner[..eq_pos]
            } else {
                inner
            }
        } else {
            filter
        };

        self.encode_tlv(0x87, attr.as_bytes())
    }

    fn encode_ber_integer(&self, value: i64) -> Vec<u8> {
        if value == 0 {
            return vec![0x00];
        }
        let mut bytes = Vec::new();
        let mut v = value;
        while v > 0 {
            bytes.push((v & 0xFF) as u8);
            v >>= 8;
        }
        bytes.reverse();
        if !bytes.is_empty() && bytes[0] & 0x80 != 0 {
            bytes.insert(0, 0x00);
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

    fn parse_bind_result(&self, data: &[u8]) -> Option<LdapResultCode> {
        // Look for Bind Response (0x61) and extract resultCode
        let mut i = 0;
        while i < data.len() {
            if data[i] == Self::TAG_BIND_RESPONSE {
                // Parse the bind response content
                let content_len = self.parse_length(&data[i + 1..])?;
                let content_start = i + 1 + self.length_field_size(&data[i + 1..]);
                let content_end = content_start + content_len;

                // Parse protocol op: SEQUENCE { resultCode ENUMERATED, ... }
                let mut j = content_start;
                if j < content_end && data[j] == Self::TAG_SEQUENCE {
                    j += 1;
                    let seq_len = self.parse_length(&data[j..])?;
                    j += self.length_field_size(&data[j..]);

                    if j < content_end && data[j] == Self::TAG_ENUMERATED {
                        j += 1;
                        let enum_len = self.parse_length(&data[j..])?;
                        j += self.length_field_size(&data[j..]);

                        if enum_len <= 4 && j + enum_len <= content_end {
                            let mut code: u32 = 0;
                            for k in 0..enum_len {
                                code = (code << 8) | data[j + k] as u32;
                            }
                            return Some(LdapResultCode::from_u32(code));
                        }
                    }
                }
            }
            i += 1;
        }
        None
    }

    fn parse_length(&self, data: &[u8]) -> Option<usize> {
        if data.is_empty() {
            return None;
        }
        if data[0] < 128 {
            Some(data[0] as usize)
        } else if data[0] == 0x81 && data.len() > 1 {
            Some(data[1] as usize)
        } else if data[0] == 0x82 && data.len() > 2 {
            Some(((data[1] as usize) << 8) | data[2] as usize)
        } else {
            None
        }
    }

    fn length_field_size(&self, data: &[u8]) -> usize {
        if data.is_empty() {
            return 0;
        }
        if data[0] < 128 {
            1
        } else if data[0] == 0x81 {
            2
        } else if data[0] == 0x82 {
            3
        } else {
            1
        }
    }

    fn contains_search_done(&self, data: &[u8]) -> bool {
        for i in 0..data.len() {
            if data[i] == Self::TAG_SEARCH_RESULT_DONE {
                return true;
            }
        }
        false
    }

    fn parse_search_results(&self, data: &[u8]) -> Vec<LdapEntry> {
        let mut entries = Vec::new();
        let mut i = 0;

        while i < data.len() {
            if data[i] == Self::TAG_SEARCH_RESULT_ENTRY {
                let content_len = match self.parse_length(&data[i + 1..]) {
                    Some(l) => l,
                    None => {
                        i += 1;
                        continue;
                    }
                };
                let content_start = i + 1 + self.length_field_size(&data[i + 1..]);

                // Parse DN (first OCTET STRING in the entry)
                if content_start < data.len() && data[content_start] == Self::TAG_OCTET_STRING {
                    let dn_len = match self.parse_length(&data[content_start + 1..]) {
                        Some(l) => l,
                        None => {
                            i += 1;
                            continue;
                        }
                    };
                    let dn_start = content_start + 1 + self.length_field_size(&data[content_start + 1..]);
                    if dn_start + dn_len <= data.len() {
                        if let Ok(dn) = std::str::from_utf8(&data[dn_start..dn_start + dn_len]) {
                            let entry = LdapEntry {
                                dn: dn.to_string(),
                                attributes: Vec::new(), // Simplified parsing
                            };
                            entries.push(entry);
                        }
                    }
                }
            }
            i += 1;
        }

        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_result_code_from_u32() {
        assert_eq!(LdapResultCode::from_u32(0), LdapResultCode::Success);
        assert_eq!(LdapResultCode::from_u32(49), LdapResultCode::InvalidCredentials);
        assert_eq!(LdapResultCode::from_u32(48), LdapResultCode::InappropriateAuthentication);
        assert_eq!(LdapResultCode::from_u32(999), LdapResultCode::Other);
    }

    #[test]
    fn test_ldap_result_code_description() {
        assert_eq!(LdapResultCode::Success.description(), "Success");
        assert_eq!(LdapResultCode::InvalidCredentials.description(), "Invalid Credentials");
        assert_eq!(LdapResultCode::Other.description(), "Other");
    }

    #[test]
    fn test_ldap_security_finding_severity() {
        assert_eq!(LdapSecurityFinding::AnonymousBindAllowed.severity(), "CRITICAL");
        assert_eq!(LdapSecurityFinding::CleartextTransport.severity(), "HIGH");
        assert_eq!(LdapSecurityFinding::BaseDnExposed.severity(), "LOW");
        assert_eq!(LdapSecurityFinding::NullBindSuccess.severity(), "CRITICAL");
    }

    #[test]
    fn test_ldap_security_finding_description() {
        assert!(!LdapSecurityFinding::AnonymousBindAllowed.description().is_empty());
        assert!(!LdapSecurityFinding::CleartextTransport.description().is_empty());
        assert!(!LdapSecurityFinding::WeakAuthentication.description().is_empty());
    }

    #[test]
    fn test_ldap_scanner_creation() {
        let scanner = LdapScanner::new(3000);
        assert_eq!(scanner.timeout_duration, Duration::from_millis(3000));
    }

    #[test]
    fn test_ldap_default_port() {
        assert_eq!(LdapScanner::DEFAULT_PORT, 389);
        assert_eq!(LdapScanner::LDAPS_PORT, 636);
    }

    #[test]
    fn test_build_bind_request() {
        let scanner = LdapScanner::new(1000);
        let request = scanner.build_bind_request(3, "dc=example,dc=com", "password");
        assert!(!request.is_empty());
        // Should start with SEQUENCE tag
        assert_eq!(request[0], 0x30);
    }

    #[test]
    fn test_build_bind_request_anonymous() {
        let scanner = LdapScanner::new(1000);
        let request = scanner.build_bind_request(3, "", "");
        assert!(!request.is_empty());
        assert_eq!(request[0], 0x30);
    }

    #[test]
    fn test_build_search_request() {
        let scanner = LdapScanner::new(1000);
        let request = scanner.build_search_request(
            "dc=example,dc=com",
            LdapScanner::SCOPE_BASE,
            LdapScanner::DEREF_NEVER,
            0,
            0,
            false,
            "(objectClass=*)",
            &["namingContexts"],
        );
        assert!(!request.is_empty());
        assert_eq!(request[0], 0x30);
    }

    #[test]
    fn test_encode_tlv() {
        let scanner = LdapScanner::new(1000);
        let encoded = scanner.encode_tlv(0x04, b"test");
        assert_eq!(encoded[0], 0x04);
        assert_eq!(encoded[1], 4);
        assert_eq!(&encoded[2..], b"test");
    }

    #[test]
    fn test_encode_tlv_long() {
        let scanner = LdapScanner::new(1000);
        let data = vec![0u8; 200];
        let encoded = scanner.encode_tlv(0x04, &data);
        assert_eq!(encoded[0], 0x04);
        assert_eq!(encoded[1], 0x81);
        assert_eq!(encoded[2], 200);
    }

    #[test]
    fn test_encode_ber_integer() {
        let scanner = LdapScanner::new(1000);
        assert_eq!(scanner.encode_ber_integer(0), vec![0x00]);
        assert_eq!(scanner.encode_ber_integer(1), vec![0x01]);
        assert_eq!(scanner.encode_ber_integer(127), vec![0x7F]);
        assert_eq!(scanner.encode_ber_integer(128), vec![0x00, 0x80]);
    }

    #[test]
    fn test_parse_length() {
        let scanner = LdapScanner::new(1000);
        assert_eq!(scanner.parse_length(&[0x05]), Some(5));
        assert_eq!(scanner.parse_length(&[0x81, 0x80]), Some(128));
        assert_eq!(scanner.parse_length(&[0x82, 0x01, 0x00]), Some(256));
        assert_eq!(scanner.parse_length(&[]), None);
    }

    #[test]
    fn test_length_field_size() {
        let scanner = LdapScanner::new(1000);
        assert_eq!(scanner.length_field_size(&[0x05]), 1);
        assert_eq!(scanner.length_field_size(&[0x81, 0x80]), 2);
        assert_eq!(scanner.length_field_size(&[0x82, 0x01, 0x00]), 3);
    }

    #[test]
    fn test_parse_bind_result_none() {
        let scanner = LdapScanner::new(1000);
        let data = [0x00, 0x00, 0x00];
        assert!(scanner.parse_bind_result(&data).is_none());
    }

    #[test]
    fn test_contains_search_done() {
        let scanner = LdapScanner::new(1000);
        let data = [0x00, 0x00, LdapScanner::TAG_SEARCH_RESULT_DONE, 0x00];
        assert!(scanner.contains_search_done(&data));
        let data2 = [0x00, 0x00, 0x00];
        assert!(!scanner.contains_search_done(&data2));
    }

    #[test]
    fn test_assess_security_anonymous() {
        let scanner = LdapScanner::new(1000);
        let findings = scanner.assess_security(true, false, 389, &["dc=example,dc=com".to_string()], &None);
        assert!(findings.iter().any(|f| matches!(f, LdapSecurityFinding::AnonymousBindAllowed)));
        assert!(findings.iter().any(|f| matches!(f, LdapSecurityFinding::CleartextTransport)));
        assert!(findings.iter().any(|f| matches!(f, LdapSecurityFinding::BaseDnExposed)));
        assert!(findings.iter().any(|f| matches!(f, LdapSecurityFinding::NoAccessControl)));
    }

    #[test]
    fn test_assess_security_ldaps() {
        let scanner = LdapScanner::new(1000);
        let findings = scanner.assess_security(false, false, 636, &[], &None);
        assert!(!findings.iter().any(|f| matches!(f, LdapSecurityFinding::CleartextTransport)));
    }

    #[test]
    fn test_assess_security_null_bind() {
        let scanner = LdapScanner::new(1000);
        let findings = scanner.assess_security(false, true, 389, &[], &None);
        assert!(findings.iter().any(|f| matches!(f, LdapSecurityFinding::NullBindSuccess)));
    }

    #[test]
    fn test_assess_security_schema_exposed() {
        let scanner = LdapScanner::new(1000);
        let subschema = Some("cn=Subschema".to_string());
        let findings = scanner.assess_security(false, false, 389, &[], &subschema);
        assert!(findings.iter().any(|f| matches!(f, LdapSecurityFinding::SchemaExposed)));
    }

    #[test]
    fn test_ldap_entry_fields() {
        let entry = LdapEntry {
            dn: "dc=example,dc=com".to_string(),
            attributes: vec![
                ("objectClass".to_string(), vec!["top".to_string(), "domain".to_string()]),
            ],
        };
        assert_eq!(entry.dn, "dc=example,dc=com");
        assert_eq!(entry.attributes.len(), 1);
    }

    #[test]
    fn test_encode_search_filter() {
        let scanner = LdapScanner::new(1000);
        let filter = scanner.encode_search_filter("(objectClass=*)");
        assert!(!filter.is_empty());
        // Should be a present filter (0x87)
        assert_eq!(filter[0], 0x87);
    }

    #[tokio::test]
    async fn test_detect_ldap_on_closed_port() {
        let scanner = LdapScanner::new(200);
        let result = scanner.detect_ldap(IpAddr::V4([127, 0, 0, 1].into()), 1).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_ldap_security_finding_new_types() {
        assert_eq!(LdapSecurityFinding::SchemaExposed.severity(), "LOW");
        assert_eq!(LdapSecurityFinding::NoAccessControl.severity(), "MEDIUM");
        assert_eq!(LdapSecurityFinding::DefaultConfig.severity(), "MEDIUM");
    }

    #[test]
    fn test_ldap_security_finding_new_descriptions() {
        assert!(!LdapSecurityFinding::SchemaExposed.description().is_empty());
        assert!(!LdapSecurityFinding::NoAccessControl.description().is_empty());
        assert!(!LdapSecurityFinding::DefaultConfig.description().is_empty());
    }

    #[test]
    fn test_build_simple_bind_v2() {
        let scanner = LdapScanner::new(1000);
        let request = scanner.build_simple_bind_v2("dc=example,dc=com", "password");
        assert!(!request.is_empty());
        assert_eq!(request[0], 0x30);
    }

    #[test]
    fn test_ldap_tag_constants() {
        assert_eq!(LdapScanner::TAG_SEQUENCE, 0x30);
        assert_eq!(LdapScanner::TAG_BIND_REQUEST, 0x60);
        assert_eq!(LdapScanner::TAG_BIND_RESPONSE, 0x61);
        assert_eq!(LdapScanner::TAG_SEARCH_REQUEST, 0x63);
        assert_eq!(LdapScanner::TAG_SEARCH_RESULT_ENTRY, 0x64);
        assert_eq!(LdapScanner::TAG_SEARCH_RESULT_DONE, 0x65);
    }

    #[test]
    fn test_ldap_scope_constants() {
        assert_eq!(LdapScanner::SCOPE_BASE, 0x00);
        assert_eq!(LdapScanner::SCOPE_ONE_LEVEL, 0x01);
        assert_eq!(LdapScanner::SCOPE_SUBTREE, 0x02);
    }
}
