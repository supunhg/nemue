/// TCP/IP Stack Fingerprinting
///
/// Advanced OS detection using TCP/IP stack characteristics

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Complete TCP/IP stack fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFingerprint {
    pub tcp_signature: Option<TcpSignature>,
    pub icmp_signature: Option<IcmpSignature>,
    pub ip_signature: Option<IpSignature>,
    pub os_matches: Vec<OsMatch>,
    pub confidence: f32,
}

/// TCP protocol signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSignature {
    pub window_size: u16,
    pub ttl: u8,
    pub max_segment_size: Option<u16>,
    pub window_scaling: Option<u8>,
    pub timestamp: Option<u32>,
    pub selective_ack: bool,
    pub tcp_options: Vec<String>,
    pub tcp_flags: u8,
    pub window_size_multiple: Option<u16>,
    pub dont_fragment: bool,
    pub explicit_congestion: bool,
    pub tcp_option_order: Vec<String>,
    pub quirks: Vec<String>,
}

/// ICMP protocol signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpSignature {
    pub ttl: u8,
    pub code: u8,
    pub echo_id: Option<u16>,
    pub echo_sequence: Option<u16>,
    pub payload_size: usize,
    pub data_pattern: Vec<u8>,
    pub tos: u8,
    pub df_bit: bool,
    pub quirks: Vec<String>,
}

/// IP protocol signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpSignature {
    pub id_sequence: IdSequence,
    pub ttl: u8,
    pub ttl_distance: u8,
    pub flags: u8,
    pub fragmentation: bool,
    pub tos: u8,
    pub ip_options: Vec<String>,
}

/// IP ID sequence pattern
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IdSequence {
    Incremental,
    IncrementalByTwo,
    Random,
    Zero,
    Constant(u16),
    Unknown,
}

/// OS match result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsMatch {
    pub os_name: String,
    pub confidence: f32,
    pub matched_features: Vec<String>,
}

/// Stack analyzer
pub struct StackAnalyzer {
    signature_db: SignatureDatabase,
}

impl StackAnalyzer {
    pub fn new() -> Self {
        Self {
            signature_db: SignatureDatabase::load_default(),
        }
    }

    /// Analyze TCP/IP stack
    pub fn analyze(
        &self,
        tcp_sig: Option<TcpSignature>,
        icmp_sig: Option<IcmpSignature>,
        ip_sig: Option<IpSignature>,
    ) -> Result<StackFingerprint> {
        let mut os_matches = Vec::new();

        for signature in &self.signature_db.signatures {
            let mut score = 0.0;
            let mut max_score = 0.0;
            let mut matched_features = Vec::new();

            if let Some(ref tcp) = tcp_sig {
                let (tcp_score, tcp_max, tcp_features) =
                    self.match_tcp_signature(tcp, &signature.tcp);
                score += tcp_score;
                max_score += tcp_max;
                matched_features.extend(tcp_features);
            }

            if let Some(ref icmp) = icmp_sig {
                let (icmp_score, icmp_max) = self.match_icmp_signature(icmp, &signature.icmp);
                score += icmp_score;
                max_score += icmp_max;
            }

            if let Some(ref ip) = ip_sig {
                let (ip_score, ip_max) = self.match_ip_signature(ip, &signature.ip);
                score += ip_score;
                max_score += ip_max;
            }

            if max_score > 0.0 {
                let confidence = score / max_score;
                if confidence > 0.5 {
                    os_matches.push(OsMatch {
                        os_name: signature.os_name.clone(),
                        confidence,
                        matched_features,
                    });
                }
            }
        }

        os_matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        let overall_confidence = os_matches.first().map(|m| m.confidence).unwrap_or(0.0);

        Ok(StackFingerprint {
            tcp_signature: tcp_sig,
            icmp_signature: icmp_sig,
            ip_signature: ip_sig,
            os_matches,
            confidence: overall_confidence,
        })
    }

    fn match_tcp_signature(
        &self,
        actual: &TcpSignature,
        expected: &TcpSignature,
    ) -> (f32, f32, Vec<String>) {
        let mut score = 0.0;
        let mut max_score = 0.0;
        let mut features = Vec::new();

        max_score += 0.2;
        if actual.ttl == expected.ttl {
            score += 0.2;
            features.push(format!("TTL: {}", actual.ttl));
        }

        max_score += 0.15;
        if actual.window_size == expected.window_size {
            score += 0.15;
        }

        max_score += 0.2;
        if actual.tcp_option_order == expected.tcp_option_order {
            score += 0.2;
        }

        (score, max_score, features)
    }

    fn match_icmp_signature(
        &self,
        actual: &IcmpSignature,
        expected: &IcmpSignature,
    ) -> (f32, f32) {
        let mut score = 0.0;
        let mut max_score = 0.0;

        max_score += 0.3;
        if actual.ttl == expected.ttl {
            score += 0.3;
        }

        (score, max_score)
    }

    fn match_ip_signature(&self, actual: &IpSignature, expected: &IpSignature) -> (f32, f32) {
        let mut score = 0.0;
        let mut max_score = 0.0;

        max_score += 0.25;
        if actual.id_sequence == expected.id_sequence {
            score += 0.25;
        }

        (score, max_score)
    }

    /// Detect IP ID sequence pattern
    pub fn detect_ip_id_sequence(packet_ids: &[u16]) -> IdSequence {
        if packet_ids.is_empty() {
            return IdSequence::Unknown;
        }

        if packet_ids.iter().all(|&id| id == 0) {
            return IdSequence::Zero;
        }

        if packet_ids.len() < 3 {
            return IdSequence::Unknown;
        }

        let mut incremental = true;
        let mut incremental_by_two = true;

        for window in packet_ids.windows(2) {
            let diff = window[1].wrapping_sub(window[0]);
            if diff != 1 {
                incremental = false;
            }
            if diff != 2 {
                incremental_by_two = false;
            }
        }

        if incremental {
            IdSequence::Incremental
        } else if incremental_by_two {
            IdSequence::IncrementalByTwo
        } else {
            IdSequence::Random
        }
    }

    /// Estimate initial TTL
    pub fn estimate_initial_ttl(observed_ttl: u8) -> u8 {
        let common_ttls = [32, 64, 128, 255];
        for &ttl in &common_ttls {
            if observed_ttl <= ttl {
                return ttl;
            }
        }
        255
    }
}

impl Default for StackAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct SignatureDatabase {
    signatures: Vec<OsSignature>,
}

#[derive(Clone)]
struct OsSignature {
    os_name: String,
    tcp: TcpSignature,
    icmp: IcmpSignature,
    ip: IpSignature,
}

impl SignatureDatabase {
    fn load_default() -> Self {
        let signatures = vec![
            OsSignature {
                os_name: "Linux 4.x/5.x".to_string(),
                tcp: TcpSignature {
                    window_size: 29200,
                    ttl: 64,
                    max_segment_size: Some(1460),
                    window_scaling: Some(7),
                    timestamp: Some(0),
                    selective_ack: true,
                    tcp_options: vec!["mss".to_string()],
                    tcp_flags: 0x02,
                    window_size_multiple: Some(64),
                    dont_fragment: true,
                    explicit_congestion: false,
                    tcp_option_order: vec!["mss".to_string(), "sackOK".to_string()],
                    quirks: Vec::new(),
                },
                icmp: IcmpSignature {
                    ttl: 64,
                    code: 0,
                    echo_id: Some(0),
                    echo_sequence: Some(0),
                    payload_size: 56,
                    data_pattern: vec![0x08],
                    tos: 0,
                    df_bit: false,
                    quirks: Vec::new(),
                },
                ip: IpSignature {
                    id_sequence: IdSequence::Random,
                    ttl: 64,
                    ttl_distance: 0,
                    flags: 0x40,
                    fragmentation: false,
                    tos: 0,
                    ip_options: Vec::new(),
                },
            },
        ];

        Self { signatures }
    }
}
