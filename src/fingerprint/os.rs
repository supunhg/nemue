use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsFingerprint {
    pub target: IpAddr,
    pub os_family: Option<OsFamily>,
    pub os_version: Option<String>,
    pub confidence: u8, // 0-100
    pub ttl: Option<u8>,
    pub window_size: Option<u16>,
    pub tcp_options: Vec<String>,
    pub tcp_timestamp: Option<u32>,
    pub ip_id_sequence: Option<String>, // Sequential, Random, Zero
    pub window_scaling: Option<u8>,
    pub max_segment_size: Option<u16>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OsFamily {
    Linux,
    Windows,
    MacOS,
    BSD,
    Unix,
    Solaris,
    AIX,
    HPUX,
    Cisco,
    NetworkDevice,
    Unknown,
}

impl OsFamily {
    pub fn from_ttl(ttl: u8) -> Self {
        match ttl {
            // Linux typically uses 64
            60..=64 => OsFamily::Linux,
            // Windows typically uses 128
            120..=128 => OsFamily::Windows,
            // Solaris uses 255
            250..=255 => OsFamily::Solaris,
            // Cisco IOS often uses 255 or 64
            _ => OsFamily::Unknown,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            OsFamily::Linux => "Linux",
            OsFamily::Windows => "Windows",
            OsFamily::MacOS => "macOS",
            OsFamily::BSD => "BSD",
            OsFamily::Unix => "Unix",
            OsFamily::Solaris => "Solaris",
            OsFamily::AIX => "AIX",
            OsFamily::HPUX => "HP-UX",
            OsFamily::Cisco => "Cisco IOS",
            OsFamily::NetworkDevice => "Network Device",
            OsFamily::Unknown => "Unknown",
        }
    }
}

pub struct OsDetector;

impl OsDetector {
    pub fn new() -> Self {
        OsDetector
    }

    /// Advanced OS detection with multiple TCP/IP stack characteristics
    pub fn detect_advanced(
        &self,
        ttl: u8,
        window_size: Option<u16>,
        tcp_options: Vec<String>,
        tcp_timestamp: Option<u32>,
        window_scaling: Option<u8>,
        max_segment_size: Option<u16>,
    ) -> OsFingerprint {
        let mut os_family = OsFamily::from_ttl(ttl);
        let mut confidence = 30; // Base confidence
        let mut os_version = None;
        let mut details = String::new();
        let mut ip_id_sequence = None;

        // TTL analysis (most reliable indicator)
        details.push_str(&format!("TTL={}; ", ttl));
        match ttl {
            64 => {
                os_family = OsFamily::Linux;
                confidence += 25;
            }
            128 => {
                os_family = OsFamily::Windows;
                confidence += 25;
            }
            255 => {
                os_family = OsFamily::Solaris;
                confidence += 20;
                details.push_str("Solaris/Network Device; ");
            }
            _ => {
                details.push_str("Non-standard TTL; ");
            }
        }

        // Window size analysis
        if let Some(win) = window_size {
            details.push_str(&format!("Win={}; ", win));
            confidence += 5;

            match win {
                // Windows signatures
                8192 => {
                    if matches!(os_family, OsFamily::Windows) {
                        os_version = Some("Windows XP/2003".to_string());
                        confidence += 15;
                    }
                }
                65535 => {
                    if matches!(os_family, OsFamily::Windows) {
                        os_version = Some("Windows 7/8/2008".to_string());
                        confidence += 15;
                    }
                }
                64240 => {
                    if matches!(os_family, OsFamily::Windows) {
                        os_version = Some("Windows 10/11/2016+".to_string());
                        confidence += 20;
                    }
                }
                // Linux signatures
                5840 | 14600 | 29200 => {
                    if matches!(os_family, OsFamily::Linux) {
                        confidence += 15;
                        details.push_str("Linux kernel 2.4+; ");
                    }
                }
                // BSD signatures  
                65535 => {
                    if ttl == 64 {
                        os_family = OsFamily::BSD;
                        confidence += 10;
                    }
                }
                _ => {}
            }
        }

        // TCP timestamp analysis
        if let Some(ts) = tcp_timestamp {
            details.push_str(&format!("TS={}; ", ts));
            confidence += 5;

            // Windows typically uses 100Hz timestamp clock
            // Linux uses 250Hz or 1000Hz
            if ts > 0 {
                if matches!(os_family, OsFamily::Linux) {
                    details.push_str("High-res timestamp (Linux); ");
                    confidence += 5;
                }
            }
        }

        // Window scaling analysis
        if let Some(wscale) = window_scaling {
            details.push_str(&format!("WScale={}; ", wscale));
            confidence += 5;

            match wscale {
                // Windows 10/11 typically uses 8
                8 => {
                    if matches!(os_family, OsFamily::Windows) {
                        confidence += 10;
                        details.push_str("Win10+ scaling; ");
                    }
                }
                // Linux often uses 7
                7 => {
                    if matches!(os_family, OsFamily::Linux) {
                        confidence += 10;
                        details.push_str("Linux scaling; ");
                    }
                }
                _ => {}
            }
        }

        // MSS analysis
        if let Some(mss) = max_segment_size {
            details.push_str(&format!("MSS={}; ", mss));
            confidence += 5;

            match mss {
                1460 => {
                    details.push_str("Ethernet MSS; ");
                    confidence += 5;
                }
                1380 | 1400 => {
                    details.push_str("VPN/Tunnel MSS; ");
                }
                _ => {}
            }
        }

        // TCP options fingerprinting (advanced)
        if !tcp_options.is_empty() {
            details.push_str(&format!("Options={:?}; ", tcp_options));
            confidence += 5;

            let opts_str = tcp_options.join(",");

            // Windows signature: mss,nop,ws,nop,nop,sackOK
            if opts_str.contains("mss") 
                && opts_str.contains("nop") 
                && opts_str.contains("sackOK") 
                && matches!(os_family, OsFamily::Windows) {
                confidence += 15;
                details.push_str("Windows TCP stack; ");
            }

            // Linux signature: mss,sackOK,timestamp,nop,wscale
            if opts_str.contains("timestamp") 
                && opts_str.contains("sackOK") 
                && matches!(os_family, OsFamily::Linux) {
                confidence += 15;
                details.push_str("Linux TCP stack; ");
            }

            // macOS signature
            if opts_str.contains("timestamp")
                && opts_str.contains("sackOK")
                && ttl == 64
                && window_size == Some(65535) {
                os_family = OsFamily::MacOS;
                os_version = Some("macOS 10.x+".to_string());
                confidence += 20;
                details.push_str("macOS signature; ");
            }
        }

        // IP ID sequence analysis (requires multiple packets)
        // This is a placeholder - would need multiple probes
        ip_id_sequence = Some("Unknown".to_string());

        // Cap confidence
        confidence = confidence.min(100);

        OsFingerprint {
            target: "0.0.0.0".parse().unwrap(),
            os_family: Some(os_family),
            os_version,
            confidence,
            ttl: Some(ttl),
            window_size,
            tcp_options,
            tcp_timestamp,
            ip_id_sequence,
            window_scaling,
            max_segment_size,
            details,
        }
    }

    /// Detect OS based on TTL and other TCP/IP stack characteristics (simple version)
    pub fn detect(&self, ttl: u8, window_size: Option<u16>, tcp_options: Vec<String>) -> OsFingerprint {
        self.detect_advanced(ttl, window_size, tcp_options, None, None, None)
    }

    /// Detect OS from multiple fingerprints (more accurate)
    pub fn detect_from_multiple(&self, fingerprints: Vec<(u8, Option<u16>, Vec<String>)>) -> OsFingerprint {
        if fingerprints.is_empty() {
            return OsFingerprint {
                target: "0.0.0.0".parse().unwrap(),
                os_family: Some(OsFamily::Unknown),
                os_version: None,
                confidence: 0,
                ttl: None,
                window_size: None,
                tcp_options: vec![],
                tcp_timestamp: None,
                ip_id_sequence: Some("Unknown".to_string()),
                window_scaling: None,
                max_segment_size: None,
                details: "No data available".to_string(),
            };
        }

        // Use the first fingerprint as base
        let (ttl, window_size, tcp_options) = fingerprints[0].clone();
        let mut result = self.detect(ttl, window_size, tcp_options);

        // Increase confidence if multiple probes agree
        if fingerprints.len() > 1 {
            let consistent = fingerprints.iter().all(|(t, _, _)| {
                OsFamily::from_ttl(*t) == result.os_family.clone().unwrap()
            });

            if consistent {
                result.confidence = (result.confidence + 10).min(100);
                result.details.push_str(&format!(" (verified by {} probes)", fingerprints.len()));
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_from_ttl() {
        assert_eq!(OsFamily::from_ttl(64), OsFamily::Linux);
        assert_eq!(OsFamily::from_ttl(128), OsFamily::Windows);
        assert_eq!(OsFamily::from_ttl(255), OsFamily::Solaris);
    }

    #[test]
    fn test_detect_linux() {
        let detector = OsDetector::new();
        let result = detector.detect(64, Some(29200), vec!["mss".to_string(), "sackOK".to_string()]);
        
        assert_eq!(result.os_family, Some(OsFamily::Linux));
        assert!(result.confidence >= 60);
    }

    #[test]
    fn test_detect_windows() {
        let detector = OsDetector::new();
        let result = detector.detect(128, Some(64240), vec!["mss".to_string(), "timestamp".to_string()]);
        
        assert_eq!(result.os_family, Some(OsFamily::Windows));
        assert!(result.confidence >= 70);
    }

    #[test]
    fn test_advanced_linux_detection() {
        let detector = OsDetector::new();
        let result = detector.detect_advanced(
            64,
            Some(29200),
            vec!["mss".to_string(), "sackOK".to_string(), "timestamp".to_string(), "nop".to_string(), "wscale".to_string()],
            Some(12345678),
            Some(7),
            Some(1460),
        );
        
        assert_eq!(result.os_family, Some(OsFamily::Linux));
        assert!(result.confidence >= 80, "Expected confidence >= 80, got {}", result.confidence);
        assert_eq!(result.window_scaling, Some(7));
        assert_eq!(result.max_segment_size, Some(1460));
    }

    #[test]
    fn test_advanced_windows10_detection() {
        let detector = OsDetector::new();
        let result = detector.detect_advanced(
            128,
            Some(64240),
            vec!["mss".to_string(), "nop".to_string(), "sackOK".to_string()],
            Some(1000),
            Some(8),
            Some(1460),
        );
        
        assert_eq!(result.os_family, Some(OsFamily::Windows));
        assert_eq!(result.os_version, Some("Windows 10/11/2016+".to_string()));
        assert!(result.confidence >= 80);
    }

    #[test]
    fn test_macos_detection() {
        let detector = OsDetector::new();
        let result = detector.detect_advanced(
            64,
            Some(65535),
            vec!["mss".to_string(), "timestamp".to_string(), "sackOK".to_string()],
            Some(50000),
            None,
            Some(1460),
        );
        
        assert_eq!(result.os_family, Some(OsFamily::MacOS));
        assert!(result.confidence >= 70);
    }
}
