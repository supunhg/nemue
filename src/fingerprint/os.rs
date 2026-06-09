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
    pub passive_indicators: Vec<String>,
    pub os_generation: Option<String>,
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
    Android,
    iOS,
    ChromeOS,
    Embedded,
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
            OsFamily::Android => "Android",
            OsFamily::iOS => "iOS",
            OsFamily::ChromeOS => "ChromeOS",
            OsFamily::Embedded => "Embedded",
            OsFamily::Unknown => "Unknown",
        }
    }

    pub fn from_banner(banner: &str) -> Option<Self> {
        let lower = banner.to_lowercase();
        if lower.contains("windows") || lower.contains("microsoft") {
            Some(OsFamily::Windows)
        } else if lower.contains("ubuntu") || lower.contains("debian") || lower.contains("centos") 
            || lower.contains("rhel") || lower.contains("fedora") || lower.contains("suse")
            || lower.contains("linux") {
            Some(OsFamily::Linux)
        } else if lower.contains("macos") || lower.contains("darwin") || lower.contains("mac os") {
            Some(OsFamily::MacOS)
        } else if lower.contains("freebsd") || lower.contains("openbsd") || lower.contains("netbsd") {
            Some(OsFamily::BSD)
        } else if lower.contains("solaris") || lower.contains("sunos") {
            Some(OsFamily::Solaris)
        } else if lower.contains("android") {
            Some(OsFamily::Android)
        } else if lower.contains("iphone") || lower.contains("ipad") || lower.contains("ios") {
            Some(OsFamily::iOS)
        } else if lower.contains("cisco") || lower.contains("ios") {
            Some(OsFamily::Cisco)
        } else if lower.contains("juniper") || lower.contains("fortinet") || lower.contains("palo alto") {
            Some(OsFamily::NetworkDevice)
        } else {
            None
        }
    }
}

pub struct OsDetector;

impl OsDetector {
    pub fn new() -> Self {
        OsDetector
    }

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
        let mut confidence = 30;
        let mut os_version = None;
        let mut os_generation = None;
        let mut details = String::new();
        let ip_id_sequence = Some("Unknown".to_string());
        let passive_indicators = Vec::new();

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

        if let Some(win) = window_size {
            details.push_str(&format!("Win={}; ", win));
            confidence += 5;

            match win {
                8192 => {
                    if matches!(os_family, OsFamily::Windows) {
                        os_version = Some("Windows XP/2003".to_string());
                        os_generation = Some("Legacy".to_string());
                        confidence += 15;
                    }
                }
                65535 => {
                    if matches!(os_family, OsFamily::Windows) {
                        os_version = Some("Windows 7/8/2008".to_string());
                        os_generation = Some("Modern".to_string());
                        confidence += 15;
                    }
                }
                64240 => {
                    if matches!(os_family, OsFamily::Windows) {
                        os_version = Some("Windows 10/11/2016+".to_string());
                        os_generation = Some("Current".to_string());
                        confidence += 20;
                    }
                }
                16384 => {
                    if matches!(os_family, OsFamily::Linux) {
                        details.push_str("Linux (OpenBSD-style); ");
                        confidence += 10;
                    }
                }
                5840 | 14600 | 29200 => {
                    if matches!(os_family, OsFamily::Linux) {
                        confidence += 15;
                        details.push_str("Linux kernel 2.4+; ");
                    }
                }
                32768 => {
                    if matches!(os_family, OsFamily::Linux) {
                        details.push_str("Linux/NetBSD; ");
                        confidence += 10;
                    }
                }
                4128 => {
                    os_family = OsFamily::Cisco;
                    os_version = Some("Cisco IOS".to_string());
                    confidence += 25;
                    details.push_str("Cisco IOS signature; ");
                }
                49240 | 49640 => {
                    os_family = OsFamily::Solaris;
                    os_version = Some("Solaris 10/11".to_string());
                    confidence += 25;
                    details.push_str("Solaris signature; ");
                }
                _ => {}
            }
        }

        if let Some(ts) = tcp_timestamp {
            details.push_str(&format!("TS={}; ", ts));
            confidence += 5;

            if ts > 0 {
                if matches!(os_family, OsFamily::Linux) {
                    details.push_str("High-res timestamp (Linux); ");
                    confidence += 5;
                }
            }
        }

        if let Some(wscale) = window_scaling {
            details.push_str(&format!("WScale={}; ", wscale));
            confidence += 5;

            match wscale {
                8 => {
                    if matches!(os_family, OsFamily::Windows) {
                        confidence += 10;
                        details.push_str("Win10+ scaling; ");
                    }
                }
                7 => {
                    if matches!(os_family, OsFamily::Linux) {
                        confidence += 10;
                        details.push_str("Linux scaling; ");
                    }
                }
                6 => {
                    if matches!(os_family, OsFamily::Linux) {
                        details.push_str("macOS/BSD scaling; ");
                        confidence += 5;
                    }
                }
                _ => {}
            }
        }

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
                1360 => {
                    details.push_str("PPPoE MSS; ");
                }
                _ => {}
            }
        }

        if !tcp_options.is_empty() {
            details.push_str(&format!("Options={:?}; ", tcp_options));
            confidence += 5;

            let opts_str = tcp_options.join(",");

            if opts_str.contains("mss") 
                && opts_str.contains("nop") 
                && opts_str.contains("sackOK") 
                && matches!(os_family, OsFamily::Windows) {
                confidence += 15;
                details.push_str("Windows TCP stack; ");
            }

            if opts_str.contains("timestamp") 
                && opts_str.contains("sackOK") 
                && matches!(os_family, OsFamily::Linux) {
                confidence += 15;
                details.push_str("Linux TCP stack; ");
            }

            if opts_str.contains("timestamp")
                && opts_str.contains("sackOK")
                && ttl == 64
                && window_size == Some(65535) {
                os_family = OsFamily::MacOS;
                os_version = Some("macOS 10.x+".to_string());
                os_generation = Some("Modern".to_string());
                confidence += 20;
                details.push_str("macOS signature; ");
            }

            if opts_str.contains("timestamp")
                && opts_str.contains("sackOK")
                && ttl == 64
                && window_size.map_or(false, |w| w <= 65535) {
                if matches!(os_family, OsFamily::Linux) {
                    details.push_str("Possible Android; ");
                }
            }
        }

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
            passive_indicators,
            os_generation,
        }
    }

    pub fn detect(&self, ttl: u8, window_size: Option<u16>, tcp_options: Vec<String>) -> OsFingerprint {
        self.detect_advanced(ttl, window_size, tcp_options, None, None, None)
    }

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
                passive_indicators: Vec::new(),
                os_generation: None,
            };
        }

        let (ttl, window_size, tcp_options) = fingerprints[0].clone();
        let mut result = self.detect(ttl, window_size, tcp_options);

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

    pub fn detect_passive(&self, banner: &str, service: &str) -> Option<(OsFamily, u8)> {
        let mut indicators = Vec::new();
        let mut os_family = None;
        let mut confidence = 0;

        if let Some(family) = OsFamily::from_banner(banner) {
            os_family = Some(family.clone());
            confidence += 40;
            indicators.push(format!("Banner OS: {}", family.as_str()));
        }

        let service_lower = service.to_lowercase();
        if service_lower.contains("iis") || service_lower.contains("asp.net") {
            os_family = Some(OsFamily::Windows);
            confidence += 30;
            indicators.push("IIS/ASP.NET detected".to_string());
        } else if service_lower.contains("apache") || service_lower.contains("nginx") {
            if banner.to_lowercase().contains("ubuntu") || banner.to_lowercase().contains("debian") {
                os_family = Some(OsFamily::Linux);
                confidence += 25;
                indicators.push("Linux web server".to_string());
            }
        }

        if service_lower.contains("ssh") {
            let banner_lower = banner.to_lowercase();
            if banner_lower.contains("ubuntu") {
                os_family = Some(OsFamily::Linux);
                confidence += 35;
                indicators.push("Ubuntu SSH".to_string());
            } else if banner_lower.contains("windows") {
                os_family = Some(OsFamily::Windows);
                confidence += 35;
                indicators.push("Windows SSH".to_string());
            } else if banner_lower.contains("cisco") {
                os_family = Some(OsFamily::Cisco);
                confidence += 40;
                indicators.push("Cisco SSH".to_string());
            }
        }

        if confidence > 0 {
            Some((os_family.unwrap_or(OsFamily::Unknown), confidence.min(100)))
        } else {
            None
        }
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

    #[test]
    fn test_new_os_families() {
        assert_eq!(OsFamily::Android.as_str(), "Android");
        assert_eq!(OsFamily::iOS.as_str(), "iOS");
        assert_eq!(OsFamily::ChromeOS.as_str(), "ChromeOS");
        assert_eq!(OsFamily::Embedded.as_str(), "Embedded");
    }

    #[test]
    fn test_os_from_banner() {
        assert_eq!(OsFamily::from_banner("Server: Microsoft-IIS/10.0"), Some(OsFamily::Windows));
        assert_eq!(OsFamily::from_banner("Server: nginx/1.18.0 (Ubuntu)"), Some(OsFamily::Linux));
        assert_eq!(OsFamily::from_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu"), Some(OsFamily::Linux));
        assert_eq!(OsFamily::from_banner("SSH-2.0-Cisco-1.25"), Some(OsFamily::Cisco));
        assert_eq!(OsFamily::from_banner("Server: Apache/2.4.41 (Ubuntu)"), Some(OsFamily::Linux));
        assert_eq!(OsFamily::from_banner("random banner"), None);
    }

    #[test]
    fn test_passive_detection() {
        let detector = OsDetector::new();
        
        let result = detector.detect_passive("Server: Microsoft-IIS/10.0", "http");
        assert!(result.is_some());
        let (family, conf) = result.unwrap();
        assert_eq!(family, OsFamily::Windows);
        assert!(conf > 0);
        
        let result = detector.detect_passive("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "ssh");
        assert!(result.is_some());
        let (family, conf) = result.unwrap();
        assert_eq!(family, OsFamily::Linux);
        assert!(conf > 0);
    }

    #[test]
    fn test_os_generation() {
        let detector = OsDetector::new();
        
        let result = detector.detect_advanced(
            128,
            Some(8192),
            vec!["mss".to_string(), "nop".to_string(), "sackOK".to_string()],
            None,
            None,
            Some(1460),
        );
        assert_eq!(result.os_generation, Some("Legacy".to_string()));
        
        let result = detector.detect_advanced(
            128,
            Some(64240),
            vec!["mss".to_string(), "nop".to_string(), "sackOK".to_string()],
            None,
            Some(8),
            Some(1460),
        );
        assert_eq!(result.os_generation, Some("Current".to_string()));
    }

    #[test]
    fn test_cisco_window_size() {
        let detector = OsDetector::new();
        let result = detector.detect_advanced(
            255,
            Some(4128),
            vec!["mss".to_string()],
            None,
            None,
            Some(1460),
        );
        
        assert_eq!(result.os_family, Some(OsFamily::Cisco));
        assert!(result.confidence >= 50);
    }

    #[test]
    fn test_solaris_window_size() {
        let detector = OsDetector::new();
        let result = detector.detect_advanced(
            255,
            Some(49240),
            vec!["mss".to_string(), "sackOK".to_string(), "ts".to_string()],
            Some(0),
            None,
            Some(1460),
        );
        
        assert_eq!(result.os_family, Some(OsFamily::Solaris));
        assert!(result.confidence >= 50);
    }
}
