use anyhow::Result;
use crate::scanner::{ScanResults, PortState, Protocol};

/// Format scan results as Nmap-compatible XML
///
/// Output conforms to Nmap's XML DTD so tools that consume Nmap XML
/// (Metasploit, Burp, OpenVAS, Dradis) can parse Nemue output.
pub fn format(results: &ScanResults) -> Result<String> {
    let mut xml = String::with_capacity(results.results.len() * 200);
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<!DOCTYPE nmaprun>\n");
    xml.push_str(&format!(
        "<nmaprun scanner=\"nemue\" args=\"nemue scan\" start=\"{}\" startstr=\"{}\" version=\"{}\" xmloutputversion=\"1.05\">\n",
        results.scan_start.timestamp(),
        results.scan_start.format("%a %b %d %H:%M:%S %Y"),
        env!("CARGO_PKG_VERSION"),
    ));

    // Scan info
    xml.push_str(&format!(
        "  <scaninfo type=\"connect\" protocol=\"tcp\" numservices=\"{}\" services=\"1-65535\" />\n",
        results.port_count,
    ));

    // Group results by target
    let mut targets: std::collections::HashMap<std::net::IpAddr, Vec<&crate::scanner::ScanResult>> =
        std::collections::HashMap::new();

    for result in &results.results {
        targets.entry(result.target).or_insert_with(Vec::new).push(result);
    }

    // Output each target
    for (target, target_results) in &targets {
        xml.push_str(&format!("  <host starttime=\"{}\" endtime=\"{}\">\n",
            results.scan_start.timestamp(),
            results.scan_end.timestamp(),
        ));
        xml.push_str(&format!("    <status state=\"up\" reason=\"syn-ack\" reason_ttl=\"0\" />\n"));
        xml.push_str(&format!("    <address addr=\"{}\" addrtype=\"ipv4\" />\n", target));

        // Hostnames
        if let Some(hostname) = target_results.iter().find_map(|r| r.hostname.as_ref()) {
            xml.push_str("    <hostnames>\n");
            xml.push_str(&format!("      <hostname name=\"{}\" type=\"PTR\" />\n", hostname));
            xml.push_str("    </hostnames>\n");
        }

        // Ports
        xml.push_str("    <ports>\n");

        for result in target_results {
            let state_str = match result.state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
                PortState::Unfiltered => "unfiltered",
                PortState::OpenFiltered => "open|filtered",
                PortState::Unknown => "unknown",
            };

            let protocol = match result.protocol {
                Protocol::TCP => "tcp",
                Protocol::UDP => "udp",
                Protocol::ICMP => "icmp",
            };

            let reason = match result.state {
                PortState::Open => "syn-ack",
                PortState::Closed => "reset",
                PortState::Filtered => "no-response",
                _ => "none",
            };

            xml.push_str(&format!(
                "      <port protocol=\"{}\" portid=\"{}\">\n",
                protocol, result.port,
            ));
            xml.push_str(&format!(
                "        <state state=\"{}\" reason=\"{}\" reason_ttl=\"64\" />\n",
                state_str, reason,
            ));

            // Service info
            if let Some(ref service) = result.service {
                let product = result.service_info.as_ref()
                    .and_then(|si| si.product.as_deref())
                    .unwrap_or("");
                let version = result.service_info.as_ref()
                    .and_then(|si| si.version.as_deref())
                    .unwrap_or("");
                let extra_info = result.service_info.as_ref()
                    .and_then(|si| si.extra_info.as_deref())
                    .unwrap_or("");

                xml.push_str(&format!(
                    "        <service name=\"{}\" product=\"{}\" version=\"{}\" extrainfo=\"{}\" method=\"probed\" conf=\"{}\" />\n",
                    service,
                    xml_escape(product),
                    xml_escape(version),
                    xml_escape(extra_info),
                    result.service_info.as_ref().map(|si| si.confidence).unwrap_or(80),
                ));
            }

            xml.push_str("      </port>\n");
        }

        // Closed ports summary
        let closed_count = target_results.iter().filter(|r| r.state == PortState::Closed).count();
        let filtered_count = target_results.iter().filter(|r| r.state == PortState::Filtered).count();
        xml.push_str(&format!(
            "      <extraports count=\"{}\" state=\"closed\">\n        <extrareasons reason=\"resets\" count=\"{}\" />\n      </extraports>\n",
            closed_count + filtered_count,
            closed_count,
        ));

        xml.push_str("    </ports>\n");

        // OS detection results
        if !results.os_fingerprints.is_empty() {
            xml.push_str("    <os>\n");
            for os_fp in &results.os_fingerprints {
                if let Some(ref family) = os_fp.os_family {
                    let family_str = format!("{:?}", family);
                    xml.push_str(&format!(
                        "      <osmatch name=\"{}\" accuracy=\"{}\" line=\"0\">\n",
                        family_str,
                        os_fp.confidence,
                    ));
                    xml.push_str(&format!(
                        "        <osclass type=\"general purpose\" vendor=\"{}\" osfamily=\"{}\" osgen=\"{}\" accuracy=\"{}\" />\n",
                        family_str,
                        family_str,
                        "",
                        os_fp.confidence,
                    ));
                    xml.push_str("      </osmatch>\n");
                }
            }
            xml.push_str("    </os>\n");
        }

        xml.push_str("  </host>\n");
    }

    // Run statistics
    let _open_count = results.results.iter().filter(|r| r.state == PortState::Open).count();
    let _total_count = results.results.len();
    xml.push_str(&format!(
        "  <runstats>\n    <finished time=\"{}\" timestr=\"{}\" elapsed=\"{}\" summary=\"Nemue done at {}; {} IP addresses ({} hosts) scanned in {} seconds\" exit=\"success\" />\n    <hosts up=\"{}\" down=\"0\" total=\"{}\" />\n  </runstats>\n",
        results.scan_end.timestamp(),
        results.scan_end.format("%a %b %d %H:%M:%S %Y"),
        (results.scan_end - results.scan_start).num_seconds(),
        results.scan_end.format("%Y-%m-%d %H:%M %Z"),
        results.target_count,
        results.target_count,
        (results.scan_end - results.scan_start).num_seconds(),
        results.target_count,
        results.target_count,
    ));

    xml.push_str("</nmaprun>\n");
    Ok(xml)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ScanResult, ScanResults, Protocol, PortState};
    use chrono::Utc;
    use std::net::IpAddr;

    fn create_test_results() -> ScanResults {
        ScanResults {
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 1,
            port_count: 3,
            results: vec![
                ScanResult {
                    target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                    port: 22,
                    state: PortState::Open,
                    protocol: Protocol::TCP,
                    service: Some("ssh".to_string()),
                    service_info: None,
                    hostname: None,
                    reason: Some("syn-ack".to_string()),
                    timestamp: Utc::now(),
                },
                ScanResult {
                    target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                    port: 80,
                    state: PortState::Open,
                    protocol: Protocol::TCP,
                    service: Some("http".to_string()),
                    service_info: None,
                    hostname: None,
                    reason: Some("syn-ack".to_string()),
                    timestamp: Utc::now(),
                },
                ScanResult {
                    target: "192.168.1.1".parse::<IpAddr>().unwrap(),
                    port: 443,
                    state: PortState::Closed,
                    protocol: Protocol::TCP,
                    service: None,
                    service_info: None,
                    hostname: None,
                    reason: Some("reset".to_string()),
                    timestamp: Utc::now(),
                },
            ],
            os_fingerprints: Vec::new(),
            script_results: Vec::new(),
        }
    }

    #[test]
    fn test_nmap_xml_format() {
        let results = create_test_results();
        let xml = format(&results).unwrap();

        // Check Nmap-compatible structure
        assert!(xml.contains("<!DOCTYPE nmaprun>"));
        assert!(xml.contains("<nmaprun scanner=\"nemue\""));
        assert!(xml.contains("<scaninfo type=\"connect\""));
        assert!(xml.contains("<host starttime="));
        assert!(xml.contains("<status state=\"up\""));
        assert!(xml.contains("<address addr=\"192.168.1.1\""));
        assert!(xml.contains("<port protocol=\"tcp\" portid=\"22\">"));
        assert!(xml.contains("<state state=\"open\""));
        assert!(xml.contains("<service name=\"ssh\""));
        assert!(xml.contains("<runstats>"));
        assert!(xml.contains("</nmaprun>"));
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("test&amp;test"), "test&amp;amp;test");
        assert_eq!(xml_escape("<b>bold</b>"), "&lt;b&gt;bold&lt;/b&gt;");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_xml_with_os_detection() {
        let mut results = create_test_results();
        results.os_fingerprints.push(crate::fingerprint::OsFingerprint {
            target: "192.168.1.1".parse().unwrap(),
            os_family: Some(crate::fingerprint::OsFamily::Linux),
            os_version: Some("5.15".to_string()),
            confidence: 85,
            ttl: Some(64),
            window_size: Some(65535),
            tcp_options: Vec::new(),
            tcp_timestamp: None,
            ip_id_sequence: None,
            window_scaling: None,
            max_segment_size: None,
            details: String::new(),
        });

        let xml = format(&results).unwrap();
        assert!(xml.contains("<os>"));
        assert!(xml.contains("<osmatch name=\"Linux\""));
        assert!(xml.contains("accuracy=\"85\""));
    }
}
