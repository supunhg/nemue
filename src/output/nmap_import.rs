#![allow(dead_code)]
// Nmap XML import module
// Parses Nmap XML output and converts to Nemue format

use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::path::Path;

use crate::scanner::{PortState, Protocol, ScanResult, ScanResults};

/// Nmap XML root element
#[derive(Debug, Deserialize)]
struct NmapRun {
    #[serde(rename = "host", default)]
    hosts: Vec<NmapHost>,
    #[serde(rename = "runstats")]
    runstats: Option<NmapRunstats>,
}

/// Nmap host element
#[derive(Debug, Deserialize)]
struct NmapHost {
    #[serde(rename = "address")]
    addresses: Vec<NmapAddress>,
    #[serde(rename = "ports")]
    ports: Option<NmapPorts>,
    #[serde(rename = "status")]
    status: Option<NmapStatus>,
}

/// Nmap address element
#[derive(Debug, Deserialize)]
struct NmapAddress {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype")]
    addrtype: Option<String>,
}

/// Nmap status element
#[derive(Debug, Deserialize)]
struct NmapStatus {
    #[serde(rename = "@state")]
    state: String,
}

/// Nmap ports element
#[derive(Debug, Deserialize)]
struct NmapPorts {
    #[serde(rename = "port", default)]
    ports: Vec<NmapPort>,
}

/// Nmap port element
#[derive(Debug, Deserialize)]
struct NmapPort {
    #[serde(rename = "@protocol")]
    protocol: String,
    #[serde(rename = "@portid")]
    portid: String,
    #[serde(rename = "state")]
    state: NmapPortState,
    #[serde(rename = "service")]
    service: Option<NmapService>,
}

/// Nmap port state element
#[derive(Debug, Deserialize)]
struct NmapPortState {
    #[serde(rename = "@state")]
    state: String,
    #[serde(rename = "@reason")]
    reason: Option<String>,
}

/// Nmap service element
#[derive(Debug, Deserialize)]
struct NmapService {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@product")]
    product: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
    #[serde(rename = "@extrainfo")]
    extrainfo: Option<String>,
}

/// Nmap runstats element
#[derive(Debug, Deserialize)]
struct NmapRunstats {
    #[serde(rename = "finished")]
    finished: Option<NmapFinished>,
}

/// Nmap finished element
#[derive(Debug, Deserialize)]
struct NmapFinished {
    #[serde(rename = "@time")]
    time: Option<String>,
    #[serde(rename = "@elapsed")]
    elapsed: Option<String>,
}

/// Import Nmap XML file and convert to Nemue format
pub fn import_nmap_xml<P: AsRef<Path>>(path: P) -> Result<ScanResults> {
    let contents = std::fs::read_to_string(path)?;
    import_nmap_xml_str(&contents)
}

/// Import Nmap XML string and convert to Nemue format
pub fn import_nmap_xml_str(xml: &str) -> Result<ScanResults> {
    let nmap_run: NmapRun =
        quick_xml::de::from_str(xml).map_err(|e| anyhow!("Failed to parse Nmap XML: {}", e))?;

    let mut results = Vec::new();
    let mut target_count = 0;

    for host in &nmap_run.hosts {
        target_count += 1;

        // Get host IP
        let host_ip = host
            .addresses
            .first()
            .map(|a| a.addr.clone())
            .unwrap_or_default();

        // Parse ports
        if let Some(ref ports) = host.ports {
            for port in &ports.ports {
                let port_num: u16 = port.portid.parse().unwrap_or(0);

                let state = match port.state.state.as_str() {
                    "open" => PortState::Open,
                    "closed" => PortState::Closed,
                    "filtered" => PortState::Filtered,
                    "unfiltered" => PortState::Unfiltered,
                    "open|filtered" => PortState::OpenFiltered,
                    _ => PortState::Unknown,
                };

                let protocol = match port.protocol.as_str() {
                    "tcp" => Protocol::TCP,
                    "udp" => Protocol::UDP,
                    _ => Protocol::TCP,
                };

                let service = port.service.as_ref().map(|s| s.name.clone());
                let service_info = port.service.as_ref().map(|s| crate::service::ServiceInfo {
                    port: port_num,
                    protocol: port.protocol.clone(),
                    service: s.name.clone(),
                    product: s.product.clone(),
                    version: s.version.clone(),
                    extra_info: s.extrainfo.clone(),
                    banner: None,
                    confidence: 80,
                    service_family: None,
                    os_hint: None,
                    cpe: None,
                });

                results.push(ScanResult {
                    target: host_ip
                        .parse()
                        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
                    port: port_num,
                    state,
                    protocol,
                    service,
                    service_info,
                    hostname: None,
                    reason: port.state.reason.clone(),
                    timestamp: chrono::Utc::now(),
                });
            }
        }
    }

    let port_count = results.len();

    Ok(ScanResults {
        scan_start: chrono::Utc::now(),
        scan_end: chrono::Utc::now(),
        target_count,
        port_count,
        results,
        os_fingerprints: Vec::new(),
        script_results: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_basic_nmap_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" start="1234567890" startstr="Tue Feb 10 2009" version="7.95" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
  <host starttime="1234567890" endtime="1234567891">
    <status state="up" reason="syn-ack" reason_ttl="0"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="http" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset" reason_ttl="64"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1234567891" timestr="Tue Feb 10 2009" elapsed="1" summary="Nmap done" exit="success"/>
    <hosts up="1" down="0" total="1"/>
  </runstats>
</nmaprun>"#;

        let results = import_nmap_xml_str(xml).unwrap();
        assert_eq!(results.target_count, 1);
        assert_eq!(results.port_count, 3);
        assert_eq!(results.results.len(), 3);

        // Check port 22
        let port22 = results.results.iter().find(|r| r.port == 22).unwrap();
        assert_eq!(port22.state, PortState::Open);
        assert_eq!(port22.service, Some("ssh".to_string()));

        // Check port 80
        let port80 = results.results.iter().find(|r| r.port == 80).unwrap();
        assert_eq!(port80.state, PortState::Open);
        assert_eq!(port80.service, Some("http".to_string()));

        // Check port 443
        let port443 = results.results.iter().find(|r| r.port == 443).unwrap();
        assert_eq!(port443.state, PortState::Closed);
    }

    #[test]
    fn test_import_empty_hosts() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap" start="0" startstr="test" version="7.95" xmloutputversion="1.05">
  <scaninfo type="syn" protocol="tcp" numservices="0" services=""/>
  <runstats>
    <finished time="0" timestr="test" elapsed="0" summary="Nmap done" exit="success"/>
    <hosts up="0" down="0" total="0"/>
  </runstats>
</nmaprun>"#;

        let results = import_nmap_xml_str(xml).unwrap();
        assert_eq!(results.target_count, 0);
        assert_eq!(results.port_count, 0);
    }
}
