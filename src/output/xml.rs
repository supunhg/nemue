use anyhow::Result;
use crate::scanner::{ScanResults, PortState};

pub fn format(results: &ScanResults) -> Result<String> {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<nemuescan>\n");
    
    // Scan info
    xml.push_str(&format!(
        "  <scaninfo starttime=\"{}\" endtime=\"{}\" targets=\"{}\" ports=\"{}\" />\n",
        results.scan_start.to_rfc3339(),
        results.scan_end.to_rfc3339(),
        results.target_count,
        results.port_count
    ));

    // Group results by target
    let mut targets: std::collections::HashMap<std::net::IpAddr, Vec<&crate::scanner::ScanResult>> = 
        std::collections::HashMap::new();
    
    for result in &results.results {
        targets.entry(result.target).or_insert_with(Vec::new).push(result);
    }

    // Output each target
    for (target, target_results) in targets {
        xml.push_str(&format!("  <host addr=\"{}\">\n", target));
        xml.push_str("    <ports>\n");
        
        for result in target_results {
            let state = match result.state {
                PortState::Open => "open",
                PortState::Closed => "closed",
                PortState::Filtered => "filtered",
                PortState::Unfiltered => "unfiltered",
                PortState::OpenFiltered => "open|filtered",
                PortState::Unknown => "unknown",
            };
            
            let service = result.service.as_ref().map(|s| s.as_str()).unwrap_or("unknown");
            
            xml.push_str(&format!(
                "      <port protocol=\"{:?}\" portid=\"{}\">\n",
                result.protocol, result.port
            ));
            xml.push_str(&format!("        <state state=\"{}\" />\n", state));
            xml.push_str(&format!("        <service name=\"{}\" />\n", service));
            xml.push_str("      </port>\n");
        }
        
        xml.push_str("    </ports>\n");
        xml.push_str("  </host>\n");
    }

    xml.push_str("</nemuescan>\n");
    Ok(xml)
}
