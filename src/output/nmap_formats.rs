use anyhow::Result;
use crate::scanner::{ScanResults, ScanResult};
use std::collections::HashMap;
use std::fmt::Write;

/// Output format types matching nmap
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NmapOutputFormat {
    /// Normal output (-oN)
    Normal,
    /// Grepable output (-oG)
    Grepable,
    /// XML output (-oX)
    Xml,
    /// JSON output (Nemue default)
    Json,
    /// All formats (-oA)
    All,
}

impl NmapOutputFormat {
    pub fn from_flag(flag: &str) -> Option<Self> {
        match flag {
            "-oN" | "normal" => Some(NmapOutputFormat::Normal),
            "-oG" | "grepable" | "grep" => Some(NmapOutputFormat::Grepable),
            "-oX" | "xml" => Some(NmapOutputFormat::Xml),
            "-oJ" | "json" => Some(NmapOutputFormat::Json),
            "-oA" | "all" => Some(NmapOutputFormat::All),
            _ => None,
        }
    }

    pub fn extension(&self) -> &str {
        match self {
            NmapOutputFormat::Normal => ".nmap",
            NmapOutputFormat::Grepable => ".gnmap",
            NmapOutputFormat::Xml => ".xml",
            NmapOutputFormat::Json => ".json",
            NmapOutputFormat::All => "",
        }
    }
}

/// Normal output formatter (nmap -oN)
pub struct NormalOutputFormatter;

impl NormalOutputFormatter {
    pub fn format(results: &ScanResults) -> Result<String> {
        let mut output = String::new();
        
        // Header
        writeln!(output, "# Nemue scan report")?;
        writeln!(output, "# Scan started at: {}", results.scan_start)?;
        writeln!(output, "# Scan finished at: {}", results.scan_end)?;
        writeln!(output)?;

        // Group results by target
        let mut by_target: HashMap<std::net::IpAddr, Vec<&ScanResult>> = HashMap::new();
        for result in &results.results {
            by_target.entry(result.target).or_insert_with(Vec::new).push(result);
        }

        // Output each target
        for (target, ports) in by_target.iter() {
            writeln!(output, "Nmap scan report for {}", target)?;
            writeln!(output, "Host is up.")?;
            
            if !ports.is_empty() {
                writeln!(output, "PORT      STATE  SERVICE")?;
                
                for port in ports {
                    let service = port.service.as_deref().unwrap_or("unknown");
                    writeln!(
                        output,
                        "{}/{}    {}  {}",
                        port.port,
                        port.protocol.to_string().to_lowercase(),
                        format_state(&port.state),
                        service
                    )?;
                }
            }
            writeln!(output)?;
        }

        // Summary
        writeln!(output, "# Nemue done: {} IP address(es) ({} host(s) up) scanned",
                 results.target_count,
                 by_target.len())?;

        Ok(output)
    }
}

/// Grepable output formatter (nmap -oG)
pub struct GrepableOutputFormatter;

impl GrepableOutputFormatter {
    pub fn format(results: &ScanResults) -> Result<String> {
        let mut output = String::new();
        
        // Header
        writeln!(output, "# Nemue grepable output")?;
        writeln!(output, "# Started {}", results.scan_start)?;
        writeln!(output, "# Ended {}", results.scan_end)?;

        // Group by target
        let mut by_target: HashMap<std::net::IpAddr, Vec<&ScanResult>> = HashMap::new();
        for result in &results.results {
            by_target.entry(result.target).or_insert_with(Vec::new).push(result);
        }

        // Output each host in grepable format
        for (target, ports) in by_target.iter() {
            write!(output, "Host: {} ()", target)?;
            write!(output, "\tStatus: Up")?;
            
            if !ports.is_empty() {
                write!(output, "\tPorts: ")?;
                
                let port_strings: Vec<String> = ports.iter().map(|p| {
                    format!(
                        "{}/{}/{}/{}/{}/{}",
                        p.port,
                        format_state(&p.state),
                        p.protocol.to_string().to_lowercase(),
                        "",  // owner (empty)
                        p.service.as_deref().unwrap_or(""),
                        ""   // version (empty for now)
                    )
                }).collect();
                
                write!(output, "{}", port_strings.join(", "))?;
            }
            
            writeln!(output)?;
        }

        writeln!(output, "# Nemue done at {}", results.scan_end)?;

        Ok(output)
    }
}

/// Output with port state reasons (--reason flag)
pub struct ReasonOutputFormatter;

impl ReasonOutputFormatter {
    pub fn format(results: &ScanResults, reason: &str) -> Result<String> {
        let mut output = String::new();
        
        writeln!(output, "# Nemue scan with reason codes")?;
        writeln!(output, "# Scan started: {}", results.scan_start)?;
        writeln!(output)?;

        let mut by_target: HashMap<std::net::IpAddr, Vec<&ScanResult>> = HashMap::new();
        for result in &results.results {
            by_target.entry(result.target).or_insert_with(Vec::new).push(result);
        }

        for (target, ports) in by_target.iter() {
            writeln!(output, "Scan report for {}", target)?;
            writeln!(output, "PORT      STATE  SERVICE    REASON")?;
            
            for port in ports {
                let service = port.service.as_deref().unwrap_or("unknown");
                writeln!(
                    output,
                    "{}/{}    {}  {:10} {}",
                    port.port,
                    port.protocol.to_string().to_lowercase(),
                    format_state(&port.state),
                    service,
                    reason
                )?;
            }
            writeln!(output)?;
        }

        Ok(output)
    }
}

/// Statistics output formatter (--stats-every)
#[derive(Debug, Clone)]
pub struct ScanStatistics {
    pub elapsed_seconds: u64,
    pub targets_completed: usize,
    pub targets_remaining: usize,
    pub ports_scanned: usize,
    pub scan_rate: f64, // ports per second
}

impl ScanStatistics {
    pub fn new(
        elapsed: u64,
        completed: usize,
        remaining: usize,
        ports: usize,
    ) -> Self {
        let scan_rate = if elapsed > 0 {
            ports as f64 / elapsed as f64
        } else {
            0.0
        };

        Self {
            elapsed_seconds: elapsed,
            targets_completed: completed,
            targets_remaining: remaining,
            ports_scanned: ports,
            scan_rate,
        }
    }

    pub fn format(&self) -> String {
        format!(
            "Stats: {:.2}s elapsed; {} hosts completed ({} remaining), {:.2} ports/s",
            self.elapsed_seconds,
            self.targets_completed,
            self.targets_remaining,
            self.scan_rate
        )
    }

    pub fn format_verbose(&self) -> String {
        format!(
            "Statistics:\n\
             \tElapsed: {}s\n\
             \tTargets completed: {}\n\
             \tTargets remaining: {}\n\
             \tPorts scanned: {}\n\
             \tScan rate: {:.2} ports/sec",
            self.elapsed_seconds,
            self.targets_completed,
            self.targets_remaining,
            self.ports_scanned,
            self.scan_rate
        )
    }
}

/// Helper to format port state consistently
fn format_state(state: &crate::scanner::PortState) -> String {
    match state {
        crate::scanner::PortState::Open => "open".to_string(),
        crate::scanner::PortState::Closed => "closed".to_string(),
        crate::scanner::PortState::Filtered => "filtered".to_string(),
        crate::scanner::PortState::Unfiltered => "unfiltered".to_string(),
        crate::scanner::PortState::OpenFiltered => "open|filtered".to_string(),
        crate::scanner::PortState::Unknown => "unknown".to_string(),
    }
}

/// Output manager for handling multiple formats simultaneously (-oA)
pub struct OutputManager {
    base_filename: Option<String>,
    formats: Vec<NmapOutputFormat>,
    include_reason: bool,
    stats_interval: Option<std::time::Duration>,
}

impl OutputManager {
    pub fn new() -> Self {
        Self {
            base_filename: None,
            formats: Vec::new(),
            include_reason: false,
            stats_interval: None,
        }
    }

    pub fn with_format(mut self, format: NmapOutputFormat) -> Self {
        self.formats.push(format);
        self
    }

    pub fn with_output_file(mut self, filename: String) -> Self {
        self.base_filename = Some(filename);
        self
    }

    pub fn with_reason(mut self) -> Self {
        self.include_reason = true;
        self
    }

    pub fn with_stats_interval(mut self, interval: std::time::Duration) -> Self {
        self.stats_interval = Some(interval);
        self
    }

    pub fn format_results(&self, results: &ScanResults) -> Result<Vec<(NmapOutputFormat, String)>> {
        let mut outputs = Vec::new();

        for format in &self.formats {
            let content = match format {
                NmapOutputFormat::Normal => NormalOutputFormatter::format(results)?,
                NmapOutputFormat::Grepable => GrepableOutputFormatter::format(results)?,
                NmapOutputFormat::Xml => {
                    // Use existing XML formatter
                    crate::output::xml::format(results)?
                }
                NmapOutputFormat::Json => {
                    // Use existing JSON formatter
                    crate::output::json::format(results)?
                }
                NmapOutputFormat::All => {
                    // All format handled separately
                    continue;
                }
            };

            outputs.push((*format, content));
        }

        Ok(outputs)
    }

    pub fn write_results(&self, results: &ScanResults) -> Result<()> {
        let outputs = self.format_results(results)?;

        for (format, content) in outputs {
            if let Some(base) = &self.base_filename {
                let filename = format!("{}{}", base, format.extension());
                std::fs::write(&filename, content)?;
                eprintln!("Output written to: {}", filename);
            } else {
                // Print to stdout if no filename
                println!("{}", content);
            }
        }

        Ok(())
    }
}

impl Default for OutputManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{ScanResults, ScanResult, PortState, Protocol};
    use chrono::Utc;

    fn create_test_results() -> ScanResults {
        let now = Utc::now();
        ScanResults {
            scan_start: now,
            scan_end: now,
            target_count: 1,
            port_count: 2,
            results: vec![
                ScanResult {
                    target: "192.168.1.1".parse().unwrap(),
                    port: 80,
                    state: PortState::Open,
                    protocol: Protocol::TCP,
                    service: Some("http".to_string()),
                    service_info: None,
                    timestamp: now,
                },
                ScanResult {
                    target: "192.168.1.1".parse().unwrap(),
                    port: 443,
                    state: PortState::Open,
                    protocol: Protocol::TCP,
                    service: Some("https".to_string()),
                    service_info: None,
                    timestamp: now,
                },
            ],
            os_fingerprints: Vec::new(),
        }
    }

    #[test]
    fn test_output_format_from_flag() {
        assert_eq!(NmapOutputFormat::from_flag("-oN"), Some(NmapOutputFormat::Normal));
        assert_eq!(NmapOutputFormat::from_flag("-oG"), Some(NmapOutputFormat::Grepable));
        assert_eq!(NmapOutputFormat::from_flag("-oX"), Some(NmapOutputFormat::Xml));
        assert_eq!(NmapOutputFormat::from_flag("-oA"), Some(NmapOutputFormat::All));
        assert_eq!(NmapOutputFormat::from_flag("invalid"), None);
    }

    #[test]
    fn test_output_format_extension() {
        assert_eq!(NmapOutputFormat::Normal.extension(), ".nmap");
        assert_eq!(NmapOutputFormat::Grepable.extension(), ".gnmap");
        assert_eq!(NmapOutputFormat::Xml.extension(), ".xml");
        assert_eq!(NmapOutputFormat::Json.extension(), ".json");
    }

    #[test]
    fn test_normal_output() {
        let results = create_test_results();
        let output = NormalOutputFormatter::format(&results).unwrap();
        
        assert!(output.contains("Nmap scan report"));
        assert!(output.contains("192.168.1.1"));
        assert!(output.contains("80/tcp"));
        assert!(output.contains("443/tcp"));
        assert!(output.contains("http"));
        assert!(output.contains("https"));
    }

    #[test]
    fn test_grepable_output() {
        let results = create_test_results();
        let output = GrepableOutputFormatter::format(&results).unwrap();
        
        assert!(output.contains("Host: 192.168.1.1"));
        assert!(output.contains("Status: Up"));
        assert!(output.contains("Ports:"));
        assert!(output.contains("80/open/tcp"));
        assert!(output.contains("443/open/tcp"));
    }

    #[test]
    fn test_reason_output() {
        let results = create_test_results();
        let output = ReasonOutputFormatter::format(&results, "syn-ack").unwrap();
        
        assert!(output.contains("REASON"));
        assert!(output.contains("syn-ack"));
        assert!(output.contains("192.168.1.1"));
    }

    #[test]
    fn test_scan_statistics() {
        let stats = ScanStatistics::new(10, 5, 15, 100);
        
        assert_eq!(stats.elapsed_seconds, 10);
        assert_eq!(stats.targets_completed, 5);
        assert_eq!(stats.targets_remaining, 15);
        assert_eq!(stats.ports_scanned, 100);
        assert_eq!(stats.scan_rate, 10.0);
        
        let formatted = stats.format();
        assert!(formatted.contains("10s") || formatted.contains("10.00s"));
        assert!(formatted.contains("5 hosts"));
        assert!(formatted.contains("10.00 ports/s"));
    }

    #[test]
    fn test_scan_statistics_verbose() {
        let stats = ScanStatistics::new(30, 10, 5, 300);
        let verbose = stats.format_verbose();
        
        assert!(verbose.contains("Elapsed: 30s"));
        assert!(verbose.contains("Targets completed: 10"));
        assert!(verbose.contains("Scan rate: 10.00"));
    }

    #[test]
    fn test_output_manager() {
        let manager = OutputManager::new()
            .with_format(NmapOutputFormat::Normal)
            .with_reason();
        
        assert_eq!(manager.formats.len(), 1);
        assert!(manager.include_reason);
    }

    #[test]
    fn test_output_manager_format_results() {
        let results = create_test_results();
        let manager = OutputManager::new()
            .with_format(NmapOutputFormat::Normal)
            .with_format(NmapOutputFormat::Grepable);
        
        let outputs = manager.format_results(&results).unwrap();
        assert_eq!(outputs.len(), 2);
        
        assert_eq!(outputs[0].0, NmapOutputFormat::Normal);
        assert_eq!(outputs[1].0, NmapOutputFormat::Grepable);
    }
}
