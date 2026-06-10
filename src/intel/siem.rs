use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Supported SIEM output formats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SiemFormat {
    /// Common Event Format (ArcSight)
    Cef,
    /// Log Event Extended Format (IBM QRadar)
    Leef,
    /// Raw JSON
    Json,
    /// Syslog (RFC 5424)
    Syslog,
}

/// SIEM integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    pub format: SiemFormat,
    /// Syslog server address (host:port) for syslog output
    #[serde(default)]
    pub syslog_addr: Option<String>,
    /// ElasticSearch URL for ES integration
    #[serde(default)]
    pub elasticsearch_url: Option<String>,
    /// ElasticSearch index name
    #[serde(default)]
    pub elasticsearch_index: Option<String>,
    /// HTTP endpoint for generic SIEM ingestion
    #[serde(default)]
    pub http_endpoint: Option<String>,
    /// Auth token for SIEM endpoint
    #[serde(default)]
    pub auth_token: Option<String>,
}

/// Severity mapping for SIEM events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SiemSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl SiemSeverity {
    pub fn from_risk_score(score: u8) -> Self {
        match score {
            0..=25 => SiemSeverity::Low,
            26..=50 => SiemSeverity::Medium,
            51..=75 => SiemSeverity::High,
            _ => SiemSeverity::Critical,
        }
    }

    pub fn to_syslog_severity(&self) -> u8 {
        match self {
            SiemSeverity::Low => 5,      // Notice
            SiemSeverity::Medium => 4,   // Warning
            SiemSeverity::High => 3,     // Error
            SiemSeverity::Critical => 2, // Critical
        }
    }
}

/// SIEM event representing a scan finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    pub event_type: String,
    pub scan_id: String,
    pub timestamp: String,
    pub severity: SiemSeverity,
    pub source_ip: Option<String>,
    pub target: String,
    pub port: Option<u16>,
    pub protocol: Option<String>,
    pub service: Option<String>,
    pub vulnerability_id: Option<String>,
    pub vulnerability_description: Option<String>,
    pub risk_score: u8,
    pub open_ports: usize,
    pub total_vulnerabilities: usize,
    pub message: String,
}

/// SIEM client for forwarding scan results
pub struct SiemClient {
    http_client: reqwest::Client,
}

impl SiemClient {
    pub fn new() -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        Self { http_client }
    }

    /// Format a SIEM event according to the configured format
    pub fn format_event(&self, event: &SiemEvent, format: &SiemFormat) -> String {
        match format {
            SiemFormat::Cef => self.to_cef(event),
            SiemFormat::Leef => self.to_leef(event),
            SiemFormat::Json => self.to_json(event),
            SiemFormat::Syslog => self.to_syslog(event),
        }
    }

    /// Send event to ElasticSearch
    pub async fn send_to_elasticsearch(
        &self,
        config: &SiemConfig,
        event: &SiemEvent,
    ) -> Result<()> {
        let url = config
            .elasticsearch_url
            .as_ref()
            .context("ElasticSearch URL not configured")?;
        let index = config
            .elasticsearch_index
            .as_deref()
            .unwrap_or("nemue-scans");

        let full_url = format!("{}/{}/_doc", url.trim_end_matches('/'), index);

        let mut req = self
            .http_client
            .post(&full_url)
            .header("Content-Type", "application/json")
            .json(event);

        if let Some(ref token) = config.auth_token {
            req = req.bearer_auth(token);
        }

        let resp = req
            .send()
            .await
            .context("Failed to send to ElasticSearch")?;

        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "ElasticSearch returned status: {}",
                resp.status()
            ));
        }

        Ok(())
    }

    /// Send event to a generic HTTP SIEM endpoint
    pub async fn send_to_http_endpoint(&self, config: &SiemConfig, payload: &str) -> Result<()> {
        let url = config
            .http_endpoint
            .as_ref()
            .context("HTTP endpoint not configured")?;

        let mut req = self
            .http_client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload.to_string());

        if let Some(ref token) = config.auth_token {
            req = req.bearer_auth(token);
        }

        let resp = req
            .send()
            .await
            .context("Failed to send to SIEM endpoint")?;

        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "SIEM endpoint returned status: {}",
                resp.status()
            ));
        }

        Ok(())
    }

    fn to_cef(&self, event: &SiemEvent) -> String {
        let severity_num = match event.severity {
            SiemSeverity::Low => 3,
            SiemSeverity::Medium => 5,
            SiemSeverity::High => 8,
            SiemSeverity::Critical => 10,
        };

        let mut extensions = Vec::new();
        extensions.push(format!("src={}", event.target));
        if let Some(port) = event.port {
            extensions.push(format!("dstPort={}", port));
        }
        if let Some(ref proto) = event.protocol {
            extensions.push(format!("transportProtocol={}", proto));
        }
        if let Some(ref svc) = event.service {
            extensions.push(format!("deviceService={}", svc));
        }
        extensions.push(format!("flexNumber1={}", event.risk_score));
        extensions.push(format!("flexString1={}", event.scan_id));
        if let Some(ref vuln_id) = event.vulnerability_id {
            extensions.push(format!("externalId={}", vuln_id));
        }

        format!(
            "CEF:0|Nemue|Nemue Security Scanner|1.0|{}|{}|{}|{}",
            event.event_type,
            event.message.replace('|', "\\|"),
            severity_num,
            extensions.join(" ")
        )
    }

    fn to_leef(&self, event: &SiemEvent) -> String {
        let severity_num = match event.severity {
            SiemSeverity::Low => 1,
            SiemSeverity::Medium => 3,
            SiemSeverity::High => 7,
            SiemSeverity::Critical => 10,
        };

        let mut attrs = Vec::new();
        attrs.push(format!("devTime={}", event.timestamp));
        attrs.push(format!("src={}", event.target));
        if let Some(port) = event.port {
            attrs.push(format!("dstPort={}", port));
        }
        attrs.push(format!("severity={}", severity_num));
        attrs.push(format!("scanId={}", event.scan_id));
        attrs.push(format!("riskScore={}", event.risk_score));
        attrs.push(format!("openPorts={}", event.open_ports));
        attrs.push(format!("vulnerabilities={}", event.total_vulnerabilities));
        if let Some(ref vuln_id) = event.vulnerability_id {
            attrs.push(format!("vulnId={}", vuln_id));
        }

        format!(
            "LEEF:2.0|Nemue|Security Scanner|1.0|{}|{}",
            event.event_type,
            attrs.join("\t")
        )
    }

    fn to_json(&self, event: &SiemEvent) -> String {
        serde_json::to_string(event).unwrap_or_default()
    }

    fn to_syslog(&self, event: &SiemEvent) -> String {
        let facility = 1; // user-level
        let severity = event.severity.to_syslog_severity();
        let priority = facility * 8 + severity;

        let timestamp = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "nemue".to_string());

        format!(
            "<{}>1 {} {} nemue - - - {}",
            priority, timestamp, hostname, event.message
        )
    }
}

impl Default for SiemClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Hostname helper (avoids external dep in test)
mod hostname {
    use std::ffi::OsString;

    pub fn get() -> Result<OsString, std::io::Error> {
        #[cfg(unix)]
        {
            Ok(OsString::from("nemue-host"))
        }
        #[cfg(not(unix))]
        {
            Ok(OsString::from("nemue-host"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> SiemEvent {
        SiemEvent {
            event_type: "scan_completed".to_string(),
            scan_id: "test-scan-001".to_string(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            severity: SiemSeverity::High,
            source_ip: Some("10.0.0.1".to_string()),
            target: "192.168.1.1".to_string(),
            port: Some(443),
            protocol: Some("TCP".to_string()),
            service: Some("https".to_string()),
            vulnerability_id: Some("CVE-2024-1234".to_string()),
            vulnerability_description: Some("Test vulnerability".to_string()),
            risk_score: 75,
            open_ports: 5,
            total_vulnerabilities: 2,
            message: "Scan completed: 2 vulnerabilities found on 192.168.1.1".to_string(),
        }
    }

    #[test]
    fn test_cef_format() {
        let client = SiemClient::new();
        let event = sample_event();
        let cef = client.format_event(&event, &SiemFormat::Cef);

        assert!(cef.starts_with("CEF:0|Nemue|"));
        assert!(cef.contains("src=192.168.1.1"));
        assert!(cef.contains("dstPort=443"));
        assert!(cef.contains("transportProtocol=TCP"));
        assert!(cef.contains("externalId=CVE-2024-1234"));
    }

    #[test]
    fn test_leef_format() {
        let client = SiemClient::new();
        let event = sample_event();
        let leef = client.format_event(&event, &SiemFormat::Leef);

        assert!(leef.starts_with("LEEF:2.0|Nemue|"));
        assert!(leef.contains("src=192.168.1.1"));
        assert!(leef.contains("dstPort=443"));
        assert!(leef.contains("scanId=test-scan-001"));
        assert!(leef.contains("vulnId=CVE-2024-1234"));
    }

    #[test]
    fn test_json_format() {
        let client = SiemClient::new();
        let event = sample_event();
        let json_str = client.format_event(&event, &SiemFormat::Json);

        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["scan_id"], "test-scan-001");
        assert_eq!(parsed["risk_score"], 75);
        assert_eq!(parsed["total_vulnerabilities"], 2);
    }

    #[test]
    fn test_syslog_format() {
        let client = SiemClient::new();
        let event = sample_event();
        let syslog = client.format_event(&event, &SiemFormat::Syslog);

        assert!(syslog.starts_with('<'));
        assert!(syslog.contains("nemue"));
        assert!(syslog.contains("2 vulnerabilities found"));
    }

    #[test]
    fn test_severity_from_risk_score() {
        assert_eq!(SiemSeverity::from_risk_score(10), SiemSeverity::Low);
        assert_eq!(SiemSeverity::from_risk_score(30), SiemSeverity::Medium);
        assert_eq!(SiemSeverity::from_risk_score(60), SiemSeverity::High);
        assert_eq!(SiemSeverity::from_risk_score(90), SiemSeverity::Critical);
    }

    #[test]
    fn test_syslog_severity_mapping() {
        assert_eq!(SiemSeverity::Low.to_syslog_severity(), 5);
        assert_eq!(SiemSeverity::Medium.to_syslog_severity(), 4);
        assert_eq!(SiemSeverity::High.to_syslog_severity(), 3);
        assert_eq!(SiemSeverity::Critical.to_syslog_severity(), 2);
    }

    #[test]
    fn test_siem_format_serialization() {
        assert_eq!(serde_json::to_string(&SiemFormat::Cef).unwrap(), "\"cef\"");
        assert_eq!(
            serde_json::to_string(&SiemFormat::Leef).unwrap(),
            "\"leef\""
        );
        assert_eq!(
            serde_json::to_string(&SiemFormat::Json).unwrap(),
            "\"json\""
        );
        assert_eq!(
            serde_json::to_string(&SiemFormat::Syslog).unwrap(),
            "\"syslog\""
        );
    }

    #[test]
    fn test_siem_config_serialization() {
        let config = SiemConfig {
            format: SiemFormat::Json,
            syslog_addr: None,
            elasticsearch_url: Some("http://localhost:9200".to_string()),
            elasticsearch_index: Some("nemue-test".to_string()),
            http_endpoint: None,
            auth_token: Some("token123".to_string()),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SiemConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.format, SiemFormat::Json);
        assert_eq!(
            deserialized.elasticsearch_url.unwrap(),
            "http://localhost:9200"
        );
    }

    #[test]
    fn test_cef_with_missing_optional_fields() {
        let client = SiemClient::new();
        let event = SiemEvent {
            event_type: "scan_started".to_string(),
            scan_id: "scan-min".to_string(),
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            severity: SiemSeverity::Low,
            source_ip: None,
            target: "10.0.0.1".to_string(),
            port: None,
            protocol: None,
            service: None,
            vulnerability_id: None,
            vulnerability_description: None,
            risk_score: 5,
            open_ports: 0,
            total_vulnerabilities: 0,
            message: "Scan started".to_string(),
        };

        let cef = client.format_event(&event, &SiemFormat::Cef);
        assert!(cef.starts_with("CEF:0|Nemue|"));
        assert!(cef.contains("src=10.0.0.1"));
        assert!(!cef.contains("dstPort="));
    }

    #[test]
    fn test_leef_with_severity_levels() {
        let client = SiemClient::new();

        for (severity, expected) in [
            (SiemSeverity::Low, "severity=1"),
            (SiemSeverity::Medium, "severity=3"),
            (SiemSeverity::High, "severity=7"),
            (SiemSeverity::Critical, "severity=10"),
        ] {
            let mut event = sample_event();
            event.severity = severity;
            let leef = client.format_event(&event, &SiemFormat::Leef);
            assert!(
                leef.contains(expected),
                "Expected {} in LEEF output",
                expected
            );
        }
    }
}
