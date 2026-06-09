use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::vuln::{VulnResult, VulnSeverity};

/// PagerDuty severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PagerDutySeverity {
    Critical,
    Error,
    Warning,
    Info,
}

impl PagerDutySeverity {
    pub fn as_str(&self) -> &str {
        match self {
            PagerDutySeverity::Critical => "critical",
            PagerDutySeverity::Error => "error",
            PagerDutySeverity::Warning => "warning",
            PagerDutySeverity::Info => "info",
        }
    }

    pub fn from_severity(severity: &VulnSeverity) -> Self {
        match severity {
            VulnSeverity::Critical => PagerDutySeverity::Critical,
            VulnSeverity::High => PagerDutySeverity::Error,
            VulnSeverity::Medium => PagerDutySeverity::Warning,
            VulnSeverity::Low | VulnSeverity::Info => PagerDutySeverity::Info,
        }
    }
}

/// PagerDuty incident state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PagerDutyIncidentState {
    Triggered,
    Acknowledged,
    Resolved,
}

/// PagerDuty escalation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyEscalationPolicy {
    pub id: String,
    pub name: String,
    pub escalation_delay_minutes: u32,
}

/// PagerDuty incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyIncident {
    pub id: Option<String>,
    pub title: String,
    pub description: String,
    pub severity: PagerDutySeverity,
    pub service_id: String,
    pub escalation_policy_id: Option<String>,
    pub urgency: String,
    pub details: serde_json::Value,
    pub dedup_key: Option<String>,
}

/// PagerDuty configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyConfig {
    pub routing_key: String,
    pub api_token: String,
    pub service_id: String,
    #[serde(default)]
    pub escalation_policy_id: Option<String>,
    #[serde(default)]
    pub default_urgency: String,
    #[serde(default)]
    pub auto_acknowledge: bool,
    #[serde(default)]
    pub auto_resolve: bool,
}

impl Default for PagerDutyConfig {
    fn default() -> Self {
        Self {
            routing_key: String::new(),
            api_token: String::new(),
            service_id: String::new(),
            escalation_policy_id: None,
            default_urgency: "high".to_string(),
            auto_acknowledge: false,
            auto_resolve: false,
        }
    }
}

/// PagerDuty API client
pub struct PagerDutyClient {
    config: PagerDutyConfig,
    http_client: reqwest::Client,
}

impl PagerDutyClient {
    pub fn new(config: PagerDutyConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        Self { config, http_client }
    }

    /// Create a PagerDuty incident from a vulnerability finding
    pub fn create_incident_from_finding(&self, finding: &VulnResult) -> PagerDutyIncident {
        let severity = PagerDutySeverity::from_severity(&finding.severity);
        let urgency = match &finding.severity {
            VulnSeverity::Critical | VulnSeverity::High => "high".to_string(),
            _ => self.config.default_urgency.clone(),
        };

        let dedup_key = format!(
            "nemue-{}-{}-{}-{}",
            finding.script_id, finding.target, finding.port,
            finding.cve_ids.first().map(|s| s.as_str()).unwrap_or("no-cve")
        );

        let details = serde_json::json!({
            "target": finding.target,
            "port": finding.port,
            "script_id": finding.script_id,
            "severity": finding.severity.as_str(),
            "cve_ids": finding.cve_ids,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "exploit_available": finding.exploit_available,
        });

        PagerDutyIncident {
            id: None,
            title: format!(
                "[{}] Security Vulnerability: {} on {}:{}",
                finding.severity.as_str(), finding.script_id, finding.target, finding.port
            ),
            description: finding.description.clone(),
            severity,
            service_id: self.config.service_id.clone(),
            escalation_policy_id: self.config.escalation_policy_id.clone(),
            urgency,
            details,
            dedup_key: Some(dedup_key),
        }
    }

    /// Build the PagerDuty Events API v2 payload for triggering an incident
    pub fn build_trigger_payload(&self, incident: &PagerDutyIncident) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "routing_key": self.config.routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": incident.title,
                "source": "nemue-security-scanner",
                "severity": incident.severity.as_str(),
                "component": "vulnerability-scanner",
                "group": "security",
                "class": "vulnerability",
                "custom_details": incident.details,
            },
        });

        if let Some(ref dedup) = incident.dedup_key {
            payload["dedup_key"] = serde_json::json!(dedup);
        }

        if let Some(ref policy_id) = incident.escalation_policy_id {
            payload["payload"]["escalation_policy"] = serde_json::json!({
                "id": policy_id,
                "type": "escalation_policy_reference"
            });
        }

        payload
    }

    /// Build payload for acknowledging an incident
    pub fn build_acknowledge_payload(&self, dedup_key: &str) -> serde_json::Value {
        serde_json::json!({
            "routing_key": self.config.routing_key,
            "event_action": "acknowledge",
            "dedup_key": dedup_key,
        })
    }

    /// Build payload for resolving an incident
    pub fn build_resolve_payload(&self, dedup_key: &str) -> serde_json::Value {
        serde_json::json!({
            "routing_key": self.config.routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key,
        })
    }

    /// Build the REST API payload for creating an incident
    pub fn build_rest_incident_payload(&self, incident: &PagerDutyIncident) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "incident": {
                "type": "incident",
                "title": incident.title,
                "service": {
                    "id": incident.service_id,
                    "type": "service_reference"
                },
                "urgency": incident.urgency,
                "body": {
                    "type": "incident_body",
                    "details": incident.description
                },
            }
        });

        if let Some(ref policy_id) = incident.escalation_policy_id {
            payload["incident"]["escalation_policy"] = serde_json::json!({
                "id": policy_id,
                "type": "escalation_policy_reference"
            });
        }

        payload
    }

    /// Trigger an incident via Events API v2
    pub async fn trigger_incident(&self, incident: &PagerDutyIncident) -> Result<String> {
        let url = "https://events.pagerduty.com/v2/enqueue";
        let payload = self.build_trigger_payload(incident);

        let resp = self.http_client.post(url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send().await
            .context("Failed to send trigger to PagerDuty Events API")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("PagerDuty Events API returned status {}: {}", status, body));
        }

        let result: serde_json::Value = resp.json().await
            .context("Failed to parse PagerDuty Events API response")?;

        result.get("dedup_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No dedup_key in PagerDuty response"))
    }

    /// Acknowledge an incident via Events API v2
    pub async fn acknowledge_incident(&self, dedup_key: &str) -> Result<()> {
        let url = "https://events.pagerduty.com/v2/enqueue";
        let payload = self.build_acknowledge_payload(dedup_key);

        let resp = self.http_client.post(url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send().await
            .context("Failed to acknowledge PagerDuty incident")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("PagerDuty acknowledge returned status {}: {}", status, body));
        }

        Ok(())
    }

    /// Resolve an incident via Events API v2
    pub async fn resolve_incident(&self, dedup_key: &str) -> Result<()> {
        let url = "https://events.pagerduty.com/v2/enqueue";
        let payload = self.build_resolve_payload(dedup_key);

        let resp = self.http_client.post(url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send().await
            .context("Failed to resolve PagerDuty incident")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("PagerDuty resolve returned status {}: {}", status, body));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding() -> VulnResult {
        VulnResult {
            script_id: "log4shell-check".to_string(),
            target: "192.168.1.50".to_string(),
            port: 8080,
            vulnerable: true,
            severity: VulnSeverity::Critical,
            cve_ids: vec!["CVE-2021-44228".to_string()],
            description: "Log4Shell remote code execution vulnerability".to_string(),
            evidence: Some("JNDI lookup string detected in headers".to_string()),
            remediation: Some("Update Log4j to 2.17.0 or later".to_string()),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()],
            exploit_available: true,
        }
    }

    fn sample_config() -> PagerDutyConfig {
        PagerDutyConfig {
            routing_key: "routing-key-123".to_string(),
            api_token: "api-token-456".to_string(),
            service_id: "service-789".to_string(),
            escalation_policy_id: Some("policy-abc".to_string()),
            default_urgency: "high".to_string(),
            auto_acknowledge: false,
            auto_resolve: false,
        }
    }

    #[test]
    fn test_severity_from_vuln() {
        assert_eq!(PagerDutySeverity::from_severity(&VulnSeverity::Critical), PagerDutySeverity::Critical);
        assert_eq!(PagerDutySeverity::from_severity(&VulnSeverity::High), PagerDutySeverity::Error);
        assert_eq!(PagerDutySeverity::from_severity(&VulnSeverity::Medium), PagerDutySeverity::Warning);
        assert_eq!(PagerDutySeverity::from_severity(&VulnSeverity::Low), PagerDutySeverity::Info);
        assert_eq!(PagerDutySeverity::from_severity(&VulnSeverity::Info), PagerDutySeverity::Info);
    }

    #[test]
    fn test_create_incident_from_finding() {
        let config = sample_config();
        let client = PagerDutyClient::new(config);
        let finding = sample_finding();

        let incident = client.create_incident_from_finding(&finding);

        assert!(incident.title.contains("CRITICAL"));
        assert!(incident.title.contains("log4shell-check"));
        assert!(incident.title.contains("192.168.1.50"));
        assert!(incident.title.contains("8080"));
        assert_eq!(incident.severity, PagerDutySeverity::Critical);
        assert_eq!(incident.urgency, "high");
        assert_eq!(incident.service_id, "service-789");
        assert_eq!(incident.escalation_policy_id, Some("policy-abc".to_string()));
        assert!(incident.dedup_key.is_some());
        assert!(incident.dedup_key.as_ref().unwrap().starts_with("nemue-log4shell-check-"));
    }

    #[test]
    fn test_incident_details() {
        let config = sample_config();
        let client = PagerDutyClient::new(config);
        let finding = sample_finding();

        let incident = client.create_incident_from_finding(&finding);

        assert_eq!(incident.details["target"], "192.168.1.50");
        assert_eq!(incident.details["port"], 8080);
        assert_eq!(incident.details["severity"], "CRITICAL");
        assert_eq!(incident.details["exploit_available"], true);
        assert!(incident.details["cve_ids"].as_array().unwrap().contains(&serde_json::json!("CVE-2021-44228")));
    }

    #[test]
    fn test_build_trigger_payload() {
        let config = sample_config();
        let client = PagerDutyClient::new(config);
        let finding = sample_finding();
        let incident = client.create_incident_from_finding(&finding);
        let payload = client.build_trigger_payload(&incident);

        assert_eq!(payload["routing_key"], "routing-key-123");
        assert_eq!(payload["event_action"], "trigger");
        assert_eq!(payload["payload"]["severity"], "critical");
        assert_eq!(payload["payload"]["source"], "nemue-security-scanner");
        assert_eq!(payload["payload"]["component"], "vulnerability-scanner");
        assert!(payload["dedup_key"].as_str().unwrap().contains("log4shell-check"));
    }

    #[test]
    fn test_build_acknowledge_payload() {
        let config = sample_config();
        let client = PagerDutyClient::new(config);
        let payload = client.build_acknowledge_payload("test-dedup-key");

        assert_eq!(payload["routing_key"], "routing-key-123");
        assert_eq!(payload["event_action"], "acknowledge");
        assert_eq!(payload["dedup_key"], "test-dedup-key");
    }

    #[test]
    fn test_build_resolve_payload() {
        let config = sample_config();
        let client = PagerDutyClient::new(config);
        let payload = client.build_resolve_payload("test-dedup-key");

        assert_eq!(payload["routing_key"], "routing-key-123");
        assert_eq!(payload["event_action"], "resolve");
        assert_eq!(payload["dedup_key"], "test-dedup-key");
    }

    #[test]
    fn test_build_rest_incident_payload() {
        let config = sample_config();
        let client = PagerDutyClient::new(config);
        let finding = sample_finding();
        let incident = client.create_incident_from_finding(&finding);
        let payload = client.build_rest_incident_payload(&incident);

        let inc = payload.get("incident").unwrap();
        assert_eq!(inc["type"], "incident");
        assert!(inc["title"].as_str().unwrap().contains("log4shell-check"));
        assert_eq!(inc["service"]["id"], "service-789");
        assert_eq!(inc["service"]["type"], "service_reference");
        assert_eq!(inc["urgency"], "high");
        assert_eq!(inc["escalation_policy"]["id"], "policy-abc");
    }

    #[test]
    fn test_dedup_key_uniqueness() {
        let config = sample_config();
        let client = PagerDutyClient::new(config);

        let finding1 = VulnResult {
            script_id: "script-a".to_string(),
            target: "1.1.1.1".to_string(),
            port: 80,
            vulnerable: true, severity: VulnSeverity::High, cve_ids: vec!["CVE-2024-0001".to_string()],
            description: "Test".to_string(), evidence: None, remediation: None,
            references: vec![], exploit_available: false,
        };
        let finding2 = VulnResult {
            script_id: "script-b".to_string(),
            target: "2.2.2.2".to_string(),
            port: 443,
            ..finding1.clone()
        };

        let inc1 = client.create_incident_from_finding(&finding1);
        let inc2 = client.create_incident_from_finding(&finding2);

        assert_ne!(inc1.dedup_key, inc2.dedup_key);
    }

    #[test]
    fn test_medium_severity_uses_default_urgency() {
        let mut config = sample_config();
        config.default_urgency = "low".to_string();
        let client = PagerDutyClient::new(config);

        let finding = VulnResult {
            severity: VulnSeverity::Medium,
            ..sample_finding()
        };

        let incident = client.create_incident_from_finding(&finding);
        assert_eq!(incident.urgency, "low");
    }

    #[test]
    fn test_critical_severity_overrides_urgency() {
        let mut config = sample_config();
        config.default_urgency = "low".to_string();
        let client = PagerDutyClient::new(config);

        let incident = client.create_incident_from_finding(&sample_finding());
        assert_eq!(incident.urgency, "high"); // Critical always gets high urgency
    }

    #[test]
    fn test_config_serialization() {
        let config = sample_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: PagerDutyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.routing_key, config.routing_key);
        assert_eq!(deserialized.service_id, config.service_id);
        assert_eq!(deserialized.escalation_policy_id, config.escalation_policy_id);
    }
}
