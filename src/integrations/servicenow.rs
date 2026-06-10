use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::vuln::{VulnResult, VulnSeverity};

/// ServiceNow incident priority
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceNowPriority {
    Critical,
    High,
    Moderate,
    Low,
    Planning,
}

impl ServiceNowPriority {
    pub fn as_str(&self) -> &str {
        match self {
            ServiceNowPriority::Critical => "1",
            ServiceNowPriority::High => "2",
            ServiceNowPriority::Moderate => "3",
            ServiceNowPriority::Low => "4",
            ServiceNowPriority::Planning => "5",
        }
    }

    pub fn label(&self) -> &str {
        match self {
            ServiceNowPriority::Critical => "1 - Critical",
            ServiceNowPriority::High => "2 - High",
            ServiceNowPriority::Moderate => "3 - Moderate",
            ServiceNowPriority::Low => "4 - Low",
            ServiceNowPriority::Planning => "5 - Planning",
        }
    }

    pub fn from_severity(severity: &VulnSeverity) -> Self {
        match severity {
            VulnSeverity::Critical => ServiceNowPriority::Critical,
            VulnSeverity::High => ServiceNowPriority::High,
            VulnSeverity::Medium => ServiceNowPriority::Moderate,
            VulnSeverity::Low => ServiceNowPriority::Low,
            VulnSeverity::Info => ServiceNowPriority::Planning,
        }
    }
}

/// ServiceNow impact level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceNowImpact {
    High,
    Medium,
    Low,
}

impl ServiceNowImpact {
    pub fn as_str(&self) -> &str {
        match self {
            ServiceNowImpact::High => "1",
            ServiceNowImpact::Medium => "2",
            ServiceNowImpact::Low => "3",
        }
    }
}

/// ServiceNow incident state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IncidentState {
    New,
    InProgress,
    OnHold,
    Resolved,
    Closed,
    Cancelled,
}

impl IncidentState {
    pub fn as_str(&self) -> &str {
        match self {
            IncidentState::New => "1",
            IncidentState::InProgress => "2",
            IncidentState::OnHold => "3",
            IncidentState::Resolved => "6",
            IncidentState::Closed => "7",
            IncidentState::Cancelled => "8",
        }
    }
}

/// ServiceNow incident representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNowIncident {
    pub sys_id: Option<String>,
    pub number: Option<String>,
    pub short_description: String,
    pub description: String,
    pub priority: ServiceNowPriority,
    pub impact: ServiceNowImpact,
    pub urgency: ServiceNowPriority,
    pub category: String,
    pub subcategory: Option<String>,
    pub assignment_group: Option<String>,
    pub assigned_to: Option<String>,
    pub cmdb_ci: Option<String>,
    pub caller_id: Option<String>,
    pub work_notes: Option<String>,
    pub custom_fields: HashMap<String, serde_json::Value>,
}

/// ServiceNow change request representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNowChangeRequest {
    pub sys_id: Option<String>,
    pub number: Option<String>,
    pub short_description: String,
    pub description: String,
    pub priority: ServiceNowPriority,
    pub risk: String,
    pub impact: ServiceNowImpact,
    pub type_: String,
    pub assignment_group: Option<String>,
    pub assigned_to: Option<String>,
    pub cmdb_ci: Option<String>,
    pub justification: Option<String>,
}

/// ServiceNow configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNowConfig {
    pub instance_url: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub assignment_group: Option<String>,
    #[serde(default)]
    pub caller_id: Option<String>,
    #[serde(default)]
    pub default_cmdb_ci: Option<String>,
    #[serde(default)]
    pub custom_table: Option<String>,
    #[serde(default)]
    pub custom_fields: HashMap<String, String>,
}

/// ServiceNow API client
pub struct ServiceNowClient {
    config: ServiceNowConfig,
    http_client: reqwest::Client,
}

impl ServiceNowClient {
    pub fn new(config: ServiceNowConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        Self {
            config,
            http_client,
        }
    }

    fn api_url(&self, table: &str) -> String {
        format!(
            "{}/api/now/table/{}",
            self.config.instance_url.trim_end_matches('/'),
            table
        )
    }

    /// Create an incident from a vulnerability finding
    pub fn create_incident_from_finding(&self, finding: &VulnResult) -> ServiceNowIncident {
        let priority = ServiceNowPriority::from_severity(&finding.severity);
        let impact = match finding.severity {
            VulnSeverity::Critical | VulnSeverity::High => ServiceNowImpact::High,
            VulnSeverity::Medium => ServiceNowImpact::Medium,
            _ => ServiceNowImpact::Low,
        };

        let description = format!(
            "Vulnerability detected by Nemue security scan.\n\n\
             Target: {}\nPort: {}\nSeverity: {}\nScript: {}\n\n\
             Description:\n{}\n\n\
             CVE IDs: {}\nExploit Available: {}",
            finding.target,
            finding.port,
            finding.severity.as_str(),
            finding.script_id,
            finding.description,
            if finding.cve_ids.is_empty() {
                "None".to_string()
            } else {
                finding.cve_ids.join(", ")
            },
            if finding.exploit_available {
                "YES"
            } else {
                "No"
            }
        );

        let work_notes = finding
            .remediation
            .as_ref()
            .map(|remediation| format!("Remediation: {}", remediation));

        let mut custom_fields = HashMap::new();
        for (snow_field, nemue_field) in &self.config.custom_fields {
            match nemue_field.as_str() {
                "target" => {
                    custom_fields.insert(snow_field.clone(), serde_json::json!(finding.target));
                }
                "port" => {
                    custom_fields.insert(snow_field.clone(), serde_json::json!(finding.port));
                }
                "cve_ids" => {
                    custom_fields.insert(snow_field.clone(), serde_json::json!(finding.cve_ids));
                }
                "script_id" => {
                    custom_fields.insert(snow_field.clone(), serde_json::json!(finding.script_id));
                }
                _ => {}
            }
        }

        ServiceNowIncident {
            sys_id: None,
            number: None,
            short_description: format!(
                "[{}] Security Vulnerability: {} on {}:{}",
                finding.severity.as_str(),
                finding.script_id,
                finding.target,
                finding.port
            ),
            description,
            priority: priority.clone(),
            impact,
            urgency: priority,
            category: "Security".to_string(),
            subcategory: Some("Vulnerability".to_string()),
            assignment_group: self.config.assignment_group.clone(),
            assigned_to: None,
            cmdb_ci: self.config.default_cmdb_ci.clone(),
            caller_id: self.config.caller_id.clone(),
            work_notes,
            custom_fields,
        }
    }

    /// Build JSON payload for creating an incident
    pub fn build_incident_payload(&self, incident: &ServiceNowIncident) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "short_description": incident.short_description,
            "description": incident.description,
            "priority": incident.priority.as_str(),
            "impact": incident.impact.as_str(),
            "urgency": incident.urgency.as_str(),
            "category": incident.category,
        });

        if let Some(ref sub) = incident.subcategory {
            payload["subcategory"] = serde_json::json!(sub);
        }
        if let Some(ref group) = incident.assignment_group {
            payload["assignment_group"] = serde_json::json!(group);
        }
        if let Some(ref user) = incident.assigned_to {
            payload["assigned_to"] = serde_json::json!(user);
        }
        if let Some(ref ci) = incident.cmdb_ci {
            payload["cmdb_ci"] = serde_json::json!(ci);
        }
        if let Some(ref caller) = incident.caller_id {
            payload["caller_id"] = serde_json::json!(caller);
        }
        if let Some(ref notes) = incident.work_notes {
            payload["work_notes"] = serde_json::json!(notes);
        }

        for (key, value) in &incident.custom_fields {
            payload[key] = value.clone();
        }

        payload
    }

    /// Create a change request from a vulnerability finding
    pub fn create_change_from_finding(&self, finding: &VulnResult) -> ServiceNowChangeRequest {
        let priority = ServiceNowPriority::from_severity(&finding.severity);
        let impact = match finding.severity {
            VulnSeverity::Critical | VulnSeverity::High => ServiceNowImpact::High,
            VulnSeverity::Medium => ServiceNowImpact::Medium,
            _ => ServiceNowImpact::Low,
        };

        ServiceNowChangeRequest {
            sys_id: None,
            number: None,
            short_description: format!(
                "Remediate: {} on {}:{}",
                finding.script_id, finding.target, finding.port
            ),
            description: format!(
                "Change request to remediate vulnerability.\n\n\
                 Target: {}\nPort: {}\nSeverity: {}\n\n\
                 {}\n\nRemediation: {}",
                finding.target,
                finding.port,
                finding.severity.as_str(),
                finding.description,
                finding
                    .remediation
                    .as_deref()
                    .unwrap_or("See security team")
            ),
            priority,
            risk: match finding.severity {
                VulnSeverity::Critical => "high".to_string(),
                VulnSeverity::High => "moderate".to_string(),
                _ => "low".to_string(),
            },
            impact,
            type_: "standard".to_string(),
            assignment_group: self.config.assignment_group.clone(),
            assigned_to: None,
            cmdb_ci: self.config.default_cmdb_ci.clone(),
            justification: Some(format!(
                "Automated change request from Nemue scan. CVE: {}",
                if finding.cve_ids.is_empty() {
                    "N/A".to_string()
                } else {
                    finding.cve_ids.join(", ")
                }
            )),
        }
    }

    /// Build JSON payload for creating a change request
    pub fn build_change_payload(&self, change: &ServiceNowChangeRequest) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "short_description": change.short_description,
            "description": change.description,
            "priority": change.priority.as_str(),
            "risk": change.risk,
            "impact": change.impact.as_str(),
            "type": change.type_,
        });

        if let Some(ref group) = change.assignment_group {
            payload["assignment_group"] = serde_json::json!(group);
        }
        if let Some(ref user) = change.assigned_to {
            payload["assigned_to"] = serde_json::json!(user);
        }
        if let Some(ref ci) = change.cmdb_ci {
            payload["cmdb_ci"] = serde_json::json!(ci);
        }
        if let Some(ref justification) = change.justification {
            payload["justification"] = serde_json::json!(justification);
        }

        payload
    }

    /// Send a request to create an incident
    pub async fn create_incident(&self, incident: &ServiceNowIncident) -> Result<String> {
        let table = self.config.custom_table.as_deref().unwrap_or("incident");
        let url = self.api_url(table);
        let payload = self.build_incident_payload(incident);

        let resp = self
            .http_client
            .post(&url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&payload)
            .send()
            .await
            .context("Failed to send create incident request to ServiceNow")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "ServiceNow returned status {}: {}",
                status,
                body
            ));
        }

        let result: serde_json::Value = resp
            .json()
            .await
            .context("Failed to parse ServiceNow response")?;

        result
            .get("result")
            .and_then(|r| r.get("number"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No incident number in ServiceNow response"))
    }

    /// Send a request to create a change request
    pub async fn create_change_request(&self, change: &ServiceNowChangeRequest) -> Result<String> {
        let url = self.api_url("change_request");
        let payload = self.build_change_payload(change);

        let resp = self
            .http_client
            .post(&url)
            .basic_auth(&self.config.username, Some(&self.config.password))
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&payload)
            .send()
            .await
            .context("Failed to send create change request to ServiceNow")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "ServiceNow change request returned status {}: {}",
                status,
                body
            ));
        }

        let result: serde_json::Value = resp
            .json()
            .await
            .context("Failed to parse ServiceNow change request response")?;

        result
            .get("result")
            .and_then(|r| r.get("number"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No change number in ServiceNow response"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::VulnResult;

    fn sample_finding() -> VulnResult {
        VulnResult {
            script_id: "ssl-heartbleed".to_string(),
            target: "10.0.0.5".to_string(),
            port: 443,
            vulnerable: true,
            severity: VulnSeverity::Critical,
            cve_ids: vec!["CVE-2014-0160".to_string()],
            description: "OpenSSL Heartbleed vulnerability".to_string(),
            evidence: Some("Server responds to heartbeat with extra data".to_string()),
            remediation: Some("Update OpenSSL to 1.0.1g or later".to_string()),
            references: vec![],
            exploit_available: true,
        }
    }

    fn sample_config() -> ServiceNowConfig {
        ServiceNowConfig {
            instance_url: "https://dev.service-now.com".to_string(),
            username: "admin".to_string(),
            password: "password".to_string(),
            assignment_group: Some("Security Team".to_string()),
            caller_id: Some("nemue-service".to_string()),
            default_cmdb_ci: Some("web-server-01".to_string()),
            custom_table: None,
            custom_fields: HashMap::new(),
        }
    }

    #[test]
    fn test_priority_from_severity() {
        assert_eq!(
            ServiceNowPriority::from_severity(&VulnSeverity::Critical),
            ServiceNowPriority::Critical
        );
        assert_eq!(
            ServiceNowPriority::from_severity(&VulnSeverity::High),
            ServiceNowPriority::High
        );
        assert_eq!(
            ServiceNowPriority::from_severity(&VulnSeverity::Medium),
            ServiceNowPriority::Moderate
        );
        assert_eq!(
            ServiceNowPriority::from_severity(&VulnSeverity::Low),
            ServiceNowPriority::Low
        );
        assert_eq!(
            ServiceNowPriority::from_severity(&VulnSeverity::Info),
            ServiceNowPriority::Planning
        );
    }

    #[test]
    fn test_priority_as_str() {
        assert_eq!(ServiceNowPriority::Critical.as_str(), "1");
        assert_eq!(ServiceNowPriority::High.as_str(), "2");
        assert_eq!(ServiceNowPriority::Moderate.as_str(), "3");
        assert_eq!(ServiceNowPriority::Low.as_str(), "4");
        assert_eq!(ServiceNowPriority::Planning.as_str(), "5");
    }

    #[test]
    fn test_create_incident_from_finding() {
        let config = sample_config();
        let client = ServiceNowClient::new(config);
        let finding = sample_finding();

        let incident = client.create_incident_from_finding(&finding);

        assert!(incident.short_description.contains("CRITICAL"));
        assert!(incident.short_description.contains("ssl-heartbleed"));
        assert!(incident.short_description.contains("10.0.0.5"));
        assert!(incident.short_description.contains("443"));
        assert_eq!(incident.priority, ServiceNowPriority::Critical);
        assert_eq!(incident.impact, ServiceNowImpact::High);
        assert_eq!(incident.category, "Security");
        assert_eq!(incident.subcategory, Some("Vulnerability".to_string()));
        assert_eq!(incident.assignment_group, Some("Security Team".to_string()));
        assert_eq!(incident.cmdb_ci, Some("web-server-01".to_string()));
    }

    #[test]
    fn test_incident_description_contains_details() {
        let config = sample_config();
        let client = ServiceNowClient::new(config);
        let finding = sample_finding();

        let incident = client.create_incident_from_finding(&finding);

        assert!(incident.description.contains("CVE-2014-0160"));
        assert!(incident.description.contains("Heartbleed"));
        assert!(incident.description.contains("YES")); // exploit available
        assert!(incident
            .work_notes
            .as_ref()
            .unwrap()
            .contains("Update OpenSSL"));
    }

    #[test]
    fn test_build_incident_payload() {
        let config = sample_config();
        let client = ServiceNowClient::new(config);
        let finding = sample_finding();
        let incident = client.create_incident_from_finding(&finding);
        let payload = client.build_incident_payload(&incident);

        assert_eq!(payload["category"], "Security");
        assert_eq!(payload["priority"], "1");
        assert_eq!(payload["impact"], "1");
        assert_eq!(payload["assignment_group"], "Security Team");
        assert_eq!(payload["cmdb_ci"], "web-server-01");
    }

    #[test]
    fn test_create_change_from_finding() {
        let config = sample_config();
        let client = ServiceNowClient::new(config);
        let finding = sample_finding();

        let change = client.create_change_from_finding(&finding);

        assert!(change.short_description.contains("ssl-heartbleed"));
        assert!(change.short_description.contains("10.0.0.5"));
        assert_eq!(change.priority, ServiceNowPriority::Critical);
        assert_eq!(change.risk, "high");
        assert_eq!(change.impact, ServiceNowImpact::High);
        assert_eq!(change.type_, "standard");
        assert!(change
            .justification
            .as_ref()
            .unwrap()
            .contains("CVE-2014-0160"));
    }

    #[test]
    fn test_build_change_payload() {
        let config = sample_config();
        let client = ServiceNowClient::new(config);
        let finding = sample_finding();
        let change = client.create_change_from_finding(&finding);
        let payload = client.build_change_payload(&change);

        assert_eq!(payload["type"], "standard");
        assert_eq!(payload["risk"], "high");
        assert!(payload["justification"]
            .as_str()
            .unwrap()
            .contains("CVE-2014-0160"));
    }

    #[test]
    fn test_custom_table_support() {
        let mut config = sample_config();
        config.custom_table = Some("u_security_incident".to_string());
        let client = ServiceNowClient::new(config);
        let finding = sample_finding();
        let incident = client.create_incident_from_finding(&finding);
        let _payload = client.build_incident_payload(&incident);
        // Custom table is used in create_incident URL construction
        assert_eq!(
            client.config.custom_table,
            Some("u_security_incident".to_string())
        );
    }

    #[test]
    fn test_custom_field_mapping() {
        let mut custom_fields = HashMap::new();
        custom_fields.insert("u_cve_list".to_string(), "cve_ids".to_string());
        custom_fields.insert("u_target_ip".to_string(), "target".to_string());

        let mut config = sample_config();
        config.custom_fields = custom_fields;
        let client = ServiceNowClient::new(config);
        let finding = sample_finding();
        let incident = client.create_incident_from_finding(&finding);

        assert!(incident.custom_fields.contains_key("u_cve_list"));
        assert!(incident.custom_fields.contains_key("u_target_ip"));
        assert_eq!(
            incident.custom_fields["u_target_ip"],
            serde_json::json!("10.0.0.5")
        );
    }

    #[test]
    fn test_impact_mapping() {
        let config = sample_config();
        let client = ServiceNowClient::new(config);

        let critical = VulnResult {
            script_id: "test".to_string(),
            target: "1.1.1.1".to_string(),
            port: 80,
            vulnerable: true,
            severity: VulnSeverity::Critical,
            cve_ids: vec![],
            description: "".to_string(),
            evidence: None,
            remediation: None,
            references: vec![],
            exploit_available: false,
        };
        assert_eq!(
            client.create_incident_from_finding(&critical).impact,
            ServiceNowImpact::High
        );

        let medium = VulnResult {
            severity: VulnSeverity::Medium,
            ..critical.clone()
        };
        assert_eq!(
            client.create_incident_from_finding(&medium).impact,
            ServiceNowImpact::Medium
        );

        let info = VulnResult {
            severity: VulnSeverity::Info,
            ..critical
        };
        assert_eq!(
            client.create_incident_from_finding(&info).impact,
            ServiceNowImpact::Low
        );
    }

    #[test]
    fn test_servicenow_config_serialization() {
        let config = sample_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ServiceNowConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.instance_url, config.instance_url);
        assert_eq!(deserialized.assignment_group, config.assignment_group);
    }
}
