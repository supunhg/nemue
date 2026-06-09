use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::vuln::{VulnResult, VulnSeverity};

/// Simple base64 encoder (avoids external dependency)
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 { result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char); } else { result.push('='); }
        if chunk.len() > 2 { result.push(CHARS[(triple & 0x3F) as usize] as char); } else { result.push('='); }
    }
    result
}

/// Jira priority levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum JiraPriority {
    Highest,
    High,
    Medium,
    Low,
    Lowest,
}

impl JiraPriority {
    pub fn as_str(&self) -> &str {
        match self {
            JiraPriority::Highest => "Highest",
            JiraPriority::High => "High",
            JiraPriority::Medium => "Medium",
            JiraPriority::Low => "Low",
            JiraPriority::Lowest => "Lowest",
        }
    }

    pub fn from_severity(severity: &VulnSeverity) -> Self {
        match severity {
            VulnSeverity::Critical => JiraPriority::Highest,
            VulnSeverity::High => JiraPriority::High,
            VulnSeverity::Medium => JiraPriority::Medium,
            VulnSeverity::Low => JiraPriority::Low,
            VulnSeverity::Info => JiraPriority::Lowest,
        }
    }
}

/// Jira issue status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum JiraStatus {
    Open,
   InProgress,
    Resolved,
    Closed,
    Reopened,
}

/// Jira issue type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum JiraIssueType {
    Bug,
    Task,
    Story,
    Epic,
    Incident,
}

/// Jira transition for updating issue status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraTransition {
    pub id: String,
    pub name: String,
}

/// Jira issue representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraIssue {
    pub key: Option<String>,
    pub project_key: String,
    pub summary: String,
    pub description: String,
    pub issue_type: JiraIssueType,
    pub priority: JiraPriority,
    pub labels: Vec<String>,
    pub assignee: Option<String>,
    pub custom_fields: HashMap<String, serde_json::Value>,
}

/// Jira API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JiraConfig {
    pub base_url: String,
    pub email: String,
    pub api_token: String,
    pub project_key: String,
    #[serde(default)]
    pub default_assignee: Option<String>,
    #[serde(default)]
    pub default_labels: Vec<String>,
    #[serde(default)]
    pub custom_field_mappings: HashMap<String, String>,
}

/// Jira API client
pub struct JiraClient {
    config: JiraConfig,
    http_client: reqwest::Client,
}

impl JiraClient {
    pub fn new(config: JiraConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        Self { config, http_client }
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/rest/api/3/{}", self.config.base_url.trim_end_matches('/'), path)
    }

    fn auth_header(&self) -> String {
        let credentials = format!("{}:{}", self.config.email, self.config.api_token);
        let encoded = base64_encode(credentials.as_bytes());
        format!("Basic {}", encoded)
    }

    /// Create a Jira issue from a vulnerability finding
    pub fn create_issue_from_finding(&self, finding: &VulnResult) -> JiraIssue {
        let priority = JiraPriority::from_severity(&finding.severity);
        let mut labels = self.config.default_labels.clone();
        labels.push("nemue-scan".to_string());
        labels.push(format!("severity-{}", finding.severity.as_str().to_lowercase()));

        let mut description = format!(
            "*Vulnerability Details*\n\n\
             *Target:* {}\n\
             *Port:* {}\n\
             *Severity:* {}\n\
             *Script ID:* {}\n",
            finding.target, finding.port, finding.severity.as_str(), finding.script_id
        );

        if !finding.cve_ids.is_empty() {
            description.push_str(&format!("*CVE IDs:* {}\n", finding.cve_ids.join(", ")));
        }

        description.push_str(&format!("\n*Description*\n{}\n", finding.description));

        if let Some(ref evidence) = finding.evidence {
            description.push_str(&format!("\n*Evidence*\n{}\n", evidence));
        }

        if let Some(ref remediation) = finding.remediation {
            description.push_str(&format!("\n*Remediation*\n{}\n", remediation));
        }

        if !finding.references.is_empty() {
            description.push_str("\n*References*\n");
            for reference in &finding.references {
                description.push_str(&format!("- [{}|{}]\n", reference, reference));
            }
        }

        if finding.exploit_available {
            description.push_str("\n{color:red}*WARNING: Exploit available for this vulnerability*{color}\n");
        }

        let mut custom_fields = HashMap::new();
        for (field_key, cve_field) in &self.config.custom_field_mappings {
            if cve_field == "cve_ids" && !finding.cve_ids.is_empty() {
                custom_fields.insert(
                    field_key.clone(),
                    serde_json::json!(finding.cve_ids),
                );
            }
        }

        JiraIssue {
            key: None,
            project_key: self.config.project_key.clone(),
            summary: format!(
                "[{}] {} - {}:{}",
                finding.severity.as_str(),
                finding.script_id,
                finding.target,
                finding.port
            ),
            description,
            issue_type: JiraIssueType::Bug,
            priority,
            labels,
            assignee: self.config.default_assignee.clone(),
            custom_fields,
        }
    }

    /// Build the JSON payload for creating a Jira issue
    pub fn build_create_payload(&self, issue: &JiraIssue) -> serde_json::Value {
        let mut fields = serde_json::json!({
            "project": { "key": issue.project_key },
            "summary": issue.summary,
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{ "type": "text", "text": issue.description }]
                }]
            },
            "issuetype": { "name": self.issue_type_name(&issue.issue_type) },
            "priority": { "name": issue.priority.as_str() },
            "labels": issue.labels,
        });

        if let Some(ref assignee) = issue.assignee {
            fields["assignee"] = serde_json::json!({ "name": assignee });
        }

        for (key, value) in &issue.custom_fields {
            fields[key] = value.clone();
        }

        serde_json::json!({ "fields": fields })
    }

    /// Build the JSON payload for updating a Jira issue
    pub fn build_update_payload(&self, issue: &JiraIssue) -> serde_json::Value {
        let mut update = serde_json::json!({});

        if !issue.summary.is_empty() {
            update["summary"] = serde_json::json!([{ "set": issue.summary }]);
        }

        if !issue.labels.is_empty() {
            update["labels"] = serde_json::json!(
                issue.labels.iter().map(|l| serde_json::json!({ "add": l })).collect::<Vec<_>>()
            );
        }

        serde_json::json!({ "update": update })
    }

    /// Build the JSON payload for transitioning an issue
    pub fn build_transition_payload(&self, transition_id: &str) -> serde_json::Value {
        serde_json::json!({
            "transition": { "id": transition_id }
        })
    }

    fn issue_type_name(&self, issue_type: &JiraIssueType) -> &str {
        match issue_type {
            JiraIssueType::Bug => "Bug",
            JiraIssueType::Task => "Task",
            JiraIssueType::Story => "Story",
            JiraIssueType::Epic => "Epic",
            JiraIssueType::Incident => "Incident",
        }
    }

    /// Send a request to create an issue in Jira
    pub async fn create_issue(&self, issue: &JiraIssue) -> Result<String> {
        let url = self.api_url("issue");
        let payload = self.build_create_payload(issue);

        let resp = self.http_client.post(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send().await
            .context("Failed to send create issue request to Jira")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Jira API returned status {}: {}", status, body));
        }

        let result: serde_json::Value = resp.json().await
            .context("Failed to parse Jira create issue response")?;

        result.get("key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No issue key in Jira response"))
    }

    /// Send a request to update an existing issue
    pub async fn update_issue(&self, issue_key: &str, issue: &JiraIssue) -> Result<()> {
        let url = self.api_url(&format!("issue/{}", issue_key));
        let payload = self.build_update_payload(issue);

        let resp = self.http_client.put(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send().await
            .context("Failed to send update issue request to Jira")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Jira API returned status {}: {}", status, body));
        }

        Ok(())
    }

    /// Transition an issue to a new status
    pub async fn transition_issue(&self, issue_key: &str, transition_id: &str) -> Result<()> {
        let url = self.api_url(&format!("issue/{}/transitions", issue_key));
        let payload = self.build_transition_payload(transition_id);

        let resp = self.http_client.post(&url)
            .header("Authorization", self.auth_header())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send().await
            .context("Failed to send transition request to Jira")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Jira transition API returned status {}: {}", status, body));
        }

        Ok(())
    }

    /// List available transitions for an issue
    pub async fn list_transitions(&self, issue_key: &str) -> Result<Vec<JiraTransition>> {
        let url = self.api_url(&format!("issue/{}/transitions", issue_key));

        let resp = self.http_client.get(&url)
            .header("Authorization", self.auth_header())
            .send().await
            .context("Failed to list transitions from Jira")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!("Jira transitions API returned status {}: {}", status, body));
        }

        let result: serde_json::Value = resp.json().await
            .context("Failed to parse Jira transitions response")?;

        let transitions = result.get("transitions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter().filter_map(|t| {
                    Some(JiraTransition {
                        id: t.get("id")?.as_str()?.to_string(),
                        name: t.get("name")?.as_str()?.to_string(),
                    })
                }).collect()
            })
            .unwrap_or_default();

        Ok(transitions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding() -> VulnResult {
        VulnResult {
            script_id: "ssh-weak-ciphers".to_string(),
            target: "192.168.1.10".to_string(),
            port: 22,
            vulnerable: true,
            severity: VulnSeverity::High,
            cve_ids: vec!["CVE-2023-1234".to_string()],
            description: "SSH server allows weak cipher suites".to_string(),
            evidence: Some("arcfour128, arcfour256 enabled".to_string()),
            remediation: Some("Disable weak ciphers in sshd_config".to_string()),
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-1234".to_string()],
            exploit_available: false,
        }
    }

    fn sample_config() -> JiraConfig {
        JiraConfig {
            base_url: "https://example.atlassian.net".to_string(),
            email: "user@example.com".to_string(),
            api_token: "test-token".to_string(),
            project_key: "SEC".to_string(),
            default_assignee: Some("security-team".to_string()),
            default_labels: vec!["automated".to_string()],
            custom_field_mappings: HashMap::new(),
        }
    }

    #[test]
    fn test_priority_from_severity() {
        assert_eq!(JiraPriority::from_severity(&VulnSeverity::Critical), JiraPriority::Highest);
        assert_eq!(JiraPriority::from_severity(&VulnSeverity::High), JiraPriority::High);
        assert_eq!(JiraPriority::from_severity(&VulnSeverity::Medium), JiraPriority::Medium);
        assert_eq!(JiraPriority::from_severity(&VulnSeverity::Low), JiraPriority::Low);
        assert_eq!(JiraPriority::from_severity(&VulnSeverity::Info), JiraPriority::Lowest);
    }

    #[test]
    fn test_create_issue_from_finding() {
        let config = sample_config();
        let client = JiraClient::new(config);
        let finding = sample_finding();

        let issue = client.create_issue_from_finding(&finding);

        assert_eq!(issue.project_key, "SEC");
        assert!(issue.summary.contains("HIGH"));
        assert!(issue.summary.contains("ssh-weak-ciphers"));
        assert!(issue.summary.contains("192.168.1.10"));
        assert_eq!(issue.priority, JiraPriority::High);
        assert!(issue.labels.contains(&"nemue-scan".to_string()));
        assert!(issue.labels.contains(&"severity-high".to_string()));
        assert!(issue.labels.contains(&"automated".to_string()));
        assert_eq!(issue.issue_type, JiraIssueType::Bug);
        assert_eq!(issue.assignee, Some("security-team".to_string()));
    }

    #[test]
    fn test_issue_description_contains_details() {
        let config = sample_config();
        let client = JiraClient::new(config);
        let finding = sample_finding();

        let issue = client.create_issue_from_finding(&finding);

        assert!(issue.description.contains("192.168.1.10"));
        assert!(issue.description.contains("22"));
        assert!(issue.description.contains("CVE-2023-1234"));
        assert!(issue.description.contains("arcfour128"));
        assert!(issue.description.contains("Disable weak ciphers"));
        assert!(issue.description.contains("nvd.nist.gov"));
    }

    #[test]
    fn test_build_create_payload() {
        let config = sample_config();
        let client = JiraClient::new(config);
        let finding = sample_finding();
        let issue = client.create_issue_from_finding(&finding);
        let payload = client.build_create_payload(&issue);

        assert!(payload.get("fields").is_some());
        let fields = payload.get("fields").unwrap();
        assert_eq!(fields["project"]["key"], "SEC");
        assert_eq!(fields["issuetype"]["name"], "Bug");
        assert_eq!(fields["priority"]["name"], "High");
        assert!(fields["labels"].as_array().unwrap().len() >= 3);
    }

    #[test]
    fn test_build_update_payload() {
        let config = sample_config();
        let client = JiraClient::new(config);
        let issue = JiraIssue {
            key: Some("SEC-123".to_string()),
            project_key: "SEC".to_string(),
            summary: "Updated summary".to_string(),
            description: "".to_string(),
            issue_type: JiraIssueType::Bug,
            priority: JiraPriority::High,
            labels: vec!["updated".to_string()],
            assignee: None,
            custom_fields: HashMap::new(),
        };

        let payload = client.build_update_payload(&issue);
        assert!(payload.get("update").is_some());
        assert!(payload["update"]["summary"].is_array());
        assert!(payload["update"]["labels"].is_array());
    }

    #[test]
    fn test_build_transition_payload() {
        let config = sample_config();
        let client = JiraClient::new(config);
        let payload = client.build_transition_payload("31");

        assert_eq!(payload["transition"]["id"], "31");
    }

    #[test]
    fn test_custom_field_mapping() {
        let mut custom_fields = HashMap::new();
        custom_fields.insert("customfield_10001".to_string(), "cve_ids".to_string());

        let mut config = sample_config();
        config.custom_field_mappings = custom_fields;

        let client = JiraClient::new(config);
        let finding = sample_finding();
        let issue = client.create_issue_from_finding(&finding);

        assert!(issue.custom_fields.contains_key("customfield_10001"));
        let cve_value = issue.custom_fields.get("customfield_10001").unwrap();
        assert_eq!(cve_value.as_array().unwrap()[0], "CVE-2023-1234");
    }

    #[test]
    fn test_jira_config_serialization() {
        let config = sample_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: JiraConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.base_url, config.base_url);
        assert_eq!(deserialized.project_key, config.project_key);
    }

    #[test]
    fn test_critical_finding_creates_highest_priority() {
        let config = sample_config();
        let client = JiraClient::new(config);
        let finding = VulnResult {
            script_id: "rce-check".to_string(),
            target: "10.0.0.1".to_string(),
            port: 443,
            vulnerable: true,
            severity: VulnSeverity::Critical,
            cve_ids: vec!["CVE-2024-9999".to_string()],
            description: "Remote code execution via deserialization".to_string(),
            evidence: None,
            remediation: None,
            references: vec![],
            exploit_available: true,
        };

        let issue = client.create_issue_from_finding(&finding);
        assert_eq!(issue.priority, JiraPriority::Highest);
        assert!(issue.description.contains("Exploit available"));
    }
}
