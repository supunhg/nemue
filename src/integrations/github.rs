use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::vuln::VulnResult;

/// GitHub label for issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubLabel {
    pub name: String,
    pub color: Option<String>,
    pub description: Option<String>,
}

/// GitHub milestone
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubMilestone {
    pub number: Option<u32>,
    pub title: String,
    pub description: Option<String>,
    pub state: String,
}

/// GitHub issue representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubIssue {
    pub number: Option<u32>,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub assignees: Vec<String>,
    pub milestone: Option<u32>,
    pub state: Option<String>,
}

/// GitHub configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    pub token: String,
    pub owner: String,
    pub repo: String,
    #[serde(default)]
    pub default_labels: Vec<String>,
    #[serde(default)]
    pub default_assignees: Vec<String>,
    #[serde(default)]
    pub default_milestone: Option<u32>,
    #[serde(default)]
    pub project_board_id: Option<u32>,
    #[serde(default)]
    pub project_column_id: Option<u32>,
}

/// GitHub API client
pub struct GitHubClient {
    config: GitHubConfig,
    http_client: reqwest::Client,
}

impl GitHubClient {
    pub fn new(config: GitHubConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("nemue-security-scanner")
            .build()
            .expect("Failed to create HTTP client");
        Self {
            config,
            http_client,
        }
    }

    fn api_url(&self, path: &str) -> String {
        format!(
            "https://api.github.com/repos/{}/{}/{}",
            self.config.owner, self.config.repo, path
        )
    }

    /// Create a GitHub issue from a vulnerability finding
    pub fn create_issue_from_finding(&self, finding: &VulnResult) -> GitHubIssue {
        let mut labels = self.config.default_labels.clone();
        labels.push("security".to_string());
        labels.push("vulnerability".to_string());
        labels.push(format!(
            "severity:{}",
            finding.severity.as_str().to_lowercase()
        ));

        let body = format!(
            "## Security Vulnerability Detected\n\n\
             | Field | Value |\n\
             |-------|-------|\n\
             | **Target** | `{}` |\n\
             | **Port** | `{}` |\n\
             | **Severity** | {} |\n\
             | **Script** | `{}` |\n\
             | **Exploit Available** | {} |\n\n\
             ### Description\n\n{}\n\n",
            finding.target,
            finding.port,
            finding.severity.as_str(),
            finding.script_id,
            if finding.exploit_available {
                "Yes"
            } else {
                "No"
            },
            finding.description,
        );

        let mut sections = body;

        if !finding.cve_ids.is_empty() {
            sections.push_str("### CVE Identifiers\n\n");
            for cve in &finding.cve_ids {
                sections.push_str(&format!(
                    "- [{0}](https://nvd.nist.gov/vuln/detail/{0})\n",
                    cve
                ));
            }
            sections.push('\n');
        }

        if let Some(ref evidence) = finding.evidence {
            sections.push_str(&format!("### Evidence\n\n```\n{}\n```\n\n", evidence));
        }

        if let Some(ref remediation) = finding.remediation {
            sections.push_str(&format!("### Remediation\n\n{}\n\n", remediation));
        }

        if !finding.references.is_empty() {
            sections.push_str("### References\n\n");
            for reference in &finding.references {
                sections.push_str(&format!("- {}\n", reference));
            }
            sections.push('\n');
        }

        sections
            .push_str("---\n*This issue was automatically created by Nemue security scanner.*\n");

        GitHubIssue {
            number: None,
            title: format!(
                "[{}] {} - {}:{}",
                finding.severity.as_str(),
                finding.script_id,
                finding.target,
                finding.port
            ),
            body: sections,
            labels,
            assignees: self.config.default_assignees.clone(),
            milestone: self.config.default_milestone,
            state: None,
        }
    }

    /// Build JSON payload for creating an issue
    pub fn build_create_payload(&self, issue: &GitHubIssue) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "title": issue.title,
            "body": issue.body,
            "labels": issue.labels,
            "assignees": issue.assignees,
        });

        if let Some(milestone) = issue.milestone {
            payload["milestone"] = serde_json::json!(milestone);
        }

        payload
    }

    /// Build JSON payload for updating an issue
    pub fn build_update_payload(&self, issue: &GitHubIssue) -> serde_json::Value {
        let mut payload = serde_json::json!({});

        if !issue.title.is_empty() {
            payload["title"] = serde_json::json!(issue.title);
        }
        if !issue.body.is_empty() {
            payload["body"] = serde_json::json!(issue.body);
        }
        if !issue.labels.is_empty() {
            payload["labels"] = serde_json::json!(issue.labels);
        }
        if let Some(state) = &issue.state {
            payload["state"] = serde_json::json!(state);
        }

        payload
    }

    /// Build JSON payload for adding an issue to a project board
    pub fn build_project_card_payload(&self, issue_url: &str) -> serde_json::Value {
        serde_json::json!({
            "content_type": "Issue",
            "content_id": issue_url,
        })
    }

    /// Create an issue in GitHub
    pub async fn create_issue(&self, issue: &GitHubIssue) -> Result<u32> {
        let url = self.api_url("issues");
        let payload = self.build_create_payload(issue);

        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("token {}", self.config.token))
            .header("Accept", "application/vnd.github.v3+json")
            .json(&payload)
            .send()
            .await
            .context("Failed to send create issue request to GitHub")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "GitHub API returned status {}: {}",
                status,
                body
            ));
        }

        let result: serde_json::Value = resp
            .json()
            .await
            .context("Failed to parse GitHub create issue response")?;

        result
            .get("number")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
            .ok_or_else(|| anyhow::anyhow!("No issue number in GitHub response"))
    }

    /// Update an existing issue
    pub async fn update_issue(&self, issue_number: u32, issue: &GitHubIssue) -> Result<()> {
        let url = self.api_url(&format!("issues/{}", issue_number));
        let payload = self.build_update_payload(issue);

        let resp = self
            .http_client
            .patch(&url)
            .header("Authorization", format!("token {}", self.config.token))
            .header("Accept", "application/vnd.github.v3+json")
            .json(&payload)
            .send()
            .await
            .context("Failed to send update issue request to GitHub")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "GitHub update issue returned status {}: {}",
                status,
                body
            ));
        }

        Ok(())
    }

    /// Add labels to an existing issue
    pub async fn add_labels(&self, issue_number: u32, labels: &[String]) -> Result<()> {
        let url = self.api_url(&format!("issues/{}/labels", issue_number));

        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("token {}", self.config.token))
            .header("Accept", "application/vnd.github.v3+json")
            .json(&serde_json::json!({ "labels": labels }))
            .send()
            .await
            .context("Failed to add labels to GitHub issue")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "GitHub add labels returned status {}: {}",
                status,
                body
            ));
        }

        Ok(())
    }

    /// Add an issue to a project board column
    pub async fn add_to_project(&self, issue_url: &str, column_id: u32) -> Result<()> {
        let url = format!(
            "https://api.github.com/projects/columns/{}/cards",
            column_id
        );
        let payload = self.build_project_card_payload(issue_url);

        let resp = self
            .http_client
            .post(&url)
            .header("Authorization", format!("token {}", self.config.token))
            .header("Accept", "application/vnd.github.inertia-preview+json")
            .json(&payload)
            .send()
            .await
            .context("Failed to add issue to GitHub project")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "GitHub project card returned status {}: {}",
                status,
                body
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::VulnSeverity;

    fn sample_finding() -> VulnResult {
        VulnResult {
            script_id: "web-xss-check".to_string(),
            target: "example.com".to_string(),
            port: 443,
            vulnerable: true,
            severity: VulnSeverity::High,
            cve_ids: vec!["CVE-2024-5678".to_string()],
            description: "Reflected XSS vulnerability in search parameter".to_string(),
            evidence: Some("Input <script>alert(1)</script> reflected in response".to_string()),
            remediation: Some("Implement output encoding and CSP headers".to_string()),
            references: vec![
                "https://owasp.org/www-community/attacks/xss/".to_string(),
                "https://nvd.nist.gov/vuln/detail/CVE-2024-5678".to_string(),
            ],
            exploit_available: true,
        }
    }

    fn sample_config() -> GitHubConfig {
        GitHubConfig {
            token: "ghp_test_token".to_string(),
            owner: "myorg".to_string(),
            repo: "security-reports".to_string(),
            default_labels: vec!["auto-generated".to_string()],
            default_assignees: vec!["security-lead".to_string()],
            default_milestone: Some(5),
            project_board_id: None,
            project_column_id: None,
        }
    }

    #[test]
    fn test_create_issue_from_finding() {
        let config = sample_config();
        let client = GitHubClient::new(config);
        let finding = sample_finding();

        let issue = client.create_issue_from_finding(&finding);

        assert!(issue.title.contains("HIGH"));
        assert!(issue.title.contains("web-xss-check"));
        assert!(issue.title.contains("example.com"));
        assert!(issue.title.contains("443"));
        assert!(issue.labels.contains(&"security".to_string()));
        assert!(issue.labels.contains(&"vulnerability".to_string()));
        assert!(issue.labels.contains(&"severity:high".to_string()));
        assert!(issue.labels.contains(&"auto-generated".to_string()));
        assert_eq!(issue.assignees, vec!["security-lead".to_string()]);
        assert_eq!(issue.milestone, Some(5));
    }

    #[test]
    fn test_issue_body_contains_all_details() {
        let config = sample_config();
        let client = GitHubClient::new(config);
        let finding = sample_finding();

        let issue = client.create_issue_from_finding(&finding);

        assert!(issue.body.contains("example.com"));
        assert!(issue.body.contains("443"));
        assert!(issue.body.contains("HIGH"));
        assert!(issue.body.contains("CVE-2024-5678"));
        assert!(issue.body.contains("Reflected XSS"));
        assert!(issue.body.contains("arcfour128") || issue.body.contains("<script>"));
        assert!(issue.body.contains("CSP headers"));
        assert!(issue.body.contains("owasp.org"));
        assert!(issue.body.contains("nvd.nist.gov"));
        assert!(issue.body.contains("Nemue security scanner"));
    }

    #[test]
    fn test_issue_body_with_exploit_available() {
        let config = sample_config();
        let client = GitHubClient::new(config);
        let finding = sample_finding();

        let issue = client.create_issue_from_finding(&finding);
        assert!(issue.body.contains("Yes"));
    }

    #[test]
    fn test_issue_body_without_optional_fields() {
        let config = sample_config();
        let client = GitHubClient::new(config);
        let finding = VulnResult {
            script_id: "test".to_string(),
            target: "1.1.1.1".to_string(),
            port: 80,
            vulnerable: true,
            severity: VulnSeverity::Info,
            cve_ids: vec![],
            description: "Informational finding".to_string(),
            evidence: None,
            remediation: None,
            references: vec![],
            exploit_available: false,
        };

        let issue = client.create_issue_from_finding(&finding);
        assert!(issue.body.contains("Informational finding"));
        assert!(!issue.body.contains("### CVE"));
        assert!(!issue.body.contains("### Evidence"));
        assert!(!issue.body.contains("### Remediation"));
        assert!(!issue.body.contains("### References"));
    }

    #[test]
    fn test_build_create_payload() {
        let config = sample_config();
        let client = GitHubClient::new(config);
        let finding = sample_finding();
        let issue = client.create_issue_from_finding(&finding);
        let payload = client.build_create_payload(&issue);

        assert!(payload.get("title").is_some());
        assert!(payload.get("body").is_some());
        assert!(payload.get("labels").is_some());
        assert!(payload.get("assignees").is_some());
        assert_eq!(payload["milestone"], 5);
    }

    #[test]
    fn test_build_update_payload() {
        let config = sample_config();
        let client = GitHubClient::new(config);
        let issue = GitHubIssue {
            number: Some(42),
            title: "Updated title".to_string(),
            body: "".to_string(),
            labels: vec!["updated".to_string()],
            assignees: vec![],
            milestone: None,
            state: Some("closed".to_string()),
        };

        let payload = client.build_update_payload(&issue);
        assert_eq!(payload["title"], "Updated title");
        assert_eq!(payload["state"], "closed");
        assert!(payload.get("body").is_none()); // Empty body not included
    }

    #[test]
    fn test_build_project_card_payload() {
        let config = sample_config();
        let client = GitHubClient::new(config);
        let payload = client.build_project_card_payload(
            "https://api.github.com/repos/myorg/security-reports/issues/42",
        );

        assert_eq!(payload["content_type"], "Issue");
        assert!(payload["content_id"]
            .as_str()
            .unwrap()
            .contains("issues/42"));
    }

    #[test]
    fn test_severity_labels() {
        let config = sample_config();
        let client = GitHubClient::new(config);

        for (severity, expected_label) in [
            (VulnSeverity::Critical, "severity:critical"),
            (VulnSeverity::High, "severity:high"),
            (VulnSeverity::Medium, "severity:medium"),
            (VulnSeverity::Low, "severity:low"),
            (VulnSeverity::Info, "severity:info"),
        ] {
            let finding = VulnResult {
                severity,
                ..sample_finding()
            };
            let issue = client.create_issue_from_finding(&finding);
            assert!(
                issue.labels.contains(&expected_label.to_string()),
                "Expected label '{}' for severity {:?}",
                expected_label,
                finding.severity
            );
        }
    }

    #[test]
    fn test_config_serialization() {
        let config = sample_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: GitHubConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.owner, config.owner);
        assert_eq!(deserialized.repo, config.repo);
        assert_eq!(deserialized.default_milestone, config.default_milestone);
    }

    #[test]
    fn test_multiple_cve_ids() {
        let config = sample_config();
        let client = GitHubClient::new(config);
        let finding = VulnResult {
            cve_ids: vec![
                "CVE-2024-0001".to_string(),
                "CVE-2024-0002".to_string(),
                "CVE-2024-0003".to_string(),
            ],
            ..sample_finding()
        };

        let issue = client.create_issue_from_finding(&finding);
        assert!(issue.body.contains("CVE-2024-0001"));
        assert!(issue.body.contains("CVE-2024-0002"));
        assert!(issue.body.contains("CVE-2024-0003"));
    }

    #[test]
    fn test_no_default_assignees() {
        let mut config = sample_config();
        config.default_assignees = vec![];
        let client = GitHubClient::new(config);
        let issue = client.create_issue_from_finding(&sample_finding());
        assert!(issue.assignees.is_empty());
    }

    #[test]
    fn test_no_milestone() {
        let mut config = sample_config();
        config.default_milestone = None;
        let client = GitHubClient::new(config);
        let issue = client.create_issue_from_finding(&sample_finding());
        assert!(issue.milestone.is_none());

        let payload = client.build_create_payload(&issue);
        assert!(payload.get("milestone").is_none());
    }
}
