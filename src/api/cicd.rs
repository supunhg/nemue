use serde::{Deserialize, Serialize};
use std::process;

/// CI/CD platform types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CiCdPlatform {
    GitHubActions,
    GitLabCI,
    Jenkins,
    Generic,
}

/// CI/CD integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdConfig {
    pub platform: CiCdPlatform,
    /// Fail pipeline if vulnerabilities above this severity are found
    #[serde(default)]
    pub fail_on_vuln: bool,
    /// Fail pipeline if risk score exceeds this threshold (0-100)
    #[serde(default = "default_risk_threshold")]
    pub risk_threshold: u8,
    /// Fail pipeline if open ports exceed this count
    #[serde(default)]
    pub max_open_ports: Option<usize>,
    /// Output format for CI/CD logs
    #[serde(default)]
    pub output_format: CiCdOutputFormat,
    /// GitHub token for PR annotations
    #[serde(default)]
    pub github_token: Option<String>,
    /// GitLab token for MR notes
    #[serde(default)]
    pub gitlab_token: Option<String>,
}

fn default_risk_threshold() -> u8 {
    80
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum CiCdOutputFormat {
    #[default]
    Text,
    Json,
    Markdown,
    GitHubAnnotation,
}

impl Default for CiCdConfig {
    fn default() -> Self {
        Self {
            platform: CiCdPlatform::Generic,
            fail_on_vuln: false,
            risk_threshold: default_risk_threshold(),
            max_open_ports: None,
            output_format: CiCdOutputFormat::Text,
            github_token: None,
            gitlab_token: None,
        }
    }
}

/// CI/CD scan result summary for pipeline decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCdResult {
    pub scan_id: String,
    pub passed: bool,
    pub exit_code: i32,
    pub targets_scanned: usize,
    pub total_open_ports: usize,
    pub total_vulnerabilities: usize,
    pub risk_score: u8,
    pub failures: Vec<String>,
    pub warnings: Vec<String>,
    pub report: String,
}

/// CI/CD exit codes
pub mod exit_codes {
    pub const SUCCESS: i32 = 0;
    pub const VULNS_FOUND: i32 = 1;
    pub const RISK_EXCEEDED: i32 = 2;
    pub const PORTS_EXCEEDED: i32 = 3;
    pub const SCAN_ERROR: i32 = 4;
}

/// CI/CD integration handler
pub struct CiCdRunner {
    config: CiCdConfig,
}

impl CiCdRunner {
    pub fn new(config: CiCdConfig) -> Self {
        Self { config }
    }

    /// Evaluate scan results and determine pipeline outcome
    pub fn evaluate(
        &self,
        scan_id: &str,
        targets_scanned: usize,
        total_open_ports: usize,
        total_vulnerabilities: usize,
        risk_score: u8,
    ) -> CiCdResult {
        let mut failures = Vec::new();
        let mut warnings = Vec::new();
        let mut exit_code = exit_codes::SUCCESS;

        if self.config.fail_on_vuln && total_vulnerabilities > 0 {
            failures.push(format!("Found {} vulnerabilities", total_vulnerabilities));
            exit_code = exit_codes::VULNS_FOUND;
        }

        if risk_score >= self.config.risk_threshold {
            failures.push(format!(
                "Risk score {} exceeds threshold {}",
                risk_score, self.config.risk_threshold
            ));
            exit_code = exit_codes::RISK_EXCEEDED;
        }

        if let Some(max_ports) = self.config.max_open_ports {
            if total_open_ports > max_ports {
                failures.push(format!(
                    "Open ports {} exceeds maximum {}",
                    total_open_ports, max_ports
                ));
                exit_code = exit_codes::PORTS_EXCEEDED;
            }
        }

        if risk_score >= 50 && risk_score < self.config.risk_threshold {
            warnings.push(format!(
                "Risk score {} is elevated but below threshold",
                risk_score
            ));
        }

        let passed = failures.is_empty();
        let report = self.format_report(
            scan_id,
            targets_scanned,
            total_open_ports,
            total_vulnerabilities,
            risk_score,
            &failures,
            &warnings,
        );

        CiCdResult {
            scan_id: scan_id.to_string(),
            passed,
            exit_code,
            targets_scanned,
            total_open_ports,
            total_vulnerabilities,
            risk_score,
            failures,
            warnings,
            report,
        }
    }

    /// Format the report based on configured output format
    fn format_report(
        &self,
        scan_id: &str,
        targets_scanned: usize,
        total_open_ports: usize,
        total_vulnerabilities: usize,
        risk_score: u8,
        failures: &[String],
        warnings: &[String],
    ) -> String {
        match self.config.output_format {
            CiCdOutputFormat::Text => self.format_text(
                scan_id,
                targets_scanned,
                total_open_ports,
                total_vulnerabilities,
                risk_score,
                failures,
                warnings,
            ),
            CiCdOutputFormat::Json => self.format_json(
                scan_id,
                targets_scanned,
                total_open_ports,
                total_vulnerabilities,
                risk_score,
                failures,
                warnings,
            ),
            CiCdOutputFormat::Markdown => self.format_markdown(
                scan_id,
                targets_scanned,
                total_open_ports,
                total_vulnerabilities,
                risk_score,
                failures,
                warnings,
            ),
            CiCdOutputFormat::GitHubAnnotation => {
                self.format_github_annotation(scan_id, failures, warnings)
            }
        }
    }

    fn format_text(
        &self,
        scan_id: &str,
        targets: usize,
        ports: usize,
        vulns: usize,
        risk: u8,
        failures: &[String],
        warnings: &[String],
    ) -> String {
        let mut out = String::new();
        out.push_str("=== Nemue CI/CD Scan Report ===\n");
        out.push_str(&format!("Scan ID:        {}\n", scan_id));
        out.push_str(&format!("Targets:        {}\n", targets));
        out.push_str(&format!("Open Ports:     {}\n", ports));
        out.push_str(&format!("Vulnerabilities:{}\n", vulns));
        out.push_str(&format!("Risk Score:     {}/100\n", risk));
        out.push_str(&format!(
            "Result:         {}\n",
            if failures.is_empty() {
                "PASSED"
            } else {
                "FAILED"
            }
        ));

        if !warnings.is_empty() {
            out.push_str("\nWarnings:\n");
            for w in warnings {
                out.push_str(&format!("  ! {}\n", w));
            }
        }

        if !failures.is_empty() {
            out.push_str("\nFailures:\n");
            for f in failures {
                out.push_str(&format!("  X {}\n", f));
            }
        }

        out
    }

    fn format_json(
        &self,
        scan_id: &str,
        targets: usize,
        ports: usize,
        vulns: usize,
        risk: u8,
        failures: &[String],
        warnings: &[String],
    ) -> String {
        let report = serde_json::json!({
            "tool": "nemue",
            "scan_id": scan_id,
            "targets_scanned": targets,
            "total_open_ports": ports,
            "total_vulnerabilities": vulns,
            "risk_score": risk,
            "passed": failures.is_empty(),
            "failures": failures,
            "warnings": warnings,
        });
        serde_json::to_string_pretty(&report).unwrap_or_default()
    }

    fn format_markdown(
        &self,
        scan_id: &str,
        targets: usize,
        ports: usize,
        vulns: usize,
        risk: u8,
        failures: &[String],
        warnings: &[String],
    ) -> String {
        let status = if failures.is_empty() {
            "PASSED"
        } else {
            "FAILED"
        };
        let emoji = if failures.is_empty() { "ok" } else { "fail" };

        let mut out = String::new();
        out.push_str(&format!("# Nemue Security Scan [{status}]\n\n"));
        out.push_str("| Metric | Value |\n|--------|-------|\n");
        out.push_str(&format!("| Scan ID | `{scan_id}` |\n"));
        out.push_str(&format!("| Targets | {targets} |\n"));
        out.push_str(&format!("| Open Ports | {ports} |\n"));
        out.push_str(&format!("| Vulnerabilities | {vulns} |\n"));
        out.push_str(&format!("| Risk Score | {risk}/100 |\n"));

        if !warnings.is_empty() {
            out.push_str("\n## Warnings\n");
            for w in warnings {
                out.push_str(&format!("- **Warning**: {w}\n"));
            }
        }

        if !failures.is_empty() {
            out.push_str("\n## Failures\n");
            for f in failures {
                out.push_str(&format!("- **{emoji}**: {f}\n"));
            }
        }

        out
    }

    fn format_github_annotation(
        &self,
        scan_id: &str,
        failures: &[String],
        warnings: &[String],
    ) -> String {
        let mut out = String::new();

        for w in warnings {
            out.push_str(&format!("::warning title=Nemue Scan {scan_id}::{w}\n"));
        }
        for f in failures {
            out.push_str(&format!("::error title=Nemue Scan {scan_id}::{f}\n"));
        }

        if failures.is_empty() && warnings.is_empty() {
            out.push_str(&format!(
                "::notice title=Nemue Scan {scan_id}::Security scan passed\n"
            ));
        }

        out
    }

    /// Apply the result to the current process (call process::exit)
    pub fn apply_exit_code(result: &CiCdResult) {
        process::exit(result.exit_code);
    }

    /// Detect CI/CD platform from environment variables
    pub fn detect_platform() -> CiCdPlatform {
        if std::env::var("GITHUB_ACTIONS").is_ok() {
            CiCdPlatform::GitHubActions
        } else if std::env::var("GITLAB_CI").is_ok() {
            CiCdPlatform::GitLabCI
        } else if std::env::var("JENKINS_URL").is_ok() {
            CiCdPlatform::Jenkins
        } else {
            CiCdPlatform::Generic
        }
    }

    /// Build GitHub Actions job summary
    pub fn github_summary(result: &CiCdResult) -> String {
        let status = if result.passed { "PASS" } else { "FAIL" };
        format!(
            "## Nemue Scan {status}\n\n\
             | Metric | Value |\n|---|---|\n\
             | Scan ID | `{}` |\n\
             | Targets | {} |\n\
             | Open Ports | {} |\n\
             | Vulnerabilities | {} |\n\
             | Risk Score | {}/100 |\n",
            result.scan_id,
            result.targets_scanned,
            result.total_open_ports,
            result.total_vulnerabilities,
            result.risk_score
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ci_cd_pass_no_vulns() {
        let config = CiCdConfig {
            fail_on_vuln: true,
            risk_threshold: 80,
            ..Default::default()
        };
        let runner = CiCdRunner::new(config);
        let result = runner.evaluate("scan-1", 5, 3, 0, 20);
        assert!(result.passed);
        assert_eq!(result.exit_code, exit_codes::SUCCESS);
        assert!(result.failures.is_empty());
    }

    #[test]
    fn test_ci_cd_fail_on_vulns() {
        let config = CiCdConfig {
            fail_on_vuln: true,
            risk_threshold: 80,
            ..Default::default()
        };
        let runner = CiCdRunner::new(config);
        let result = runner.evaluate("scan-2", 5, 3, 2, 40);
        assert!(!result.passed);
        assert_eq!(result.exit_code, exit_codes::VULNS_FOUND);
        assert!(!result.failures.is_empty());
    }

    #[test]
    fn test_ci_cd_fail_on_risk() {
        let config = CiCdConfig {
            fail_on_vuln: false,
            risk_threshold: 70,
            ..Default::default()
        };
        let runner = CiCdRunner::new(config);
        let result = runner.evaluate("scan-3", 3, 10, 0, 85);
        assert!(!result.passed);
        assert_eq!(result.exit_code, exit_codes::RISK_EXCEEDED);
    }

    #[test]
    fn test_ci_cd_fail_on_ports() {
        let config = CiCdConfig {
            max_open_ports: Some(5),
            ..Default::default()
        };
        let runner = CiCdRunner::new(config);
        let result = runner.evaluate("scan-4", 1, 10, 0, 10);
        assert!(!result.passed);
        assert_eq!(result.exit_code, exit_codes::PORTS_EXCEEDED);
    }

    #[test]
    fn test_ci_cd_warning_elevated_risk() {
        let config = CiCdConfig {
            risk_threshold: 80,
            ..Default::default()
        };
        let runner = CiCdRunner::new(config);
        let result = runner.evaluate("scan-5", 2, 1, 0, 60);
        assert!(result.passed);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_text_format() {
        let config = CiCdConfig {
            output_format: CiCdOutputFormat::Text,
            ..Default::default()
        };
        let runner = CiCdRunner::new(config);
        let result = runner.evaluate("scan-txt", 1, 2, 0, 10);
        assert!(result.report.contains("Nemue CI/CD Scan Report"));
        assert!(result.report.contains("PASSED"));
    }

    #[test]
    fn test_json_format() {
        let config = CiCdConfig {
            output_format: CiCdOutputFormat::Json,
            ..Default::default()
        };
        let runner = CiCdRunner::new(config);
        let result = runner.evaluate("scan-json", 1, 2, 0, 10);
        let parsed: serde_json::Value = serde_json::from_str(&result.report).unwrap();
        assert_eq!(parsed["scan_id"], "scan-json");
        assert_eq!(parsed["passed"], true);
    }

    #[test]
    fn test_markdown_format() {
        let config = CiCdConfig {
            output_format: CiCdOutputFormat::Markdown,
            ..Default::default()
        };
        let runner = CiCdRunner::new(config);
        let result = runner.evaluate("scan-md", 1, 2, 0, 10);
        assert!(result.report.contains("# Nemue Security Scan"));
        assert!(result.report.contains("| Metric | Value |"));
    }

    #[test]
    fn test_github_annotation_format() {
        let config = CiCdConfig {
            output_format: CiCdOutputFormat::GitHubAnnotation,
            fail_on_vuln: true,
            ..Default::default()
        };
        let runner = CiCdRunner::new(config);
        let result = runner.evaluate("scan-gh", 1, 2, 3, 90);
        assert!(result.report.contains("::error"));
    }

    #[test]
    fn test_github_summary() {
        let result = CiCdResult {
            scan_id: "scan-sum".to_string(),
            passed: true,
            exit_code: 0,
            targets_scanned: 3,
            total_open_ports: 5,
            total_vulnerabilities: 0,
            risk_score: 25,
            failures: vec![],
            warnings: vec![],
            report: String::new(),
        };
        let summary = CiCdRunner::github_summary(&result);
        assert!(summary.contains("Nemue Scan PASS"));
        assert!(summary.contains("scan-sum"));
    }

    #[test]
    fn test_exit_code_constants() {
        assert_eq!(exit_codes::SUCCESS, 0);
        assert_eq!(exit_codes::VULNS_FOUND, 1);
        assert_eq!(exit_codes::RISK_EXCEEDED, 2);
        assert_eq!(exit_codes::PORTS_EXCEEDED, 3);
        assert_eq!(exit_codes::SCAN_ERROR, 4);
    }

    #[test]
    fn test_ci_cd_config_default() {
        let config = CiCdConfig::default();
        assert_eq!(config.platform, CiCdPlatform::Generic);
        assert!(!config.fail_on_vuln);
        assert_eq!(config.risk_threshold, 80);
        assert!(config.max_open_ports.is_none());
    }

    #[test]
    fn test_detect_platform_generic() {
        // When running tests outside CI, GITHUB_ACTIONS etc. are not set
        // In CI, the platform will be detected correctly
        let platform = CiCdRunner::detect_platform();
        // Just verify it returns a valid platform
        assert!(matches!(
            platform,
            CiCdPlatform::Generic
                | CiCdPlatform::GitHubActions
                | CiCdPlatform::GitLabCI
                | CiCdPlatform::Jenkins
        ));
    }

    #[test]
    fn test_platform_serialization() {
        assert_eq!(
            serde_json::to_string(&CiCdPlatform::GitHubActions).unwrap(),
            "\"githubactions\""
        );
        assert_eq!(
            serde_json::to_string(&CiCdPlatform::GitLabCI).unwrap(),
            "\"gitlabci\""
        );
        assert_eq!(
            serde_json::to_string(&CiCdPlatform::Jenkins).unwrap(),
            "\"jenkins\""
        );
        assert_eq!(
            serde_json::to_string(&CiCdPlatform::Generic).unwrap(),
            "\"generic\""
        );
    }
}
