// HTML report generation with interactive elements
use crate::reporting::{ScanReport, Severity};

pub struct HtmlReportGenerator;

impl HtmlReportGenerator {
    pub fn generate(report: &ScanReport) -> String {
        let mut html = String::new();
        
        html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("  <meta charset=\"UTF-8\">\n");
        html.push_str("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        html.push_str(&format!("  <title>Security Scan Report - {}</title>\n", report.metadata.report_id));
        html.push_str("  <style>\n");
        html.push_str(Self::css());
        html.push_str("  </style>\n");
        html.push_str("</head>\n<body>\n");
        
        html.push_str(&Self::header(report));
        html.push_str(&Self::executive_summary(report));
        html.push_str(&Self::vulnerability_chart(report));
        html.push_str(&Self::findings_table(report));
        html.push_str(&Self::compliance_section(report));
        html.push_str(&Self::recommendations_section(report));
        html.push_str(&Self::footer());
        
        html.push_str("</body>\n</html>");
        html
    }

    fn css() -> &'static str {
        r#"
    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
    h2 { color: #555; margin-top: 30px; border-left: 4px solid #007bff; padding-left: 10px; }
    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; margin: -30px -30px 20px -30px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
    .metric { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff; }
    .metric-label { font-size: 12px; color: #666; text-transform: uppercase; }
    .metric-value { font-size: 24px; font-weight: bold; color: #333; }
    .vuln-chart { display: flex; gap: 10px; margin: 20px 0; }
    .vuln-bar { flex: 1; text-align: center; padding: 10px; border-radius: 5px; color: white; }
    .critical { background: #dc3545; }
    .high { background: #fd7e14; }
    .medium { background: #ffc107; color: #333; }
    .low { background: #28a745; }
    .info { background: #17a2b8; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background: #007bff; color: white; }
    tr:hover { background: #f5f5f5; }
    .badge { padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
    .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; }
"#
    }

    fn header(report: &ScanReport) -> String {
        format!(
            r#"<div class="container">
  <div class="header">
    <h1>🔒 Security Scan Report</h1>
    <p>Report ID: {} | Generated: {}</p>
  </div>
"#,
            report.metadata.report_id,
            report.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        )
    }

    fn executive_summary(report: &ScanReport) -> String {
        let summary = &report.executive_summary;
        format!(
            r#"  <h2>📊 Executive Summary</h2>
  <div class="summary">
    <div class="metric">
      <div class="metric-label">Total Hosts</div>
      <div class="metric-value">{}</div>
    </div>
    <div class="metric">
      <div class="metric-label">Hosts Up</div>
      <div class="metric-value">{}</div>
    </div>
    <div class="metric">
      <div class="metric-label">Open Ports</div>
      <div class="metric-value">{}</div>
    </div>
    <div class="metric">
      <div class="metric-label">Risk Score</div>
      <div class="metric-value">{:.1}/10</div>
    </div>
    <div class="metric">
      <div class="metric-label">Compliance</div>
      <div class="metric-value">{:.1}%</div>
    </div>
  </div>
"#,
            summary.total_hosts,
            summary.hosts_up,
            summary.open_ports,
            summary.risk_score,
            summary.compliance_score
        )
    }

    fn vulnerability_chart(report: &ScanReport) -> String {
        let v = &report.executive_summary.vulnerabilities;
        format!(
            r#"  <h2>🚨 Vulnerabilities</h2>
  <div class="vuln-chart">
    <div class="vuln-bar critical">
      <div>Critical</div>
      <div style="font-size: 28px; font-weight: bold;">{}</div>
    </div>
    <div class="vuln-bar high">
      <div>High</div>
      <div style="font-size: 28px; font-weight: bold;">{}</div>
    </div>
    <div class="vuln-bar medium">
      <div>Medium</div>
      <div style="font-size: 28px; font-weight: bold;">{}</div>
    </div>
    <div class="vuln-bar low">
      <div>Low</div>
      <div style="font-size: 28px; font-weight: bold;">{}</div>
    </div>
    <div class="vuln-bar info">
      <div>Info</div>
      <div style="font-size: 28px; font-weight: bold;">{}</div>
    </div>
  </div>
"#,
            v.critical, v.high, v.medium, v.low, v.info
        )
    }

    fn findings_table(report: &ScanReport) -> String {
        if report.findings.is_empty() {
            return String::from("  <h2>🔍 Findings</h2>\n  <p>No findings to report.</p>\n");
        }

        let mut html = String::from("  <h2>🔍 Findings</h2>\n  <table>\n");
        html.push_str("    <tr><th>Severity</th><th>Title</th><th>Hosts</th><th>CVSS</th><th>CVE IDs</th></tr>\n");
        
        for finding in &report.findings {
            let severity_class = match finding.severity {
                Severity::Critical => "critical",
                Severity::High => "high",
                Severity::Medium => "medium",
                Severity::Low => "low",
                Severity::Info => "info",
            };
            
            html.push_str(&format!(
                "    <tr>\n      <td><span class=\"badge {}\">{:?}</span></td>\n      <td>{}</td>\n      <td>{}</td>\n      <td>{}</td>\n      <td>{}</td>\n    </tr>\n",
                severity_class,
                finding.severity,
                finding.title,
                finding.affected_hosts.len(),
                finding.cvss_score.map_or("-".to_string(), |s| format!("{:.1}", s)),
                finding.cve_ids.join(", ")
            ));
        }
        
        html.push_str("  </table>\n");
        html
    }

    fn compliance_section(report: &ScanReport) -> String {
        let mut html = String::from("  <h2>✅ Compliance Status</h2>\n");
        html.push_str(&format!("  <p>Overall Compliance Score: <strong>{:.1}%</strong></p>\n", 
            report.compliance.overall_score));
        
        if !report.compliance.frameworks.is_empty() {
            html.push_str("  <table>\n");
            html.push_str("    <tr><th>Framework</th><th>Version</th><th>Passing</th><th>Failing</th><th>Score</th></tr>\n");
            
            for framework in &report.compliance.frameworks {
                html.push_str(&format!(
                    "    <tr>\n      <td>{}</td>\n      <td>{}</td>\n      <td>{}</td>\n      <td>{}</td>\n      <td>{:.1}%</td>\n    </tr>\n",
                    framework.name,
                    framework.version,
                    framework.controls_passing,
                    framework.controls_failing,
                    framework.score
                ));
            }
            
            html.push_str("  </table>\n");
        }
        
        html
    }

    fn recommendations_section(report: &ScanReport) -> String {
        if report.recommendations.is_empty() {
            return String::new();
        }

        let mut html = String::from("  <h2>💡 Recommendations</h2>\n  <table>\n");
        html.push_str("    <tr><th>Priority</th><th>Category</th><th>Title</th><th>Impact</th><th>Effort</th></tr>\n");
        
        for rec in &report.recommendations {
            html.push_str(&format!(
                "    <tr>\n      <td><span class=\"badge\">{:?}</span></td>\n      <td>{}</td>\n      <td>{}</td>\n      <td>{}</td>\n      <td>{}</td>\n    </tr>\n",
                rec.priority,
                rec.category,
                rec.title,
                rec.impact,
                rec.effort
            ));
        }
        
        html.push_str("  </table>\n");
        html
    }

    fn footer() -> &'static str {
        r#"  <div class="footer">
    <p>Generated by Nemue Security Scanner v0.1.0</p>
    <p>&copy; 2025 - Automated Security Assessment Report</p>
  </div>
</div>
"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reporting::*;
    use chrono::Utc;

    fn sample_report() -> ScanReport {
        ReportBuilder::new()
            .metadata(ReportMetadata {
                scan_id: "scan-001".to_string(),
                report_id: "report-001".to_string(),
                generated_at: Utc::now(),
                scan_start: Utc::now(),
                scan_end: Utc::now(),
                target_count: 10,
                version: "0.1.0".to_string(),
            })
            .summary(ExecutiveSummary {
                total_hosts: 10,
                hosts_up: 8,
                total_ports: 1000,
                open_ports: 45,
                vulnerabilities: VulnerabilitySummary {
                    critical: 2,
                    high: 5,
                    medium: 10,
                    low: 8,
                    info: 3,
                },
                risk_score: 7.5,
                compliance_score: 75.0,
            })
            .compliance(ComplianceStatus {
                frameworks: vec![],
                overall_score: 75.0,
            })
            .build()
            .unwrap()
    }

    #[test]
    fn test_html_generation() {
        let report = sample_report();
        let html = HtmlReportGenerator::generate(&report);
        
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Security Scan Report"));
        assert!(html.contains("report-001"));
    }

    #[test]
    fn test_html_contains_summary() {
        let report = sample_report();
        let html = HtmlReportGenerator::generate(&report);
        
        assert!(html.contains("Executive Summary"));
        assert!(html.contains("Total Hosts"));
        assert!(html.contains("10"));
    }

    #[test]
    fn test_html_contains_vulnerabilities() {
        let report = sample_report();
        let html = HtmlReportGenerator::generate(&report);
        
        assert!(html.contains("Vulnerabilities"));
        assert!(html.contains("Critical"));
        assert!(html.contains("High"));
    }

    #[test]
    fn test_html_with_findings() {
        let mut builder = ReportBuilder::new()
            .metadata(ReportMetadata {
                scan_id: "scan-001".to_string(),
                report_id: "report-001".to_string(),
                generated_at: Utc::now(),
                scan_start: Utc::now(),
                scan_end: Utc::now(),
                target_count: 1,
                version: "0.1.0".to_string(),
            })
            .summary(ExecutiveSummary {
                total_hosts: 1,
                hosts_up: 1,
                total_ports: 100,
                open_ports: 5,
                vulnerabilities: VulnerabilitySummary {
                    critical: 1,
                    high: 0,
                    medium: 0,
                    low: 0,
                    info: 0,
                },
                risk_score: 8.0,
                compliance_score: 60.0,
            })
            .compliance(ComplianceStatus {
                frameworks: vec![],
                overall_score: 60.0,
            })
            .add_finding(Finding {
                id: "f-001".to_string(),
                severity: Severity::Critical,
                title: "Test Finding".to_string(),
                description: "Test".to_string(),
                affected_hosts: vec!["192.168.1.1".to_string()],
                cvss_score: Some(9.8),
                cve_ids: vec!["CVE-2021-1234".to_string()],
                remediation: "Fix it".to_string(),
            });

        let report = builder.build().unwrap();
        let html = HtmlReportGenerator::generate(&report);
        
        assert!(html.contains("Findings"));
        assert!(html.contains("Test Finding"));
        assert!(html.contains("9.8"));
    }
}
