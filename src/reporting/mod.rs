// Report generation module for compliance and analysis
pub mod compliance;
pub mod html;
pub mod audit;
pub mod trends;
pub mod templates;
pub mod dashboard;
pub mod analytics;
pub mod scheduler;
pub mod collaboration;
pub mod pdf;
pub mod markdown;
pub mod custom;
pub mod executive;
pub mod xml_report;
pub mod sarif;
pub mod junit;
pub mod cyclonedx;
pub mod spdx;

pub use compliance::{
    ComplianceMapper, Framework, Control, ControlTest, CheckType,
    ComplianceResult, ControlResult, ControlStatus,
};
pub use html::HtmlReportGenerator;
pub use audit::{AuditTrail, AuditEntry, AuditMetadata, EventType, Evidence, EvidenceType};
pub use trends::{TrendAnalyzer, ScanSnapshot, ScanMetrics, VulnerabilityMetrics, TrendReport, Trend, TrendDirection};
pub use templates::{TemplateEngine, ReportTemplate, TemplateSection, ContentType};
pub use dashboard::{
    Dashboard, DashboardBuilder, Widget, WidgetType, WidgetData, MetricData, ChartData, AlertLevel,
    LiveStatistics, RealTimeMonitor, MonitorStatus, ScanProgress, MonitorEvent, MonitorEventType,
    InteractiveChart, ChartKind, DataSeries, DataPoint, ChartAxes, ChartInteractions, ChartAnnotation,
    AnnotationType, DrillDown, DrillDownType, DrillFilter, DrillDownData, DrillEntry,
};
pub use analytics::{
    AnalyticsEngine, RiskModel, ModelType, Prediction, RiskFactor, VulnerabilityPrediction,
    TrendAnalysis, TrendDataPoint, AnalysisTrendDirection, ForecastPoint,
    StatisticalSummary, DistributionType, ComparativeResult, ComparisonMetric,
    PredictiveModel, PredictedVulnerability,
};
pub use scheduler::{
    ReportScheduler, ReportSchedule, ScheduledReportType, Recurrence, ScheduleConfig,
    OutputFormat, DistributionList, Recipient, RecipientRole, ReportArchive, ArchiveEntry,
    ArchiveMetadata, GenerationLogEntry, GenerationStatus, ArchiveStats,
};
pub use collaboration::{
    CollaborationManager, SharedReport, ReportVersion, Comment, Reaction, Annotation as CollabAnnotation,
    AnnotationKind, AnnotationCoordinates, ShareEntry, Permission, ReportStatus,
    AccessPolicy, AccessRule, AccessCondition, ConditionOperator, CollabAuditEntry, CollabAction,
};
pub use pdf::PdfReportGenerator;
pub use markdown::MarkdownReportGenerator;
pub use custom::{ReportCustomization, Branding, CustomSeverity, CustomSection, SectionContent, ChartType, CustomRecommendation};
pub use executive::ExecutiveReport;
pub use xml_report::XmlReportGenerator;
pub use sarif::SarifReportGenerator;
pub use junit::JunitReportGenerator;
pub use cyclonedx::CycloneDxReportGenerator;
pub use spdx::SpdxReportGenerator;

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub metadata: ReportMetadata,
    pub executive_summary: ExecutiveSummary,
    pub findings: Vec<Finding>,
    pub compliance: ComplianceStatus,
    pub recommendations: Vec<Recommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub scan_id: String,
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub scan_start: DateTime<Utc>,
    pub scan_end: DateTime<Utc>,
    pub target_count: usize,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub total_hosts: usize,
    pub hosts_up: usize,
    pub total_ports: usize,
    pub open_ports: usize,
    pub vulnerabilities: VulnerabilitySummary,
    pub risk_score: f64,
    pub compliance_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilitySummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub affected_hosts: Vec<String>,
    pub cvss_score: Option<f64>,
    pub cve_ids: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub frameworks: Vec<ComplianceFramework>,
    pub overall_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFramework {
    pub name: String,
    pub version: String,
    pub controls_total: usize,
    pub controls_passing: usize,
    pub controls_failing: usize,
    pub score: f64,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub priority: Priority,
    pub category: String,
    pub title: String,
    pub description: String,
    pub impact: String,
    pub effort: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

pub struct ReportBuilder {
    metadata: Option<ReportMetadata>,
    summary: Option<ExecutiveSummary>,
    findings: Vec<Finding>,
    compliance: Option<ComplianceStatus>,
    recommendations: Vec<Recommendation>,
}

impl ReportBuilder {
    pub fn new() -> Self {
        Self {
            metadata: None,
            summary: None,
            findings: Vec::new(),
            compliance: None,
            recommendations: Vec::new(),
        }
    }

    pub fn metadata(mut self, metadata: ReportMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn summary(mut self, summary: ExecutiveSummary) -> Self {
        self.summary = Some(summary);
        self
    }

    pub fn add_finding(mut self, finding: Finding) -> Self {
        self.findings.push(finding);
        self
    }

    pub fn compliance(mut self, compliance: ComplianceStatus) -> Self {
        self.compliance = Some(compliance);
        self
    }

    pub fn add_recommendation(mut self, recommendation: Recommendation) -> Self {
        self.recommendations.push(recommendation);
        self
    }

    pub fn build(self) -> Result<ScanReport, String> {
        Ok(ScanReport {
            metadata: self.metadata.ok_or("Metadata is required")?,
            executive_summary: self.summary.ok_or("Executive summary is required")?,
            findings: self.findings,
            compliance: self.compliance.ok_or("Compliance status is required")?,
            recommendations: self.recommendations,
        })
    }
}

impl ScanReport {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_text(&self) -> String {
        let mut output = String::new();
        
        output.push_str("=".repeat(80).as_str());
        output.push('\n');
        output.push_str(&format!("SECURITY SCAN REPORT - {}\n", self.metadata.report_id));
        output.push_str("=".repeat(80).as_str());
        output.push('\n');
        output.push('\n');

        output.push_str(&format!("Generated: {}\n", self.metadata.generated_at));
        output.push_str(&format!("Scan Duration: {} to {}\n", 
            self.metadata.scan_start, self.metadata.scan_end));
        output.push('\n');

        output.push_str("EXECUTIVE SUMMARY\n");
        output.push_str("-".repeat(80).as_str());
        output.push('\n');
        output.push_str(&format!("Total Hosts: {}\n", self.executive_summary.total_hosts));
        output.push_str(&format!("Hosts Up: {}\n", self.executive_summary.hosts_up));
        output.push_str(&format!("Open Ports: {}/{}\n", 
            self.executive_summary.open_ports, self.executive_summary.total_ports));
        output.push_str(&format!("Risk Score: {:.1}/10\n", self.executive_summary.risk_score));
        output.push_str(&format!("Compliance Score: {:.1}%\n", self.executive_summary.compliance_score));
        output.push('\n');

        output.push_str("VULNERABILITIES\n");
        output.push_str("-".repeat(80).as_str());
        output.push('\n');
        let vuln = &self.executive_summary.vulnerabilities;
        output.push_str(&format!("  Critical: {}\n", vuln.critical));
        output.push_str(&format!("  High: {}\n", vuln.high));
        output.push_str(&format!("  Medium: {}\n", vuln.medium));
        output.push_str(&format!("  Low: {}\n", vuln.low));
        output.push_str(&format!("  Info: {}\n", vuln.info));
        output.push('\n');

        if !self.findings.is_empty() {
            output.push_str("FINDINGS\n");
            output.push_str("-".repeat(80).as_str());
            output.push('\n');
            for finding in &self.findings {
                output.push_str(&format!("[{:?}] {}\n", finding.severity, finding.title));
                output.push_str(&format!("  Affected: {} hosts\n", finding.affected_hosts.len()));
                if let Some(cvss) = finding.cvss_score {
                    output.push_str(&format!("  CVSS: {:.1}\n", cvss));
                }
                output.push('\n');
            }
        }

        output
    }

    pub fn to_csv(&self) -> String {
        let mut output = String::new();

        // Header section
        output.push_str("# Report Metadata\n");
        output.push_str(&format!("Report ID,{}\n", self.metadata.report_id));
        output.push_str(&format!("Scan ID,{}\n", self.metadata.scan_id));
        output.push_str(&format!("Generated,{}\n", self.metadata.generated_at.format("%Y-%m-%d %H:%M:%S UTC")));
        output.push_str(&format!("Targets,{}\n", self.metadata.target_count));
        output.push('\n');

        // Summary section
        output.push_str("# Executive Summary\n");
        output.push_str(&format!("Total Hosts,{}\n", self.executive_summary.total_hosts));
        output.push_str(&format!("Hosts Up,{}\n", self.executive_summary.hosts_up));
        output.push_str(&format!("Open Ports,{}/{}\n", self.executive_summary.open_ports, self.executive_summary.total_ports));
        output.push_str(&format!("Risk Score,{:.1}\n", self.executive_summary.risk_score));
        output.push_str(&format!("Compliance Score,{:.1}%\n", self.executive_summary.compliance_score));
        output.push_str(&format!("Critical Vulns,{}\n", self.executive_summary.vulnerabilities.critical));
        output.push_str(&format!("High Vulns,{}\n", self.executive_summary.vulnerabilities.high));
        output.push_str(&format!("Medium Vulns,{}\n", self.executive_summary.vulnerabilities.medium));
        output.push_str(&format!("Low Vulns,{}\n", self.executive_summary.vulnerabilities.low));
        output.push('\n');

        // Findings
        output.push_str("ID,Severity,Title,Affected Hosts,CVSS,CVE IDs,Remediation\n");
        for finding in &self.findings {
            let hosts = finding.affected_hosts.join(";");
            let cves = finding.cve_ids.join(";");
            let cvss = finding.cvss_score.map_or("-".to_string(), |s| format!("{:.1}", s));
            let remediation = finding.remediation.replace(',', ";").replace('\n', " ");
            output.push_str(&format!(
                "{},{:?},{},{},{},{},{}\n",
                finding.id, finding.severity, finding.title, hosts, cvss, cves, remediation
            ));
        }

        // Recommendations
        if !self.recommendations.is_empty() {
            output.push('\n');
            output.push_str("# Recommendations\n");
            output.push_str("Priority,Category,Title,Impact,Effort\n");
            for rec in &self.recommendations {
                output.push_str(&format!(
                    "{:?},{},{},{},{}\n",
                    rec.priority, rec.category, rec.title, rec.impact, rec.effort
                ));
            }
        }

        output
    }

    pub fn to_xml(&self) -> String {
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<security_report>\n");
        xml.push_str(&format!("  <metadata>\n    <report_id>{}</report_id>\n    <scan_id>{}</scan_id>\n", self.metadata.report_id, self.metadata.scan_id));
        xml.push_str(&format!("    <generated_at>{}</generated_at>\n    <version>{}</version>\n  </metadata>\n", self.metadata.generated_at.format("%Y-%m-%dT%H:%M:%SZ"), self.metadata.version));

        xml.push_str("  <executive_summary>\n");
        xml.push_str(&format!("    <total_hosts>{}</total_hosts>\n", self.executive_summary.total_hosts));
        xml.push_str(&format!("    <hosts_up>{}</hosts_up>\n", self.executive_summary.hosts_up));
        xml.push_str(&format!("    <open_ports>{}</open_ports>\n", self.executive_summary.open_ports));
        xml.push_str(&format!("    <risk_score>{:.1}</risk_score>\n", self.executive_summary.risk_score));
        xml.push_str(&format!("    <compliance_score>{:.1}</compliance_score>\n", self.executive_summary.compliance_score));
        xml.push_str(&format!("    <vulnerabilities critical=\"{}\" high=\"{}\" medium=\"{}\" low=\"{}\" info=\"{}\" />\n",
            self.executive_summary.vulnerabilities.critical,
            self.executive_summary.vulnerabilities.high,
            self.executive_summary.vulnerabilities.medium,
            self.executive_summary.vulnerabilities.low,
            self.executive_summary.vulnerabilities.info));
        xml.push_str("  </executive_summary>\n");

        xml.push_str("  <findings>\n");
        for finding in &self.findings {
            xml.push_str(&format!("    <finding id=\"{}\">\n", finding.id));
            xml.push_str(&format!("      <severity>{:?}</severity>\n", finding.severity));
            xml.push_str(&format!("      <title>{}</title>\n", Self::xml_escape(&finding.title)));
            xml.push_str(&format!("      <description>{}</description>\n", Self::xml_escape(&finding.description)));
            for host in &finding.affected_hosts {
                xml.push_str(&format!("      <affected_host>{}</affected_host>\n", host));
            }
            if let Some(cvss) = finding.cvss_score {
                xml.push_str(&format!("      <cvss_score>{:.1}</cvss_score>\n", cvss));
            }
            for cve in &finding.cve_ids {
                xml.push_str(&format!("      <cve_id>{}</cve_id>\n", cve));
            }
            xml.push_str(&format!("      <remediation>{}</remediation>\n", Self::xml_escape(&finding.remediation)));
            xml.push_str("    </finding>\n");
        }
        xml.push_str("  </findings>\n");

        xml.push_str(&format!("  <compliance overall_score=\"{:.1}\">\n", self.compliance.overall_score));
        for fw in &self.compliance.frameworks {
            xml.push_str(&format!("    <framework name=\"{}\" version=\"{}\" score=\"{:.1}\" passing=\"{}\" failing=\"{}\" />\n",
                Self::xml_escape(&fw.name), fw.version, fw.score, fw.controls_passing, fw.controls_failing));
        }
        xml.push_str("  </compliance>\n");

        xml.push_str("  <recommendations>\n");
        for rec in &self.recommendations {
            xml.push_str(&format!("    <recommendation priority=\"{:?}\">\n", rec.priority));
            xml.push_str(&format!("      <category>{}</category>\n", Self::xml_escape(&rec.category)));
            xml.push_str(&format!("      <title>{}</title>\n", Self::xml_escape(&rec.title)));
            xml.push_str(&format!("      <impact>{}</impact>\n", Self::xml_escape(&rec.impact)));
            xml.push_str(&format!("      <effort>{}</effort>\n", Self::xml_escape(&rec.effort)));
            xml.push_str("    </recommendation>\n");
        }
        xml.push_str("  </recommendations>\n");
        xml.push_str("</security_report>\n");
        xml
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> ReportMetadata {
        ReportMetadata {
            scan_id: "scan-001".to_string(),
            report_id: "report-001".to_string(),
            generated_at: Utc::now(),
            scan_start: Utc::now(),
            scan_end: Utc::now(),
            target_count: 10,
            version: "0.1.0".to_string(),
        }
    }

    fn sample_summary() -> ExecutiveSummary {
        ExecutiveSummary {
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
        }
    }

    #[test]
    fn test_report_builder() {
        let report = ReportBuilder::new()
            .metadata(sample_metadata())
            .summary(sample_summary())
            .compliance(ComplianceStatus {
                frameworks: vec![],
                overall_score: 75.0,
            })
            .build();

        assert!(report.is_ok());
        let report = report.unwrap();
        assert_eq!(report.metadata.scan_id, "scan-001");
        assert_eq!(report.executive_summary.total_hosts, 10);
    }

    #[test]
    fn test_report_builder_missing_fields() {
        let report = ReportBuilder::new()
            .metadata(sample_metadata())
            .build();

        assert!(report.is_err());
    }

    #[test]
    fn test_add_finding() {
        let finding = Finding {
            id: "finding-001".to_string(),
            severity: Severity::High,
            title: "Test Finding".to_string(),
            description: "Test description".to_string(),
            affected_hosts: vec!["192.168.1.1".to_string()],
            cvss_score: Some(7.5),
            cve_ids: vec!["CVE-2021-1234".to_string()],
            remediation: "Test remediation".to_string(),
        };

        let report = ReportBuilder::new()
            .metadata(sample_metadata())
            .summary(sample_summary())
            .compliance(ComplianceStatus {
                frameworks: vec![],
                overall_score: 75.0,
            })
            .add_finding(finding)
            .build()
            .unwrap();

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].title, "Test Finding");
    }

    #[test]
    fn test_to_json() {
        let report = ReportBuilder::new()
            .metadata(sample_metadata())
            .summary(sample_summary())
            .compliance(ComplianceStatus {
                frameworks: vec![],
                overall_score: 75.0,
            })
            .build()
            .unwrap();

        let json = report.to_json();
        assert!(json.is_ok());
        assert!(json.unwrap().contains("scan-001"));
    }

    #[test]
    fn test_to_text() {
        let report = ReportBuilder::new()
            .metadata(sample_metadata())
            .summary(sample_summary())
            .compliance(ComplianceStatus {
                frameworks: vec![],
                overall_score: 75.0,
            })
            .build()
            .unwrap();

        let text = report.to_text();
        assert!(text.contains("SECURITY SCAN REPORT"));
        assert!(text.contains("EXECUTIVE SUMMARY"));
        assert!(text.contains("VULNERABILITIES"));
    }

    #[test]
    fn test_to_csv() {
        let finding = Finding {
            id: "finding-001".to_string(),
            severity: Severity::Critical,
            title: "Critical Issue".to_string(),
            description: "Test".to_string(),
            affected_hosts: vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()],
            cvss_score: Some(9.8),
            cve_ids: vec!["CVE-2021-1234".to_string()],
            remediation: "Fix it".to_string(),
        };

        let report = ReportBuilder::new()
            .metadata(sample_metadata())
            .summary(sample_summary())
            .compliance(ComplianceStatus {
                frameworks: vec![],
                overall_score: 75.0,
            })
            .add_finding(finding)
            .add_recommendation(Recommendation {
                priority: Priority::Critical,
                category: "Patch".to_string(),
                title: "Apply security patch".to_string(),
                description: "Install latest patches".to_string(),
                impact: "High".to_string(),
                effort: "Low".to_string(),
            })
            .build()
            .unwrap();

        let csv = report.to_csv();
        assert!(csv.contains("ID,Severity,Title"));
        assert!(csv.contains("Critical,Critical Issue"));
        assert!(csv.contains("9.8"));
        assert!(csv.contains("Report ID"));
        assert!(csv.contains("Executive Summary"));
        assert!(csv.contains("Recommendations"));
        assert!(csv.contains("Apply security patch"));
    }

    #[test]
    fn test_to_xml() {
        let finding = Finding {
            id: "finding-001".to_string(),
            severity: Severity::Critical,
            title: "Test <finding>".to_string(),
            description: "Desc".to_string(),
            affected_hosts: vec!["10.0.0.1".to_string()],
            cvss_score: Some(9.8),
            cve_ids: vec!["CVE-2021-1234".to_string()],
            remediation: "Fix & patch".to_string(),
        };

        let report = ReportBuilder::new()
            .metadata(sample_metadata())
            .summary(sample_summary())
            .compliance(ComplianceStatus {
                frameworks: vec![ComplianceFramework {
                    name: "PCI-DSS".to_string(),
                    version: "4.0".to_string(),
                    controls_total: 10,
                    controls_passing: 8,
                    controls_failing: 2,
                    score: 80.0,
                    findings: vec![],
                }],
                overall_score: 80.0,
            })
            .add_finding(finding)
            .build()
            .unwrap();

        let xml = report.to_xml();
        assert!(xml.contains("<?xml version=\"1.0\""));
        assert!(xml.contains("<security_report>"));
        assert!(xml.contains("<severity>Critical</severity>"));
        assert!(xml.contains("&lt;finding&gt;"));
        assert!(xml.contains("Fix &amp; patch"));
        assert!(xml.contains("<framework name=\"PCI-DSS\""));
        assert!(xml.contains("</security_report>"));
    }
}
