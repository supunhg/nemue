// Template engine for custom report generation
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TemplateEngine {
    templates: HashMap<String, ReportTemplate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportTemplate {
    pub name: String,
    pub description: String,
    pub sections: Vec<TemplateSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSection {
    pub title: String,
    pub content_type: ContentType,
    pub filters: Vec<String>,
    pub sort_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContentType {
    Summary,
    Findings,
    Compliance,
    Recommendations,
    Metrics,
    Custom(String),
}

impl Default for TemplateEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            templates: HashMap::new(),
        };

        engine.add_template(Self::executive_template());
        engine.add_template(Self::technical_template());
        engine.add_template(Self::compliance_template());
        engine.add_template(Self::security_assessment_template());
        engine.add_template(Self::compliance_audit_template());
        engine.add_template(Self::penetration_test_template());
        engine.add_template(Self::vulnerability_assessment_template());
        engine
    }

    pub fn add_template(&mut self, template: ReportTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    pub fn get_template(&self, name: &str) -> Option<&ReportTemplate> {
        self.templates.get(name)
    }

    pub fn list_templates(&self) -> Vec<String> {
        self.templates.keys().cloned().collect()
    }

    fn executive_template() -> ReportTemplate {
        ReportTemplate {
            name: "Executive Summary".to_string(),
            description: "High-level overview for executives and management".to_string(),
            sections: vec![
                TemplateSection {
                    title: "Executive Summary".to_string(),
                    content_type: ContentType::Summary,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Critical Findings".to_string(),
                    content_type: ContentType::Findings,
                    filters: vec!["severity:critical".to_string(), "severity:high".to_string()],
                    sort_by: Some("severity".to_string()),
                },
                TemplateSection {
                    title: "Compliance Status".to_string(),
                    content_type: ContentType::Compliance,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Recommendations".to_string(),
                    content_type: ContentType::Recommendations,
                    filters: vec!["priority:critical".to_string(), "priority:high".to_string()],
                    sort_by: Some("priority".to_string()),
                },
            ],
        }
    }

    fn technical_template() -> ReportTemplate {
        ReportTemplate {
            name: "Technical Report".to_string(),
            description: "Detailed technical analysis for security teams".to_string(),
            sections: vec![
                TemplateSection {
                    title: "Scan Overview".to_string(),
                    content_type: ContentType::Summary,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "All Findings".to_string(),
                    content_type: ContentType::Findings,
                    filters: vec![],
                    sort_by: Some("severity".to_string()),
                },
                TemplateSection {
                    title: "Performance Metrics".to_string(),
                    content_type: ContentType::Metrics,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Detailed Recommendations".to_string(),
                    content_type: ContentType::Recommendations,
                    filters: vec![],
                    sort_by: Some("priority".to_string()),
                },
            ],
        }
    }

    fn compliance_template() -> ReportTemplate {
        ReportTemplate {
            name: "Compliance Report".to_string(),
            description: "Compliance-focused report for auditors".to_string(),
            sections: vec![
                TemplateSection {
                    title: "Compliance Overview".to_string(),
                    content_type: ContentType::Compliance,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Non-Compliant Findings".to_string(),
                    content_type: ContentType::Findings,
                    filters: vec!["compliance:fail".to_string()],
                    sort_by: Some("severity".to_string()),
                },
                TemplateSection {
                    title: "Remediation Plan".to_string(),
                    content_type: ContentType::Recommendations,
                    filters: vec!["compliance:fail".to_string()],
                    sort_by: Some("priority".to_string()),
                },
            ],
        }
    }

    pub fn security_assessment_template() -> ReportTemplate {
        ReportTemplate {
            name: "Security Assessment".to_string(),
            description: "Comprehensive security posture assessment with risk analysis".to_string(),
            sections: vec![
                TemplateSection {
                    title: "Assessment Overview".to_string(),
                    content_type: ContentType::Summary,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Risk Analysis".to_string(),
                    content_type: ContentType::Metrics,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Critical & High Findings".to_string(),
                    content_type: ContentType::Findings,
                    filters: vec!["severity:critical".to_string(), "severity:high".to_string()],
                    sort_by: Some("severity".to_string()),
                },
                TemplateSection {
                    title: "All Findings".to_string(),
                    content_type: ContentType::Findings,
                    filters: vec![],
                    sort_by: Some("severity".to_string()),
                },
                TemplateSection {
                    title: "Compliance Mapping".to_string(),
                    content_type: ContentType::Compliance,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Remediation Roadmap".to_string(),
                    content_type: ContentType::Recommendations,
                    filters: vec![],
                    sort_by: Some("priority".to_string()),
                },
            ],
        }
    }

    pub fn compliance_audit_template() -> ReportTemplate {
        ReportTemplate {
            name: "Compliance Audit".to_string(),
            description: "Formal compliance audit report with control evidence and gaps"
                .to_string(),
            sections: vec![
                TemplateSection {
                    title: "Audit Scope & Methodology".to_string(),
                    content_type: ContentType::Summary,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Control Assessment Results".to_string(),
                    content_type: ContentType::Compliance,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Gap Analysis".to_string(),
                    content_type: ContentType::Findings,
                    filters: vec!["compliance:fail".to_string()],
                    sort_by: Some("severity".to_string()),
                },
                TemplateSection {
                    title: "Evidence Summary".to_string(),
                    content_type: ContentType::Metrics,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Corrective Action Plan".to_string(),
                    content_type: ContentType::Recommendations,
                    filters: vec![],
                    sort_by: Some("priority".to_string()),
                },
            ],
        }
    }

    pub fn penetration_test_template() -> ReportTemplate {
        ReportTemplate {
            name: "Penetration Test".to_string(),
            description: "Penetration test findings with exploitation details and attack paths"
                .to_string(),
            sections: vec![
                TemplateSection {
                    title: "Executive Overview".to_string(),
                    content_type: ContentType::Summary,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Attack Path Summary".to_string(),
                    content_type: ContentType::Metrics,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Exploitable Vulnerabilities".to_string(),
                    content_type: ContentType::Findings,
                    filters: vec![],
                    sort_by: Some("severity".to_string()),
                },
                TemplateSection {
                    title: "Hosts Compromised".to_string(),
                    content_type: ContentType::Findings,
                    filters: vec!["severity:critical".to_string(), "severity:high".to_string()],
                    sort_by: Some("severity".to_string()),
                },
                TemplateSection {
                    title: "Remediation & Hardening".to_string(),
                    content_type: ContentType::Recommendations,
                    filters: vec![],
                    sort_by: Some("priority".to_string()),
                },
            ],
        }
    }

    pub fn vulnerability_assessment_template() -> ReportTemplate {
        ReportTemplate {
            name: "Vulnerability Assessment".to_string(),
            description: "Focused vulnerability assessment with CVSS scoring and prioritization"
                .to_string(),
            sections: vec![
                TemplateSection {
                    title: "Assessment Summary".to_string(),
                    content_type: ContentType::Summary,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Vulnerability Distribution".to_string(),
                    content_type: ContentType::Metrics,
                    filters: vec![],
                    sort_by: None,
                },
                TemplateSection {
                    title: "Critical Vulnerabilities".to_string(),
                    content_type: ContentType::Findings,
                    filters: vec!["severity:critical".to_string()],
                    sort_by: Some("cvss".to_string()),
                },
                TemplateSection {
                    title: "High Vulnerabilities".to_string(),
                    content_type: ContentType::Findings,
                    filters: vec!["severity:high".to_string()],
                    sort_by: Some("cvss".to_string()),
                },
                TemplateSection {
                    title: "Medium & Low Vulnerabilities".to_string(),
                    content_type: ContentType::Findings,
                    filters: vec!["severity:medium".to_string(), "severity:low".to_string()],
                    sort_by: Some("cvss".to_string()),
                },
                TemplateSection {
                    title: "Prioritized Remediation".to_string(),
                    content_type: ContentType::Recommendations,
                    filters: vec![],
                    sort_by: Some("priority".to_string()),
                },
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_engine_creation() {
        let engine = TemplateEngine::new();
        assert_eq!(engine.templates.len(), 7);
    }

    #[test]
    fn test_list_templates() {
        let engine = TemplateEngine::new();
        let templates = engine.list_templates();
        assert!(templates.contains(&"Executive Summary".to_string()));
        assert!(templates.contains(&"Technical Report".to_string()));
        assert!(templates.contains(&"Compliance Report".to_string()));
        assert!(templates.contains(&"Security Assessment".to_string()));
        assert!(templates.contains(&"Compliance Audit".to_string()));
        assert!(templates.contains(&"Penetration Test".to_string()));
        assert!(templates.contains(&"Vulnerability Assessment".to_string()));
    }

    #[test]
    fn test_get_template() {
        let engine = TemplateEngine::new();
        let template = engine.get_template("Executive Summary");
        assert!(template.is_some());

        let template = template.unwrap();
        assert_eq!(template.name, "Executive Summary");
        assert_eq!(template.sections.len(), 4);
    }

    #[test]
    fn test_executive_template() {
        let template = TemplateEngine::executive_template();
        assert_eq!(template.name, "Executive Summary");
        assert_eq!(template.sections.len(), 4);
        assert_eq!(template.sections[0].content_type, ContentType::Summary);
    }

    #[test]
    fn test_technical_template() {
        let template = TemplateEngine::technical_template();
        assert_eq!(template.name, "Technical Report");
        assert_eq!(template.sections.len(), 4);
    }

    #[test]
    fn test_compliance_template() {
        let template = TemplateEngine::compliance_template();
        assert_eq!(template.name, "Compliance Report");
        assert_eq!(template.sections.len(), 3);
    }

    #[test]
    fn test_add_custom_template() {
        let mut engine = TemplateEngine::new();

        let custom_template = ReportTemplate {
            name: "Custom Template".to_string(),
            description: "A custom template".to_string(),
            sections: vec![TemplateSection {
                title: "Custom Section".to_string(),
                content_type: ContentType::Custom("custom".to_string()),
                filters: vec![],
                sort_by: None,
            }],
        };

        engine.add_template(custom_template);
        assert_eq!(engine.templates.len(), 8);
        assert!(engine.get_template("Custom Template").is_some());
    }

    #[test]
    fn test_template_sections() {
        let template = TemplateEngine::executive_template();

        let critical_findings = &template.sections[1];
        assert_eq!(critical_findings.title, "Critical Findings");
        assert_eq!(critical_findings.content_type, ContentType::Findings);
        assert_eq!(critical_findings.filters.len(), 2);
        assert_eq!(critical_findings.sort_by, Some("severity".to_string()));
    }

    #[test]
    fn test_security_assessment_template() {
        let template = TemplateEngine::security_assessment_template();
        assert_eq!(template.name, "Security Assessment");
        assert_eq!(template.sections.len(), 6);
        assert_eq!(template.sections[0].content_type, ContentType::Summary);
        assert_eq!(template.sections[1].content_type, ContentType::Metrics);
        assert_eq!(template.sections[2].content_type, ContentType::Findings);
        assert_eq!(template.sections[4].content_type, ContentType::Compliance);
        assert_eq!(
            template.sections[5].content_type,
            ContentType::Recommendations
        );
    }

    #[test]
    fn test_compliance_audit_template() {
        let template = TemplateEngine::compliance_audit_template();
        assert_eq!(template.name, "Compliance Audit");
        assert_eq!(template.sections.len(), 5);
        assert_eq!(template.sections[0].title, "Audit Scope & Methodology");
        assert_eq!(template.sections[1].title, "Control Assessment Results");
        assert_eq!(template.sections[2].title, "Gap Analysis");
        assert_eq!(template.sections[3].title, "Evidence Summary");
        assert_eq!(template.sections[4].title, "Corrective Action Plan");
    }

    #[test]
    fn test_penetration_test_template() {
        let template = TemplateEngine::penetration_test_template();
        assert_eq!(template.name, "Penetration Test");
        assert_eq!(template.sections.len(), 5);
        assert_eq!(template.sections[0].title, "Executive Overview");
        assert_eq!(template.sections[2].title, "Exploitable Vulnerabilities");
        assert_eq!(template.sections[3].title, "Hosts Compromised");
    }

    #[test]
    fn test_vulnerability_assessment_template() {
        let template = TemplateEngine::vulnerability_assessment_template();
        assert_eq!(template.name, "Vulnerability Assessment");
        assert_eq!(template.sections.len(), 6);
        assert_eq!(template.sections[0].title, "Assessment Summary");
        assert_eq!(template.sections[2].title, "Critical Vulnerabilities");
        assert_eq!(template.sections[3].title, "High Vulnerabilities");
        assert_eq!(template.sections[4].title, "Medium & Low Vulnerabilities");
        assert_eq!(template.sections[5].title, "Prioritized Remediation");
    }
}
