// Template engine for custom report generation
use serde::{Serialize, Deserialize};
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

impl TemplateEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            templates: HashMap::new(),
        };
        
        // Add default templates
        engine.add_template(Self::executive_template());
        engine.add_template(Self::technical_template());
        engine.add_template(Self::compliance_template());
        
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_engine_creation() {
        let engine = TemplateEngine::new();
        assert_eq!(engine.templates.len(), 3);
    }

    #[test]
    fn test_list_templates() {
        let engine = TemplateEngine::new();
        let templates = engine.list_templates();
        assert!(templates.contains(&"Executive Summary".to_string()));
        assert!(templates.contains(&"Technical Report".to_string()));
        assert!(templates.contains(&"Compliance Report".to_string()));
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
            sections: vec![
                TemplateSection {
                    title: "Custom Section".to_string(),
                    content_type: ContentType::Custom("custom".to_string()),
                    filters: vec![],
                    sort_by: None,
                },
            ],
        };

        engine.add_template(custom_template);
        assert_eq!(engine.templates.len(), 4);
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
}
