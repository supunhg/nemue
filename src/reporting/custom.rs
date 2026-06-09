// Report customization: sections, branding, severity levels, recommendations
use serde::{Serialize, Deserialize};
use crate::reporting::Priority;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportCustomization {
    pub branding: Branding,
    pub severity_levels: Vec<CustomSeverity>,
    pub custom_sections: Vec<CustomSection>,
    pub custom_recommendations: Vec<CustomRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branding {
    pub organization_name: String,
    pub logo_url: Option<String>,
    pub primary_color: String,
    pub secondary_color: String,
    pub footer_text: String,
    pub header_text: Option<String>,
    pub confidential: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSeverity {
    pub level: String,
    pub label: String,
    pub color: String,
    pub score_range_min: f64,
    pub score_range_max: f64,
    pub icon: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSection {
    pub id: String,
    pub title: String,
    pub order: usize,
    pub content: SectionContent,
    pub visible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SectionContent {
    Text(String),
    Markdown(String),
    KeyValue(Vec<(String, String)>),
    Table { headers: Vec<String>, rows: Vec<Vec<String>> },
    Chart { chart_type: ChartType, data: Vec<(String, f64)> },
    FindingSummary,
    ComplianceOverview,
    RiskMatrix,
    CustomHtml(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChartType {
    Bar,
    Pie,
    Line,
    Donut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRecommendation {
    pub category: String,
    pub priority: Priority,
    pub title: String,
    pub description: String,
    pub remediation_steps: Vec<String>,
    pub references: Vec<String>,
    pub estimated_effort: String,
    pub business_impact: String,
}

impl ReportCustomization {
    pub fn new(organization_name: &str) -> Self {
        Self {
            branding: Branding {
                organization_name: organization_name.to_string(),
                logo_url: None,
                primary_color: "#007bff".to_string(),
                secondary_color: "#6c757d".to_string(),
                footer_text: format!("{} - Confidential Security Report", organization_name),
                header_text: None,
                confidential: true,
            },
            severity_levels: Self::default_severity_levels(),
            custom_sections: Vec::new(),
            custom_recommendations: Vec::new(),
        }
    }

    pub fn default_severity_levels() -> Vec<CustomSeverity> {
        vec![
            CustomSeverity {
                level: "critical".to_string(),
                label: "Critical".to_string(),
                color: "#dc3545".to_string(),
                score_range_min: 9.0,
                score_range_max: 10.0,
                icon: Some("🔴".to_string()),
            },
            CustomSeverity {
                level: "high".to_string(),
                label: "High".to_string(),
                color: "#fd7e14".to_string(),
                score_range_min: 7.0,
                score_range_max: 8.9,
                icon: Some("🟠".to_string()),
            },
            CustomSeverity {
                level: "medium".to_string(),
                label: "Medium".to_string(),
                color: "#ffc107".to_string(),
                score_range_min: 4.0,
                score_range_max: 6.9,
                icon: Some("🟡".to_string()),
            },
            CustomSeverity {
                level: "low".to_string(),
                label: "Low".to_string(),
                color: "#28a745".to_string(),
                score_range_min: 0.1,
                score_range_max: 3.9,
                icon: Some("🟢".to_string()),
            },
            CustomSeverity {
                level: "info".to_string(),
                label: "Informational".to_string(),
                color: "#17a2b8".to_string(),
                score_range_min: 0.0,
                score_range_max: 0.0,
                icon: Some("🔵".to_string()),
            },
        ]
    }

    pub fn set_branding(&mut self, branding: Branding) {
        self.branding = branding;
    }

    pub fn add_custom_severity(&mut self, severity: CustomSeverity) {
        self.severity_levels.push(severity);
    }

    pub fn add_section(&mut self, section: CustomSection) {
        self.custom_sections.push(section);
        self.custom_sections.sort_by_key(|s| s.order);
    }

    pub fn add_recommendation(&mut self, recommendation: CustomRecommendation) {
        self.custom_recommendations.push(recommendation);
    }

    pub fn get_severity_for_score(&self, score: f64) -> Option<&CustomSeverity> {
        self.severity_levels.iter().find(|s| score >= s.score_range_min && score <= s.score_range_max)
    }

    pub fn get_section(&self, id: &str) -> Option<&CustomSection> {
        self.custom_sections.iter().find(|s| s.id == id)
    }

    pub fn remove_section(&mut self, id: &str) {
        self.custom_sections.retain(|s| s.id != id);
    }

    pub fn sections_ordered(&self) -> Vec<&CustomSection> {
        let mut sections: Vec<&CustomSection> = self.custom_sections.iter().collect();
        sections.sort_by_key(|s| s.order);
        sections
    }

    pub fn render_section_html(&self, section: &CustomSection) -> String {
        if !section.visible {
            return String::new();
        }
        let mut html = format!("  <div class=\"custom-section\" id=\"{}\">\n", section.id);
        html.push_str(&format!("    <h2>{}</h2>\n", section.title));
        match &section.content {
            SectionContent::Text(text) => {
                html.push_str(&format!("    <p>{}</p>\n", text));
            }
            SectionContent::Markdown(md) => {
                html.push_str(&format!("    <div class=\"markdown\">{}</div>\n", Self::simple_md_to_html(md)));
            }
            SectionContent::KeyValue(pairs) => {
                html.push_str("    <dl>\n");
                for (key, value) in pairs {
                    html.push_str(&format!("      <dt><strong>{}</strong></dt><dd>{}</dd>\n", key, value));
                }
                html.push_str("    </dl>\n");
            }
            SectionContent::Table { headers, rows } => {
                html.push_str("    <table>\n      <tr>");
                for h in headers {
                    html.push_str(&format!("<th>{}</th>", h));
                }
                html.push_str("</tr>\n");
                for row in rows {
                    html.push_str("      <tr>");
                    for cell in row {
                        html.push_str(&format!("<td>{}</td>", cell));
                    }
                    html.push_str("</tr>\n");
                }
                html.push_str("    </table>\n");
            }
            SectionContent::Chart { chart_type, data } => {
                html.push_str(&Self::render_chart_html(chart_type, data));
            }
            SectionContent::FindingSummary => {
                html.push_str("    <p class=\"placeholder\">[Finding summary rendered from report data]</p>\n");
            }
            SectionContent::ComplianceOverview => {
                html.push_str("    <p class=\"placeholder\">[Compliance overview rendered from report data]</p>\n");
            }
            SectionContent::RiskMatrix => {
                html.push_str("    <p class=\"placeholder\">[Risk matrix rendered from report data]</p>\n");
            }
            SectionContent::CustomHtml(inner_html) => {
                html.push_str(inner_html);
            }
        }
        html.push_str("  </div>\n");
        html
    }

    fn simple_md_to_html(md: &str) -> String {
        let mut html = String::new();
        for line in md.lines() {
            if line.starts_with("### ") {
                html.push_str(&format!("<h3>{}</h3>\n", &line[4..]));
            } else if line.starts_with("## ") {
                html.push_str(&format!("<h2>{}</h2>\n", &line[3..]));
            } else if line.starts_with("# ") {
                html.push_str(&format!("<h1>{}</h1>\n", &line[2..]));
            } else if line.starts_with("- ") {
                html.push_str(&format!("<li>{}</li>\n", &line[2..]));
            } else if line.starts_with("**") && line.ends_with("**") {
                html.push_str(&format!("<p><strong>{}</strong></p>\n", &line[2..line.len()-2]));
            } else if line.is_empty() {
                html.push('\n');
            } else {
                html.push_str(&format!("<p>{}</p>\n", line));
            }
        }
        html
    }

    fn render_chart_html(chart_type: &ChartType, data: &[(String, f64)]) -> String {
        let mut html = String::from("    <div class=\"chart\">\n");
        let max_val = data.iter().map(|(_, v)| *v).fold(0.0_f64, f64::max);
        match chart_type {
            ChartType::Bar | ChartType::Line => {
                html.push_str("      <div class=\"bar-chart\" style=\"display:flex;align-items:flex-end;height:150px;gap:8px;\">\n");
                for (label, value) in data {
                    let height = if max_val > 0.0 { (value / max_val * 140.0) as u32 } else { 0 };
                    html.push_str(&format!(
                        "        <div style=\"display:flex;flex-direction:column;align-items:center;\">\n\
                         \x20         <div style=\"background:#007bff;width:30px;height:{}px;\"></div>\n\
                         \x20         <small>{}</small><small>{:.1}</small>\n\
                         \x20       </div>\n",
                        height, label, value
                    ));
                }
                html.push_str("      </div>\n");
            }
            ChartType::Pie | ChartType::Donut => {
                let total: f64 = data.iter().map(|(_, v)| v).sum();
                html.push_str("      <table>\n");
                for (label, value) in data {
                    let pct = if total > 0.0 { value / total * 100.0 } else { 0.0 };
                    html.push_str(&format!("        <tr><td>{}</td><td>{:.1}</td><td>{:.1}%</td></tr>\n", label, value, pct));
                }
                html.push_str("      </table>\n");
            }
        }
        html.push_str("    </div>\n");
        html
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl CustomSection {
    pub fn text(id: &str, title: &str, order: usize, text: &str) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            order,
            content: SectionContent::Text(text.to_string()),
            visible: true,
        }
    }

    pub fn markdown(id: &str, title: &str, order: usize, md: &str) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            order,
            content: SectionContent::Markdown(md.to_string()),
            visible: true,
        }
    }

    pub fn table(id: &str, title: &str, order: usize, headers: Vec<String>, rows: Vec<Vec<String>>) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            order,
            content: SectionContent::Table { headers, rows },
            visible: true,
        }
    }

    pub fn chart(id: &str, title: &str, order: usize, chart_type: ChartType, data: Vec<(String, f64)>) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            order,
            content: SectionContent::Chart { chart_type, data },
            visible: true,
        }
    }

    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_customization_creation() {
        let custom = ReportCustomization::new("Acme Corp");
        assert_eq!(custom.branding.organization_name, "Acme Corp");
        assert_eq!(custom.severity_levels.len(), 5);
        assert!(custom.custom_sections.is_empty());
    }

    #[test]
    fn test_default_severity_levels() {
        let levels = ReportCustomization::default_severity_levels();
        assert_eq!(levels.len(), 5);
        assert_eq!(levels[0].level, "critical");
        assert_eq!(levels[4].level, "info");
    }

    #[test]
    fn test_get_severity_for_score() {
        let custom = ReportCustomization::new("Test");
        let sev = custom.get_severity_for_score(9.5);
        assert!(sev.is_some());
        assert_eq!(sev.unwrap().level, "critical");

        let sev = custom.get_severity_for_score(5.0);
        assert!(sev.is_some());
        assert_eq!(sev.unwrap().level, "medium");

        let sev = custom.get_severity_for_score(0.0);
        assert!(sev.is_some());
        assert_eq!(sev.unwrap().level, "info");
    }

    #[test]
    fn test_add_section() {
        let mut custom = ReportCustomization::new("Test");
        custom.add_section(CustomSection::text("s1", "Section 1", 1, "Hello"));
        assert_eq!(custom.custom_sections.len(), 1);
        assert_eq!(custom.get_section("s1").unwrap().title, "Section 1");
    }

    #[test]
    fn test_remove_section() {
        let mut custom = ReportCustomization::new("Test");
        custom.add_section(CustomSection::text("s1", "Section 1", 1, "Hello"));
        custom.remove_section("s1");
        assert!(custom.custom_sections.is_empty());
    }

    #[test]
    fn test_sections_ordered() {
        let mut custom = ReportCustomization::new("Test");
        custom.add_section(CustomSection::text("s2", "Second", 2, "B"));
        custom.add_section(CustomSection::text("s1", "First", 1, "A"));
        let ordered = custom.sections_ordered();
        assert_eq!(ordered[0].title, "First");
        assert_eq!(ordered[1].title, "Second");
    }

    #[test]
    fn test_render_text_section_html() {
        let custom = ReportCustomization::new("Test");
        let section = CustomSection::text("s1", "Test", 1, "Hello World");
        let html = custom.render_section_html(&section);
        assert!(html.contains("Hello World"));
        assert!(html.contains("Test"));
    }

    #[test]
    fn test_render_table_section_html() {
        let custom = ReportCustomization::new("Test");
        let section = CustomSection::table(
            "t1", "Table", 1,
            vec!["A".to_string(), "B".to_string()],
            vec![vec!["1".to_string(), "2".to_string()]],
        );
        let html = custom.render_section_html(&section);
        assert!(html.contains("<th>A</th>"));
        assert!(html.contains("<td>1</td>"));
    }

    #[test]
    fn test_render_chart_html() {
        let custom = ReportCustomization::new("Test");
        let section = CustomSection::chart(
            "c1", "Chart", 1,
            ChartType::Bar,
            vec![("A".to_string(), 10.0), ("B".to_string(), 20.0)],
        );
        let html = custom.render_section_html(&section);
        assert!(html.contains("bar-chart"));
    }

    #[test]
    fn test_render_markdown_section_html() {
        let custom = ReportCustomization::new("Test");
        let section = CustomSection::markdown("m1", "MD", 1, "# Title\n\nSome text\n- Item 1");
        let html = custom.render_section_html(&section);
        assert!(html.contains("<h1>Title</h1>"));
        assert!(html.contains("<li>Item 1</li>"));
    }

    #[test]
    fn test_hidden_section_not_rendered() {
        let custom = ReportCustomization::new("Test");
        let mut section = CustomSection::text("s1", "Hidden", 1, "Secret");
        section.set_visible(false);
        let html = custom.render_section_html(&section);
        assert!(html.is_empty());
    }

    #[test]
    fn test_custom_section_kv() {
        let section = CustomSection {
            id: "kv".to_string(),
            title: "Key Value".to_string(),
            order: 1,
            content: SectionContent::KeyValue(vec![
                ("Key1".to_string(), "Val1".to_string()),
                ("Key2".to_string(), "Val2".to_string()),
            ]),
            visible: true,
        };
        let custom = ReportCustomization::new("Test");
        let html = custom.render_section_html(&section);
        assert!(html.contains("Key1"));
        assert!(html.contains("Val2"));
    }

    #[test]
    fn test_to_json() {
        let custom = ReportCustomization::new("Test");
        let json = custom.to_json().unwrap();
        assert!(json.contains("Acme Corp") == false);
        assert!(json.contains("Test"));
    }

    #[test]
    fn test_custom_severity() {
        let mut custom = ReportCustomization::new("Test");
        custom.add_custom_severity(CustomSeverity {
            level: "emergency".to_string(),
            label: "Emergency".to_string(),
            color: "#ff0000".to_string(),
            score_range_min: 10.0,
            score_range_max: 10.0,
            icon: None,
        });
        assert_eq!(custom.severity_levels.len(), 6);
    }

    #[test]
    fn test_branding_defaults() {
        let custom = ReportCustomization::new("Test");
        assert!(custom.branding.confidential);
        assert_eq!(custom.branding.primary_color, "#007bff");
        assert!(custom.branding.logo_url.is_none());
    }

    #[test]
    fn test_pie_chart_html() {
        let section = CustomSection::chart(
            "pc", "Pie", 1,
            ChartType::Pie,
            vec![("A".to_string(), 30.0), ("B".to_string(), 70.0)],
        );
        let custom = ReportCustomization::new("Test");
        let html = custom.render_section_html(&section);
        assert!(html.contains("42.9%") || html.contains("30.0"));
    }
}
