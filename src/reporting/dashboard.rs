// Dashboard data aggregation for real-time monitoring
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub updated_at: DateTime<Utc>,
    pub widgets: Vec<Widget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Widget {
    pub id: String,
    pub widget_type: WidgetType,
    pub title: String,
    pub data: WidgetData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WidgetType {
    Metric,
    Chart,
    Table,
    Alert,
    Timeline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WidgetData {
    Metric(MetricData),
    Chart(ChartData),
    Table(TableData),
    Alert(AlertData),
    Timeline(TimelineData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricData {
    pub value: f64,
    pub unit: String,
    pub trend: Option<f64>,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartData {
    pub chart_type: String,
    pub labels: Vec<String>,
    pub datasets: Vec<Dataset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    pub label: String,
    pub data: Vec<f64>,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableData {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertData {
    pub level: AlertLevel,
    pub message: String,
    pub count: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertLevel {
    Critical,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineData {
    pub events: Vec<TimelineEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub title: String,
    pub description: String,
    pub event_type: String,
}

pub struct DashboardBuilder {
    widgets: Vec<Widget>,
}

impl DashboardBuilder {
    pub fn new() -> Self {
        Self {
            widgets: Vec::new(),
        }
    }

    pub fn add_metric(mut self, id: &str, title: &str, value: f64, unit: &str, color: &str) -> Self {
        self.widgets.push(Widget {
            id: id.to_string(),
            widget_type: WidgetType::Metric,
            title: title.to_string(),
            data: WidgetData::Metric(MetricData {
                value,
                unit: unit.to_string(),
                trend: None,
                color: color.to_string(),
            }),
        });
        self
    }

    pub fn add_chart(mut self, id: &str, title: &str, chart_type: &str, labels: Vec<String>, datasets: Vec<Dataset>) -> Self {
        self.widgets.push(Widget {
            id: id.to_string(),
            widget_type: WidgetType::Chart,
            title: title.to_string(),
            data: WidgetData::Chart(ChartData {
                chart_type: chart_type.to_string(),
                labels,
                datasets,
            }),
        });
        self
    }

    pub fn add_alert(mut self, id: &str, title: &str, level: AlertLevel, message: &str, count: usize) -> Self {
        self.widgets.push(Widget {
            id: id.to_string(),
            widget_type: WidgetType::Alert,
            title: title.to_string(),
            data: WidgetData::Alert(AlertData {
                level,
                message: message.to_string(),
                count,
            }),
        });
        self
    }

    pub fn build(self) -> Dashboard {
        Dashboard {
            updated_at: Utc::now(),
            widgets: self.widgets,
        }
    }
}

impl Dashboard {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn get_widget(&self, id: &str) -> Option<&Widget> {
        self.widgets.iter().find(|w| w.id == id)
    }

    pub fn widget_count(&self) -> usize {
        self.widgets.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_builder() {
        let dashboard = DashboardBuilder::new()
            .add_metric("risk-score", "Risk Score", 7.5, "/10", "red")
            .add_metric("hosts-up", "Hosts Up", 45.0, "hosts", "green")
            .build();

        assert_eq!(dashboard.widgets.len(), 2);
    }

    #[test]
    fn test_add_metric() {
        let dashboard = DashboardBuilder::new()
            .add_metric("test", "Test Metric", 100.0, "units", "blue")
            .build();

        assert_eq!(dashboard.widgets.len(), 1);
        assert_eq!(dashboard.widgets[0].widget_type, WidgetType::Metric);
        assert_eq!(dashboard.widgets[0].title, "Test Metric");
    }

    #[test]
    fn test_add_chart() {
        let dataset = Dataset {
            label: "Vulnerabilities".to_string(),
            data: vec![5.0, 10.0, 15.0],
            color: "red".to_string(),
        };

        let dashboard = DashboardBuilder::new()
            .add_chart(
                "vuln-chart",
                "Vulnerability Trend",
                "line",
                vec!["Day 1".to_string(), "Day 2".to_string(), "Day 3".to_string()],
                vec![dataset],
            )
            .build();

        assert_eq!(dashboard.widgets.len(), 1);
        assert_eq!(dashboard.widgets[0].widget_type, WidgetType::Chart);
    }

    #[test]
    fn test_add_alert() {
        let dashboard = DashboardBuilder::new()
            .add_alert("critical-alert", "Critical Issues", AlertLevel::Critical, "5 critical vulnerabilities found", 5)
            .build();

        assert_eq!(dashboard.widgets.len(), 1);
        assert_eq!(dashboard.widgets[0].widget_type, WidgetType::Alert);
    }

    #[test]
    fn test_get_widget() {
        let dashboard = DashboardBuilder::new()
            .add_metric("test-metric", "Test", 100.0, "units", "blue")
            .build();

        let widget = dashboard.get_widget("test-metric");
        assert!(widget.is_some());
        assert_eq!(widget.unwrap().title, "Test");
    }

    #[test]
    fn test_widget_count() {
        let dashboard = DashboardBuilder::new()
            .add_metric("m1", "Metric 1", 1.0, "u", "c")
            .add_metric("m2", "Metric 2", 2.0, "u", "c")
            .add_metric("m3", "Metric 3", 3.0, "u", "c")
            .build();

        assert_eq!(dashboard.widget_count(), 3);
    }

    #[test]
    fn test_to_json() {
        let dashboard = DashboardBuilder::new()
            .add_metric("test", "Test", 100.0, "units", "blue")
            .build();

        let json = dashboard.to_json();
        assert!(json.is_ok());
        assert!(json.unwrap().contains("Test"));
    }

    #[test]
    fn test_metric_data() {
        let data = MetricData {
            value: 7.5,
            unit: "/10".to_string(),
            trend: Some(-5.0),
            color: "red".to_string(),
        };

        assert_eq!(data.value, 7.5);
        assert_eq!(data.trend, Some(-5.0));
    }

    #[test]
    fn test_alert_levels() {
        let critical = AlertLevel::Critical;
        let warning = AlertLevel::Warning;
        let info = AlertLevel::Info;

        assert_ne!(critical, warning);
        assert_ne!(warning, info);
    }
}
