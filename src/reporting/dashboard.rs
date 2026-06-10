// Dashboard with real-time scan monitoring, live statistics, interactive charts, and drill-down
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub updated_at: DateTime<Utc>,
    pub widgets: Vec<Widget>,
    pub live_stats: LiveStatistics,
    pub drill_downs: Vec<DrillDown>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveStatistics {
    pub active_scans: usize,
    pub scans_completed_today: usize,
    pub hosts_scanned_today: usize,
    pub vulnerabilities_found_today: usize,
    pub average_scan_duration_secs: f64,
    pub current_throughput_hosts_per_sec: f64,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrillDown {
    pub id: String,
    pub parent_widget_id: String,
    pub drill_type: DrillDownType,
    pub filters: Vec<DrillFilter>,
    pub data: DrillDownData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DrillDownType {
    HostDetail,
    PortDetail,
    VulnerabilityDetail,
    ServiceDetail,
    TimelineDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrillFilter {
    pub field: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrillDownData {
    pub title: String,
    pub entries: Vec<DrillEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DrillEntry {
    pub key: String,
    pub value: String,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealTimeMonitor {
    pub monitor_id: String,
    pub started_at: DateTime<Utc>,
    pub poll_interval_ms: u64,
    pub status: MonitorStatus,
    pub scan_progress: Vec<ScanProgress>,
    pub event_buffer: Vec<MonitorEvent>,
    pub max_buffer_size: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MonitorStatus {
    Running,
    Paused,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub target: String,
    pub progress_percent: f64,
    pub hosts_completed: usize,
    pub hosts_total: usize,
    pub current_phase: String,
    pub elapsed_secs: u64,
    pub estimated_remaining_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: MonitorEventType,
    pub scan_id: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MonitorEventType {
    ScanStarted,
    ScanProgress,
    ScanCompleted,
    ScanFailed,
    VulnerabilityFound,
    HostDiscovered,
    AlertRaised,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractiveChart {
    pub chart_id: String,
    pub title: String,
    pub chart_type: ChartKind,
    pub data_series: Vec<DataSeries>,
    pub axes: ChartAxes,
    pub interactions: ChartInteractions,
    pub annotations: Vec<ChartAnnotation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChartKind {
    Line,
    Bar,
    Pie,
    Scatter,
    Heatmap,
    Treemap,
    Gauge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSeries {
    pub name: String,
    pub points: Vec<DataPoint>,
    pub color: String,
    pub visible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoint {
    pub x: f64,
    pub y: f64,
    pub label: Option<String>,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartAxes {
    pub x_label: String,
    pub y_label: String,
    pub x_min: Option<f64>,
    pub x_max: Option<f64>,
    pub y_min: Option<f64>,
    pub y_max: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartInteractions {
    pub zoom_enabled: bool,
    pub pan_enabled: bool,
    pub tooltip_enabled: bool,
    pub click_drill_down: bool,
    pub brush_select: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartAnnotation {
    pub annotation_type: AnnotationType,
    pub value: f64,
    pub label: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnnotationType {
    ThresholdLine,
    TrendLine,
    AverageLine,
    RegionMarker,
}

// Existing widget types
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
    drill_downs: Vec<DrillDown>,
}

impl DashboardBuilder {
    pub fn new() -> Self {
        Self {
            widgets: Vec::new(),
            drill_downs: Vec::new(),
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

    pub fn add_drill_down(mut self, drill_down: DrillDown) -> Self {
        self.drill_downs.push(drill_down);
        self
    }

    pub fn build(self) -> Dashboard {
        Dashboard {
            updated_at: Utc::now(),
            widgets: self.widgets,
            live_stats: LiveStatistics::default(),
            drill_downs: self.drill_downs,
        }
    }
}

impl Default for LiveStatistics {
    fn default() -> Self {
        Self {
            active_scans: 0,
            scans_completed_today: 0,
            hosts_scanned_today: 0,
            vulnerabilities_found_today: 0,
            average_scan_duration_secs: 0.0,
            current_throughput_hosts_per_sec: 0.0,
            uptime_secs: 0,
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

    pub fn update_live_stats(&mut self, stats: LiveStatistics) {
        self.live_stats = stats;
        self.updated_at = Utc::now();
    }

    pub fn get_drill_down(&self, id: &str) -> Option<&DrillDown> {
        self.drill_downs.iter().find(|d| d.id == id)
    }

    pub fn get_drill_downs_for_widget(&self, widget_id: &str) -> Vec<&DrillDown> {
        self.drill_downs.iter().filter(|d| d.parent_widget_id == widget_id).collect()
    }
}

impl RealTimeMonitor {
    pub fn new(monitor_id: &str, poll_interval_ms: u64) -> Self {
        Self {
            monitor_id: monitor_id.to_string(),
            started_at: Utc::now(),
            poll_interval_ms,
            status: MonitorStatus::Running,
            scan_progress: Vec::new(),
            event_buffer: Vec::new(),
            max_buffer_size: 1000,
        }
    }

    pub fn add_scan_progress(&mut self, progress: ScanProgress) {
        if let Some(existing) = self.scan_progress.iter_mut().find(|p| p.scan_id == progress.scan_id) {
            *existing = progress;
        } else {
            self.scan_progress.push(progress);
        }
    }

    pub fn push_event(&mut self, event: MonitorEvent) {
        self.event_buffer.push(event);
        if self.event_buffer.len() > self.max_buffer_size {
            self.event_buffer.remove(0);
        }
    }

    pub fn pause(&mut self) {
        self.status = MonitorStatus::Paused;
    }

    pub fn resume(&mut self) {
        self.status = MonitorStatus::Running;
    }

    pub fn stop(&mut self) {
        self.status = MonitorStatus::Stopped;
    }

    pub fn get_progress(&self, scan_id: &str) -> Option<&ScanProgress> {
        self.scan_progress.iter().find(|p| p.scan_id == scan_id)
    }

    pub fn get_recent_events(&self, count: usize) -> Vec<&MonitorEvent> {
        let skip = self.event_buffer.len().saturating_sub(count);
        self.event_buffer.iter().skip(skip).collect()
    }

    pub fn elapsed(&self) -> Duration {
        Utc::now() - self.started_at
    }

    pub fn is_running(&self) -> bool {
        self.status == MonitorStatus::Running
    }
}

impl InteractiveChart {
    pub fn new(chart_id: &str, title: &str, chart_type: ChartKind) -> Self {
        Self {
            chart_id: chart_id.to_string(),
            title: title.to_string(),
            chart_type,
            data_series: Vec::new(),
            axes: ChartAxes {
                x_label: "X".to_string(),
                y_label: "Y".to_string(),
                x_min: None,
                x_max: None,
                y_min: None,
                y_max: None,
            },
            interactions: ChartInteractions {
                zoom_enabled: true,
                pan_enabled: true,
                tooltip_enabled: true,
                click_drill_down: true,
                brush_select: false,
            },
            annotations: Vec::new(),
        }
    }

    pub fn add_series(mut self, series: DataSeries) -> Self {
        self.data_series.push(series);
        self
    }

    pub fn set_axes(mut self, x_label: &str, y_label: &str) -> Self {
        self.axes.x_label = x_label.to_string();
        self.axes.y_label = y_label.to_string();
        self
    }

    pub fn add_threshold(mut self, value: f64, label: &str, color: &str) -> Self {
        self.annotations.push(ChartAnnotation {
            annotation_type: AnnotationType::ThresholdLine,
            value,
            label: label.to_string(),
            color: color.to_string(),
        });
        self
    }

    pub fn toggle_series(&mut self, name: &str) -> bool {
        if let Some(series) = self.data_series.iter_mut().find(|s| s.name == name) {
            series.visible = !series.visible;
            true
        } else {
            false
        }
    }

    pub fn visible_series(&self) -> Vec<&DataSeries> {
        self.data_series.iter().filter(|s| s.visible).collect()
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl DataSeries {
    pub fn new(name: &str, color: &str) -> Self {
        Self {
            name: name.to_string(),
            points: Vec::new(),
            color: color.to_string(),
            visible: true,
        }
    }

    pub fn add_point(mut self, x: f64, y: f64) -> Self {
        self.points.push(DataPoint { x, y, label: None, metadata: None });
        self
    }

    pub fn add_labeled_point(mut self, x: f64, y: f64, label: &str) -> Self {
        self.points.push(DataPoint {
            x, y,
            label: Some(label.to_string()),
            metadata: None,
        });
        self
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

    #[test]
    fn test_real_time_monitor_creation() {
        let monitor = RealTimeMonitor::new("mon-1", 1000);
        assert_eq!(monitor.monitor_id, "mon-1");
        assert_eq!(monitor.poll_interval_ms, 1000);
        assert!(monitor.is_running());
        assert!(monitor.scan_progress.is_empty());
    }

    #[test]
    fn test_monitor_scan_progress() {
        let mut monitor = RealTimeMonitor::new("mon-1", 500);
        monitor.add_scan_progress(ScanProgress {
            scan_id: "scan-1".to_string(),
            target: "192.168.1.0/24".to_string(),
            progress_percent: 45.0,
            hosts_completed: 45,
            hosts_total: 100,
            current_phase: "Port Scanning".to_string(),
            elapsed_secs: 120,
            estimated_remaining_secs: Some(150),
        });

        assert_eq!(monitor.scan_progress.len(), 1);
        let progress = monitor.get_progress("scan-1").unwrap();
        assert_eq!(progress.progress_percent, 45.0);
    }

    #[test]
    fn test_monitor_progress_update() {
        let mut monitor = RealTimeMonitor::new("mon-1", 500);
        monitor.add_scan_progress(ScanProgress {
            scan_id: "scan-1".to_string(),
            target: "10.0.0.0/8".to_string(),
            progress_percent: 20.0,
            hosts_completed: 20,
            hosts_total: 100,
            current_phase: "Discovery".to_string(),
            elapsed_secs: 60,
            estimated_remaining_secs: Some(240),
        });
        monitor.add_scan_progress(ScanProgress {
            scan_id: "scan-1".to_string(),
            target: "10.0.0.0/8".to_string(),
            progress_percent: 50.0,
            hosts_completed: 50,
            hosts_total: 100,
            current_phase: "Port Scanning".to_string(),
            elapsed_secs: 150,
            estimated_remaining_secs: Some(150),
        });

        assert_eq!(monitor.scan_progress.len(), 1);
        assert_eq!(monitor.get_progress("scan-1").unwrap().progress_percent, 50.0);
    }

    #[test]
    fn test_monitor_events() {
        let mut monitor = RealTimeMonitor::new("mon-1", 1000);
        monitor.push_event(MonitorEvent {
            timestamp: Utc::now(),
            event_type: MonitorEventType::ScanStarted,
            scan_id: "scan-1".to_string(),
            message: "Scan started".to_string(),
        });
        monitor.push_event(MonitorEvent {
            timestamp: Utc::now(),
            event_type: MonitorEventType::VulnerabilityFound,
            scan_id: "scan-1".to_string(),
            message: "Critical vuln found".to_string(),
        });

        let recent = monitor.get_recent_events(5);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].event_type, MonitorEventType::ScanStarted);
        assert_eq!(recent[1].event_type, MonitorEventType::VulnerabilityFound);
    }

    #[test]
    fn test_monitor_pause_resume_stop() {
        let mut monitor = RealTimeMonitor::new("mon-1", 1000);
        assert!(monitor.is_running());

        monitor.pause();
        assert_eq!(monitor.status, MonitorStatus::Paused);
        assert!(!monitor.is_running());

        monitor.resume();
        assert!(monitor.is_running());

        monitor.stop();
        assert_eq!(monitor.status, MonitorStatus::Stopped);
    }

    #[test]
    fn test_monitor_event_buffer_limit() {
        let mut monitor = RealTimeMonitor::new("mon-1", 1000);
        monitor.max_buffer_size = 3;

        for i in 0..5 {
            monitor.push_event(MonitorEvent {
                timestamp: Utc::now(),
                event_type: MonitorEventType::ScanProgress,
                scan_id: "scan-1".to_string(),
                message: format!("Progress {}", i),
            });
        }

        assert_eq!(monitor.event_buffer.len(), 3);
        assert_eq!(monitor.event_buffer[0].message, "Progress 2");
    }

    #[test]
    fn test_interactive_chart_creation() {
        let chart = InteractiveChart::new("chart-1", "Vuln Trend", ChartKind::Line);
        assert_eq!(chart.chart_id, "chart-1");
        assert_eq!(chart.chart_type, ChartKind::Line);
        assert!(chart.data_series.is_empty());
        assert!(chart.interactions.zoom_enabled);
    }

    #[test]
    fn test_interactive_chart_with_series() {
        let series = DataSeries::new("Critical", "red")
            .add_point(1.0, 5.0)
            .add_point(2.0, 8.0)
            .add_point(3.0, 3.0);

        let chart = InteractiveChart::new("chart-1", "Trend", ChartKind::Line)
            .add_series(series)
            .set_axes("Day", "Count")
            .add_threshold(7.0, "Alert Threshold", "orange");

        assert_eq!(chart.data_series.len(), 1);
        assert_eq!(chart.data_series[0].points.len(), 3);
        assert_eq!(chart.axes.x_label, "Day");
        assert_eq!(chart.annotations.len(), 1);
    }

    #[test]
    fn test_chart_toggle_series() {
        let series = DataSeries::new("Critical", "red").add_point(1.0, 5.0);
        let mut chart = InteractiveChart::new("chart-1", "Trend", ChartKind::Line)
            .add_series(series);

        assert_eq!(chart.visible_series().len(), 1);
        assert!(chart.toggle_series("Critical"));
        assert_eq!(chart.visible_series().len(), 0);
        assert!(chart.toggle_series("Critical"));
        assert_eq!(chart.visible_series().len(), 1);
        assert!(!chart.toggle_series("Nonexistent"));
    }

    #[test]
    fn test_data_series_builder() {
        let series = DataSeries::new("High", "orange")
            .add_point(0.0, 10.0)
            .add_labeled_point(1.0, 15.0, "peak");

        assert_eq!(series.name, "High");
        assert_eq!(series.points.len(), 2);
        assert!(series.points[0].label.is_none());
        assert_eq!(series.points[1].label.as_deref(), Some("peak"));
    }

    #[test]
    fn test_chart_kinds() {
        assert_ne!(ChartKind::Line, ChartKind::Bar);
        assert_ne!(ChartKind::Pie, ChartKind::Scatter);
        assert_ne!(ChartKind::Heatmap, ChartKind::Gauge);
    }

    #[test]
    fn test_annotation_types() {
        let a = AnnotationType::ThresholdLine;
        let b = AnnotationType::TrendLine;
        assert_ne!(a, b);
    }

    #[test]
    fn test_dashboard_live_stats() {
        let mut dashboard = DashboardBuilder::new()
            .add_metric("m1", "Metric", 1.0, "u", "c")
            .build();

        assert_eq!(dashboard.live_stats.active_scans, 0);

        dashboard.update_live_stats(LiveStatistics {
            active_scans: 3,
            scans_completed_today: 12,
            hosts_scanned_today: 450,
            vulnerabilities_found_today: 67,
            average_scan_duration_secs: 180.0,
            current_throughput_hosts_per_sec: 2.5,
            uptime_secs: 86400,
        });

        assert_eq!(dashboard.live_stats.active_scans, 3);
        assert_eq!(dashboard.live_stats.scans_completed_today, 12);
    }

    #[test]
    fn test_dashboard_drill_downs() {
        let drill = DrillDown {
            id: "drill-1".to_string(),
            parent_widget_id: "vuln-chart".to_string(),
            drill_type: DrillDownType::VulnerabilityDetail,
            filters: vec![DrillFilter {
                field: "severity".to_string(),
                value: "critical".to_string(),
            }],
            data: DrillDownData {
                title: "Critical Vulnerabilities".to_string(),
                entries: vec![
                    DrillEntry {
                        key: "CVE-2024-1234".to_string(),
                        value: "Remote Code Execution".to_string(),
                        severity: Some("Critical".to_string()),
                    },
                ],
            },
        };

        let dashboard = DashboardBuilder::new()
            .add_chart("vuln-chart", "Vulns", "bar", vec![], vec![])
            .add_drill_down(drill)
            .build();

        assert_eq!(dashboard.drill_downs.len(), 1);
        let d = dashboard.get_drill_down("drill-1").unwrap();
        assert_eq!(d.drill_type, DrillDownType::VulnerabilityDetail);
        assert_eq!(d.data.entries[0].key, "CVE-2024-1234");

        let widget_drills = dashboard.get_drill_downs_for_widget("vuln-chart");
        assert_eq!(widget_drills.len(), 1);

        let no_drills = dashboard.get_drill_downs_for_widget("other-widget");
        assert!(no_drills.is_empty());
    }

    #[test]
    fn test_monitor_event_types() {
        assert_ne!(MonitorEventType::ScanStarted, MonitorEventType::ScanCompleted);
        assert_ne!(MonitorEventType::VulnerabilityFound, MonitorEventType::HostDiscovered);
    }

    #[test]
    fn test_monitor_elapsed() {
        let monitor = RealTimeMonitor::new("mon-1", 1000);
        let elapsed = monitor.elapsed();
        assert!(elapsed.num_milliseconds() >= 0);
    }
}
