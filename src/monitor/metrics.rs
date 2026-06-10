use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

impl std::fmt::Display for MetricType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricType::Counter => write!(f, "counter"),
            MetricType::Gauge => write!(f, "gauge"),
            MetricType::Histogram => write!(f, "histogram"),
            MetricType::Summary => write!(f, "summary"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricLabels {
    labels: HashMap<String, String>,
}

impl MetricLabels {
    pub fn new() -> Self {
        Self {
            labels: HashMap::new(),
        }
    }

    pub fn with(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_string(), value.to_string());
        self
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.labels.get(key).map(|s| s.as_str())
    }

    pub fn keys(&self) -> Vec<&str> {
        self.labels.keys().map(|s| s.as_str()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }

    pub fn to_sorted_string(&self) -> String {
        let mut pairs: Vec<_> = self.labels.iter().collect();
        pairs.sort_by_key(|(a, _)| *a);
        pairs
            .iter()
            .map(|(k, v)| format!("{}=\"{}\"", k, v))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl Default for MetricLabels {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    pub name: String,
    pub metric_type: MetricType,
    pub value: f64,
    pub labels: MetricLabels,
    pub help: String,
    pub timestamp: DateTime<Utc>,
}

impl Metric {
    pub fn new(name: &str, metric_type: MetricType, value: f64, help: &str) -> Self {
        Self {
            name: name.to_string(),
            metric_type,
            value,
            labels: MetricLabels::new(),
            help: help.to_string(),
            timestamp: Utc::now(),
        }
    }

    pub fn with_labels(mut self, labels: MetricLabels) -> Self {
        self.labels = labels;
        self
    }

    pub fn prometheus_name(&self) -> String {
        format!("nemue_{}", self.name.replace('.', "_"))
    }

    pub fn to_prometheus_string(&self) -> String {
        let name = self.prometheus_name();
        let mut lines = Vec::new();

        lines.push(format!("# HELP {} {}", name, self.help));
        lines.push(format!("# TYPE {} {}", name, self.metric_type));

        if self.labels.is_empty() {
            lines.push(format!("{} {}", name, self.value));
        } else {
            lines.push(format!(
                "{{{}}} {}",
                self.labels.to_sorted_string(),
                self.value
            ));
        }

        lines.join("\n")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramBucket {
    pub upper_bound: f64,
    pub count: u64,
}

impl HistogramBucket {
    pub fn new(upper_bound: f64, count: u64) -> Self {
        Self { upper_bound, count }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Histogram {
    pub name: String,
    pub help: String,
    pub buckets: Vec<HistogramBucket>,
    pub sum: f64,
    pub count: u64,
    pub labels: MetricLabels,
    pub created_at: DateTime<Utc>,
}

impl Histogram {
    pub fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            buckets: Vec::new(),
            sum: 0.0,
            count: 0,
            labels: MetricLabels::new(),
            created_at: Utc::now(),
        }
    }

    pub fn with_labels(mut self, labels: MetricLabels) -> Self {
        self.labels = labels;
        self
    }

    pub fn with_default_buckets(mut self) -> Self {
        self.buckets = vec![
            HistogramBucket::new(0.005, 0),
            HistogramBucket::new(0.01, 0),
            HistogramBucket::new(0.025, 0),
            HistogramBucket::new(0.05, 0),
            HistogramBucket::new(0.1, 0),
            HistogramBucket::new(0.25, 0),
            HistogramBucket::new(0.5, 0),
            HistogramBucket::new(1.0, 0),
            HistogramBucket::new(2.5, 0),
            HistogramBucket::new(5.0, 0),
            HistogramBucket::new(10.0, 0),
            HistogramBucket::new(f64::INFINITY, 0),
        ];
        self
    }

    pub fn with_buckets(mut self, bounds: &[f64]) -> Self {
        self.buckets = bounds.iter().map(|&b| HistogramBucket::new(b, 0)).collect();
        if self
            .buckets
            .last()
            .is_none_or(|b| b.upper_bound != f64::INFINITY)
        {
            self.buckets.push(HistogramBucket::new(f64::INFINITY, 0));
        }
        self
    }

    pub fn observe(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;
        for bucket in &mut self.buckets {
            if value <= bucket.upper_bound {
                bucket.count += 1;
            }
        }
    }

    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryQuantile {
    pub quantile: f64,
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub name: String,
    pub help: String,
    pub quantiles: Vec<SummaryQuantile>,
    pub sum: f64,
    pub count: u64,
    pub labels: MetricLabels,
    pub created_at: DateTime<Utc>,
    observations: Vec<f64>,
}

impl Summary {
    pub fn new(name: &str, help: &str) -> Self {
        Self {
            name: name.to_string(),
            help: help.to_string(),
            quantiles: Vec::new(),
            sum: 0.0,
            count: 0,
            labels: MetricLabels::new(),
            created_at: Utc::now(),
            observations: Vec::new(),
        }
    }

    pub fn with_labels(mut self, labels: MetricLabels) -> Self {
        self.labels = labels;
        self
    }

    pub fn observe(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;
        self.observations.push(value);
    }

    pub fn calculate_quantiles(&mut self, quantiles: &[f64]) {
        if self.observations.is_empty() {
            self.quantiles = Vec::new();
            return;
        }

        let mut sorted = self.observations.clone();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        self.quantiles = quantiles
            .iter()
            .map(|&q| {
                let idx = (q * (sorted.len() - 1) as f64).round() as usize;
                SummaryQuantile {
                    quantile: q,
                    value: sorted[idx],
                }
            })
            .collect();
    }

    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }

    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSample {
    pub name: String,
    pub value: f64,
    pub labels: MetricLabels,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedMetric {
    pub name: String,
    pub count: u64,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub labels: MetricLabels,
}

impl AggregatedMetric {
    pub fn from_samples(name: &str, samples: &[MetricSample], labels: MetricLabels) -> Self {
        let count = samples.len() as u64;
        let sum: f64 = samples.iter().map(|s| s.value).sum();
        let min = samples
            .iter()
            .map(|s| s.value)
            .fold(f64::INFINITY, f64::min);
        let max = samples
            .iter()
            .map(|s| s.value)
            .fold(f64::NEG_INFINITY, f64::max);
        let avg = if count > 0 { sum / count as f64 } else { 0.0 };

        Self {
            name: name.to_string(),
            count,
            sum,
            min,
            max,
            avg,
            labels,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricExporterConfig {
    pub endpoint: String,
    pub format: ExportFormat,
    pub interval_seconds: u64,
    pub prefix: String,
    pub additional_labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Prometheus,
    Json,
    InfluxDb,
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportFormat::Prometheus => write!(f, "prometheus"),
            ExportFormat::Json => write!(f, "json"),
            ExportFormat::InfluxDb => write!(f, "influxdb"),
        }
    }
}

impl MetricExporterConfig {
    pub fn new(endpoint: &str, format: ExportFormat) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            format,
            interval_seconds: 15,
            prefix: "nemue".to_string(),
            additional_labels: HashMap::new(),
        }
    }

    pub fn with_interval(mut self, seconds: u64) -> Self {
        self.interval_seconds = seconds;
        self
    }

    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.prefix = prefix.to_string();
        self
    }

    pub fn with_label(mut self, key: &str, value: &str) -> Self {
        self.additional_labels
            .insert(key.to_string(), value.to_string());
        self
    }
}

pub struct MetricsRegistry {
    metrics: HashMap<String, Metric>,
    histograms: HashMap<String, Histogram>,
    summaries: HashMap<String, Summary>,
    samples: HashMap<String, Vec<MetricSample>>,
    max_samples_per_metric: usize,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            metrics: HashMap::new(),
            histograms: HashMap::new(),
            summaries: HashMap::new(),
            samples: HashMap::new(),
            max_samples_per_metric: 10_000,
        }
    }

    pub fn with_max_samples(mut self, max: usize) -> Self {
        self.max_samples_per_metric = max;
        self
    }

    pub fn register_counter(&mut self, name: &str, help: &str) {
        let metric = Metric::new(name, MetricType::Counter, 0.0, help);
        self.metrics.insert(name.to_string(), metric);
    }

    pub fn register_gauge(&mut self, name: &str, help: &str) {
        let metric = Metric::new(name, MetricType::Gauge, 0.0, help);
        self.metrics.insert(name.to_string(), metric);
    }

    pub fn register_histogram(&mut self, name: &str, help: &str) {
        let hist = Histogram::new(name, help).with_default_buckets();
        self.histograms.insert(name.to_string(), hist);
    }

    pub fn register_histogram_with_buckets(&mut self, name: &str, help: &str, bounds: &[f64]) {
        let hist = Histogram::new(name, help).with_buckets(bounds);
        self.histograms.insert(name.to_string(), hist);
    }

    pub fn register_summary(&mut self, name: &str, help: &str) {
        let summary = Summary::new(name, help);
        self.summaries.insert(name.to_string(), summary);
    }

    pub fn increment_counter(&mut self, name: &str) {
        self.increment_counter_by(name, 1.0);
    }

    pub fn increment_counter_by(&mut self, name: &str, value: f64) {
        if let Some(metric) = self.metrics.get_mut(name) {
            if metric.metric_type == MetricType::Counter {
                metric.value += value;
                metric.timestamp = Utc::now();
            }
        }
        if let Some(metric) = self.metrics.get(name) {
            if metric.metric_type == MetricType::Counter {
                let val = metric.value;
                let labels = metric.labels.clone();
                self.record_sample(name, val, &labels);
            }
        }
    }

    pub fn set_gauge(&mut self, name: &str, value: f64) {
        if let Some(metric) = self.metrics.get_mut(name) {
            if metric.metric_type == MetricType::Gauge {
                metric.value = value;
                metric.timestamp = Utc::now();
            }
        }
        if let Some(metric) = self.metrics.get(name) {
            if metric.metric_type == MetricType::Gauge {
                let labels = metric.labels.clone();
                self.record_sample(name, value, &labels);
            }
        }
    }

    pub fn observe_histogram(&mut self, name: &str, value: f64) {
        if let Some(hist) = self.histograms.get_mut(name) {
            hist.observe(value);
        }
        if let Some(hist) = self.histograms.get(name) {
            let labels = hist.labels.clone();
            self.record_sample(name, value, &labels);
        }
    }

    pub fn observe_summary(&mut self, name: &str, value: f64) {
        if let Some(summary) = self.summaries.get_mut(name) {
            summary.observe(value);
        }
        if let Some(summary) = self.summaries.get(name) {
            let labels = summary.labels.clone();
            self.record_sample(name, value, &labels);
        }
    }

    fn record_sample(&mut self, name: &str, value: f64, labels: &MetricLabels) {
        let sample = MetricSample {
            name: name.to_string(),
            value,
            labels: labels.clone(),
            timestamp: Utc::now(),
        };

        let samples = self.samples.entry(name.to_string()).or_default();
        samples.push(sample);

        if samples.len() > self.max_samples_per_metric {
            samples.remove(0);
        }
    }

    pub fn get_metric(&self, name: &str) -> Option<&Metric> {
        self.metrics.get(name)
    }

    pub fn get_metric_value(&self, name: &str) -> Option<f64> {
        self.metrics.get(name).map(|m| m.value)
    }

    pub fn get_histogram(&self, name: &str) -> Option<&Histogram> {
        self.histograms.get(name)
    }

    pub fn get_summary(&self, name: &str) -> Option<&Summary> {
        self.summaries.get(name)
    }

    pub fn get_samples(&self, name: &str) -> Option<&Vec<MetricSample>> {
        self.samples.get(name)
    }

    pub fn aggregate(&self, name: &str) -> Option<AggregatedMetric> {
        let samples = self.samples.get(name)?;
        if samples.is_empty() {
            return None;
        }

        Some(AggregatedMetric::from_samples(
            name,
            samples,
            samples[0].labels.clone(),
        ))
    }

    pub fn metric_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.metrics.keys().map(|s| s.as_str()).collect();
        names.extend(self.histograms.keys().map(|s| s.as_str()));
        names.extend(self.summaries.keys().map(|s| s.as_str()));
        names.sort();
        names
    }

    pub fn metric_count(&self) -> usize {
        self.metrics.len() + self.histograms.len() + self.summaries.len()
    }

    pub fn to_prometheus(&self) -> String {
        let mut output = String::new();

        for metric in self.metrics.values() {
            output.push_str(&metric.to_prometheus_string());
            output.push('\n');
        }

        for hist in self.histograms.values() {
            let name = format!("nemue_{}", hist.name.replace('.', "_"));
            output.push_str(&format!("# HELP {} {}\n", name, hist.help));
            output.push_str(&format!("# TYPE {} histogram\n", name));

            for bucket in &hist.buckets {
                let bound = if bucket.upper_bound == f64::INFINITY {
                    "+Inf".to_string()
                } else {
                    bucket.upper_bound.to_string()
                };
                output.push_str(&format!(
                    "{}_bucket{{le=\"{}\"}} {}\n",
                    name, bound, bucket.count
                ));
            }
            output.push_str(&format!("{}_sum {}\n", name, hist.sum));
            output.push_str(&format!("{}_count {}\n", name, hist.count));
        }

        for summary in self.summaries.values() {
            let name = format!("nemue_{}", summary.name.replace('.', "_"));
            output.push_str(&format!("# HELP {} {}\n", name, summary.help));
            output.push_str(&format!("# TYPE {} summary\n", name));

            for q in &summary.quantiles {
                output.push_str(&format!("{{quantile=\"{}\"}} {}\n", q.quantile, q.value));
            }
            output.push_str(&format!("{}_sum {}\n", name, summary.sum));
            output.push_str(&format!("{}_count {}\n", name, summary.count));
        }

        output
    }

    pub fn to_json(&self) -> String {
        let export = JsonExport {
            counters: self
                .metrics
                .iter()
                .filter(|(_, m)| m.metric_type == MetricType::Counter)
                .map(|(k, m)| (k.clone(), m.value))
                .collect(),
            gauges: self
                .metrics
                .iter()
                .filter(|(_, m)| m.metric_type == MetricType::Gauge)
                .map(|(k, m)| (k.clone(), m.value))
                .collect(),
            histogram_summaries: self
                .histograms
                .iter()
                .map(|(k, h)| {
                    (
                        k.clone(),
                        HistogramSummary {
                            count: h.count,
                            sum: h.sum,
                            mean: h.mean(),
                        },
                    )
                })
                .collect(),
        };
        serde_json::to_string(&export).unwrap_or_else(|_| "{}".to_string())
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
struct JsonExport {
    counters: HashMap<String, f64>,
    gauges: HashMap<String, f64>,
    histogram_summaries: HashMap<String, HistogramSummary>,
}

#[derive(Serialize)]
struct HistogramSummary {
    count: u64,
    sum: f64,
    mean: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_type_display() {
        assert_eq!(MetricType::Counter.to_string(), "counter");
        assert_eq!(MetricType::Gauge.to_string(), "gauge");
        assert_eq!(MetricType::Histogram.to_string(), "histogram");
        assert_eq!(MetricType::Summary.to_string(), "summary");
    }

    #[test]
    fn test_metric_labels() {
        let labels = MetricLabels::new()
            .with("method", "GET")
            .with("status", "200");

        assert_eq!(labels.get("method"), Some("GET"));
        assert_eq!(labels.get("status"), Some("200"));
        assert_eq!(labels.get("missing"), None);
        assert_eq!(labels.len(), 2);
        assert!(!labels.is_empty());
    }

    #[test]
    fn test_metric_labels_sorted_string() {
        let labels = MetricLabels::new()
            .with("z", "1")
            .with("a", "2")
            .with("m", "3");

        let s = labels.to_sorted_string();
        assert_eq!(s, "a=\"2\", m=\"3\", z=\"1\"");
    }

    #[test]
    fn test_metric_creation() {
        let metric = Metric::new(
            "requests_total",
            MetricType::Counter,
            42.0,
            "Total requests",
        )
        .with_labels(MetricLabels::new().with("method", "GET"));

        assert_eq!(metric.name, "requests_total");
        assert_eq!(metric.metric_type, MetricType::Counter);
        assert_eq!(metric.value, 42.0);
        assert_eq!(metric.help, "Total requests");
    }

    #[test]
    fn test_metric_prometheus_name() {
        let metric = Metric::new("http.requests.total", MetricType::Counter, 0.0, "test");
        assert_eq!(metric.prometheus_name(), "nemue_http_requests_total");
    }

    #[test]
    fn test_metric_to_prometheus_string() {
        let metric = Metric::new("scan_count", MetricType::Counter, 10.0, "Number of scans");
        let prom = metric.to_prometheus_string();
        assert!(prom.contains("# HELP nemue_scan_count Number of scans"));
        assert!(prom.contains("# TYPE nemue_scan_count counter"));
        assert!(prom.contains("nemue_scan_count 10"));
    }

    #[test]
    fn test_histogram_observe() {
        let mut hist = Histogram::new("request_duration", "Request duration")
            .with_buckets(&[0.1, 0.5, 1.0, 5.0]);

        hist.observe(0.05);
        hist.observe(0.3);
        hist.observe(0.8);
        hist.observe(2.0);

        assert_eq!(hist.count, 4);
        assert!((hist.sum - 3.15).abs() < 0.001);
        assert!((hist.mean() - 0.7875).abs() < 0.001);

        assert_eq!(hist.buckets[0].count, 1);
        assert_eq!(hist.buckets[1].count, 2);
        assert_eq!(hist.buckets[2].count, 3);
        assert_eq!(hist.buckets[3].count, 4);
    }

    #[test]
    fn test_histogram_default_buckets() {
        let hist = Histogram::new("test", "test").with_default_buckets();
        assert!(!hist.buckets.is_empty());
        assert_eq!(hist.buckets.last().unwrap().upper_bound, f64::INFINITY);
    }

    #[test]
    fn test_histogram_with_labels() {
        let labels = MetricLabels::new().with("endpoint", "/api");
        let hist = Histogram::new("latency", "latency").with_labels(labels);
        assert_eq!(hist.labels.get("endpoint"), Some("/api"));
    }

    #[test]
    fn test_summary_observe_and_quantiles() {
        let mut summary = Summary::new("response_time", "Response time");
        for i in 1..=100 {
            summary.observe(i as f64);
        }

        summary.calculate_quantiles(&[0.5, 0.9, 0.99]);

        assert_eq!(summary.count, 100);
        assert_eq!(summary.mean(), 50.5);
        assert_eq!(summary.quantiles.len(), 3);

        let p50 = summary
            .quantiles
            .iter()
            .find(|q| q.quantile == 0.5)
            .unwrap();
        assert!((p50.value - 50.0).abs() < 5.0);
    }

    #[test]
    fn test_summary_empty_quantiles() {
        let mut summary = Summary::new("empty", "empty");
        summary.calculate_quantiles(&[0.5]);
        assert!(summary.quantiles.is_empty());
    }

    #[test]
    fn test_metric_sample_aggregation() {
        let labels = MetricLabels::new().with("host", "web1");
        let samples: Vec<MetricSample> = (0..5)
            .map(|i| MetricSample {
                name: "cpu".to_string(),
                value: (i * 10) as f64,
                labels: labels.clone(),
                timestamp: Utc::now(),
            })
            .collect();

        let agg = AggregatedMetric::from_samples("cpu", &samples, labels);
        assert_eq!(agg.count, 5);
        assert_eq!(agg.sum, 100.0);
        assert_eq!(agg.min, 0.0);
        assert_eq!(agg.max, 40.0);
        assert_eq!(agg.avg, 20.0);
    }

    #[test]
    fn test_metrics_registry_register_counter() {
        let mut registry = MetricsRegistry::new();
        registry.register_counter("scans_total", "Total scans");
        assert!(registry.get_metric("scans_total").is_some());
        assert_eq!(registry.get_metric_value("scans_total"), Some(0.0));
    }

    #[test]
    fn test_metrics_registry_register_gauge() {
        let mut registry = MetricsRegistry::new();
        registry.register_gauge("active_sessions", "Active sessions");
        registry.set_gauge("active_sessions", 5.0);
        assert_eq!(registry.get_metric_value("active_sessions"), Some(5.0));
    }

    #[test]
    fn test_metrics_registry_increment_counter() {
        let mut registry = MetricsRegistry::new();
        registry.register_counter("requests", "Requests");
        registry.increment_counter("requests");
        registry.increment_counter("requests");
        registry.increment_counter_by("requests", 3.0);
        assert_eq!(registry.get_metric_value("requests"), Some(5.0));
    }

    #[test]
    fn test_metrics_registry_increment_wrong_type() {
        let mut registry = MetricsRegistry::new();
        registry.register_gauge("g", "gauge");
        registry.increment_counter("g");
        assert_eq!(registry.get_metric_value("g"), Some(0.0));
    }

    #[test]
    fn test_metrics_registry_set_gauge_wrong_type() {
        let mut registry = MetricsRegistry::new();
        registry.register_counter("c", "counter");
        registry.set_gauge("c", 99.0);
        assert_eq!(registry.get_metric_value("c"), Some(0.0));
    }

    #[test]
    fn test_metrics_registry_histogram() {
        let mut registry = MetricsRegistry::new();
        registry.register_histogram("req_duration", "Request duration");
        registry.observe_histogram("req_duration", 0.1);
        registry.observe_histogram("req_duration", 0.5);

        let hist = registry.get_histogram("req_duration").unwrap();
        assert_eq!(hist.count, 2);
        assert!((hist.sum - 0.6).abs() < 0.001);
    }

    #[test]
    fn test_metrics_registry_summary() {
        let mut registry = MetricsRegistry::new();
        registry.register_summary("latency", "Latency");
        registry.observe_summary("latency", 100.0);
        registry.observe_summary("latency", 200.0);

        let summary = registry.get_summary("latency").unwrap();
        assert_eq!(summary.count, 2);
        assert_eq!(summary.mean(), 150.0);
    }

    #[test]
    fn test_metrics_registry_samples() {
        let mut registry = MetricsRegistry::new();
        registry.register_counter("c", "test");
        registry.increment_counter("c");
        registry.increment_counter("c");

        let samples = registry.get_samples("c").unwrap();
        assert_eq!(samples.len(), 2);
    }

    #[test]
    fn test_metrics_registry_max_samples() {
        let mut registry = MetricsRegistry::new().with_max_samples(3);
        registry.register_gauge("g", "test");

        for i in 0..5 {
            registry.set_gauge("g", i as f64);
        }

        let samples = registry.get_samples("g").unwrap();
        assert_eq!(samples.len(), 3);
    }

    #[test]
    fn test_metrics_registry_aggregate() {
        let mut registry = MetricsRegistry::new();
        registry.register_gauge("cpu", "CPU");
        registry.set_gauge("cpu", 50.0);
        registry.set_gauge("cpu", 70.0);
        registry.set_gauge("cpu", 60.0);

        let agg = registry.aggregate("cpu").unwrap();
        assert_eq!(agg.count, 3);
        assert_eq!(agg.min, 50.0);
        assert_eq!(agg.max, 70.0);
    }

    #[test]
    fn test_metrics_registry_aggregate_empty() {
        let registry = MetricsRegistry::new();
        assert!(registry.aggregate("missing").is_none());
    }

    #[test]
    fn test_metrics_registry_metric_names() {
        let mut registry = MetricsRegistry::new();
        registry.register_counter("b_counter", "test");
        registry.register_gauge("a_gauge", "test");
        registry.register_histogram("c_hist", "test");

        let names = registry.metric_names();
        assert_eq!(names.len(), 3);
        assert_eq!(names[0], "a_gauge");
        assert_eq!(names[1], "b_counter");
        assert_eq!(names[2], "c_hist");
    }

    #[test]
    fn test_metrics_registry_metric_count() {
        let mut registry = MetricsRegistry::new();
        registry.register_counter("c", "test");
        registry.register_gauge("g", "test");
        registry.register_histogram("h", "test");
        registry.register_summary("s", "test");

        assert_eq!(registry.metric_count(), 4);
    }

    #[test]
    fn test_metrics_registry_to_prometheus() {
        let mut registry = MetricsRegistry::new();
        registry.register_counter("scans", "Total scans");
        registry.increment_counter_by("scans", 42.0);
        registry.register_gauge("active", "Active");
        registry.set_gauge("active", 3.0);

        let prom = registry.to_prometheus();
        assert!(prom.contains("nemue_scans 42"));
        assert!(prom.contains("nemue_active 3"));
        assert!(prom.contains("# TYPE nemue_scans counter"));
        assert!(prom.contains("# TYPE nemue_active gauge"));
    }

    #[test]
    fn test_metrics_registry_to_json() {
        let mut registry = MetricsRegistry::new();
        registry.register_counter("req", "Requests");
        registry.increment_counter_by("req", 10.0);
        registry.register_gauge("mem", "Memory");
        registry.set_gauge("mem", 512.0);

        let json = registry.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["counters"]["req"], 10.0);
        assert_eq!(parsed["gauges"]["mem"], 512.0);
    }

    #[test]
    fn test_metrics_registry_default() {
        let registry = MetricsRegistry::default();
        assert_eq!(registry.metric_count(), 0);
    }

    #[test]
    fn test_export_format_display() {
        assert_eq!(ExportFormat::Prometheus.to_string(), "prometheus");
        assert_eq!(ExportFormat::Json.to_string(), "json");
        assert_eq!(ExportFormat::InfluxDb.to_string(), "influxdb");
    }

    #[test]
    fn test_metric_exporter_config() {
        let config = MetricExporterConfig::new("http://prom:9091", ExportFormat::Prometheus)
            .with_interval(30)
            .with_prefix("myapp")
            .with_label("env", "prod");

        assert_eq!(config.endpoint, "http://prom:9091");
        assert_eq!(config.format, ExportFormat::Prometheus);
        assert_eq!(config.interval_seconds, 30);
        assert_eq!(config.prefix, "myapp");
        assert_eq!(config.additional_labels.get("env").unwrap(), "prod");
    }

    #[test]
    fn test_metric_labels_default() {
        let labels = MetricLabels::default();
        assert!(labels.is_empty());
    }

    #[test]
    fn test_histogram_mean_empty() {
        let hist = Histogram::new("empty", "empty");
        assert_eq!(hist.mean(), 0.0);
    }

    #[test]
    fn test_summary_mean_empty() {
        let summary = Summary::new("empty", "empty");
        assert_eq!(summary.mean(), 0.0);
    }

    #[test]
    fn test_summary_observation_count() {
        let mut summary = Summary::new("test", "test");
        summary.observe(1.0);
        summary.observe(2.0);
        assert_eq!(summary.observation_count(), 2);
    }
}
