use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "trace"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Error => write!(f, "error"),
            LogLevel::Fatal => write!(f, "fatal"),
        }
    }
}

impl LogLevel {
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" | "warning" => LogLevel::Warn,
            "error" => LogLevel::Error,
            "fatal" | "critical" => LogLevel::Fatal,
            _ => LogLevel::Info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub message: String,
    pub source: String,
    pub fields: HashMap<String, String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
}

impl LogEntry {
    pub fn new(level: LogLevel, message: &str, source: &str) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            message: message.to_string(),
            source: source.to_string(),
            fields: HashMap::new(),
            trace_id: None,
            span_id: None,
        }
    }

    pub fn with_field(mut self, key: &str, value: &str) -> Self {
        self.fields.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_fields(mut self, fields: HashMap<String, String>) -> Self {
        self.fields.extend(fields);
        self
    }

    pub fn with_trace(mut self, trace_id: &str, span_id: &str) -> Self {
        self.trace_id = Some(trace_id.to_string());
        self.span_id = Some(span_id.to_string());
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    pub fn to_text(&self) -> String {
        let trace = match (&self.trace_id, &self.span_id) {
            (Some(tid), Some(sid)) => format!(" [{}:{}]", tid, sid),
            _ => String::new(),
        };

        if self.fields.is_empty() {
            format!(
                "{} [{}] {}{} {}",
                self.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                self.level,
                self.source,
                trace,
                self.message
            )
        } else {
            let fields_str: Vec<String> = self
                .fields
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            format!(
                "{} [{}] {}{} {} {}",
                self.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ"),
                self.level,
                self.source,
                trace,
                self.message,
                fields_str.join(" ")
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
    Logfmt,
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogFormat::Json => write!(f, "json"),
            LogFormat::Text => write!(f, "text"),
            LogFormat::Logfmt => write!(f, "logfmt"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    pub max_size_bytes: u64,
    pub max_files: usize,
    pub compress_rotated: bool,
}

impl RotationConfig {
    pub fn new(max_size_bytes: u64, max_files: usize) -> Self {
        Self {
            max_size_bytes,
            max_files,
            compress_rotated: true,
        }
    }

    pub fn with_compress(mut self, compress: bool) -> Self {
        self.compress_rotated = compress;
        self
    }
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self::new(100 * 1024 * 1024, 10)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogExporterConfig {
    pub endpoint: String,
    pub format: LogFormat,
    pub batch_size: usize,
    pub flush_interval_seconds: u64,
    pub labels: HashMap<String, String>,
}

impl LogExporterConfig {
    pub fn new(endpoint: &str, format: LogFormat) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            format,
            batch_size: 100,
            flush_interval_seconds: 5,
            labels: HashMap::new(),
        }
    }

    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    pub fn with_flush_interval(mut self, seconds: u64) -> Self {
        self.flush_interval_seconds = seconds;
        self
    }

    pub fn with_label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_string(), value.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFilter {
    pub min_level: LogLevel,
    pub sources: Option<Vec<String>>,
    pub message_pattern: Option<String>,
}

impl LogFilter {
    pub fn new(min_level: LogLevel) -> Self {
        Self {
            min_level,
            sources: None,
            message_pattern: None,
        }
    }

    pub fn with_sources(mut self, sources: Vec<String>) -> Self {
        self.sources = Some(sources);
        self
    }

    pub fn with_message_pattern(mut self, pattern: &str) -> Self {
        self.message_pattern = Some(pattern.to_string());
        self
    }

    pub fn matches(&self, entry: &LogEntry) -> bool {
        if entry.level < self.min_level {
            return false;
        }

        if let Some(ref sources) = self.sources {
            if !sources.iter().any(|s| s == &entry.source) {
                return false;
            }
        }

        if let Some(ref pattern) = self.message_pattern {
            if !entry.message.contains(pattern.as_str()) {
                return false;
            }
        }

        true
    }
}

pub struct StructuredLogger {
    entries: Vec<LogEntry>,
    min_level: LogLevel,
    format: LogFormat,
    max_entries: usize,
    source: String,
    rotation: Option<RotationConfig>,
    exporter: Option<LogExporterConfig>,
    filters: Vec<LogFilter>,
}

impl StructuredLogger {
    pub fn new(source: &str) -> Self {
        Self {
            entries: Vec::new(),
            min_level: LogLevel::Info,
            format: LogFormat::Json,
            max_entries: 100_000,
            source: source.to_string(),
            rotation: None,
            exporter: None,
            filters: Vec::new(),
        }
    }

    pub fn with_min_level(mut self, level: LogLevel) -> Self {
        self.min_level = level;
        self
    }

    pub fn with_format(mut self, format: LogFormat) -> Self {
        self.format = format;
        self
    }

    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    pub fn with_rotation(mut self, config: RotationConfig) -> Self {
        self.rotation = Some(config);
        self
    }

    pub fn with_exporter(mut self, config: LogExporterConfig) -> Self {
        self.exporter = Some(config);
        self
    }

    pub fn add_filter(&mut self, filter: LogFilter) {
        self.filters.push(filter);
    }

    pub fn log(&mut self, entry: LogEntry) {
        if entry.level < self.min_level {
            return;
        }

        if !self.filters.iter().all(|f| f.matches(&entry)) {
            return;
        }

        self.entries.push(entry);

        if self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
    }

    pub fn trace(&mut self, message: &str) {
        self.log(LogEntry::new(
            LogLevel::Trace,
            message,
            &self.source.clone(),
        ));
    }

    pub fn debug(&mut self, message: &str) {
        self.log(LogEntry::new(
            LogLevel::Debug,
            message,
            &self.source.clone(),
        ));
    }

    pub fn info(&mut self, message: &str) {
        self.log(LogEntry::new(LogLevel::Info, message, &self.source.clone()));
    }

    pub fn warn(&mut self, message: &str) {
        self.log(LogEntry::new(LogLevel::Warn, message, &self.source.clone()));
    }

    pub fn error(&mut self, message: &str) {
        self.log(LogEntry::new(
            LogLevel::Error,
            message,
            &self.source.clone(),
        ));
    }

    pub fn fatal(&mut self, message: &str) {
        self.log(LogEntry::new(
            LogLevel::Fatal,
            message,
            &self.source.clone(),
        ));
    }

    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn entries_by_level(&self, level: LogLevel) -> Vec<&LogEntry> {
        self.entries.iter().filter(|e| e.level == level).collect()
    }

    pub fn entries_by_source(&self, source: &str) -> Vec<&LogEntry> {
        self.entries.iter().filter(|e| e.source == source).collect()
    }

    pub fn recent_entries(&self, count: usize) -> &[LogEntry] {
        let start = self.entries.len().saturating_sub(count);
        &self.entries[start..]
    }

    pub fn entries_since(&self, since: DateTime<Utc>) -> Vec<&LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp >= since)
            .collect()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn format_entry(&self, entry: &LogEntry) -> String {
        match self.format {
            LogFormat::Json => entry.to_json(),
            LogFormat::Text => entry.to_text(),
            LogFormat::Logfmt => self.to_logfmt(entry),
        }
    }

    fn to_logfmt(&self, entry: &LogEntry) -> String {
        let mut parts = vec![
            format!("ts={}", entry.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ")),
            format!("level={}", entry.level),
            format!("source={}", entry.source),
            format!("msg=\"{}\"", entry.message),
        ];

        if let Some(ref tid) = entry.trace_id {
            parts.push(format!("trace_id={}", tid));
        }
        if let Some(ref sid) = entry.span_id {
            parts.push(format!("span_id={}", sid));
        }

        for (k, v) in &entry.fields {
            parts.push(format!("{}={}", k, v));
        }

        parts.join(" ")
    }

    pub fn format_all(&self) -> String {
        self.entries
            .iter()
            .map(|e| self.format_entry(e))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn exporter_config(&self) -> Option<&LogExporterConfig> {
        self.exporter.as_ref()
    }

    pub fn rotation_config(&self) -> Option<&RotationConfig> {
        self.rotation.as_ref()
    }
}

impl Default for StructuredLogger {
    fn default() -> Self {
        Self::new("nemue")
    }
}

pub struct LogAggregator {
    loggers: HashMap<String, StructuredLogger>,
    combined_entries: Vec<LogEntry>,
    max_combined: usize,
}

impl LogAggregator {
    pub fn new() -> Self {
        Self {
            loggers: HashMap::new(),
            combined_entries: Vec::new(),
            max_combined: 500_000,
        }
    }

    pub fn with_max_combined(mut self, max: usize) -> Self {
        self.max_combined = max;
        self
    }

    pub fn register_logger(&mut self, name: &str, logger: StructuredLogger) {
        self.loggers.insert(name.to_string(), logger);
    }

    pub fn get_logger(&self, name: &str) -> Option<&StructuredLogger> {
        self.loggers.get(name)
    }

    pub fn get_logger_mut(&mut self, name: &str) -> Option<&mut StructuredLogger> {
        self.loggers.get_mut(name)
    }

    pub fn logger_count(&self) -> usize {
        self.loggers.len()
    }

    pub fn ingest(&mut self, entry: LogEntry) {
        self.combined_entries.push(entry);
        if self.combined_entries.len() > self.max_combined {
            self.combined_entries.remove(0);
        }
    }

    pub fn combined_entries(&self) -> &[LogEntry] {
        &self.combined_entries
    }

    pub fn combined_count(&self) -> usize {
        self.combined_entries.len()
    }

    pub fn all_entries(&self) -> Vec<&LogEntry> {
        let mut all: Vec<&LogEntry> = self.combined_entries.iter().collect();
        for logger in self.loggers.values() {
            all.extend(logger.entries());
        }
        all.sort_by_key(|a| a.timestamp);
        all
    }

    pub fn total_entry_count(&self) -> usize {
        let logger_total: usize = self.loggers.values().map(|l| l.entry_count()).sum();
        logger_total + self.combined_entries.len()
    }

    pub fn entries_by_level(&self, level: LogLevel) -> Vec<&LogEntry> {
        let mut all = self.all_entries();
        all.retain(|e| e.level == level);
        all
    }

    pub fn clear_all(&mut self) {
        self.combined_entries.clear();
        for logger in self.loggers.values_mut() {
            logger.clear();
        }
    }
}

impl Default for LogAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Trace.to_string(), "trace");
        assert_eq!(LogLevel::Debug.to_string(), "debug");
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(LogLevel::Error.to_string(), "error");
        assert_eq!(LogLevel::Fatal.to_string(), "fatal");
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Fatal);
    }

    #[test]
    fn test_log_level_from_str_lossy() {
        assert_eq!(LogLevel::from_str_lossy("TRACE"), LogLevel::Trace);
        assert_eq!(LogLevel::from_str_lossy("Warning"), LogLevel::Warn);
        assert_eq!(LogLevel::from_str_lossy("CRITICAL"), LogLevel::Fatal);
        assert_eq!(LogLevel::from_str_lossy("unknown"), LogLevel::Info);
    }

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(LogLevel::Info, "server started", "main")
            .with_field("port", "8080")
            .with_field("host", "0.0.0.0")
            .with_trace("abc123", "span1");

        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.message, "server started");
        assert_eq!(entry.source, "main");
        assert_eq!(entry.fields.get("port").unwrap(), "8080");
        assert_eq!(entry.trace_id.unwrap(), "abc123");
        assert_eq!(entry.span_id.unwrap(), "span1");
    }

    #[test]
    fn test_log_entry_with_fields() {
        let mut fields = HashMap::new();
        fields.insert("key1".to_string(), "val1".to_string());
        fields.insert("key2".to_string(), "val2".to_string());

        let entry = LogEntry::new(LogLevel::Info, "test", "src").with_fields(fields);
        assert_eq!(entry.fields.len(), 2);
    }

    #[test]
    fn test_log_entry_to_json() {
        let entry = LogEntry::new(LogLevel::Error, "connection failed", "db");
        let json = entry.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["level"], "error");
        assert_eq!(parsed["message"], "connection failed");
        assert_eq!(parsed["source"], "db");
    }

    #[test]
    fn test_log_entry_to_text() {
        let entry = LogEntry::new(LogLevel::Info, "hello", "app");
        let text = entry.to_text();
        assert!(text.contains("[info]"));
        assert!(text.contains("app"));
        assert!(text.contains("hello"));
    }

    #[test]
    fn test_log_entry_to_text_with_fields() {
        let entry = LogEntry::new(LogLevel::Info, "req", "api")
            .with_field("method", "GET")
            .with_field("path", "/health");

        let text = entry.to_text();
        assert!(text.contains("method=GET"));
        assert!(text.contains("path=/health"));
    }

    #[test]
    fn test_log_entry_to_text_with_trace() {
        let entry = LogEntry::new(LogLevel::Info, "test", "svc").with_trace("tid", "sid");
        let text = entry.to_text();
        assert!(text.contains("[tid:sid]"));
    }

    #[test]
    fn test_log_format_display() {
        assert_eq!(LogFormat::Json.to_string(), "json");
        assert_eq!(LogFormat::Text.to_string(), "text");
        assert_eq!(LogFormat::Logfmt.to_string(), "logfmt");
    }

    #[test]
    fn test_rotation_config() {
        let config = RotationConfig::new(50 * 1024 * 1024, 5).with_compress(false);
        assert_eq!(config.max_size_bytes, 50 * 1024 * 1024);
        assert_eq!(config.max_files, 5);
        assert!(!config.compress_rotated);
    }

    #[test]
    fn test_rotation_config_default() {
        let config = RotationConfig::default();
        assert_eq!(config.max_size_bytes, 100 * 1024 * 1024);
        assert_eq!(config.max_files, 10);
        assert!(config.compress_rotated);
    }

    #[test]
    fn test_log_exporter_config() {
        let config = LogExporterConfig::new("http://loki:3100", LogFormat::Json)
            .with_batch_size(50)
            .with_flush_interval(10)
            .with_label("env", "prod");

        assert_eq!(config.endpoint, "http://loki:3100");
        assert_eq!(config.format, LogFormat::Json);
        assert_eq!(config.batch_size, 50);
        assert_eq!(config.flush_interval_seconds, 10);
        assert_eq!(config.labels.get("env").unwrap(), "prod");
    }

    #[test]
    fn test_log_filter_matches() {
        let filter = LogFilter::new(LogLevel::Warn);
        assert!(!filter.matches(&LogEntry::new(LogLevel::Info, "test", "src")));
        assert!(filter.matches(&LogEntry::new(LogLevel::Warn, "test", "src")));
        assert!(filter.matches(&LogEntry::new(LogLevel::Error, "test", "src")));
    }

    #[test]
    fn test_log_filter_with_sources() {
        let filter =
            LogFilter::new(LogLevel::Info).with_sources(vec!["api".to_string(), "db".to_string()]);

        assert!(filter.matches(&LogEntry::new(LogLevel::Info, "test", "api")));
        assert!(filter.matches(&LogEntry::new(LogLevel::Info, "test", "db")));
        assert!(!filter.matches(&LogEntry::new(LogLevel::Info, "test", "auth")));
    }

    #[test]
    fn test_log_filter_with_message_pattern() {
        let filter = LogFilter::new(LogLevel::Info).with_message_pattern("connection");

        assert!(filter.matches(&LogEntry::new(
            LogLevel::Info,
            "connection established",
            "net"
        )));
        assert!(!filter.matches(&LogEntry::new(LogLevel::Info, "server started", "net")));
    }

    #[test]
    fn test_structured_logger_creation() {
        let logger = StructuredLogger::new("scanner")
            .with_min_level(LogLevel::Debug)
            .with_format(LogFormat::Text)
            .with_max_entries(1000);

        assert_eq!(logger.entry_count(), 0);
    }

    #[test]
    fn test_structured_logger_log_levels() {
        let mut logger = StructuredLogger::new("test").with_min_level(LogLevel::Warn);

        logger.trace("trace");
        logger.debug("debug");
        logger.info("info");
        logger.warn("warn");
        logger.error("error");
        logger.fatal("fatal");

        assert_eq!(logger.entry_count(), 3);
        assert_eq!(logger.entries_by_level(LogLevel::Warn).len(), 1);
        assert_eq!(logger.entries_by_level(LogLevel::Error).len(), 1);
        assert_eq!(logger.entries_by_level(LogLevel::Fatal).len(), 1);
    }

    #[test]
    fn test_structured_logger_max_entries() {
        let mut logger = StructuredLogger::new("test")
            .with_min_level(LogLevel::Info)
            .with_max_entries(5);

        for i in 0..10 {
            logger.info(&format!("msg {}", i));
        }

        assert_eq!(logger.entry_count(), 5);
    }

    #[test]
    fn test_structured_logger_entries_by_source() {
        let mut logger = StructuredLogger::new("main").with_min_level(LogLevel::Info);

        logger.log(LogEntry::new(LogLevel::Info, "a", "src1"));
        logger.log(LogEntry::new(LogLevel::Info, "b", "src2"));
        logger.log(LogEntry::new(LogLevel::Info, "c", "src1"));

        assert_eq!(logger.entries_by_source("src1").len(), 2);
        assert_eq!(logger.entries_by_source("src2").len(), 1);
    }

    #[test]
    fn test_structured_logger_recent_entries() {
        let mut logger = StructuredLogger::new("test").with_min_level(LogLevel::Info);

        for i in 0..10 {
            logger.info(&format!("msg {}", i));
        }

        let recent = logger.recent_entries(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].message, "msg 7");
    }

    #[test]
    fn test_structured_logger_entries_since() {
        let mut logger = StructuredLogger::new("test").with_min_level(LogLevel::Info);
        logger.info("before");

        let since = Utc::now();
        logger.info("after");

        let entries = logger.entries_since(since);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "after");
    }

    #[test]
    fn test_structured_logger_format_json() {
        let mut logger = StructuredLogger::new("test")
            .with_min_level(LogLevel::Info)
            .with_format(LogFormat::Json);

        logger.info("test message");

        let formatted = logger.format_all();
        assert!(formatted.contains("\"message\":\"test message\""));
    }

    #[test]
    fn test_structured_logger_format_text() {
        let mut logger = StructuredLogger::new("test")
            .with_min_level(LogLevel::Info)
            .with_format(LogFormat::Text);

        logger.info("hello");

        let formatted = logger.format_all();
        assert!(formatted.contains("[info]"));
        assert!(formatted.contains("hello"));
    }

    #[test]
    fn test_structured_logger_format_logfmt() {
        let mut logger = StructuredLogger::new("svc")
            .with_min_level(LogLevel::Info)
            .with_format(LogFormat::Logfmt);

        logger.info("started");

        let formatted = logger.format_all();
        assert!(formatted.contains("level=info"));
        assert!(formatted.contains("source=svc"));
        assert!(formatted.contains("msg=\"started\""));
    }

    #[test]
    fn test_structured_logger_with_filter() {
        let mut logger = StructuredLogger::new("test").with_min_level(LogLevel::Info);

        logger.add_filter(LogFilter::new(LogLevel::Info).with_sources(vec!["allowed".to_string()]));

        logger.log(LogEntry::new(LogLevel::Info, "ok", "allowed"));
        logger.log(LogEntry::new(LogLevel::Info, "blocked", "denied"));

        assert_eq!(logger.entry_count(), 1);
    }

    #[test]
    fn test_structured_logger_rotation_config() {
        let logger = StructuredLogger::new("test").with_rotation(RotationConfig::new(1024, 3));
        assert!(logger.rotation_config().is_some());
    }

    #[test]
    fn test_structured_logger_exporter_config() {
        let logger = StructuredLogger::new("test")
            .with_exporter(LogExporterConfig::new("http://loki:3100", LogFormat::Json));
        assert!(logger.exporter_config().is_some());
    }

    #[test]
    fn test_structured_logger_clear() {
        let mut logger = StructuredLogger::new("test").with_min_level(LogLevel::Info);
        logger.info("a");
        logger.info("b");
        assert_eq!(logger.entry_count(), 2);

        logger.clear();
        assert_eq!(logger.entry_count(), 0);
    }

    #[test]
    fn test_structured_logger_default() {
        let logger = StructuredLogger::default();
        assert_eq!(logger.entry_count(), 0);
    }

    #[test]
    fn test_log_aggregator_register_and_get() {
        let mut agg = LogAggregator::new();
        agg.register_logger("scanner", StructuredLogger::new("scanner"));

        assert!(agg.get_logger("scanner").is_some());
        assert!(agg.get_logger("missing").is_none());
        assert_eq!(agg.logger_count(), 1);
    }

    #[test]
    fn test_log_aggregator_get_mut() {
        let mut agg = LogAggregator::new();
        agg.register_logger(
            "svc",
            StructuredLogger::new("svc").with_min_level(LogLevel::Info),
        );

        let logger = agg.get_logger_mut("svc").unwrap();
        logger.info("hello");

        assert_eq!(agg.get_logger("svc").unwrap().entry_count(), 1);
    }

    #[test]
    fn test_log_aggregator_ingest() {
        let mut agg = LogAggregator::new();
        agg.ingest(LogEntry::new(LogLevel::Info, "external", "ext"));
        agg.ingest(LogEntry::new(LogLevel::Error, "fail", "ext"));

        assert_eq!(agg.combined_count(), 2);
    }

    #[test]
    fn test_log_aggregator_max_combined() {
        let mut agg = LogAggregator::new().with_max_combined(3);

        for i in 0..5 {
            agg.ingest(LogEntry::new(LogLevel::Info, &format!("msg {}", i), "src"));
        }

        assert_eq!(agg.combined_count(), 3);
    }

    #[test]
    fn test_log_aggregator_all_entries_sorted() {
        let mut agg = LogAggregator::new();
        agg.register_logger(
            "a",
            StructuredLogger::new("a").with_min_level(LogLevel::Info),
        );

        agg.get_logger_mut("a").unwrap().info("from logger");
        agg.ingest(LogEntry::new(LogLevel::Info, "from aggregator", "ext"));

        let all = agg.all_entries();
        assert_eq!(all.len(), 2);
        assert!(all[0].timestamp <= all[1].timestamp);
    }

    #[test]
    fn test_log_aggregator_total_entry_count() {
        let mut agg = LogAggregator::new();
        agg.register_logger(
            "a",
            StructuredLogger::new("a").with_min_level(LogLevel::Info),
        );
        agg.get_logger_mut("a").unwrap().info("test");
        agg.ingest(LogEntry::new(LogLevel::Info, "test", "ext"));

        assert_eq!(agg.total_entry_count(), 2);
    }

    #[test]
    fn test_log_aggregator_entries_by_level() {
        let mut agg = LogAggregator::new();
        agg.ingest(LogEntry::new(LogLevel::Info, "i", "s"));
        agg.ingest(LogEntry::new(LogLevel::Error, "e", "s"));
        agg.ingest(LogEntry::new(LogLevel::Info, "i2", "s"));

        assert_eq!(agg.entries_by_level(LogLevel::Info).len(), 2);
        assert_eq!(agg.entries_by_level(LogLevel::Error).len(), 1);
    }

    #[test]
    fn test_log_aggregator_clear_all() {
        let mut agg = LogAggregator::new();
        agg.register_logger(
            "a",
            StructuredLogger::new("a").with_min_level(LogLevel::Info),
        );
        agg.get_logger_mut("a").unwrap().info("test");
        agg.ingest(LogEntry::new(LogLevel::Info, "test", "ext"));

        agg.clear_all();
        assert_eq!(agg.combined_count(), 0);
        assert_eq!(agg.get_logger("a").unwrap().entry_count(), 0);
    }

    #[test]
    fn test_log_aggregator_default() {
        let agg = LogAggregator::default();
        assert_eq!(agg.logger_count(), 0);
        assert_eq!(agg.combined_count(), 0);
    }

    #[test]
    fn test_log_entry_serialization() {
        let entry = LogEntry::new(LogLevel::Info, "test", "src")
            .with_field("key", "val")
            .with_trace("t1", "s1");

        let json = serde_json::to_string(&entry).unwrap();
        let loaded: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.level, LogLevel::Info);
        assert_eq!(loaded.message, "test");
        assert_eq!(loaded.trace_id.unwrap(), "t1");
    }

    #[test]
    fn test_log_filter_serialization() {
        let filter = LogFilter::new(LogLevel::Warn)
            .with_sources(vec!["api".to_string()])
            .with_message_pattern("error");

        let json = serde_json::to_string(&filter).unwrap();
        let loaded: LogFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.min_level, LogLevel::Warn);
        assert_eq!(loaded.sources.unwrap().len(), 1);
    }

    #[test]
    fn test_rotation_config_serialization() {
        let config = RotationConfig::new(1024, 5);
        let json = serde_json::to_string(&config).unwrap();
        let loaded: RotationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.max_size_bytes, 1024);
    }
}
