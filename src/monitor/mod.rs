pub mod engine;
pub mod health;
pub mod metrics;
pub mod alerts;
pub mod logging;

pub use engine::{
    MonitorEngine, MonitorConfig, MonitorSession, MonitorStatus,
    ChangeDetection, ChangeType,
};

pub use health::{
    HealthMonitor, HealthCheck, HealthStatus, ComponentType,
    SystemHealth, DependencyHealth, HealthEndpoint,
};

pub use metrics::{
    MetricsRegistry, Metric, MetricType, MetricLabels,
    Histogram, HistogramBucket, Summary, SummaryQuantile,
    MetricSample, AggregatedMetric, MetricExporterConfig, ExportFormat,
};

pub use alerts::{
    AlertManager, Alert, AlertRule, AlertSeverity, AlertStatus,
    AlertChannel, AlertChannelType, AlertNotification, AlertHistoryEntry,
    ComparisonOperator, EscalationPolicy, EscalationLevel,
};

pub use logging::{
    StructuredLogger, LogAggregator, LogEntry, LogLevel, LogFormat,
    LogFilter, RotationConfig, LogExporterConfig,
};
