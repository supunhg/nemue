use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Degraded => write!(f, "degraded"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentType {
    System,
    Service,
    Database,
    Cache,
    Queue,
    ExternalApi,
    Network,
    Storage,
}

impl std::fmt::Display for ComponentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentType::System => write!(f, "system"),
            ComponentType::Service => write!(f, "service"),
            ComponentType::Database => write!(f, "database"),
            ComponentType::Cache => write!(f, "cache"),
            ComponentType::Queue => write!(f, "queue"),
            ComponentType::ExternalApi => write!(f, "external_api"),
            ComponentType::Network => write!(f, "network"),
            ComponentType::Storage => write!(f, "storage"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    pub name: String,
    pub component_type: ComponentType,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub latency_ms: Option<f64>,
    pub metadata: HashMap<String, String>,
    pub checked_at: DateTime<Utc>,
}

impl HealthCheck {
    pub fn new(name: &str, component_type: ComponentType, status: HealthStatus) -> Self {
        Self {
            name: name.to_string(),
            component_type,
            status,
            message: None,
            latency_ms: None,
            metadata: HashMap::new(),
            checked_at: Utc::now(),
        }
    }

    pub fn with_message(mut self, msg: &str) -> Self {
        self.message = Some(msg.to_string());
        self
    }

    pub fn with_latency(mut self, latency_ms: f64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn is_healthy(&self) -> bool {
        self.status == HealthStatus::Healthy
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub overall_status: HealthStatus,
    pub components: Vec<HealthCheck>,
    pub uptime_seconds: u64,
    pub version: String,
    pub checked_at: DateTime<Utc>,
}

impl SystemHealth {
    pub fn new(version: &str, uptime_seconds: u64) -> Self {
        Self {
            overall_status: HealthStatus::Healthy,
            components: Vec::new(),
            uptime_seconds,
            version: version.to_string(),
            checked_at: Utc::now(),
        }
    }

    pub fn healthy_count(&self) -> usize {
        self.components.iter().filter(|c| c.is_healthy()).count()
    }

    pub fn unhealthy_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status == HealthStatus::Unhealthy)
            .count()
    }

    pub fn degraded_count(&self) -> usize {
        self.components
            .iter()
            .filter(|c| c.status == HealthStatus::Degraded)
            .count()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyHealth {
    pub name: String,
    pub url: String,
    pub status: HealthStatus,
    pub latency_ms: f64,
    pub last_checked: DateTime<Utc>,
    pub consecutive_failures: u32,
    pub error_message: Option<String>,
}

impl DependencyHealth {
    pub fn new(name: &str, url: &str) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
            status: HealthStatus::Healthy,
            latency_ms: 0.0,
            last_checked: Utc::now(),
            consecutive_failures: 0,
            error_message: None,
        }
    }

    pub fn record_success(&mut self, latency_ms: f64) {
        self.status = HealthStatus::Healthy;
        self.latency_ms = latency_ms;
        self.last_checked = Utc::now();
        self.consecutive_failures = 0;
        self.error_message = None;
    }

    pub fn record_failure(&mut self, error: &str) {
        self.consecutive_failures += 1;
        self.last_checked = Utc::now();
        self.error_message = Some(error.to_string());
        self.status = if self.consecutive_failures >= 3 {
            HealthStatus::Unhealthy
        } else {
            HealthStatus::Degraded
        };
    }

    pub fn is_available(&self) -> bool {
        self.status != HealthStatus::Unhealthy
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthEndpoint {
    pub path: String,
    pub method: String,
    pub component_name: String,
    pub timeout_ms: u64,
    pub expected_status: u16,
}

impl HealthEndpoint {
    pub fn new(path: &str, component_name: &str) -> Self {
        Self {
            path: path.to_string(),
            method: "GET".to_string(),
            component_name: component_name.to_string(),
            timeout_ms: 5000,
            expected_status: 200,
        }
    }

    pub fn with_method(mut self, method: &str) -> Self {
        self.method = method.to_string();
        self
    }

    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    pub fn with_expected_status(mut self, status: u16) -> Self {
        self.expected_status = status;
        self
    }
}

pub struct HealthMonitor {
    checks: HashMap<String, HealthCheck>,
    dependencies: HashMap<String, DependencyHealth>,
    endpoints: Vec<HealthEndpoint>,
    version: String,
    start_time: DateTime<Utc>,
}

impl HealthMonitor {
    pub fn new(version: &str) -> Self {
        Self {
            checks: HashMap::new(),
            dependencies: HashMap::new(),
            endpoints: Vec::new(),
            version: version.to_string(),
            start_time: Utc::now(),
        }
    }

    pub fn register_check(&mut self, check: HealthCheck) {
        self.checks.insert(check.name.clone(), check);
    }

    pub fn register_dependency(&mut self, dep: DependencyHealth) {
        self.dependencies.insert(dep.name.clone(), dep);
    }

    pub fn register_endpoint(&mut self, endpoint: HealthEndpoint) {
        self.endpoints.push(endpoint);
    }

    pub fn update_check(&mut self, name: &str, check: HealthCheck) {
        self.checks.insert(name.to_string(), check);
    }

    pub fn update_dependency_success(&mut self, name: &str, latency_ms: f64) {
        if let Some(dep) = self.dependencies.get_mut(name) {
            dep.record_success(latency_ms);
        }
    }

    pub fn update_dependency_failure(&mut self, name: &str, error: &str) {
        if let Some(dep) = self.dependencies.get_mut(name) {
            dep.record_failure(error);
        }
    }

    pub fn get_check(&self, name: &str) -> Option<&HealthCheck> {
        self.checks.get(name)
    }

    pub fn get_dependency(&self, name: &str) -> Option<&DependencyHealth> {
        self.dependencies.get(name)
    }

    pub fn get_system_health(&self) -> SystemHealth {
        let uptime = Utc::now().signed_duration_since(self.start_time);
        let mut health = SystemHealth::new(&self.version, uptime.num_seconds().max(0) as u64);

        health.components = self.checks.values().cloned().collect();

        let has_unhealthy = health
            .components
            .iter()
            .any(|c| c.status == HealthStatus::Unhealthy);
        let has_degraded = health
            .components
            .iter()
            .any(|c| c.status == HealthStatus::Degraded);

        health.overall_status = if has_unhealthy {
            HealthStatus::Unhealthy
        } else if has_degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        health
    }

    pub fn get_dependency_health(&self) -> Vec<&DependencyHealth> {
        self.dependencies.values().collect()
    }

    pub fn all_healthy(&self) -> bool {
        self.checks.values().all(|c| c.is_healthy())
            && self.dependencies.values().all(|d| d.is_available())
    }

    pub fn endpoints(&self) -> &[HealthEndpoint] {
        &self.endpoints
    }

    pub fn check_count(&self) -> usize {
        self.checks.len()
    }

    pub fn dependency_count(&self) -> usize {
        self.dependencies.len()
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new("0.1.0")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
    }

    #[test]
    fn test_component_type_display() {
        assert_eq!(ComponentType::System.to_string(), "system");
        assert_eq!(ComponentType::Service.to_string(), "service");
        assert_eq!(ComponentType::Database.to_string(), "database");
        assert_eq!(ComponentType::Cache.to_string(), "cache");
    }

    #[test]
    fn test_health_check_creation() {
        let check = HealthCheck::new("database", ComponentType::Database, HealthStatus::Healthy)
            .with_message("Connection pool healthy")
            .with_latency(5.2)
            .with_metadata("pool_size", "10");

        assert_eq!(check.name, "database");
        assert_eq!(check.component_type, ComponentType::Database);
        assert_eq!(check.status, HealthStatus::Healthy);
        assert!(check.is_healthy());
        assert_eq!(check.message.unwrap(), "Connection pool healthy");
        assert_eq!(check.latency_ms.unwrap(), 5.2);
        assert_eq!(check.metadata.get("pool_size").unwrap(), "10");
    }

    #[test]
    fn test_health_check_not_healthy() {
        let check = HealthCheck::new("cache", ComponentType::Cache, HealthStatus::Degraded);
        assert!(!check.is_healthy());
    }

    #[test]
    fn test_system_health_counts() {
        let mut health = SystemHealth::new("1.0.0", 3600);
        health.components.push(HealthCheck::new(
            "a",
            ComponentType::Service,
            HealthStatus::Healthy,
        ));
        health.components.push(HealthCheck::new(
            "b",
            ComponentType::Database,
            HealthStatus::Degraded,
        ));
        health.components.push(HealthCheck::new(
            "c",
            ComponentType::Cache,
            HealthStatus::Unhealthy,
        ));
        health.components.push(HealthCheck::new(
            "d",
            ComponentType::Network,
            HealthStatus::Healthy,
        ));

        assert_eq!(health.healthy_count(), 2);
        assert_eq!(health.degraded_count(), 1);
        assert_eq!(health.unhealthy_count(), 1);
    }

    #[test]
    fn test_dependency_health_record_success() {
        let mut dep = DependencyHealth::new("auth-api", "https://auth.example.com/health");
        dep.record_failure("timeout");
        dep.record_failure("timeout");
        assert_eq!(dep.status, HealthStatus::Degraded);
        assert_eq!(dep.consecutive_failures, 2);

        dep.record_success(42.5);
        assert_eq!(dep.status, HealthStatus::Healthy);
        assert_eq!(dep.consecutive_failures, 0);
        assert_eq!(dep.latency_ms, 42.5);
        assert!(dep.error_message.is_none());
    }

    #[test]
    fn test_dependency_health_consecutive_failures() {
        let mut dep = DependencyHealth::new("payment-api", "https://pay.example.com/health");
        dep.record_failure("500");
        assert_eq!(dep.status, HealthStatus::Degraded);

        dep.record_failure("500");
        assert_eq!(dep.status, HealthStatus::Degraded);

        dep.record_failure("500");
        assert_eq!(dep.status, HealthStatus::Unhealthy);
        assert!(!dep.is_available());
    }

    #[test]
    fn test_dependency_health_is_available() {
        let mut dep = DependencyHealth::new("api", "https://api.example.com");
        assert!(dep.is_available());

        dep.record_failure("err");
        assert!(dep.is_available());

        dep.record_failure("err");
        dep.record_failure("err");
        assert!(!dep.is_available());
    }

    #[test]
    fn test_health_endpoint_builder() {
        let ep = HealthEndpoint::new("/api/health", "api-server")
            .with_method("POST")
            .with_timeout(3000)
            .with_expected_status(204);

        assert_eq!(ep.path, "/api/health");
        assert_eq!(ep.method, "POST");
        assert_eq!(ep.component_name, "api-server");
        assert_eq!(ep.timeout_ms, 3000);
        assert_eq!(ep.expected_status, 204);
    }

    #[test]
    fn test_health_endpoint_defaults() {
        let ep = HealthEndpoint::new("/health", "service");
        assert_eq!(ep.method, "GET");
        assert_eq!(ep.timeout_ms, 5000);
        assert_eq!(ep.expected_status, 200);
    }

    #[test]
    fn test_health_monitor_register_and_get() {
        let mut monitor = HealthMonitor::new("1.0.0");
        let check = HealthCheck::new("db", ComponentType::Database, HealthStatus::Healthy);
        monitor.register_check(check);

        assert!(monitor.get_check("db").is_some());
        assert!(monitor.get_check("missing").is_none());
        assert_eq!(monitor.check_count(), 1);
    }

    #[test]
    fn test_health_monitor_dependencies() {
        let mut monitor = HealthMonitor::new("1.0.0");
        let dep = DependencyHealth::new("redis", "redis://localhost:6379");
        monitor.register_dependency(dep);

        assert_eq!(monitor.dependency_count(), 1);
        monitor.update_dependency_success("redis", 2.1);
        let d = monitor.get_dependency("redis").unwrap();
        assert_eq!(d.latency_ms, 2.1);
        assert_eq!(d.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_health_monitor_update_check() {
        let mut monitor = HealthMonitor::new("1.0.0");
        monitor.register_check(HealthCheck::new(
            "svc",
            ComponentType::Service,
            HealthStatus::Healthy,
        ));
        assert!(monitor.get_check("svc").unwrap().is_healthy());

        monitor.update_check(
            "svc",
            HealthCheck::new("svc", ComponentType::Service, HealthStatus::Unhealthy)
                .with_message("service down"),
        );
        assert!(!monitor.get_check("svc").unwrap().is_healthy());
    }

    #[test]
    fn test_health_monitor_system_health_all_healthy() {
        let mut monitor = HealthMonitor::new("1.0.0");
        monitor.register_check(HealthCheck::new(
            "a",
            ComponentType::Service,
            HealthStatus::Healthy,
        ));
        monitor.register_check(HealthCheck::new(
            "b",
            ComponentType::Database,
            HealthStatus::Healthy,
        ));

        let health = monitor.get_system_health();
        assert_eq!(health.overall_status, HealthStatus::Healthy);
        assert_eq!(health.components.len(), 2);
        assert!(monitor.all_healthy());
    }

    #[test]
    fn test_health_monitor_system_health_degraded() {
        let mut monitor = HealthMonitor::new("1.0.0");
        monitor.register_check(HealthCheck::new(
            "a",
            ComponentType::Service,
            HealthStatus::Healthy,
        ));
        monitor.register_check(HealthCheck::new(
            "b",
            ComponentType::Cache,
            HealthStatus::Degraded,
        ));

        let health = monitor.get_system_health();
        assert_eq!(health.overall_status, HealthStatus::Degraded);
        assert!(!monitor.all_healthy());
    }

    #[test]
    fn test_health_monitor_system_health_unhealthy() {
        let mut monitor = HealthMonitor::new("1.0.0");
        monitor.register_check(HealthCheck::new(
            "a",
            ComponentType::Service,
            HealthStatus::Healthy,
        ));
        monitor.register_check(HealthCheck::new(
            "b",
            ComponentType::Database,
            HealthStatus::Unhealthy,
        ));
        monitor.register_check(HealthCheck::new(
            "c",
            ComponentType::Cache,
            HealthStatus::Degraded,
        ));

        let health = monitor.get_system_health();
        assert_eq!(health.overall_status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_health_monitor_endpoints() {
        let mut monitor = HealthMonitor::new("1.0.0");
        monitor.register_endpoint(HealthEndpoint::new("/health", "main"));
        monitor.register_endpoint(HealthEndpoint::new("/ready", "readiness"));

        assert_eq!(monitor.endpoints().len(), 2);
    }

    #[test]
    fn test_health_monitor_all_healthy_includes_dependencies() {
        let mut monitor = HealthMonitor::new("1.0.0");
        monitor.register_check(HealthCheck::new(
            "svc",
            ComponentType::Service,
            HealthStatus::Healthy,
        ));

        let mut dep = DependencyHealth::new("ext", "https://ext.example.com");
        dep.record_failure("err");
        dep.record_failure("err");
        dep.record_failure("err");
        monitor.register_dependency(dep);

        assert!(!monitor.all_healthy());
    }

    #[test]
    fn test_health_monitor_default() {
        let monitor = HealthMonitor::default();
        assert_eq!(monitor.version, "0.1.0");
        assert_eq!(monitor.check_count(), 0);
    }

    #[test]
    fn test_health_check_serialization() {
        let check = HealthCheck::new("db", ComponentType::Database, HealthStatus::Healthy)
            .with_message("ok")
            .with_latency(1.0);

        let json = serde_json::to_string(&check).unwrap();
        let loaded: HealthCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.name, "db");
        assert_eq!(loaded.status, HealthStatus::Healthy);
    }

    #[test]
    fn test_system_health_serialization() {
        let mut health = SystemHealth::new("2.0.0", 7200);
        health.components.push(HealthCheck::new(
            "api",
            ComponentType::Service,
            HealthStatus::Healthy,
        ));

        let json = serde_json::to_string(&health).unwrap();
        let loaded: SystemHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.version, "2.0.0");
        assert_eq!(loaded.components.len(), 1);
    }

    #[test]
    fn test_dependency_health_serialization() {
        let dep = DependencyHealth::new("api", "https://api.example.com");
        let json = serde_json::to_string(&dep).unwrap();
        let loaded: DependencyHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.name, "api");
        assert_eq!(loaded.url, "https://api.example.com");
    }
}
