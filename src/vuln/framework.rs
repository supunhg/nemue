use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

/// Vulnerability script category
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum VulnCategory {
    /// Authentication and credential issues
    Authentication,
    /// Information disclosure vulnerabilities
    InfoDisclosure,
    /// Remote code execution vulnerabilities
    RemoteCodeExecution,
    /// Denial of service vulnerabilities
    DenialOfService,
    /// Privilege escalation vulnerabilities
    PrivilegeEscalation,
    /// SQL injection vulnerabilities
    SqlInjection,
    /// Cross-site scripting vulnerabilities
    CrossSiteScripting,
    /// Configuration issues
    Misconfiguration,
    /// Default credentials
    DefaultCredentials,
    /// Cryptographic issues
    Cryptography,
    /// Other vulnerabilities
    Other,
}

impl VulnCategory {
    pub fn as_str(&self) -> &str {
        match self {
            VulnCategory::Authentication => "auth",
            VulnCategory::InfoDisclosure => "info-disclosure",
            VulnCategory::RemoteCodeExecution => "rce",
            VulnCategory::DenialOfService => "dos",
            VulnCategory::PrivilegeEscalation => "privesc",
            VulnCategory::SqlInjection => "sqli",
            VulnCategory::CrossSiteScripting => "xss",
            VulnCategory::Misconfiguration => "config",
            VulnCategory::DefaultCredentials => "default-creds",
            VulnCategory::Cryptography => "crypto",
            VulnCategory::Other => "other",
        }
    }
}

/// Vulnerability severity level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum VulnSeverity {
    /// Informational finding
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

impl VulnSeverity {
    pub fn as_str(&self) -> &str {
        match self {
            VulnSeverity::Info => "INFO",
            VulnSeverity::Low => "LOW",
            VulnSeverity::Medium => "MEDIUM",
            VulnSeverity::High => "HIGH",
            VulnSeverity::Critical => "CRITICAL",
        }
    }

    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => VulnSeverity::Critical,
            s if s >= 7.0 => VulnSeverity::High,
            s if s >= 4.0 => VulnSeverity::Medium,
            s if s >= 0.1 => VulnSeverity::Low,
            _ => VulnSeverity::Info,
        }
    }
}

/// Result of a vulnerability check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnResult {
    /// Script that produced this result
    pub script_id: String,
    /// Target host
    pub target: String,
    /// Target port
    pub port: u16,
    /// Whether vulnerability was detected
    pub vulnerable: bool,
    /// Vulnerability severity
    pub severity: VulnSeverity,
    /// CVE identifiers
    pub cve_ids: Vec<String>,
    /// Detailed description
    pub description: String,
    /// Evidence/proof
    pub evidence: Option<String>,
    /// Remediation advice
    pub remediation: Option<String>,
    /// References (URLs)
    pub references: Vec<String>,
    /// Exploit availability
    pub exploit_available: bool,
}

/// Vulnerability detection script metadata
#[derive(Clone)]
pub struct VulnScript {
    /// Unique script identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Script description
    pub description: String,
    /// Script category
    pub category: VulnCategory,
    /// Target ports (empty for all ports)
    pub ports: Vec<u16>,
    /// Target services (empty for all services)
    pub services: Vec<String>,
    /// Script execution function
    pub execute: Arc<dyn Fn(&str, u16) -> Result<VulnResult> + Send + Sync>,
}

impl VulnScript {
    /// Create a new vulnerability script
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        category: VulnCategory,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            category,
            ports: Vec::new(),
            services: Vec::new(),
            execute: Arc::new(|_, _| {
                Err(anyhow::anyhow!("Script execution not implemented"))
            }),
        }
    }

    /// Set target ports
    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.ports = ports;
        self
    }

    /// Set target services
    pub fn with_services(mut self, services: Vec<String>) -> Self {
        self.services = services;
        self
    }

    /// Set execution function
    pub fn with_executor<F>(mut self, executor: F) -> Self
    where
        F: Fn(&str, u16) -> Result<VulnResult> + Send + Sync + 'static,
    {
        self.execute = Arc::new(executor);
        self
    }

    /// Check if script should run against this port/service
    pub fn matches(&self, port: u16, service: Option<&str>) -> bool {
        // If ports are specified, check port match
        let port_match = self.ports.is_empty() || self.ports.contains(&port);

        // If services are specified, check service match
        let service_match = if self.services.is_empty() {
            true
        } else if let Some(svc) = service {
            self.services.iter().any(|s| svc.contains(s))
        } else {
            false
        };

        port_match && service_match
    }

    /// Execute the script
    pub fn run(&self, target: &str, port: u16) -> Result<VulnResult> {
        (self.execute)(target, port)
    }
}

/// Script execution engine with parallelization and timeout support
pub struct ScriptEngine {
    scripts: HashMap<String, VulnScript>,
    max_parallel: usize,
    timeout_secs: u64,
}

impl ScriptEngine {
    /// Create a new script engine
    pub fn new() -> Self {
        Self {
            scripts: HashMap::new(),
            max_parallel: 10,
            timeout_secs: 30,
        }
    }

    /// Set maximum parallel script execution
    pub fn with_max_parallel(mut self, max: usize) -> Self {
        self.max_parallel = max;
        self
    }

    /// Set script timeout in seconds
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Register a script
    pub fn register(&mut self, script: VulnScript) {
        self.scripts.insert(script.id.clone(), script);
    }

    /// Get script by ID
    pub fn get(&self, id: &str) -> Option<&VulnScript> {
        self.scripts.get(id)
    }

    /// List all scripts
    pub fn list_scripts(&self) -> Vec<&VulnScript> {
        self.scripts.values().collect()
    }

    /// List scripts by category
    pub fn list_by_category(&self, category: &VulnCategory) -> Vec<&VulnScript> {
        self.scripts
            .values()
            .filter(|s| &s.category == category)
            .collect()
    }

    /// Execute all matching scripts against a target
    pub async fn run_all(
        &self,
        target: &str,
        port: u16,
        service: Option<&str>,
    ) -> Result<Vec<VulnResult>> {
        let matching_scripts: Vec<_> = self
            .scripts
            .values()
            .filter(|s| s.matches(port, service))
            .collect();

        if matching_scripts.is_empty() {
            return Ok(Vec::new());
        }

        self.execute_scripts(matching_scripts, target, port).await
    }

    /// Execute scripts from a specific category
    pub async fn run_category(
        &self,
        category: &VulnCategory,
        target: &str,
        port: u16,
        service: Option<&str>,
    ) -> Result<Vec<VulnResult>> {
        let matching_scripts: Vec<_> = self
            .scripts
            .values()
            .filter(|s| &s.category == category && s.matches(port, service))
            .collect();

        self.execute_scripts(matching_scripts, target, port).await
    }

    /// Execute a specific script by ID
    pub async fn run_script(
        &self,
        script_id: &str,
        target: &str,
        port: u16,
    ) -> Result<VulnResult> {
        let script = self
            .scripts
            .get(script_id)
            .context("Script not found")?;

        self.execute_with_timeout(script, target, port).await
    }

    /// Execute multiple scripts in parallel with timeout
    async fn execute_scripts(
        &self,
        scripts: Vec<&VulnScript>,
        target: &str,
        port: u16,
    ) -> Result<Vec<VulnResult>> {
        let semaphore = Arc::new(Semaphore::new(self.max_parallel));
        let mut tasks = Vec::new();

        for script in scripts {
            let sem = semaphore.clone();
            let script = script.clone();
            let target = target.to_string();
            let timeout_duration = Duration::from_secs(self.timeout_secs);

            let task = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                
                let result = timeout(
                    timeout_duration,
                    tokio::task::spawn_blocking(move || script.run(&target, port))
                ).await;

                match result {
                    Ok(Ok(Ok(vuln_result))) => Some(vuln_result),
                    Ok(Ok(Err(_))) => None, // Script error
                    Ok(Err(_)) => None,      // Task join error
                    Err(_) => None,          // Timeout
                }
            });

            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(Some(result)) = task.await {
                results.push(result);
            }
        }

        Ok(results)
    }

    /// Execute a single script with timeout
    async fn execute_with_timeout(
        &self,
        script: &VulnScript,
        target: &str,
        port: u16,
    ) -> Result<VulnResult> {
        let script = script.clone();
        let target = target.to_string();
        let timeout_duration = Duration::from_secs(self.timeout_secs);

        let result = timeout(
            timeout_duration,
            tokio::task::spawn_blocking(move || script.run(&target, port))
        ).await;

        match result {
            Ok(Ok(vuln_result)) => vuln_result,
            Ok(Err(e)) => Err(anyhow::anyhow!("Script execution failed: {}", e)),
            Err(_) => Err(anyhow::anyhow!("Script execution timeout")),
        }
    }
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(VulnSeverity::from_cvss(9.5), VulnSeverity::Critical);
        assert_eq!(VulnSeverity::from_cvss(7.8), VulnSeverity::High);
        assert_eq!(VulnSeverity::from_cvss(5.5), VulnSeverity::Medium);
        assert_eq!(VulnSeverity::from_cvss(2.1), VulnSeverity::Low);
        assert_eq!(VulnSeverity::from_cvss(0.0), VulnSeverity::Info);
    }

    #[test]
    fn test_script_matching() {
        let script = VulnScript::new(
            "test",
            "Test Script",
            "Testing",
            VulnCategory::Authentication,
        )
        .with_ports(vec![22, 23])
        .with_services(vec!["ssh".to_string()]);

        assert!(script.matches(22, Some("ssh")));
        assert!(script.matches(23, Some("ssh-openssh")));
        assert!(!script.matches(80, Some("ssh")));
        assert!(!script.matches(22, Some("http")));
    }

    #[test]
    fn test_engine_registration() {
        let mut engine = ScriptEngine::new();
        
        let script = VulnScript::new(
            "test-1",
            "Test Script 1",
            "Testing",
            VulnCategory::Authentication,
        );
        
        engine.register(script);
        assert!(engine.get("test-1").is_some());
        assert!(engine.get("nonexistent").is_none());
    }

    #[test]
    fn test_list_by_category() {
        let mut engine = ScriptEngine::new();
        
        engine.register(VulnScript::new(
            "auth-1",
            "Auth Test 1",
            "Testing",
            VulnCategory::Authentication,
        ));
        
        engine.register(VulnScript::new(
            "auth-2",
            "Auth Test 2",
            "Testing",
            VulnCategory::Authentication,
        ));
        
        engine.register(VulnScript::new(
            "rce-1",
            "RCE Test",
            "Testing",
            VulnCategory::RemoteCodeExecution,
        ));

        let auth_scripts = engine.list_by_category(&VulnCategory::Authentication);
        assert_eq!(auth_scripts.len(), 2);

        let rce_scripts = engine.list_by_category(&VulnCategory::RemoteCodeExecution);
        assert_eq!(rce_scripts.len(), 1);
    }

    #[tokio::test]
    async fn test_script_execution() {
        let script = VulnScript::new(
            "test",
            "Test Script",
            "Testing",
            VulnCategory::Authentication,
        )
        .with_executor(|target, port| {
            Ok(VulnResult {
                script_id: "test".to_string(),
                target: target.to_string(),
                port,
                vulnerable: true,
                severity: VulnSeverity::High,
                cve_ids: vec!["CVE-2024-1234".to_string()],
                description: "Test vulnerability".to_string(),
                evidence: Some("Test evidence".to_string()),
                remediation: Some("Update software".to_string()),
                references: vec!["https://example.com".to_string()],
                exploit_available: false,
            })
        });

        let mut engine = ScriptEngine::new();
        engine.register(script);

        let result = engine.run_script("test", "192.168.1.1", 22).await.unwrap();
        assert_eq!(result.script_id, "test");
        assert!(result.vulnerable);
        assert_eq!(result.severity, VulnSeverity::High);
    }
}
