//! Container Runtime Scanning Module
//!
//! Provides scanning for container runtimes including containerd, CRI-O, and Podman.

use serde::{Deserialize, Serialize};
use std::process::Command;

use crate::containers::ContainerSeverity;

/// Container runtime type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RuntimeType {
    #[default]
    Unknown,
    Containerd,
    CRIO,
    Podman,
    Docker,
}

impl RuntimeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuntimeType::Containerd => "containerd",
            RuntimeType::CRIO => "CRI-O",
            RuntimeType::Podman => "Podman",
            RuntimeType::Docker => "Docker",
            RuntimeType::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for RuntimeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Runtime scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Runtime to scan (None = auto-detect)
    pub runtime: Option<RuntimeType>,
    /// Check runtime configuration
    pub check_config: bool,
    /// Check seccomp profiles
    pub check_seccomp: bool,
    /// Check AppArmor profiles
    pub check_apparmor: bool,
    /// Check SELinux configuration
    pub check_selinux: bool,
    /// Check runtime version for known vulnerabilities
    pub check_version: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            runtime: None,
            check_config: true,
            check_seccomp: true,
            check_apparmor: true,
            check_selinux: true,
            check_version: true,
        }
    }
}

/// Runtime information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeInfo {
    pub runtime_type: RuntimeType,
    pub version: String,
    pub root_dir: String,
    pub log_level: String,
    pub cgroup_driver: String,
    pub default_runtime: String,
    pub runtimes: Vec<RuntimeEndpoint>,
    pub seccomp_enabled: bool,
    pub seccomp_profile: String,
    pub apparmor_enabled: bool,
    pub selinux_enabled: bool,
    pub user_namespace_enabled: bool,
    pub no_new_privileges: bool,
}

/// Runtime endpoint configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeEndpoint {
    pub name: String,
    pub runtime_type: String,
    pub endpoint: String,
}

/// Security finding from runtime scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeFinding {
    pub title: String,
    pub description: String,
    pub severity: ContainerSeverity,
    pub category: String,
    pub recommendation: String,
}

/// Runtime scan results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeResults {
    pub runtime_info: Option<RuntimeInfo>,
    pub findings: Vec<RuntimeFinding>,
    pub detected_runtime: RuntimeType,
}

/// Container runtime scanner
pub struct RuntimeScanner {
    config: RuntimeConfig,
}

impl RuntimeScanner {
    pub fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }

    pub fn with_default() -> Self {
        Self::new(RuntimeConfig::default())
    }

    /// Run full runtime security scan
    pub fn scan(&self) -> RuntimeResults {
        let mut results = RuntimeResults::default();

        // Detect runtime
        results.detected_runtime = self.config.runtime.unwrap_or_else(|| self.detect_runtime());

        // Gather runtime info based on detected type
        results.runtime_info = match results.detected_runtime {
            RuntimeType::Containerd => self.scan_containerd(),
            RuntimeType::CRIO => self.scan_crio(),
            RuntimeType::Podman => self.scan_podman(),
            RuntimeType::Docker => self.scan_docker_runtime(),
            RuntimeType::Unknown => None,
        };

        // Run security assessments
        results.findings = self.assess_security(&results);

        results
    }

    /// Auto-detect which container runtime is in use
    fn detect_runtime(&self) -> RuntimeType {
        // Check for containerd
        if Command::new("containerd")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return RuntimeType::Containerd;
        }

        // Check for CRI-O
        if Command::new("crio")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return RuntimeType::CRIO;
        }

        // Check for Podman
        if Command::new("podman")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return RuntimeType::Podman;
        }

        // Check for Docker
        if Command::new("docker")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return RuntimeType::Docker;
        }

        RuntimeType::Unknown
    }

    /// Scan containerd configuration
    fn scan_containerd(&self) -> Option<RuntimeInfo> {
        let version_output = Command::new("containerd").arg("--version").output().ok()?;

        let version_str = String::from_utf8_lossy(&version_output.stdout);
        let version = version_str.lines().next().unwrap_or("").trim().to_string();

        // Try to read containerd config
        let config_output = Command::new("containerd")
            .arg("config")
            .arg("dump")
            .output()
            .ok();

        let config_str = config_output
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let seccomp_enabled = !config_str.contains("disable_seccomp = true");
        let apparmor_enabled = !config_str.contains("disable_apparmor = true");

        Some(RuntimeInfo {
            runtime_type: RuntimeType::Containerd,
            version,
            root_dir: Self::extract_config_value(&config_str, "root"),
            log_level: Self::extract_config_value(&config_str, "level"),
            cgroup_driver: String::new(),
            default_runtime: Self::extract_config_value(&config_str, "default_runtime_name"),
            runtimes: Vec::new(),
            seccomp_enabled,
            seccomp_profile: String::new(),
            apparmor_enabled,
            selinux_enabled: false,
            user_namespace_enabled: config_str.contains("enable_unprivileged"),
            no_new_privileges: config_str.contains("no_new_privileges = true"),
        })
    }

    /// Scan CRI-O configuration
    fn scan_crio(&self) -> Option<RuntimeInfo> {
        let version_output = Command::new("crio").arg("--version").output().ok()?;

        let version_str = String::from_utf8_lossy(&version_output.stdout);
        let version = version_str.lines().next().unwrap_or("").trim().to_string();

        // Try to read CRI-O config
        let config_paths = ["/etc/crio/crio.conf", "/etc/crio/crio.conf.d/"];
        let mut config_str = String::new();
        for path in &config_paths {
            if let Ok(content) = std::fs::read_to_string(path) {
                config_str.push_str(&content);
            }
        }

        let seccomp_enabled =
            !config_str.contains("seccomp_enabled = false") && !config_str.contains("\"\"");
        let apparmor_enabled = !config_str.contains("apparmor_enabled = false");

        Some(RuntimeInfo {
            runtime_type: RuntimeType::CRIO,
            version,
            root_dir: Self::extract_config_value(&config_str, "root"),
            log_level: Self::extract_config_value(&config_str, "log_level"),
            cgroup_driver: Self::extract_config_value(&config_str, "cgroup_manager"),
            default_runtime: Self::extract_config_value(&config_str, "default_runtime"),
            runtimes: Vec::new(),
            seccomp_enabled,
            seccomp_profile: Self::extract_config_value(&config_str, "seccomp_profile"),
            apparmor_enabled,
            selinux_enabled: config_str.contains("selinux = true"),
            user_namespace_enabled: config_str.contains("manage_ns_lifecycle = true"),
            no_new_privileges: config_str.contains("no_new_privileges = true"),
        })
    }

    /// Scan Podman configuration
    fn scan_podman(&self) -> Option<RuntimeInfo> {
        let version_output = Command::new("podman").arg("--version").output().ok()?;

        let version_str = String::from_utf8_lossy(&version_output.stdout);
        let version = version_str
            .split_whitespace()
            .last()
            .unwrap_or("")
            .to_string();

        // Get Podman info
        let info_output = Command::new("podman")
            .arg("info")
            .arg("--format")
            .arg("json")
            .output()
            .ok();

        let info: serde_json::Value = info_output
            .and_then(|o| serde_json::from_slice(&o.stdout).ok())
            .unwrap_or_default();

        let host = info.get("host");
        let store = info.get("store");

        let seccomp_enabled = host
            .and_then(|h| h.get("security"))
            .and_then(|s| s.get("seccomp_enabled"))
            .and_then(|b| b.as_bool())
            .unwrap_or(true);

        let apparmor_enabled = host
            .and_then(|h| h.get("security"))
            .and_then(|s| s.get("apparmor_enabled"))
            .and_then(|b| b.as_bool())
            .unwrap_or(false);

        let selinux_enabled = host
            .and_then(|h| h.get("security"))
            .and_then(|s| s.get("selinux_enabled"))
            .and_then(|b| b.as_bool())
            .unwrap_or(false);

        let graph_root = store
            .and_then(|s| s.get("graphRoot"))
            .and_then(|g| g.as_str())
            .unwrap_or("")
            .to_string();

        Some(RuntimeInfo {
            runtime_type: RuntimeType::Podman,
            version,
            root_dir: graph_root,
            log_level: String::new(),
            cgroup_driver: host
                .and_then(|h| h.get("cgroupManager"))
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string(),
            default_runtime: String::new(),
            runtimes: Vec::new(),
            seccomp_enabled,
            seccomp_profile: String::new(),
            apparmor_enabled,
            selinux_enabled,
            user_namespace_enabled: false,
            no_new_privileges: false,
        })
    }

    /// Scan Docker runtime configuration
    fn scan_docker_runtime(&self) -> Option<RuntimeInfo> {
        let version_output = Command::new("docker")
            .arg("version")
            .arg("--format")
            .arg("{{.Server.Version}}")
            .output()
            .ok()?;

        let version = String::from_utf8_lossy(&version_output.stdout)
            .trim()
            .to_string();

        let info_output = Command::new("docker")
            .arg("info")
            .arg("--format")
            .arg("{{.SecurityOptions}}|{{.CgroupDriver}}|{{.Driver}}")
            .output()
            .ok()?;

        let info_str = String::from_utf8_lossy(&info_output.stdout);
        let parts: Vec<&str> = info_str.trim().splitn(3, '|').collect();

        let security_opts = parts.first().unwrap_or(&"").to_string();
        let seccomp_enabled = security_opts.contains("seccomp");
        let apparmor_enabled = security_opts.contains("apparmor");
        let selinux_enabled = security_opts.contains("selinux");
        let userns_enabled = security_opts.contains("userns");

        Some(RuntimeInfo {
            runtime_type: RuntimeType::Docker,
            version,
            root_dir: String::new(),
            log_level: String::new(),
            cgroup_driver: parts.get(1).unwrap_or(&"").to_string(),
            default_runtime: String::new(),
            runtimes: Vec::new(),
            seccomp_enabled,
            seccomp_profile: String::new(),
            apparmor_enabled,
            selinux_enabled,
            user_namespace_enabled: userns_enabled,
            no_new_privileges: false,
        })
    }

    fn extract_config_value(config: &str, key: &str) -> String {
        for line in config.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(key) {
                if let Some(val) = trimmed.split('=').nth(1) {
                    return val.trim().trim_matches('"').to_string();
                }
            }
        }
        String::new()
    }

    /// Perform security assessment on runtime configuration
    fn assess_security(&self, results: &RuntimeResults) -> Vec<RuntimeFinding> {
        let mut findings = Vec::new();

        if let Some(ref info) = results.runtime_info {
            // Check seccomp
            if self.config.check_seccomp && !info.seccomp_enabled {
                findings.push(RuntimeFinding {
                    title: "Seccomp not enabled".to_string(),
                    description: format!("{} does not have seccomp enabled. Seccomp profiles limit available system calls.", info.runtime_type),
                    severity: ContainerSeverity::High,
                    category: "runtime".to_string(),
                    recommendation: "Enable seccomp with a default profile to restrict system calls.".to_string(),
                });
            }

            // Check AppArmor
            if self.config.check_apparmor && !info.apparmor_enabled {
                findings.push(RuntimeFinding {
                    title: "AppArmor not enabled".to_string(),
                    description: format!("{} does not have AppArmor enabled. AppArmor provides mandatory access control.", info.runtime_type),
                    severity: ContainerSeverity::Medium,
                    category: "runtime".to_string(),
                    recommendation: "Enable AppArmor enforcement for container processes.".to_string(),
                });
            }

            // Check SELinux
            if self.config.check_selinux && !info.selinux_enabled {
                findings.push(RuntimeFinding {
                    title: "SELinux not enabled".to_string(),
                    description: format!("{} does not have SELinux enabled. SELinux provides additional access control.", info.runtime_type),
                    severity: ContainerSeverity::Low,
                    category: "runtime".to_string(),
                    recommendation: "Enable SELinux in enforcing mode for container isolation.".to_string(),
                });
            }

            // Check no-new-privileges
            if !info.no_new_privileges {
                findings.push(RuntimeFinding {
                    title: "no_new_privileges not set by default".to_string(),
                    description: "Without no_new_privileges, processes can gain additional privileges via setuid binaries.".to_string(),
                    severity: ContainerSeverity::Medium,
                    category: "runtime".to_string(),
                    recommendation: "Enable no_new_privileges by default in the runtime configuration.".to_string(),
                });
            }

            // Check user namespace support
            if !info.user_namespace_enabled {
                findings.push(RuntimeFinding {
                    title: "User namespace support not enabled".to_string(),
                    description: "User namespaces provide additional isolation by mapping container root to non-privileged host user.".to_string(),
                    severity: ContainerSeverity::Medium,
                    category: "runtime".to_string(),
                    recommendation: "Enable unprivileged user namespace support in the runtime.".to_string(),
                });
            }

            // Check version-specific issues
            if self.config.check_version {
                findings
                    .extend(self.check_version_vulnerabilities(&info.runtime_type, &info.version));
            }
        }

        findings
    }

    fn check_version_vulnerabilities(
        &self,
        runtime_type: &RuntimeType,
        version: &str,
    ) -> Vec<RuntimeFinding> {
        let mut findings = Vec::new();

        // Check for known old versions (simplified - real implementation would check CVE databases)
        let is_old = match runtime_type {
            RuntimeType::Containerd => Self::is_version_below(version, "1.6"),
            RuntimeType::CRIO => Self::is_version_below(version, "1.25"),
            RuntimeType::Podman => Self::is_version_below(version, "4.0"),
            RuntimeType::Docker => Self::is_version_below(version, "20.10"),
            RuntimeType::Unknown => false,
        };

        if is_old {
            findings.push(RuntimeFinding {
                title: format!("{} version may have known vulnerabilities", runtime_type),
                description: format!("{} {} may be outdated and have known CVEs. Consider updating to the latest stable version.", runtime_type, version),
                severity: ContainerSeverity::Medium,
                category: "version".to_string(),
                recommendation: format!("Update {} to the latest stable version.", runtime_type),
            });
        }

        findings
    }

    fn is_version_below(version: &str, target: &str) -> bool {
        let v_parts: Vec<u32> = version
            .trim_start_matches(|c: char| !c.is_ascii_digit())
            .split('.')
            .filter_map(|p| p.parse().ok())
            .collect();
        let t_parts: Vec<u32> = target.split('.').filter_map(|p| p.parse().ok()).collect();

        for (v, t) in v_parts.iter().zip(t_parts.iter()) {
            if v < t {
                return true;
            }
            if v > t {
                return false;
            }
        }
        v_parts.len() < t_parts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_type_display() {
        assert_eq!(format!("{}", RuntimeType::Containerd), "containerd");
        assert_eq!(format!("{}", RuntimeType::CRIO), "CRI-O");
        assert_eq!(format!("{}", RuntimeType::Podman), "Podman");
        assert_eq!(format!("{}", RuntimeType::Docker), "Docker");
        assert_eq!(format!("{}", RuntimeType::Unknown), "Unknown");
    }

    #[test]
    fn test_runtime_config_default() {
        let config = RuntimeConfig::default();
        assert!(config.runtime.is_none());
        assert!(config.check_config);
        assert!(config.check_seccomp);
        assert!(config.check_apparmor);
        assert!(config.check_selinux);
        assert!(config.check_version);
    }

    #[test]
    fn test_runtime_scanner_creation() {
        let scanner = RuntimeScanner::with_default();
        assert!(scanner.config.runtime.is_none());
    }

    #[test]
    fn test_runtime_results_default() {
        let results = RuntimeResults::default();
        assert!(results.runtime_info.is_none());
        assert!(results.findings.is_empty());
        assert_eq!(results.detected_runtime, RuntimeType::Unknown);
    }

    #[test]
    fn test_version_below() {
        assert!(RuntimeScanner::is_version_below("1.5.0", "1.6"));
        assert!(!RuntimeScanner::is_version_below("1.6.0", "1.6"));
        assert!(!RuntimeScanner::is_version_below("1.7.0", "1.6"));
        assert!(RuntimeScanner::is_version_below("19.03", "20.10"));
        assert!(!RuntimeScanner::is_version_below("20.10", "20.10"));
    }

    #[test]
    fn test_extract_config_value() {
        let config = "root = \"/var/lib/containerd\"\nlevel = \"info\"\n";
        assert_eq!(
            RuntimeScanner::extract_config_value(config, "root"),
            "/var/lib/containerd"
        );
        assert_eq!(
            RuntimeScanner::extract_config_value(config, "level"),
            "info"
        );
        assert_eq!(RuntimeScanner::extract_config_value(config, "missing"), "");
    }

    #[test]
    fn test_assess_security_seccomp_disabled() {
        let scanner = RuntimeScanner::with_default();
        let results = RuntimeResults {
            runtime_info: Some(RuntimeInfo {
                runtime_type: RuntimeType::Containerd,
                seccomp_enabled: false,
                apparmor_enabled: true,
                selinux_enabled: true,
                user_namespace_enabled: true,
                no_new_privileges: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = scanner.assess_security(&results);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::High && f.title.contains("Seccomp")));
    }

    #[test]
    fn test_assess_security_apparmor_disabled() {
        let scanner = RuntimeScanner::with_default();
        let results = RuntimeResults {
            runtime_info: Some(RuntimeInfo {
                runtime_type: RuntimeType::Podman,
                seccomp_enabled: true,
                apparmor_enabled: false,
                selinux_enabled: true,
                user_namespace_enabled: true,
                no_new_privileges: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = scanner.assess_security(&results);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Medium && f.title.contains("AppArmor")));
    }

    #[test]
    fn test_assess_security_selinux_disabled() {
        let scanner = RuntimeScanner::with_default();
        let results = RuntimeResults {
            runtime_info: Some(RuntimeInfo {
                runtime_type: RuntimeType::CRIO,
                seccomp_enabled: true,
                apparmor_enabled: true,
                selinux_enabled: false,
                user_namespace_enabled: true,
                no_new_privileges: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = scanner.assess_security(&results);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Low && f.title.contains("SELinux")));
    }

    #[test]
    fn test_assess_security_no_new_privileges_disabled() {
        let scanner = RuntimeScanner::with_default();
        let results = RuntimeResults {
            runtime_info: Some(RuntimeInfo {
                runtime_type: RuntimeType::Docker,
                seccomp_enabled: true,
                apparmor_enabled: true,
                selinux_enabled: true,
                user_namespace_enabled: true,
                no_new_privileges: false,
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = scanner.assess_security(&results);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Medium
                && f.title.contains("no_new_privileges")));
    }

    #[test]
    fn test_assess_security_user_namespace_disabled() {
        let scanner = RuntimeScanner::with_default();
        let results = RuntimeResults {
            runtime_info: Some(RuntimeInfo {
                runtime_type: RuntimeType::Containerd,
                seccomp_enabled: true,
                apparmor_enabled: true,
                selinux_enabled: true,
                user_namespace_enabled: false,
                no_new_privileges: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = scanner.assess_security(&results);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == ContainerSeverity::Medium
                    && f.title.contains("User namespace"))
        );
    }

    #[test]
    fn test_assess_security_all_good() {
        let scanner = RuntimeScanner::with_default();
        let results = RuntimeResults {
            runtime_info: Some(RuntimeInfo {
                runtime_type: RuntimeType::Containerd,
                version: "1.7.0".to_string(),
                seccomp_enabled: true,
                apparmor_enabled: true,
                selinux_enabled: true,
                user_namespace_enabled: true,
                no_new_privileges: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let findings = scanner.assess_security(&results);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_version_vulnerabilities_old() {
        let scanner = RuntimeScanner::with_default();
        let findings = scanner.check_version_vulnerabilities(&RuntimeType::Containerd, "1.5.0");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, ContainerSeverity::Medium);
    }

    #[test]
    fn test_check_version_vulnerabilities_current() {
        let scanner = RuntimeScanner::with_default();
        let findings = scanner.check_version_vulnerabilities(&RuntimeType::Containerd, "1.7.0");
        assert!(findings.is_empty());
    }
}
