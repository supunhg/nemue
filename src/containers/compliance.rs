//! Container Compliance Scanning Module
//!
//! CIS Docker and Kubernetes benchmark compliance checks,
//! container security best practices assessment, and compliance reporting.

use serde::{Deserialize, Serialize};

use crate::containers::ContainerSeverity;
use crate::containers::docker::DockerResults;
use crate::containers::kubernetes::KubernetesResults;

/// Benchmark type to run
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BenchmarkType {
    CisDocker,
    CisKubernetes,
    ContainerBestPractices,
    All,
}

/// Compliance check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Which benchmarks to run
    pub benchmarks: Vec<BenchmarkType>,
    /// Include informational findings
    pub include_info: bool,
    /// Fail threshold (checks at or above this severity count as failures)
    pub fail_threshold: ContainerSeverity,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            benchmarks: vec![BenchmarkType::All],
            include_info: true,
            fail_threshold: ContainerSeverity::Medium,
        }
    }
}

/// Individual compliance check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCheck {
    pub id: String,
    pub benchmark: BenchmarkType,
    pub title: String,
    pub description: String,
    pub severity: ContainerSeverity,
    pub result: ComplianceResult,
    pub evidence: String,
    pub remediation: String,
}

/// Result of a compliance check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceResult {
    Pass,
    Fail,
    Warn,
    Info,
    NotApplicable,
}

impl ComplianceResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            ComplianceResult::Pass => "PASS",
            ComplianceResult::Fail => "FAIL",
            ComplianceResult::Warn => "WARN",
            ComplianceResult::Info => "INFO",
            ComplianceResult::NotApplicable => "N/A",
        }
    }
}

impl std::fmt::Display for ComplianceResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Full compliance report
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub checks: Vec<ComplianceCheck>,
    pub total_checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub na: usize,
    pub compliance_score: f64,
    pub benchmark_scores: Vec<BenchmarkScore>,
}

/// Score breakdown per benchmark
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkScore {
    pub benchmark: BenchmarkType,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub score: f64,
}

/// Compliance scanner
pub struct ComplianceScanner {
    config: ComplianceConfig,
}

impl ComplianceScanner {
    pub fn new(config: ComplianceConfig) -> Self {
        Self { config }
    }

    pub fn with_default() -> Self {
        Self::new(ComplianceConfig::default())
    }

    /// Run compliance checks against Docker results
    pub fn scan_docker(&self, docker_results: &DockerResults) -> ComplianceReport {
        let mut checks = Vec::new();

        checks.extend(self.cis_docker_host_configuration(docker_results));
        checks.extend(self.cis_docker_daemon(docker_results));
        checks.extend(self.cis_docker_container_images(docker_results));
        checks.extend(self.cis_docker_container_runtime(docker_results));
        checks.extend(self.cis_docker_security(docker_results));

        self.build_report(checks)
    }

    /// Run compliance checks against Kubernetes results
    pub fn scan_kubernetes(&self, k8s_results: &KubernetesResults) -> ComplianceReport {
        let mut checks = Vec::new();

        checks.extend(self.cis_k8s_api_server(k8s_results));
        checks.extend(self.cis_k8s_pods(k8s_results));
        checks.extend(self.cis_k8s_rbac(k8s_results));
        checks.extend(self.cis_k8s_network_policies(k8s_results));
        checks.extend(self.cis_k8s_secrets(k8s_results));

        self.build_report(checks)
    }

    fn build_report(&self, checks: Vec<ComplianceCheck>) -> ComplianceReport {
        let total_checks = checks.len();
        let passed = checks.iter().filter(|c| c.result == ComplianceResult::Pass).count();
        let failed = checks.iter().filter(|c| c.result == ComplianceResult::Fail).count();
        let warnings = checks.iter().filter(|c| c.result == ComplianceResult::Warn).count();
        let na = checks.iter().filter(|c| c.result == ComplianceResult::NotApplicable).count();

        let applicable = total_checks - na;
        let compliance_score = if applicable > 0 {
            (passed as f64 / applicable as f64) * 100.0
        } else {
            100.0
        };

        ComplianceReport {
            checks,
            total_checks,
            passed,
            failed,
            warnings,
            na,
            compliance_score,
            benchmark_scores: Vec::new(),
        }
    }

    // CIS Docker Benchmark checks
    fn cis_docker_host_configuration(&self, _results: &DockerResults) -> Vec<ComplianceCheck> {
        let mut checks = Vec::new();

        // 1.1 - Ensure a separate partition for containers exists
        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-1.1".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Ensure a separate partition for containers exists".to_string(),
            description: "Docker should use a separate partition for container data to prevent resource exhaustion.".to_string(),
            severity: ContainerSeverity::Medium,
            result: ComplianceResult::Warn,
            evidence: "Manual verification required - check if /var/lib/docker is on a separate partition.".to_string(),
            remediation: "Create a separate partition for /var/lib/docker and mount it.".to_string(),
        });

        // 1.2 - Ensure only trusted users are added to the docker group
        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-1.2".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Ensure only trusted users are in the docker group".to_string(),
            description: "Users in the docker group have root-equivalent access to the host.".to_string(),
            severity: ContainerSeverity::High,
            result: ComplianceResult::Warn,
            evidence: "Manual verification required - check /etc/group for docker group membership.".to_string(),
            remediation: "Remove untrusted users from the docker group. Use rootless Docker or Podman as alternatives.".to_string(),
        });

        checks
    }

    fn cis_docker_daemon(&self, results: &DockerResults) -> Vec<ComplianceCheck> {
        let mut checks = Vec::new();

        if let Some(ref daemon) = results.daemon_info {
            // 2.1 - Ensure network traffic is restricted between containers
            checks.push(ComplianceCheck {
                id: "CIS-DOCKER-2.1".to_string(),
                benchmark: BenchmarkType::CisDocker,
                title: "Ensure network traffic is restricted between containers".to_string(),
                description: "By default, all containers on the same network can communicate with each other.".to_string(),
                severity: ContainerSeverity::Medium,
                result: ComplianceResult::Warn,
                evidence: "Manual verification required - check if --icc=false is set on the Docker daemon.".to_string(),
                remediation: "Set --icc=false in the Docker daemon configuration or use network policies.".to_string(),
            });

            // 2.2 - Ensure logging level is set to info
            checks.push(ComplianceCheck {
                id: "CIS-DOCKER-2.2".to_string(),
                benchmark: BenchmarkType::CisDocker,
                title: "Ensure logging level is set to info".to_string(),
                description: "Setting an appropriate log level ensures sufficient logging for security auditing.".to_string(),
                severity: ContainerSeverity::Low,
                result: if daemon.logging_driver.is_empty() || daemon.logging_driver == "none" {
                    ComplianceResult::Fail
                } else {
                    ComplianceResult::Pass
                },
                evidence: format!("Logging driver: {}", daemon.logging_driver),
                remediation: "Set --log-level=info in the Docker daemon configuration.".to_string(),
            });

            // 2.8 - Enable user namespace support
            let has_userns = daemon.security_options.iter().any(|s| s.contains("userns"));
            checks.push(ComplianceCheck {
                id: "CIS-DOCKER-2.8".to_string(),
                benchmark: BenchmarkType::CisDocker,
                title: "Enable user namespace support".to_string(),
                description: "User namespaces provide an additional layer of container isolation.".to_string(),
                severity: ContainerSeverity::Medium,
                result: if has_userns { ComplianceResult::Pass } else { ComplianceResult::Fail },
                evidence: format!("Security options: {:?}", daemon.security_options),
                remediation: "Enable user namespace remapping by setting --userns-remap=default.".to_string(),
            });

            // 2.13 - Enable live restore
            checks.push(ComplianceCheck {
                id: "CIS-DOCKER-2.13".to_string(),
                benchmark: BenchmarkType::CisDocker,
                title: "Enable live restore".to_string(),
                description: "Live restore keeps containers running during daemon downtime.".to_string(),
                severity: ContainerSeverity::Low,
                result: if daemon.live_restore { ComplianceResult::Pass } else { ComplianceResult::Fail },
                evidence: format!("Live restore enabled: {}", daemon.live_restore),
                remediation: "Set --live-restore in the Docker daemon configuration.".to_string(),
            });

            // 2.14 - Disable userland proxy
            checks.push(ComplianceCheck {
                id: "CIS-DOCKER-2.14".to_string(),
                benchmark: BenchmarkType::CisDocker,
                title: "Disable userland proxy".to_string(),
                description: "The userland proxy is less efficient and can pose security risks.".to_string(),
                severity: ContainerSeverity::Low,
                result: ComplianceResult::Warn,
                evidence: "Manual verification required - check if --userland-proxy=false is set.".to_string(),
                remediation: "Set --userland-proxy=false in the Docker daemon configuration.".to_string(),
            });

            // 2.15 - Enable daemon-wide custom seccomp profile
            let has_seccomp = daemon.security_options.iter().any(|s| s.contains("seccomp"));
            checks.push(ComplianceCheck {
                id: "CIS-DOCKER-2.15".to_string(),
                benchmark: BenchmarkType::CisDocker,
                title: "Enable daemon-wide custom seccomp profile".to_string(),
                description: "Seccomp profiles limit the system calls available to containers.".to_string(),
                severity: ContainerSeverity::Medium,
                result: if has_seccomp { ComplianceResult::Pass } else { ComplianceResult::Fail },
                evidence: format!("Security options: {:?}", daemon.security_options),
                remediation: "Apply a custom seccomp profile using --seccomp-profile.".to_string(),
            });

            // 2.16 - Disable experimental features in production
            checks.push(ComplianceCheck {
                id: "CIS-DOCKER-2.16".to_string(),
                benchmark: BenchmarkType::CisDocker,
                title: "Disable experimental features in production".to_string(),
                description: "Experimental features may have security issues and should not be used in production.".to_string(),
                severity: ContainerSeverity::Low,
                result: ComplianceResult::Warn,
                evidence: "Manual verification required - check if Docker daemon is running in experimental mode.".to_string(),
                remediation: "Do not use --experimental flag in production environments.".to_string(),
            });
        }

        checks
    }

    fn cis_docker_container_images(&self, results: &DockerResults) -> Vec<ComplianceCheck> {
        let mut checks = Vec::new();

        // 4.1 - Ensure container image has a user
        let images_without_user: Vec<&str> = results.images.iter()
            .filter(|i| i.user.is_empty() || i.user == "root")
            .filter_map(|i| i.tags.first().map(|s| s.as_str()))
            .collect();

        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-4.1".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Ensure container images include a USER instruction".to_string(),
            description: "Running containers as root increases the impact of container breakout vulnerabilities.".to_string(),
            severity: ContainerSeverity::Medium,
            result: if images_without_user.is_empty() { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: if images_without_user.is_empty() {
                "All images specify a non-root user.".to_string()
            } else {
                format!("Images without USER: {}", images_without_user.join(", "))
            },
            remediation: "Add a USER instruction in Dockerfiles to run as a non-root user.".to_string(),
        });

        // 4.7 - Ensure HEALTHCHECK instructions are present
        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-4.7".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Ensure HEALTHCHECK instructions are present".to_string(),
            description: "HEALTHCHECK instructions enable Docker to detect and restart unhealthy containers.".to_string(),
            severity: ContainerSeverity::Low,
            result: ComplianceResult::Warn,
            evidence: "Manual verification required - check Dockerfiles for HEALTHCHECK instructions.".to_string(),
            remediation: "Add HEALTHCHECK instructions to all Dockerfiles.".to_string(),
        });

        checks
    }

    fn cis_docker_container_runtime(&self, results: &DockerResults) -> Vec<ComplianceCheck> {
        let mut checks = Vec::new();

        // 5.1 - Do not disable AppArmor profile
        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-5.1".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Do not disable AppArmor profile".to_string(),
            description: "AppArmor provides mandatory access control for container processes.".to_string(),
            severity: ContainerSeverity::Medium,
            result: ComplianceResult::Warn,
            evidence: "Manual verification required - check if --security-opt apparmor=unconfined is used.".to_string(),
            remediation: "Do not disable the default AppArmor profile for containers.".to_string(),
        });

        // 5.2 - Verify SELinux security options
        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-5.2".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Verify SELinux security options".to_string(),
            description: "SELinux provides additional access control for containers.".to_string(),
            severity: ContainerSeverity::Medium,
            result: ComplianceResult::Warn,
            evidence: "Manual verification required - check if SELinux is properly configured.".to_string(),
            remediation: "Set appropriate SELinux labels using --security-opt label=level.".to_string(),
        });

        // 5.3 - Restrict Linux kernel capabilities
        let privileged_count = results.containers.iter().filter(|c| c.privileged).count();
        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-5.3".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Restrict Linux kernel capabilities".to_string(),
            description: "Containers should only have the minimum required capabilities.".to_string(),
            severity: ContainerSeverity::High,
            result: if privileged_count == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} privileged containers found", privileged_count),
            remediation: "Remove --privileged flag and use --cap-drop ALL followed by --cap-add for needed capabilities.".to_string(),
        });

        // 5.4 - Do not use privileged containers
        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-5.4".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Do not use privileged containers".to_string(),
            description: "Privileged containers bypass all security boundaries.".to_string(),
            severity: ContainerSeverity::Critical,
            result: if privileged_count == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} privileged containers found", privileged_count),
            remediation: "Remove --privileged flag from all container configurations.".to_string(),
        });

        // 5.5 - Do not mount sensitive host directories
        let sensitive_mounts = results.containers.iter()
            .flat_map(|c| c.mounts.iter().map(move |m| (c.name.as_str(), m.source.as_str())))
            .filter(|(_, src)| matches!(*src, "/" | "/etc" | "/var/run/docker.sock" | "/proc" | "/sys"))
            .count();

        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-5.5".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Do not mount sensitive host directories on containers".to_string(),
            description: "Mounting sensitive host directories can lead to container breakout.".to_string(),
            severity: ContainerSeverity::Critical,
            result: if sensitive_mounts == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} sensitive host mounts found", sensitive_mounts),
            remediation: "Avoid mounting /, /etc, /proc, /sys, or /var/run/docker.sock.".to_string(),
        });

        // 5.7 - Do not map privileged ports
        let privileged_ports = results.containers.iter()
            .flat_map(|c| c.ports.iter())
            .filter(|p| p.host_port.map_or(false, |hp| hp < 1024))
            .count();

        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-5.7".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Do not map privileged ports within containers".to_string(),
            description: "Mapping privileged ports (<1024) can lead to spoofing attacks.".to_string(),
            severity: ContainerSeverity::Low,
            result: if privileged_ports == 0 { ComplianceResult::Pass } else { ComplianceResult::Warn },
            evidence: format!("{} privileged port mappings found", privileged_ports),
            remediation: "Use ports above 1024 for container port mappings.".to_string(),
        });

        // 5.9 - Do not share the host's network namespace
        let host_net_count = results.containers.iter().filter(|c| c.network_mode == "host").count();
        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-5.9".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Do not share the host's network namespace".to_string(),
            description: "Sharing the host network namespace removes network isolation.".to_string(),
            severity: ContainerSeverity::High,
            result: if host_net_count == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} containers using host networking", host_net_count),
            remediation: "Remove --network=host and use bridge or custom networks.".to_string(),
        });

        // 5.10 - Limit memory for containers
        let no_mem_limit = results.containers.iter().filter(|c| c.memory_limit == 0).count();
        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-5.10".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Limit memory for containers".to_string(),
            description: "Containers without memory limits can cause denial of service.".to_string(),
            severity: ContainerSeverity::Medium,
            result: if no_mem_limit == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} containers without memory limits", no_mem_limit),
            remediation: "Set --memory flag for all containers.".to_string(),
        });

        // 5.12 - Mount container's root filesystem as read-only
        checks.push(ComplianceCheck {
            id: "CIS-DOCKER-5.12".to_string(),
            benchmark: BenchmarkType::CisDocker,
            title: "Mount container's root filesystem as read only".to_string(),
            description: "Read-only root filesystems prevent attackers from modifying binaries.".to_string(),
            severity: ContainerSeverity::Medium,
            result: ComplianceResult::Warn,
            evidence: "Manual verification required - check if --read-only is used.".to_string(),
            remediation: "Use --read-only flag and provide writable tmpfs mounts where needed.".to_string(),
        });

        checks
    }

    fn cis_docker_security(&self, results: &DockerResults) -> Vec<ComplianceCheck> {
        let mut checks = Vec::new();

        // Check for containers running as root
        let root_containers: Vec<&str> = results.containers.iter()
            .filter(|c| c.user.is_empty() || c.user == "root" || c.user == "0")
            .map(|c| c.name.as_str())
            .collect();

        checks.push(ComplianceCheck {
            id: "CONTAINER-SEC-001".to_string(),
            benchmark: BenchmarkType::ContainerBestPractices,
            title: "Do not run containers as root".to_string(),
            description: "Running as root increases the impact of container breakout vulnerabilities.".to_string(),
            severity: ContainerSeverity::High,
            result: if root_containers.is_empty() { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("Containers running as root: {:?}", root_containers),
            remediation: "Use USER directive in Dockerfile or --user flag.".to_string(),
        });

        // Check for sensitive environment variables
        let sensitive_env_count: usize = results.containers.iter()
            .flat_map(|c| c.env_vars.iter())
            .filter(|e| {
                let upper = e.to_uppercase();
                upper.contains("PASSWORD") || upper.contains("SECRET") || upper.contains("TOKEN") || upper.contains("API_KEY")
            })
            .count();

        checks.push(ComplianceCheck {
            id: "CONTAINER-SEC-002".to_string(),
            benchmark: BenchmarkType::ContainerBestPractices,
            title: "Do not store secrets in environment variables".to_string(),
            description: "Secrets in environment variables are visible via docker inspect.".to_string(),
            severity: ContainerSeverity::Medium,
            result: if sensitive_env_count == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} sensitive environment variables found", sensitive_env_count),
            remediation: "Use Docker secrets or external secret management.".to_string(),
        });

        // Check for Docker socket mounts
        let socket_mounts = results.containers.iter()
            .filter(|c| c.mounts.iter().any(|m| m.source.contains("docker.sock")))
            .count();

        checks.push(ComplianceCheck {
            id: "CONTAINER-SEC-003".to_string(),
            benchmark: BenchmarkType::ContainerBestPractices,
            title: "Do not mount the Docker socket inside containers".to_string(),
            description: "Mounting the Docker socket allows full control over the Docker daemon.".to_string(),
            severity: ContainerSeverity::Critical,
            result: if socket_mounts == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} containers mounting Docker socket", socket_mounts),
            remediation: "Avoid mounting /var/run/docker.sock inside containers.".to_string(),
        });

        // Check for containers with no restart policy limit
        let always_restart = results.containers.iter()
            .filter(|c| c.restart_policy == "always")
            .count();

        checks.push(ComplianceCheck {
            id: "CONTAINER-SEC-004".to_string(),
            benchmark: BenchmarkType::ContainerBestPractices,
            title: "Use appropriate restart policies".to_string(),
            description: "The 'always' restart policy can mask security issues.".to_string(),
            severity: ContainerSeverity::Low,
            result: if always_restart == 0 { ComplianceResult::Pass } else { ComplianceResult::Warn },
            evidence: format!("{} containers with 'always' restart policy", always_restart),
            remediation: "Use 'on-failure' with max retry count instead of 'always'.".to_string(),
        });

        checks
    }

    // CIS Kubernetes Benchmark checks
    fn cis_k8s_api_server(&self, results: &KubernetesResults) -> Vec<ComplianceCheck> {
        let mut checks = Vec::new();

        if let Some(ref api) = results.api_server_info {
            // 1.1.1 - Ensure that the API server pod specification file permissions are set to 644 or more restrictive
            checks.push(ComplianceCheck {
                id: "CIS-K8S-1.1.1".to_string(),
                benchmark: BenchmarkType::CisKubernetes,
                title: "Ensure API server pod specification file permissions are 644 or more restrictive".to_string(),
                description: "The API server pod specification should have restricted file permissions.".to_string(),
                severity: ContainerSeverity::Medium,
                result: ComplianceResult::Warn,
                evidence: "Manual verification required on control plane node.".to_string(),
                remediation: "Run: chmod 644 /etc/kubernetes/manifests/kube-apiserver.manifest".to_string(),
            });

            // 1.2.1 - Ensure that the --anonymous-auth argument is set to false
            checks.push(ComplianceCheck {
                id: "CIS-K8S-1.2.1".to_string(),
                benchmark: BenchmarkType::CisKubernetes,
                title: "Ensure anonymous authentication is disabled".to_string(),
                description: "Anonymous authentication allows unauthenticated requests to the API server.".to_string(),
                severity: ContainerSeverity::High,
                result: if api.anonymous_auth_enabled { ComplianceResult::Fail } else { ComplianceResult::Pass },
                evidence: format!("Anonymous auth enabled: {}", api.anonymous_auth_enabled),
                remediation: "Set --anonymous-auth=false in the API server configuration.".to_string(),
            });

            // 1.2.7 - Ensure that the --audit-log-path argument is set
            checks.push(ComplianceCheck {
                id: "CIS-K8S-1.2.7".to_string(),
                benchmark: BenchmarkType::CisKubernetes,
                title: "Ensure audit logging is enabled".to_string(),
                description: "Audit logging records API server activities for security monitoring.".to_string(),
                severity: ContainerSeverity::High,
                result: if api.audit_logging_enabled { ComplianceResult::Pass } else { ComplianceResult::Fail },
                evidence: format!("Audit logging enabled: {}", api.audit_logging_enabled),
                remediation: "Set --audit-log-path=/var/log/kubernetes/audit.log and configure audit policy.".to_string(),
            });

            // 1.2.31 - Ensure that the --encryption-provider-config argument is set
            checks.push(ComplianceCheck {
                id: "CIS-K8S-1.2.31".to_string(),
                benchmark: BenchmarkType::CisKubernetes,
                title: "Ensure etcd encryption is configured".to_string(),
                description: "etcd stores all cluster data; encryption protects sensitive information at rest.".to_string(),
                severity: ContainerSeverity::High,
                result: if api.etcd_encryption_enabled { ComplianceResult::Pass } else { ComplianceResult::Fail },
                evidence: format!("etcd encryption enabled: {}", api.etcd_encryption_enabled),
                remediation: "Configure --encryption-provider-config with aescbc or secretbox provider.".to_string(),
            });
        }

        checks
    }

    fn cis_k8s_pods(&self, results: &KubernetesResults) -> Vec<ComplianceCheck> {
        let mut checks = Vec::new();

        // 5.1.1 - Ensure that the cluster-admin role is only used where required
        let default_sa_pods = results.pods.iter()
            .filter(|p| p.service_account == "default")
            .count();

        checks.push(ComplianceCheck {
            id: "CIS-K8S-5.1.1".to_string(),
            benchmark: BenchmarkType::CisKubernetes,
            title: "Ensure default service account is not used".to_string(),
            description: "Pods should use dedicated service accounts with minimal permissions.".to_string(),
            severity: ContainerSeverity::Medium,
            result: if default_sa_pods == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} pods using default service account", default_sa_pods),
            remediation: "Create dedicated service accounts for each application.".to_string(),
        });

        // 5.1.3 - Minimize the admission of containers with allowPrivilegeEscalation
        let priv_esc_count = results.pods.iter()
            .flat_map(|p| p.containers.iter())
            .filter(|c| c.security_context.allow_privilege_escalation)
            .count();

        checks.push(ComplianceCheck {
            id: "CIS-K8S-5.1.3".to_string(),
            benchmark: BenchmarkType::CisKubernetes,
            title: "Minimize containers allowing privilege escalation".to_string(),
            description: "Privilege escalation allows child processes to gain more privileges than the parent.".to_string(),
            severity: ContainerSeverity::High,
            result: if priv_esc_count == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} containers allowing privilege escalation", priv_esc_count),
            remediation: "Set allowPrivilegeEscalation: false in pod security contexts.".to_string(),
        });

        // 5.1.5 - Minimize the admission of containers with added capabilities
        let caps_add_count = results.pods.iter()
            .flat_map(|p| p.containers.iter())
            .filter(|c| !c.security_context.capabilities_add.is_empty())
            .count();

        checks.push(ComplianceCheck {
            id: "CIS-K8S-5.1.5".to_string(),
            benchmark: BenchmarkType::CisKubernetes,
            title: "Minimize containers with added capabilities".to_string(),
            description: "Containers should only have the minimum required capabilities.".to_string(),
            severity: ContainerSeverity::Medium,
            result: if caps_add_count == 0 { ComplianceResult::Pass } else { ComplianceResult::Warn },
            evidence: format!("{} containers with additional capabilities", caps_add_count),
            remediation: "Use --cap-drop ALL and add only required capabilities.".to_string(),
        });

        // 5.1.6 - Minimize the admission of root containers
        let root_containers = results.pods.iter()
            .flat_map(|p| p.containers.iter())
            .filter(|c| !c.security_context.run_as_non_root)
            .count();

        checks.push(ComplianceCheck {
            id: "CIS-K8S-5.1.6".to_string(),
            benchmark: BenchmarkType::CisKubernetes,
            title: "Minimize the admission of root containers".to_string(),
            description: "Containers should run as non-root users.".to_string(),
            severity: ContainerSeverity::Medium,
            result: if root_containers == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} containers without runAsNonRoot", root_containers),
            remediation: "Set runAsNonRoot: true in pod or container security contexts.".to_string(),
        });

        // 5.2.1 - Minimize the admission of privileged containers
        let privileged_pods = results.pods.iter().filter(|p| p.privileged).count();
        checks.push(ComplianceCheck {
            id: "CIS-K8S-5.2.1".to_string(),
            benchmark: BenchmarkType::CisKubernetes,
            title: "Minimize the admission of privileged containers".to_string(),
            description: "Privileged containers have full access to the host.".to_string(),
            severity: ContainerSeverity::Critical,
            result: if privileged_pods == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} privileged pods found", privileged_pods),
            remediation: "Use Pod Security Standards to prevent privileged containers.".to_string(),
        });

        // 5.2.2 - Minimize the admission of containers wishing to share the host process ID namespace
        let host_pid_pods = results.pods.iter().filter(|p| p.host_pid).count();
        checks.push(ComplianceCheck {
            id: "CIS-K8S-5.2.2".to_string(),
            benchmark: BenchmarkType::CisKubernetes,
            title: "Minimize containers sharing host PID namespace".to_string(),
            description: "Sharing the host PID namespace allows containers to see all host processes.".to_string(),
            severity: ContainerSeverity::High,
            result: if host_pid_pods == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} pods with hostPID enabled", host_pid_pods),
            remediation: "Remove hostPID: true from pod specifications.".to_string(),
        });

        // 5.2.3 - Minimize the admission of containers wishing to share the host network namespace
        let host_net_pods = results.pods.iter().filter(|p| p.host_network).count();
        checks.push(ComplianceCheck {
            id: "CIS-K8S-5.2.3".to_string(),
            benchmark: BenchmarkType::CisKubernetes,
            title: "Minimize containers sharing host network namespace".to_string(),
            description: "Sharing the host network namespace removes network isolation.".to_string(),
            severity: ContainerSeverity::High,
            result: if host_net_pods == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} pods with hostNetwork enabled", host_net_pods),
            remediation: "Remove hostNetwork: true from pod specifications.".to_string(),
        });

        // 5.4.1 - Prefer using secrets as files over secrets as environment variables
        let secret_env_count = results.pods.iter()
            .flat_map(|p| p.containers.iter())
            .flat_map(|c| c.env_vars.iter())
            .filter(|e| e.to_uppercase().contains("SECRET") || e.to_uppercase().contains("TOKEN"))
            .count();

        checks.push(ComplianceCheck {
            id: "CIS-K8S-5.4.1".to_string(),
            benchmark: BenchmarkType::CisKubernetes,
            title: "Prefer secrets as files over environment variables".to_string(),
            description: "Secrets in environment variables can be exposed via kubectl describe pod.".to_string(),
            severity: ContainerSeverity::Medium,
            result: if secret_env_count == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
            evidence: format!("{} secrets referenced as environment variables", secret_env_count),
            remediation: "Mount secrets as volumes instead of using environment variables.".to_string(),
        });

        checks
    }

    fn cis_k8s_rbac(&self, results: &KubernetesResults) -> Vec<ComplianceCheck> {
        let mut checks = Vec::new();

        if let Some(ref rbac) = results.rbac_assessment {
            // Check for cluster-admin bindings
            let admin_bindings = rbac.bindings.iter()
                .filter(|b| b.role_ref == "cluster-admin")
                .count();

            checks.push(ComplianceCheck {
                id: "CIS-K8S-5.1.1".to_string(),
                benchmark: BenchmarkType::CisKubernetes,
                title: "Minimize cluster-admin role bindings".to_string(),
                description: "The cluster-admin role grants full control over every resource.".to_string(),
                severity: ContainerSeverity::High,
                result: if admin_bindings <= 1 { ComplianceResult::Pass } else { ComplianceResult::Fail },
                evidence: format!("{} cluster-admin bindings found", admin_bindings),
                remediation: "Use more restrictive roles and limit cluster-admin bindings.".to_string(),
            });

            // Check for wildcard permissions
            let wildcard_roles = rbac.cluster_roles.iter()
                .filter(|r| r.rules.iter().any(|rule| rule.verbs.contains(&"*".to_string()) && rule.resources.contains(&"*".to_string())))
                .count();

            checks.push(ComplianceCheck {
                id: "CIS-K8S-5.1.2".to_string(),
                benchmark: BenchmarkType::CisKubernetes,
                title: "Minimize wildcard use in Roles and ClusterRoles".to_string(),
                description: "Wildcard permissions grant excessive access to resources.".to_string(),
                severity: ContainerSeverity::High,
                result: if wildcard_roles == 0 { ComplianceResult::Pass } else { ComplianceResult::Fail },
                evidence: format!("{} roles with wildcard permissions", wildcard_roles),
                remediation: "Replace wildcards with specific resource and verb combinations.".to_string(),
            });

            // Check for automount service account tokens
            let automount_count = rbac.service_accounts.iter()
                .filter(|sa| sa.automount_token)
                .count();

            checks.push(ComplianceCheck {
                id: "CIS-K8S-5.1.5".to_string(),
                benchmark: BenchmarkType::CisKubernetes,
                title: "Minimize automounting of service account tokens".to_string(),
                description: "Auto-mounted tokens can be used by attackers if pods are compromised.".to_string(),
                severity: ContainerSeverity::Medium,
                result: if automount_count == 0 { ComplianceResult::Pass } else { ComplianceResult::Warn },
                evidence: format!("{} service accounts with automount enabled", automount_count),
                remediation: "Set automountServiceAccountToken: false on service accounts.".to_string(),
            });
        }

        checks
    }

    fn cis_k8s_network_policies(&self, _results: &KubernetesResults) -> Vec<ComplianceCheck> {
        let mut checks = Vec::new();

        // 5.3.2 - Ensure that all Namespaces have Network Policies defined
        checks.push(ComplianceCheck {
            id: "CIS-K8S-5.3.2".to_string(),
            benchmark: BenchmarkType::CisKubernetes,
            title: "Ensure all namespaces have NetworkPolicies".to_string(),
            description: "NetworkPolicies restrict pod-to-pod communication and limit blast radius.".to_string(),
            severity: ContainerSeverity::Medium,
            result: ComplianceResult::Warn,
            evidence: "Manual verification required - check if NetworkPolicies exist for all namespaces.".to_string(),
            remediation: "Create default-deny NetworkPolicies for each namespace.".to_string(),
        });

        checks
    }

    fn cis_k8s_secrets(&self, results: &KubernetesResults) -> Vec<ComplianceCheck> {
        let mut checks = Vec::new();

        // Check for etcd encryption
        if let Some(ref api) = results.api_server_info {
            checks.push(ComplianceCheck {
                id: "CIS-K8S-5.4.1".to_string(),
                benchmark: BenchmarkType::CisKubernetes,
                title: "Consider external secret storage".to_string(),
                description: "Kubernetes Secrets are base64-encoded, not encrypted by default.".to_string(),
                severity: ContainerSeverity::Medium,
                result: if api.etcd_encryption_enabled { ComplianceResult::Pass } else { ComplianceResult::Warn },
                evidence: format!("etcd encryption: {}", if api.etcd_encryption_enabled { "enabled" } else { "not confirmed" }),
                remediation: "Enable etcd encryption or use an external secret store (Vault, AWS Secrets Manager).".to_string(),
            });
        }

        checks
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::containers::docker::{DockerContainer, DockerDaemonInfo, DockerResults};
    use crate::containers::kubernetes::{ContainerSecurityContext, KubeApiServerInfo, KubeContainer, KubePod, KubernetesResults};

    #[test]
    fn test_compliance_config_default() {
        let config = ComplianceConfig::default();
        assert!(config.include_info);
        assert_eq!(config.fail_threshold, ContainerSeverity::Medium);
    }

    #[test]
    fn test_compliance_scanner_creation() {
        let scanner = ComplianceScanner::with_default();
        assert!(scanner.config.include_info);
    }

    #[test]
    fn test_compliance_result_display() {
        assert_eq!(format!("{}", ComplianceResult::Pass), "PASS");
        assert_eq!(format!("{}", ComplianceResult::Fail), "FAIL");
        assert_eq!(format!("{}", ComplianceResult::Warn), "WARN");
    }

    #[test]
    fn test_build_report_empty() {
        let scanner = ComplianceScanner::with_default();
        let report = scanner.build_report(Vec::new());
        assert_eq!(report.total_checks, 0);
        assert_eq!(report.compliance_score, 100.0);
    }

    #[test]
    fn test_build_report_with_checks() {
        let scanner = ComplianceScanner::with_default();
        let checks = vec![
            ComplianceCheck {
                id: "TEST-1".to_string(),
                benchmark: BenchmarkType::CisDocker,
                title: "Test".to_string(),
                description: "Test".to_string(),
                severity: ContainerSeverity::Medium,
                result: ComplianceResult::Pass,
                evidence: "Test".to_string(),
                remediation: "Test".to_string(),
            },
            ComplianceCheck {
                id: "TEST-2".to_string(),
                benchmark: BenchmarkType::CisDocker,
                title: "Test".to_string(),
                description: "Test".to_string(),
                severity: ContainerSeverity::Medium,
                result: ComplianceResult::Fail,
                evidence: "Test".to_string(),
                remediation: "Test".to_string(),
            },
        ];
        let report = scanner.build_report(checks);
        assert_eq!(report.total_checks, 2);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.compliance_score, 50.0);
    }

    #[test]
    fn test_docker_scan_privileged_containers() {
        let scanner = ComplianceScanner::with_default();
        let mut docker_results = DockerResults::default();
        docker_results.containers.push(DockerContainer {
            privileged: true,
            ..Default::default()
        });

        let report = scanner.scan_docker(&docker_results);
        assert!(report.checks.iter().any(|c| c.id == "CIS-DOCKER-5.3" && c.result == ComplianceResult::Fail));
        assert!(report.checks.iter().any(|c| c.id == "CIS-DOCKER-5.4" && c.result == ComplianceResult::Fail));
    }

    #[test]
    fn test_docker_scan_no_privileged() {
        let scanner = ComplianceScanner::with_default();
        let docker_results = DockerResults::default();

        let report = scanner.scan_docker(&docker_results);
        assert!(report.checks.iter().any(|c| c.id == "CIS-DOCKER-5.3" && c.result == ComplianceResult::Pass));
    }

    #[test]
    fn test_docker_scan_host_network() {
        let scanner = ComplianceScanner::with_default();
        let mut docker_results = DockerResults::default();
        docker_results.containers.push(DockerContainer {
            network_mode: "host".to_string(),
            ..Default::default()
        });

        let report = scanner.scan_docker(&docker_results);
        assert!(report.checks.iter().any(|c| c.id == "CIS-DOCKER-5.9" && c.result == ComplianceResult::Fail));
    }

    #[test]
    fn test_docker_scan_daemon_userns() {
        let scanner = ComplianceScanner::with_default();
        let mut docker_results = DockerResults::default();
        docker_results.daemon_info = Some(DockerDaemonInfo {
            security_options: vec!["name=userns".to_string()],
            logging_driver: "json-file".to_string(),
            live_restore: true,
            ..Default::default()
        });

        let report = scanner.scan_docker(&docker_results);
        assert!(report.checks.iter().any(|c| c.id == "CIS-DOCKER-2.8" && c.result == ComplianceResult::Pass));
        assert!(report.checks.iter().any(|c| c.id == "CIS-DOCKER-2.13" && c.result == ComplianceResult::Pass));
    }

    #[test]
    fn test_k8s_scan_privileged_pods() {
        let scanner = ComplianceScanner::with_default();
        let mut k8s_results = KubernetesResults::default();
        k8s_results.pods.push(KubePod {
            privileged: true,
            ..Default::default()
        });

        let report = scanner.scan_kubernetes(&k8s_results);
        assert!(report.checks.iter().any(|c| c.id == "CIS-K8S-5.2.1" && c.result == ComplianceResult::Fail));
    }

    #[test]
    fn test_k8s_scan_default_service_account() {
        let scanner = ComplianceScanner::with_default();
        let mut k8s_results = KubernetesResults::default();
        k8s_results.pods.push(KubePod {
            service_account: "default".to_string(),
            ..Default::default()
        });

        let report = scanner.scan_kubernetes(&k8s_results);
        assert!(report.checks.iter().any(|c| c.id == "CIS-K8S-5.1.1" && c.result == ComplianceResult::Fail));
    }

    #[test]
    fn test_k8s_scan_api_server_anon_auth() {
        let scanner = ComplianceScanner::with_default();
        let mut k8s_results = KubernetesResults::default();
        k8s_results.api_server_info = Some(KubeApiServerInfo {
            anonymous_auth_enabled: true,
            ..Default::default()
        });

        let report = scanner.scan_kubernetes(&k8s_results);
        assert!(report.checks.iter().any(|c| c.id == "CIS-K8S-1.2.1" && c.result == ComplianceResult::Fail));
    }

    #[test]
    fn test_docker_scan_socket_mount() {
        let scanner = ComplianceScanner::with_default();
        let mut docker_results = DockerResults::default();
        docker_results.containers.push(DockerContainer {
            mounts: vec![crate::containers::docker::ContainerMount {
                source: "/var/run/docker.sock".to_string(),
                destination: "/var/run/docker.sock".to_string(),
                mode: "rw".to_string(),
                rw: true,
            }],
            ..Default::default()
        });

        let report = scanner.scan_docker(&docker_results);
        assert!(report.checks.iter().any(|c| c.id == "CONTAINER-SEC-003" && c.result == ComplianceResult::Fail));
    }

    #[test]
    fn test_k8s_scan_host_pid() {
        let scanner = ComplianceScanner::with_default();
        let mut k8s_results = KubernetesResults::default();
        k8s_results.pods.push(KubePod {
            host_pid: true,
            ..Default::default()
        });

        let report = scanner.scan_kubernetes(&k8s_results);
        assert!(report.checks.iter().any(|c| c.id == "CIS-K8S-5.2.2" && c.result == ComplianceResult::Fail));
    }

    #[test]
    fn test_k8s_scan_privilege_escalation() {
        let scanner = ComplianceScanner::with_default();
        let mut k8s_results = KubernetesResults::default();
        k8s_results.pods.push(KubePod {
            containers: vec![KubeContainer {
                security_context: ContainerSecurityContext {
                    allow_privilege_escalation: true,
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        });

        let report = scanner.scan_kubernetes(&k8s_results);
        assert!(report.checks.iter().any(|c| c.id == "CIS-K8S-5.1.3" && c.result == ComplianceResult::Fail));
    }
}
