//! Docker Security Scanning Module
//!
//! Provides Docker daemon enumeration, container inspection, image scanning,
//! network analysis, volume scanning, and security assessment.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

use crate::containers::ContainerSeverity;

/// Docker daemon configuration for scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerConfig {
    /// Docker daemon socket path
    pub socket_path: String,
    /// Docker API version to use
    pub api_version: String,
    /// Include stopped containers
    pub include_stopped: bool,
    /// Scan images for vulnerabilities
    pub scan_images: bool,
    /// Check network security
    pub check_networks: bool,
    /// Check volume mounts
    pub check_volumes: bool,
    /// Timeout for Docker API calls in seconds
    pub timeout_seconds: u64,
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            socket_path: "/var/run/docker.sock".to_string(),
            api_version: "1.41".to_string(),
            include_stopped: true,
            scan_images: true,
            check_networks: true,
            check_volumes: true,
            timeout_seconds: 30,
        }
    }
}

/// Docker daemon information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DockerDaemonInfo {
    pub version: String,
    pub api_version: String,
    pub os: String,
    pub arch: String,
    pub kernel_version: String,
    pub storage_driver: String,
    pub logging_driver: String,
    pub cgroup_driver: String,
    pub live_restore: bool,
    pub containers_total: u64,
    pub containers_running: u64,
    pub images_count: u64,
    pub server_addr: String,
    pub security_options: Vec<String>,
    pub registries: Vec<String>,
    pub insecure_registries: Vec<String>,
}

/// Docker container information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DockerContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub state: String,
    pub created: String,
    pub ports: Vec<ContainerPort>,
    pub mounts: Vec<ContainerMount>,
    pub networks: Vec<String>,
    pub env_vars: Vec<String>,
    pub labels: HashMap<String, String>,
    pub privileged: bool,
    pub pid_mode: String,
    pub network_mode: String,
    pub ipc_mode: String,
    pub user: String,
    pub restart_policy: String,
    pub memory_limit: u64,
    pub cpu_shares: u64,
    pub capabilities_add: Vec<String>,
    pub capabilities_drop: Vec<String>,
}

/// Container port mapping
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerPort {
    pub container_port: u16,
    pub host_port: Option<u16>,
    pub host_ip: String,
    pub protocol: String,
}

/// Container volume mount
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerMount {
    pub source: String,
    pub destination: String,
    pub mode: String,
    pub rw: bool,
}

/// Docker image information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DockerImage {
    pub id: String,
    pub tags: Vec<String>,
    pub size: u64,
    pub created: String,
    pub layers: u64,
    pub has_vulnerabilities: bool,
    pub vulnerability_count: u64,
    pub user: String,
}

/// Docker network information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DockerNetwork {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub scope: String,
    pub internal: bool,
    pub attachable: bool,
    pub ipam_driver: String,
    pub subnet: String,
    pub gateway: String,
    pub containers: Vec<String>,
    pub enable_ipv6: bool,
}

/// Docker volume information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DockerVolume {
    pub name: String,
    pub driver: String,
    pub mountpoint: String,
    pub scope: String,
    pub labels: HashMap<String, String>,
    pub size: Option<u64>,
}

/// Security finding from Docker scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerSecurityFinding {
    pub title: String,
    pub description: String,
    pub severity: ContainerSeverity,
    pub category: String,
    pub recommendation: String,
}

/// Docker scan results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DockerResults {
    pub daemon_info: Option<DockerDaemonInfo>,
    pub containers: Vec<DockerContainer>,
    pub images: Vec<DockerImage>,
    pub networks: Vec<DockerNetwork>,
    pub volumes: Vec<DockerVolume>,
    pub security_findings: Vec<DockerSecurityFinding>,
    pub is_daemon_accessible: bool,
}

/// Docker security scanner
pub struct DockerScanner {
    config: DockerConfig,
}

impl DockerScanner {
    pub fn new(config: DockerConfig) -> Self {
        Self { config }
    }

    pub fn with_default() -> Self {
        Self::new(DockerConfig::default())
    }

    /// Run full Docker security scan
    pub fn scan(&self) -> DockerResults {
        let mut results = DockerResults::default();

        // Check if Docker daemon is accessible
        results.is_daemon_accessible = self.is_daemon_accessible();

        if !results.is_daemon_accessible {
            results.security_findings.push(DockerSecurityFinding {
                title: "Docker daemon not accessible".to_string(),
                description: "Cannot connect to Docker daemon. Verify Docker is installed and running.".to_string(),
                severity: ContainerSeverity::Info,
                category: "daemon".to_string(),
                recommendation: "Ensure Docker is installed and the current user has permissions to access the Docker socket.".to_string(),
            });
            return results;
        }

        // Enumerate daemon info
        results.daemon_info = self.enumerate_daemon();

        // Enumerate containers
        results.containers = self.enumerate_containers();

        // Enumerate images
        if self.config.scan_images {
            results.images = self.enumerate_images();
        }

        // Enumerate networks
        if self.config.check_networks {
            results.networks = self.enumerate_networks();
        }

        // Enumerate volumes
        if self.config.check_volumes {
            results.volumes = self.enumerate_volumes();
        }

        // Run security assessment
        results.security_findings = self.assess_security(&results);

        results
    }

    /// Check if Docker daemon is accessible
    fn is_daemon_accessible(&self) -> bool {
        Command::new("docker")
            .arg("info")
            .arg("--format")
            .arg("{{.ServerVersion}}")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Enumerate Docker daemon information
    pub fn enumerate_daemon(&self) -> Option<DockerDaemonInfo> {
        let version_output = Command::new("docker")
            .arg("version")
            .arg("--format")
            .arg("{{.Server.Version}}|{{.Server.ApiVersion}}|{{.Server.Os}}|{{.Server.Arch}}|{{.Server.KernelVersion}}")
            .output()
            .ok()?;

        if !version_output.status.success() {
            return None;
        }

        let version_str = String::from_utf8_lossy(&version_output.stdout);
        let parts: Vec<&str> = version_str.trim().split('|').collect();

        let info_output = Command::new("docker")
            .arg("info")
            .arg("--format")
            .arg("{{.Driver}}|{{.LoggingDriver}}|{{.CgroupDriver}}|{{.LiveRestoreEnabled}}|{{.Containers}}|{{.ContainersRunning}}|{{.Images}}|{{.ServerVersion}}")
            .output()
            .ok()?;

        let info_str = String::from_utf8_lossy(&info_output.stdout);
        let info_parts: Vec<&str> = info_str.trim().split('|').collect();

        let security_output = Command::new("docker")
            .arg("info")
            .arg("--format")
            .arg("{{.SecurityOptions}}")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();

        let security_options: Vec<String> = security_output
            .trim_matches(|c| c == '[' || c == ']')
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let daemon_info = DockerDaemonInfo {
            version: parts.first().unwrap_or(&"").to_string(),
            api_version: parts.get(1).unwrap_or(&"").to_string(),
            os: parts.get(2).unwrap_or(&"").to_string(),
            arch: parts.get(3).unwrap_or(&"").to_string(),
            kernel_version: parts.get(4).unwrap_or(&"").to_string(),
            storage_driver: info_parts.first().unwrap_or(&"").to_string(),
            logging_driver: info_parts.get(1).unwrap_or(&"").to_string(),
            cgroup_driver: info_parts.get(2).unwrap_or(&"").to_string(),
            live_restore: info_parts.get(3).unwrap_or(&"false").to_string().parse().unwrap_or(false),
            containers_total: info_parts.get(4).unwrap_or(&"0").to_string().parse().unwrap_or(0),
            containers_running: info_parts.get(5).unwrap_or(&"0").to_string().parse().unwrap_or(0),
            images_count: info_parts.get(6).unwrap_or(&"0").to_string().parse().unwrap_or(0),
            server_addr: String::new(),
            security_options,
            registries: Vec::new(),
            insecure_registries: Vec::new(),
        };

        Some(daemon_info)
    }

    /// Enumerate running (and optionally stopped) containers
    pub fn enumerate_containers(&self) -> Vec<DockerContainer> {
        let all_flag = if self.config.include_stopped { "-a" } else { "" };

        let output = Command::new("docker")
            .arg("ps")
            .arg("--format")
            .arg("{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.State}}|{{.CreatedAt}}|{{.Ports}}|{{.Networks}}|{{.Mounts}}")
            .arg(all_flag)
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| self.parse_container_line(line))
            .collect()
    }

    fn parse_container_line(&self, line: &str) -> DockerContainer {
        let parts: Vec<&str> = line.splitn(9, '|').collect();

        let id = parts.first().unwrap_or(&"").to_string();
        let name = parts.get(1).unwrap_or(&"").to_string();
        let image = parts.get(2).unwrap_or(&"").to_string();
        let status = parts.get(3).unwrap_or(&"").to_string();
        let state = parts.get(4).unwrap_or(&"").to_string();
        let created = parts.get(5).unwrap_or(&"").to_string();
        let ports_str = parts.get(6).unwrap_or(&"").to_string();
        let networks_str = parts.get(7).unwrap_or(&"").to_string();
        let mounts_str = parts.get(8).unwrap_or(&"").to_string();

        let ports = self.parse_ports(&ports_str);
        let networks: Vec<String> = networks_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let mounts: Vec<ContainerMount> = mounts_str
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| {
                let parts: Vec<&str> = s.split(':').collect();
                ContainerMount {
                    source: parts.first().unwrap_or(&"").to_string(),
                    destination: parts.get(1).unwrap_or(&"").to_string(),
                    mode: parts.get(2).unwrap_or(&"rw").to_string(),
                    rw: true,
                }
            })
            .collect();

        // Get detailed info for security checks
        let (privileged, pid_mode, network_mode, ipc_mode, user, restart_policy, memory_limit, cpu_shares, caps_add, caps_drop, env_vars) =
            self.get_container_security_details(&id);

        DockerContainer {
            id,
            name,
            image,
            status,
            state,
            created,
            ports,
            mounts,
            networks,
            env_vars,
            labels: HashMap::new(),
            privileged,
            pid_mode,
            network_mode,
            ipc_mode,
            user,
            restart_policy,
            memory_limit,
            cpu_shares,
            capabilities_add: caps_add,
            capabilities_drop: caps_drop,
        }
    }

    fn parse_ports(&self, ports_str: &str) -> Vec<ContainerPort> {
        ports_str
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|p| {
                let parts: Vec<&str> = p.trim().split("->").collect();
                if parts.len() == 2 {
                    let host_part: Vec<&str> = parts[0].split(':').collect();
                    let container_port: u16 = parts[1]
                        .split('/')
                        .next()
                        .unwrap_or("0")
                        .parse()
                        .unwrap_or(0);
                    let host_port: u16 = host_part
                        .last()
                        .unwrap_or(&"0")
                        .parse()
                        .unwrap_or(0);
                    let host_ip = if host_part.len() > 1 {
                        host_part[0].to_string()
                    } else {
                        "0.0.0.0".to_string()
                    };
                    Some(ContainerPort {
                        container_port,
                        host_port: Some(host_port),
                        host_ip,
                        protocol: "tcp".to_string(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_container_security_details(
        &self,
        container_id: &str,
    ) -> (bool, String, String, String, String, String, u64, u64, Vec<String>, Vec<String>, Vec<String>) {
        let inspect_output = Command::new("docker")
            .arg("inspect")
            .arg("--format")
            .arg("{{.HostConfig.Privileged}}|{{.HostConfig.PidMode}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.IpcMode}}|{{.Config.User}}|{{.HostConfig.RestartPolicy.Name}}|{{.HostConfig.Memory}}|{{.HostConfig.CpuShares}}|{{.HostConfig.CapAdd}}|{{.HostConfig.CapDrop}}|{{.Config.Env}}")
            .arg(container_id)
            .output();

        let default = (
            false, String::new(), String::new(), String::new(),
            String::new(), String::new(), 0, 0,
            Vec::new(), Vec::new(), Vec::new(),
        );

        let output = match inspect_output {
            Ok(o) if o.status.success() => o,
            _ => return default,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = stdout.trim().splitn(11, '|').collect();

        let privileged = parts.first().unwrap_or(&"false").trim().parse().unwrap_or(false);
        let pid_mode = parts.get(1).unwrap_or(&"").to_string();
        let network_mode = parts.get(2).unwrap_or(&"").to_string();
        let ipc_mode = parts.get(3).unwrap_or(&"").to_string();
        let user = parts.get(4).unwrap_or(&"").to_string();
        let restart_policy = parts.get(5).unwrap_or(&"").to_string();
        let memory_limit: u64 = parts.get(6).unwrap_or(&"0").trim().parse().unwrap_or(0);
        let cpu_shares: u64 = parts.get(7).unwrap_or(&"0").trim().parse().unwrap_or(0);

        let caps_add = Self::parse_cap_list(parts.get(8).unwrap_or(&"[]"));
        let caps_drop = Self::parse_cap_list(parts.get(9).unwrap_or(&"[]"));

        let env_vars: Vec<String> = parts
            .get(10)
            .unwrap_or(&"[]")
            .trim_matches(|c| c == '[' || c == ']')
            .split(' ')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        (privileged, pid_mode, network_mode, ipc_mode, user, restart_policy, memory_limit, cpu_shares, caps_add, caps_drop, env_vars)
    }

    fn parse_cap_list(s: &str) -> Vec<String> {
        s.trim_matches(|c| c == '[' || c == ']')
            .split(' ')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "<nil>")
            .collect()
    }

    /// Enumerate Docker images
    pub fn enumerate_images(&self) -> Vec<DockerImage> {
        let output = Command::new("docker")
            .arg("images")
            .arg("--format")
            .arg("{{.ID}}|{{.Repository}}:{{.Tag}}|{{.Size}}|{{.CreatedAt}}")
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let parts: Vec<&str> = line.splitn(4, '|').collect();
                DockerImage {
                    id: parts.first().unwrap_or(&"").to_string(),
                    tags: vec![parts.get(1).unwrap_or(&"").to_string()],
                    size: Self::parse_size(parts.get(2).unwrap_or(&"0")),
                    created: parts.get(3).unwrap_or(&"").to_string(),
                    layers: 0,
                    has_vulnerabilities: false,
                    vulnerability_count: 0,
                    user: String::new(),
                }
            })
            .collect()
    }

    fn parse_size(s: &str) -> u64 {
        let s = s.trim();
        if s.ends_with("GB") {
            (s.trim_end_matches("GB").trim().parse::<f64>().unwrap_or(0.0) * 1_073_741_824.0) as u64
        } else if s.ends_with("MB") {
            (s.trim_end_matches("MB").trim().parse::<f64>().unwrap_or(0.0) * 1_048_576.0) as u64
        } else if s.ends_with("kB") {
            (s.trim_end_matches("kB").trim().parse::<f64>().unwrap_or(0.0) * 1024.0) as u64
        } else {
            s.trim_end_matches("B").trim().parse::<f64>().unwrap_or(0.0) as u64
        }
    }

    /// Enumerate Docker networks
    pub fn enumerate_networks(&self) -> Vec<DockerNetwork> {
        let output = Command::new("docker")
            .arg("network")
            .arg("ls")
            .arg("--format")
            .arg("{{.ID}}|{{.Name}}|{{.Driver}}|{{.Scope}}")
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .filter(|line| !line.is_empty())
            .filter_map(|line| {
                let parts: Vec<&str> = line.splitn(4, '|').collect();
                let name = parts.get(1).unwrap_or(&"").to_string();
                let driver = parts.get(2).unwrap_or(&"").to_string();

                // Get detailed network info
                let inspect = self.inspect_network(parts.first().unwrap_or(&""));

                Some(DockerNetwork {
                    id: parts.first().unwrap_or(&"").to_string(),
                    name: name.clone(),
                    driver: driver.clone(),
                    scope: parts.get(3).unwrap_or(&"").to_string(),
                    internal: inspect.0,
                    attachable: inspect.1,
                    ipam_driver: inspect.2,
                    subnet: inspect.3,
                    gateway: inspect.4,
                    containers: inspect.5,
                    enable_ipv6: inspect.6,
                })
            })
            .collect()
    }

    fn inspect_network(&self, network_id: &str) -> (bool, bool, String, String, String, Vec<String>, bool) {
        let output = Command::new("docker")
            .arg("network")
            .arg("inspect")
            .arg("--format")
            .arg("{{.Internal}}|{{.Attachable}}|{{.IPAM.Driver}}|{{range .IPAM.Config}}{{.Subnet}}{{end}}|{{range .IPAM.Config}}{{.Gateway}}{{end}}|{{.EnableIPv6}}")
            .arg(network_id)
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return (false, false, String::new(), String::new(), String::new(), Vec::new(), false),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = stdout.trim().splitn(6, '|').collect();

        (
            parts.first().unwrap_or(&"false").trim().parse().unwrap_or(false),
            parts.get(1).unwrap_or(&"false").trim().parse().unwrap_or(false),
            parts.get(2).unwrap_or(&"").to_string(),
            parts.get(3).unwrap_or(&"").to_string(),
            parts.get(4).unwrap_or(&"").to_string(),
            Vec::new(),
            parts.get(5).unwrap_or(&"false").trim().parse().unwrap_or(false),
        )
    }

    /// Enumerate Docker volumes
    pub fn enumerate_volumes(&self) -> Vec<DockerVolume> {
        let output = Command::new("docker")
            .arg("volume")
            .arg("ls")
            .arg("--format")
            .arg("{{.Name}}|{{.Driver}}|{{.Mountpoint}}|{{.Scope}}")
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        stdout
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let parts: Vec<&str> = line.splitn(4, '|').collect();
                DockerVolume {
                    name: parts.first().unwrap_or(&"").to_string(),
                    driver: parts.get(1).unwrap_or(&"").to_string(),
                    mountpoint: parts.get(2).unwrap_or(&"").to_string(),
                    scope: parts.get(3).unwrap_or(&"").to_string(),
                    labels: HashMap::new(),
                    size: None,
                }
            })
            .collect()
    }

    /// Perform security assessment on collected Docker data
    pub fn assess_security(&self, results: &DockerResults) -> Vec<DockerSecurityFinding> {
        let mut findings = Vec::new();

        // Check daemon security
        if let Some(ref daemon) = results.daemon_info {
            findings.extend(self.assess_daemon_security(daemon));
        }

        // Check container security
        for container in &results.containers {
            findings.extend(self.assess_container_security(container));
        }

        // Check network security
        for network in &results.networks {
            findings.extend(self.assess_network_security(network));
        }

        // Check volume security
        for volume in &results.volumes {
            findings.extend(self.assess_volume_security(volume));
        }

        findings
    }

    fn assess_daemon_security(&self, daemon: &DockerDaemonInfo) -> Vec<DockerSecurityFinding> {
        let mut findings = Vec::new();

        // Check if running as root
        let is_root = Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().ok())
            .map(|uid| uid == 0)
            .unwrap_or(false);

        if !is_root && !daemon.security_options.iter().any(|s| s.contains("rootlesskit")) {
            findings.push(DockerSecurityFinding {
                title: "Docker daemon not running in rootless mode".to_string(),
                description: "The Docker daemon runs as root by default, which increases the attack surface.".to_string(),
                severity: ContainerSeverity::Medium,
                category: "daemon".to_string(),
                recommendation: "Consider using rootless Docker mode to reduce attack surface.".to_string(),
            });
        }

        // Check for user namespace remapping
        if !daemon.security_options.iter().any(|s| s.contains("userns")) {
            findings.push(DockerSecurityFinding {
                title: "User namespace remapping not enabled".to_string(),
                description: "User namespace remapping provides an additional layer of isolation by mapping container root to a non-privileged host user.".to_string(),
                severity: ContainerSeverity::Medium,
                category: "daemon".to_string(),
                recommendation: "Enable user namespace remapping in Docker daemon configuration (--userns-remap=default).".to_string(),
            });
        }

        // Check for live restore
        if !daemon.live_restore {
            findings.push(DockerSecurityFinding {
                title: "Live restore not enabled".to_string(),
                description: "Without live restore, containers are stopped when the daemon is restarted, which can cause service disruptions.".to_string(),
                severity: ContainerSeverity::Low,
                category: "daemon".to_string(),
                recommendation: "Enable live restore in daemon configuration for better availability.".to_string(),
            });
        }

        // Check for insecure registries
        if !daemon.insecure_registries.is_empty() {
            findings.push(DockerSecurityFinding {
                title: "Insecure registries configured".to_string(),
                description: format!(
                    "Insecure registries detected: {}. These registries do not use TLS, making them vulnerable to MITM attacks.",
                    daemon.insecure_registries.join(", ")
                ),
                severity: ContainerSeverity::High,
                category: "daemon".to_string(),
                recommendation: "Remove insecure registries and use only TLS-enabled registries.".to_string(),
            });
        }

        // Check logging driver
        if daemon.logging_driver == "none" || daemon.logging_driver.is_empty() {
            findings.push(DockerSecurityFinding {
                title: "No logging driver configured".to_string(),
                description: "Without a logging driver, container activity cannot be audited.".to_string(),
                severity: ContainerSeverity::Medium,
                category: "daemon".to_string(),
                recommendation: "Configure a logging driver (e.g., json-file, syslog, or journald) for audit trail.".to_string(),
            });
        }

        findings
    }

    fn assess_container_security(&self, container: &DockerContainer) -> Vec<DockerSecurityFinding> {
        let mut findings = Vec::new();

        // Check privileged mode
        if container.privileged {
            findings.push(DockerSecurityFinding {
                title: format!("Container '{}' running in privileged mode", container.name),
                description: "Privileged containers have full access to the host, effectively disabling all security boundaries.".to_string(),
                severity: ContainerSeverity::Critical,
                category: "container".to_string(),
                recommendation: "Remove --privileged flag and use specific capabilities instead.".to_string(),
            });
        }

        // Check for host PID namespace
        if container.pid_mode == "host" {
            findings.push(DockerSecurityFinding {
                title: format!("Container '{}' sharing host PID namespace", container.name),
                description: "Sharing the host PID namespace allows the container to see and signal all processes on the host.".to_string(),
                severity: ContainerSeverity::High,
                category: "container".to_string(),
                recommendation: "Remove --pid=host and use the default container PID namespace.".to_string(),
            });
        }

        // Check for host network mode
        if container.network_mode == "host" {
            findings.push(DockerSecurityFinding {
                title: format!("Container '{}' using host network", container.name),
                description: "Host network mode removes network isolation between the container and the host.".to_string(),
                severity: ContainerSeverity::High,
                category: "container".to_string(),
                recommendation: "Use bridge or custom network instead of host networking.".to_string(),
            });
        }

        // Check for host IPC mode
        if container.ipc_mode == "host" {
            findings.push(DockerSecurityFinding {
                title: format!("Container '{}' sharing host IPC namespace", container.name),
                description: "Sharing the host IPC namespace allows the container to access host shared memory.".to_string(),
                severity: ContainerSeverity::Medium,
                category: "container".to_string(),
                recommendation: "Remove --ipc=host and use the default container IPC namespace.".to_string(),
            });
        }

        // Check for root user
        if container.user.is_empty() || container.user == "root" || container.user == "0" {
            findings.push(DockerSecurityFinding {
                title: format!("Container '{}' running as root", container.name),
                description: "Running containers as root increases the impact of container breakout vulnerabilities.".to_string(),
                severity: ContainerSeverity::Medium,
                category: "container".to_string(),
                recommendation: "Use a non-root user in the Dockerfile (USER directive) or with --user flag.".to_string(),
            });
        }

        // Check for dangerous capabilities
        let dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE"];
        for cap in &container.capabilities_add {
            if dangerous_caps.contains(&cap.as_str()) {
                findings.push(DockerSecurityFinding {
                    title: format!("Container '{}' has dangerous capability: {}", container.name, cap),
                    description: format!("The {} capability grants elevated privileges that can be used to escape the container.", cap),
                    severity: ContainerSeverity::High,
                    category: "container".to_string(),
                    recommendation: format!("Remove --cap-add={} and grant only necessary capabilities.", cap),
                });
            }
        }

        // Check for sensitive mounts
        for mount in &container.mounts {
            let sensitive_paths = ["/", "/etc", "/var/run/docker.sock", "/proc", "/sys", "/dev"];
            for sensitive in &sensitive_paths {
                if mount.source == *sensitive || mount.source.starts_with(&format!("{}/", sensitive)) {
                    let severity = if mount.source == "/var/run/docker.sock" || mount.source == "/" {
                        ContainerSeverity::Critical
                    } else {
                        ContainerSeverity::High
                    };
                    findings.push(DockerSecurityFinding {
                        title: format!("Container '{}' mounting sensitive host path: {}", container.name, mount.source),
                        description: format!("Mounting {} gives the container access to critical host resources.", mount.source),
                        severity,
                        category: "container".to_string(),
                        recommendation: "Avoid mounting sensitive host paths. Use named volumes or bind only specific subdirectories.".to_string(),
                    });
                }
            }
        }

        // Check for exposed ports
        for port in &container.ports {
            if let Some(host_port) = port.host_port {
                if host_port < 1024 && port.host_ip == "0.0.0.0" {
                    findings.push(DockerSecurityFinding {
                        title: format!("Container '{}' binding to privileged port {} on all interfaces", container.name, host_port),
                        description: "Binding to privileged ports on all interfaces increases exposure.".to_string(),
                        severity: ContainerSeverity::Low,
                        category: "container".to_string(),
                        recommendation: "Bind to specific interfaces and use non-privileged ports when possible.".to_string(),
                    });
                }
            }
        }

        // Check for sensitive environment variables
        let sensitive_env_patterns = ["PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY", "AWS_SECRET"];
        for env in &container.env_vars {
            for pattern in &sensitive_env_patterns {
                if env.to_uppercase().contains(pattern) {
                    findings.push(DockerSecurityFinding {
                        title: format!("Container '{}' has sensitive environment variable", container.name),
                        description: format!("Environment variable matching '{}' pattern detected. Secrets in environment variables can be exposed via docker inspect.", pattern),
                        severity: ContainerSeverity::Medium,
                        category: "container".to_string(),
                        recommendation: "Use Docker secrets or external secret management instead of environment variables.".to_string(),
                    });
                    break;
                }
            }
        }

        // Check for no memory limit
        if container.memory_limit == 0 {
            findings.push(DockerSecurityFinding {
                title: format!("Container '{}' has no memory limit", container.name),
                description: "Containers without memory limits can consume all available host memory, causing denial of service.".to_string(),
                severity: ContainerSeverity::Low,
                category: "container".to_string(),
                recommendation: "Set memory limits with --memory flag to prevent resource exhaustion.".to_string(),
            });
        }

        // Check restart policy
        if container.restart_policy == "always" {
            findings.push(DockerSecurityFinding {
                title: format!("Container '{}' has 'always' restart policy", container.name),
                description: "Always-restarting containers can mask security issues and persist compromised services.".to_string(),
                severity: ContainerSeverity::Low,
                category: "container".to_string(),
                recommendation: "Consider using 'on-failure' with a max retry count instead of 'always'.".to_string(),
            });
        }

        findings
    }

    fn assess_network_security(&self, network: &DockerNetwork) -> Vec<DockerSecurityFinding> {
        let mut findings = Vec::new();

        // Check for host network
        if network.name == "host" {
            findings.push(DockerSecurityFinding {
                title: "Host network exists".to_string(),
                description: "The host network driver removes network isolation between containers and the host.".to_string(),
                severity: ContainerSeverity::Info,
                category: "network".to_string(),
                recommendation: "Avoid using the host network. Use bridge or custom networks instead.".to_string(),
            });
        }

        // Check for internal networks
        if !network.internal && network.driver == "bridge" && network.name != "bridge" {
            findings.push(DockerSecurityFinding {
                title: format!("Network '{}' is not internal", network.name),
                description: "Non-internal networks have outbound internet access, which may not be needed.".to_string(),
                severity: ContainerSeverity::Low,
                category: "network".to_string(),
                recommendation: "Use --internal flag for networks that don't need external connectivity.".to_string(),
            });
        }

        findings
    }

    fn assess_volume_security(&self, volume: &DockerVolume) -> Vec<DockerSecurityFinding> {
        let mut findings = Vec::new();

        // Check for tmpfs with no size limit
        if volume.driver == "local" && volume.mountpoint.starts_with("/var/lib/docker/volumes/") {
            // This is a standard volume, no specific finding needed unless it's a sensitive path
        }

        // Check for NFS volumes (potential data exposure)
        if volume.driver == "local" && volume.mountpoint.contains(":/") {
            findings.push(DockerSecurityFinding {
                title: format!("Volume '{}' appears to be an NFS mount", volume.name),
                description: "NFS mounts can expose data to the network. Ensure NFS is properly secured.".to_string(),
                severity: ContainerSeverity::Low,
                category: "volume".to_string(),
                recommendation: "Use Kerberos authentication and limit NFS exports to specific hosts.".to_string(),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_docker_config_default() {
        let config = DockerConfig::default();
        assert_eq!(config.socket_path, "/var/run/docker.sock");
        assert_eq!(config.api_version, "1.41");
        assert!(config.include_stopped);
        assert!(config.scan_images);
        assert!(config.check_networks);
        assert!(config.check_volumes);
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_docker_scanner_creation() {
        let scanner = DockerScanner::with_default();
        assert_eq!(scanner.config.socket_path, "/var/run/docker.sock");
    }

    #[test]
    fn test_parse_ports() {
        let scanner = DockerScanner::with_default();
        let ports = scanner.parse_ports("0.0.0.0:8080->80/tcp, 0.0.0.0:443->443/tcp");
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].container_port, 80);
        assert_eq!(ports[0].host_port, Some(8080));
        assert_eq!(ports[1].container_port, 443);
        assert_eq!(ports[1].host_port, Some(443));
    }

    #[test]
    fn test_parse_ports_empty() {
        let scanner = DockerScanner::with_default();
        let ports = scanner.parse_ports("");
        assert!(ports.is_empty());
    }

    #[test]
    fn test_parse_size() {
        assert_eq!(DockerScanner::parse_size("1.5GB"), 1_610_612_736);
        assert_eq!(DockerScanner::parse_size("256MB"), 268_435_456);
        assert_eq!(DockerScanner::parse_size("100kB"), 102_400);
    }

    #[test]
    fn test_parse_cap_list() {
        let caps = DockerScanner::parse_cap_list("[SYS_ADMIN NET_ADMIN]");
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0], "SYS_ADMIN");
        assert_eq!(caps[1], "NET_ADMIN");
    }

    #[test]
    fn test_parse_cap_list_empty() {
        let caps = DockerScanner::parse_cap_list("[]");
        assert!(caps.is_empty());
    }

    #[test]
    fn test_docker_results_default() {
        let results = DockerResults::default();
        assert!(results.containers.is_empty());
        assert!(results.images.is_empty());
        assert!(results.networks.is_empty());
        assert!(results.volumes.is_empty());
        assert!(results.security_findings.is_empty());
        assert!(!results.is_daemon_accessible);
    }

    #[test]
    fn test_assess_privileged_container() {
        let scanner = DockerScanner::with_default();
        let container = DockerContainer {
            id: "abc123".to_string(),
            name: "test".to_string(),
            image: "nginx".to_string(),
            privileged: true,
            ..Default::default()
        };
        let findings = scanner.assess_container_security(&container);
        assert!(findings.iter().any(|f| f.severity == ContainerSeverity::Critical && f.title.contains("privileged")));
    }

    #[test]
    fn test_assess_host_pid_container() {
        let scanner = DockerScanner::with_default();
        let container = DockerContainer {
            id: "abc123".to_string(),
            name: "test".to_string(),
            image: "nginx".to_string(),
            pid_mode: "host".to_string(),
            ..Default::default()
        };
        let findings = scanner.assess_container_security(&container);
        assert!(findings.iter().any(|f| f.severity == ContainerSeverity::High && f.title.contains("PID")));
    }

    #[test]
    fn test_assess_host_network_container() {
        let scanner = DockerScanner::with_default();
        let container = DockerContainer {
            id: "abc123".to_string(),
            name: "test".to_string(),
            image: "nginx".to_string(),
            network_mode: "host".to_string(),
            ..Default::default()
        };
        let findings = scanner.assess_container_security(&container);
        assert!(findings.iter().any(|f| f.severity == ContainerSeverity::High && f.title.contains("host network")));
    }

    #[test]
    fn test_assess_root_user_container() {
        let scanner = DockerScanner::with_default();
        let container = DockerContainer {
            id: "abc123".to_string(),
            name: "test".to_string(),
            image: "nginx".to_string(),
            user: "root".to_string(),
            ..Default::default()
        };
        let findings = scanner.assess_container_security(&container);
        assert!(findings.iter().any(|f| f.severity == ContainerSeverity::Medium && f.title.contains("root")));
    }

    #[test]
    fn test_assess_dangerous_capability() {
        let scanner = DockerScanner::with_default();
        let container = DockerContainer {
            id: "abc123".to_string(),
            name: "test".to_string(),
            image: "nginx".to_string(),
            capabilities_add: vec!["SYS_ADMIN".to_string()],
            ..Default::default()
        };
        let findings = scanner.assess_container_security(&container);
        assert!(findings.iter().any(|f| f.severity == ContainerSeverity::High && f.title.contains("SYS_ADMIN")));
    }

    #[test]
    fn test_assess_docker_socket_mount() {
        let scanner = DockerScanner::with_default();
        let container = DockerContainer {
            id: "abc123".to_string(),
            name: "test".to_string(),
            image: "nginx".to_string(),
            mounts: vec![ContainerMount {
                source: "/var/run/docker.sock".to_string(),
                destination: "/var/run/docker.sock".to_string(),
                mode: "rw".to_string(),
                rw: true,
            }],
            ..Default::default()
        };
        let findings = scanner.assess_container_security(&container);
        assert!(findings.iter().any(|f| f.severity == ContainerSeverity::Critical && f.title.contains("docker.sock")));
    }

    #[test]
    fn test_assess_sensitive_env_var() {
        let scanner = DockerScanner::with_default();
        let container = DockerContainer {
            id: "abc123".to_string(),
            name: "test".to_string(),
            image: "nginx".to_string(),
            env_vars: vec!["DB_PASSWORD=secret123".to_string()],
            ..Default::default()
        };
        let findings = scanner.assess_container_security(&container);
        assert!(findings.iter().any(|f| f.severity == ContainerSeverity::Medium && f.title.contains("sensitive")));
    }

    #[test]
    fn test_assess_no_memory_limit() {
        let scanner = DockerScanner::with_default();
        let container = DockerContainer {
            id: "abc123".to_string(),
            name: "test".to_string(),
            image: "nginx".to_string(),
            memory_limit: 0,
            ..Default::default()
        };
        let findings = scanner.assess_container_security(&container);
        assert!(findings.iter().any(|f| f.severity == ContainerSeverity::Low && f.title.contains("memory")));
    }

    #[test]
    fn test_assess_insecure_registry() {
        let scanner = DockerScanner::with_default();
        let daemon = DockerDaemonInfo {
            insecure_registries: vec!["http://registry.local".to_string()],
            ..Default::default()
        };
        let findings = scanner.assess_daemon_security(&daemon);
        assert!(findings.iter().any(|f| f.severity == ContainerSeverity::High && f.title.contains("Insecure")));
    }

    #[test]
    fn test_assess_no_logging_driver() {
        let scanner = DockerScanner::with_default();
        let daemon = DockerDaemonInfo {
            logging_driver: "none".to_string(),
            ..Default::default()
        };
        let findings = scanner.assess_daemon_security(&daemon);
        assert!(findings.iter().any(|f| f.severity == ContainerSeverity::Medium && f.title.contains("logging")));
    }
}
