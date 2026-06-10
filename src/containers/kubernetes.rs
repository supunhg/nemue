//! Kubernetes Security Scanning Module
//!
//! Provides Kubernetes API server enumeration, pod/service/deployment inspection,
//! RBAC assessment, and security analysis.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

use crate::containers::ContainerSeverity;

/// Kubernetes scanning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeConfig {
    /// Path to kubeconfig file
    pub kubeconfig: Option<String>,
    /// Kubernetes context to use
    pub context: Option<String>,
    /// Namespace to scan (None = all namespaces)
    pub namespace: Option<String>,
    /// Check RBAC policies
    pub check_rbac: bool,
    /// Check network policies
    pub check_network_policies: bool,
    /// Check pod security standards
    pub check_pod_security: bool,
    /// Check secrets
    pub check_secrets: bool,
    /// Timeout for kubectl commands in seconds
    pub timeout_seconds: u64,
}

impl Default for KubeConfig {
    fn default() -> Self {
        Self {
            kubeconfig: None,
            context: None,
            namespace: None,
            check_rbac: true,
            check_network_policies: true,
            check_pod_security: true,
            check_secrets: true,
            timeout_seconds: 30,
        }
    }
}

/// Kubernetes API server information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubeApiServerInfo {
    pub version: String,
    pub platform: String,
    pub cluster_name: String,
    pub server_address: String,
    pub node_count: u64,
    pub namespace_count: u64,
    pub service_count: u64,
    pub pod_count: u64,
    pub admission_controllers: Vec<String>,
    pub audit_logging_enabled: bool,
    pub etcd_encryption_enabled: bool,
    pub anonymous_auth_enabled: bool,
    pub authorization_mode: String,
}

/// Kubernetes pod information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubePod {
    pub name: String,
    pub namespace: String,
    pub status: String,
    pub node: String,
    pub service_account: String,
    pub containers: Vec<KubeContainer>,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub host_network: bool,
    pub host_pid: bool,
    pub host_ipc: bool,
    pub privileged: bool,
    pub run_as_non_root: bool,
    pub run_as_user: Option<u64>,
    pub fs_group: Option<u64>,
    pub volumes: Vec<KubeVolumeMount>,
    pub security_context: PodSecurityContext,
}

/// Kubernetes container within a pod
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubeContainer {
    pub name: String,
    pub image: String,
    pub ports: Vec<u16>,
    pub resources: ContainerResources,
    pub security_context: ContainerSecurityContext,
    pub env_vars: Vec<String>,
    pub liveness_probe: bool,
    pub readiness_probe: bool,
}

/// Container resource limits/requests
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerResources {
    pub cpu_request: Option<String>,
    pub cpu_limit: Option<String>,
    pub memory_request: Option<String>,
    pub memory_limit: Option<String>,
}

/// Container security context
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerSecurityContext {
    pub privileged: bool,
    pub run_as_non_root: bool,
    pub read_only_root_fs: bool,
    pub allow_privilege_escalation: bool,
    pub capabilities_add: Vec<String>,
    pub capabilities_drop: Vec<String>,
}

/// Pod-level security context
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PodSecurityContext {
    pub run_as_non_root: bool,
    pub run_as_user: Option<u64>,
    pub fs_group: Option<u64>,
    pub supplemental_groups: Vec<u64>,
}

/// Volume mount information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubeVolumeMount {
    pub name: String,
    pub mount_path: String,
    pub volume_type: String,
    pub read_only: bool,
    pub host_path: Option<String>,
}

/// Kubernetes service information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubeService {
    pub name: String,
    pub namespace: String,
    pub service_type: String,
    pub cluster_ip: String,
    pub external_ips: Vec<String>,
    pub ports: Vec<ServicePort>,
    pub selector: HashMap<String, String>,
    pub labels: HashMap<String, String>,
}

/// Service port definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServicePort {
    pub name: String,
    pub port: u16,
    pub target_port: u16,
    pub protocol: String,
    pub node_port: Option<u16>,
}

/// Kubernetes deployment information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubeDeployment {
    pub name: String,
    pub namespace: String,
    pub replicas: u32,
    pub ready_replicas: u32,
    pub strategy: String,
    pub labels: HashMap<String, String>,
    pub selector: HashMap<String, String>,
    pub pod_template: PodTemplateSpec,
}

/// Pod template specification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PodTemplateSpec {
    pub service_account: String,
    pub automount_sa_token: bool,
    pub containers: Vec<KubeContainer>,
}

/// RBAC assessment results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubeRbacAssessment {
    pub cluster_roles: Vec<KubeClusterRole>,
    pub roles: Vec<KubeRole>,
    pub bindings: Vec<KubeRoleBinding>,
    pub service_accounts: Vec<KubeServiceAccount>,
    pub findings: Vec<RbacFinding>,
}

/// Cluster role information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubeClusterRole {
    pub name: String,
    pub rules: Vec<RbacRule>,
    pub is_aggregation: bool,
}

/// Namespace role information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubeRole {
    pub name: String,
    pub namespace: String,
    pub rules: Vec<RbacRule>,
}

/// RBAC rule definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RbacRule {
    pub api_groups: Vec<String>,
    pub resources: Vec<String>,
    pub verbs: Vec<String>,
    pub resource_names: Vec<String>,
}

/// Role binding information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubeRoleBinding {
    pub name: String,
    pub namespace: String,
    pub role_ref: String,
    pub subjects: Vec<String>,
}

/// Service account information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubeServiceAccount {
    pub name: String,
    pub namespace: String,
    pub automount_token: bool,
    pub secrets_count: u32,
}

/// RBAC security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacFinding {
    pub title: String,
    pub description: String,
    pub severity: ContainerSeverity,
    pub subject: String,
    pub recommendation: String,
}

/// Kubernetes security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubeSecurityFinding {
    pub title: String,
    pub description: String,
    pub severity: ContainerSeverity,
    pub category: String,
    pub namespace: String,
    pub resource: String,
    pub recommendation: String,
}

/// Kubernetes scan results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubernetesResults {
    pub api_server_info: Option<KubeApiServerInfo>,
    pub pods: Vec<KubePod>,
    pub services: Vec<KubeService>,
    pub deployments: Vec<KubeDeployment>,
    pub rbac_assessment: Option<KubeRbacAssessment>,
    pub security_findings: Vec<KubeSecurityFinding>,
    pub is_accessible: bool,
}

/// Kubernetes security scanner
pub struct KubernetesScanner {
    config: KubeConfig,
}

impl KubernetesScanner {
    pub fn new(config: KubeConfig) -> Self {
        Self { config }
    }

    pub fn with_default() -> Self {
        Self::new(KubeConfig::default())
    }

    /// Run full Kubernetes security scan
    pub fn scan(&self) -> KubernetesResults {
        let mut results = KubernetesResults::default();

        // Check if kubectl is available and cluster is accessible
        results.is_accessible = self.is_cluster_accessible();

        if !results.is_accessible {
            results.security_findings.push(KubeSecurityFinding {
                title: "Kubernetes cluster not accessible".to_string(),
                description: "Cannot connect to Kubernetes cluster. Verify kubectl is configured and cluster is running.".to_string(),
                severity: ContainerSeverity::Info,
                category: "cluster".to_string(),
                namespace: String::new(),
                resource: String::new(),
                recommendation: "Ensure kubectl is installed and kubeconfig is properly configured.".to_string(),
            });
            return results;
        }

        // Enumerate API server
        results.api_server_info = self.enumerate_api_server();

        // Enumerate pods
        results.pods = self.enumerate_pods();

        // Enumerate services
        results.services = self.enumerate_services();

        // Enumerate deployments
        results.deployments = self.enumerate_deployments();

        // RBAC assessment
        if self.config.check_rbac {
            results.rbac_assessment = Some(self.assess_rbac());
        }

        // Run security assessment
        results.security_findings = self.assess_security(&results);

        results
    }

    /// Check if Kubernetes cluster is accessible
    fn is_cluster_accessible(&self) -> bool {
        let mut cmd = Command::new("kubectl");
        cmd.arg("cluster-info");
        if let Some(ref ctx) = self.config.context {
            cmd.arg("--context").arg(ctx);
        }
        cmd.output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Build kubectl command with optional kubeconfig and context
    fn kubectl_cmd(&self) -> Command {
        let mut cmd = Command::new("kubectl");
        if let Some(ref kc) = self.config.kubeconfig {
            cmd.arg("--kubeconfig").arg(kc);
        }
        if let Some(ref ctx) = self.config.context {
            cmd.arg("--context").arg(ctx);
        }
        cmd
    }

    /// Enumerate Kubernetes API server information
    pub fn enumerate_api_server(&self) -> Option<KubeApiServerInfo> {
        let mut cmd = self.kubectl_cmd();
        cmd.arg("version").arg("-o").arg("json");
        let output = cmd.output().ok()?;
        if !output.status.success() {
            return None;
        }

        let version_json: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
        let server_version = version_json.get("serverVersion")?;

        let version = server_version
            .get("gitVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let platform = server_version
            .get("platform")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // Get cluster info
        let mut cmd = self.kubectl_cmd();
        cmd.arg("config").arg("current-context");
        let ctx_output = cmd.output().ok();
        let cluster_name = ctx_output
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().to_string().into())
            .unwrap_or_default();

        // Get node count
        let node_count = self.get_resource_count("nodes");
        let namespace_count = self.get_resource_count("namespaces");
        let service_count = self.get_resource_count("services");
        let pod_count = self.get_resource_count("pods");

        Some(KubeApiServerInfo {
            version,
            platform,
            cluster_name,
            server_address: String::new(),
            node_count,
            namespace_count,
            service_count,
            pod_count,
            admission_controllers: Vec::new(),
            audit_logging_enabled: false,
            etcd_encryption_enabled: false,
            anonymous_auth_enabled: false,
            authorization_mode: String::new(),
        })
    }

    fn get_resource_count(&self, resource: &str) -> u64 {
        let mut cmd = self.kubectl_cmd();
        cmd.arg("get")
            .arg(resource)
            .arg("--all-namespaces")
            .arg("-o")
            .arg("json");
        cmd.output()
            .ok()
            .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok())
            .and_then(|v| {
                v.get("items")
                    .and_then(|i| i.as_array().map(|a| a.len() as u64))
            })
            .unwrap_or(0)
    }

    /// Enumerate Kubernetes pods
    pub fn enumerate_pods(&self) -> Vec<KubePod> {
        let mut cmd = self.kubectl_cmd();
        cmd.arg("get").arg("pods").arg("-o").arg("json");
        if let Some(ref ns) = self.config.namespace {
            cmd.arg("-n").arg(ns);
        } else {
            cmd.arg("--all-namespaces");
        }

        let output = match cmd.output() {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let json: serde_json::Value = match serde_json::from_slice(&output.stdout) {
            Ok(v) => v,
            _ => return Vec::new(),
        };

        let items = match json.get("items").and_then(|i| i.as_array()) {
            Some(items) => items,
            None => return Vec::new(),
        };

        items
            .iter()
            .filter_map(|item| self.parse_pod(item))
            .collect()
    }

    fn parse_pod(&self, item: &serde_json::Value) -> Option<KubePod> {
        let metadata = item.get("metadata")?;
        let spec = item.get("spec")?;
        let status = item.get("status")?;

        let name = metadata.get("name")?.as_str()?.to_string();
        let namespace = metadata
            .get("namespace")
            .and_then(|n| n.as_str())
            .unwrap_or("default")
            .to_string();

        let phase = status
            .get("phase")
            .and_then(|p| p.as_str())
            .unwrap_or("Unknown")
            .to_string();

        let node = spec
            .get("nodeName")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();

        let service_account = spec
            .get("serviceAccountName")
            .and_then(|s| s.as_str())
            .unwrap_or("default")
            .to_string();

        let host_network = spec
            .get("hostNetwork")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let host_pid = spec
            .get("hostPID")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let host_ipc = spec
            .get("hostIPC")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);

        // Parse security context
        let pod_sc = spec.get("securityContext");
        let run_as_non_root = pod_sc
            .and_then(|sc| sc.get("runAsNonRoot"))
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let run_as_user = pod_sc
            .and_then(|sc| sc.get("runAsUser"))
            .and_then(|u| u.as_u64());
        let fs_group = pod_sc
            .and_then(|sc| sc.get("fsGroup"))
            .and_then(|f| f.as_u64());

        // Parse containers
        let containers: Vec<KubeContainer> = spec
            .get("containers")
            .and_then(|c| c.as_array())
            .map(|arr| arr.iter().filter_map(|c| self.parse_container(c)).collect())
            .unwrap_or_default();

        // Check if any container is privileged
        let privileged = containers.iter().any(|c| c.security_context.privileged);

        // Parse volumes
        let volumes = spec
            .get("volumes")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| self.parse_volume(v)).collect())
            .unwrap_or_default();

        // Parse labels
        let labels = metadata
            .get("labels")
            .and_then(|l| l.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Parse annotations
        let annotations = metadata
            .get("annotations")
            .and_then(|a| a.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Some(KubePod {
            name,
            namespace,
            status: phase,
            node,
            service_account,
            containers,
            labels,
            annotations,
            host_network,
            host_pid,
            host_ipc,
            privileged,
            run_as_non_root,
            run_as_user,
            fs_group,
            volumes,
            security_context: PodSecurityContext {
                run_as_non_root,
                run_as_user,
                fs_group,
                supplemental_groups: Vec::new(),
            },
        })
    }

    fn parse_container(&self, item: &serde_json::Value) -> Option<KubeContainer> {
        let name = item.get("name")?.as_str()?.to_string();
        let image = item
            .get("image")
            .and_then(|i| i.as_str())
            .unwrap_or("")
            .to_string();

        let ports: Vec<u16> = item
            .get("ports")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|p| {
                        p.get("containerPort")
                            .and_then(|c| c.as_u64())
                            .map(|c| c as u16)
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Parse resources
        let resources = item
            .get("resources")
            .map(|r| ContainerResources {
                cpu_request: r
                    .get("requests")
                    .and_then(|req| req.get("cpu"))
                    .and_then(|c| c.as_str())
                    .map(String::from),
                cpu_limit: r
                    .get("limits")
                    .and_then(|lim| lim.get("cpu"))
                    .and_then(|c| c.as_str())
                    .map(String::from),
                memory_request: r
                    .get("requests")
                    .and_then(|req| req.get("memory"))
                    .and_then(|m| m.as_str())
                    .map(String::from),
                memory_limit: r
                    .get("limits")
                    .and_then(|lim| lim.get("memory"))
                    .and_then(|m| m.as_str())
                    .map(String::from),
            })
            .unwrap_or_default();

        // Parse security context
        let sc = item.get("securityContext");
        let security_context = ContainerSecurityContext {
            privileged: sc
                .and_then(|s| s.get("privileged"))
                .and_then(|b| b.as_bool())
                .unwrap_or(false),
            run_as_non_root: sc
                .and_then(|s| s.get("runAsNonRoot"))
                .and_then(|b| b.as_bool())
                .unwrap_or(false),
            read_only_root_fs: sc
                .and_then(|s| s.get("readOnlyRootFilesystem"))
                .and_then(|b| b.as_bool())
                .unwrap_or(false),
            allow_privilege_escalation: sc
                .and_then(|s| s.get("allowPrivilegeEscalation"))
                .and_then(|b| b.as_bool())
                .unwrap_or(true),
            capabilities_add: sc
                .and_then(|s| s.get("capabilities"))
                .and_then(|c| c.get("add"))
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            capabilities_drop: sc
                .and_then(|s| s.get("capabilities"))
                .and_then(|c| c.get("drop"))
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
        };

        let env_vars: Vec<String> = item
            .get("env")
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        let name = e.get("name")?.as_str()?;
                        let value = e.get("value").and_then(|v| v.as_str()).unwrap_or("");
                        Some(format!("{}={}", name, value))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let liveness_probe = item.get("livenessProbe").is_some();
        let readiness_probe = item.get("readinessProbe").is_some();

        Some(KubeContainer {
            name,
            image,
            ports,
            resources,
            security_context,
            env_vars,
            liveness_probe,
            readiness_probe,
        })
    }

    fn parse_volume(&self, item: &serde_json::Value) -> Option<KubeVolumeMount> {
        let name = item.get("name")?.as_str()?.to_string();

        // Determine volume type
        let (volume_type, host_path) = if item.get("hostPath").is_some() {
            let hp = item
                .get("hostPath")
                .and_then(|h| h.get("path"))
                .and_then(|p| p.as_str())
                .unwrap_or("");
            ("hostPath".to_string(), Some(hp.to_string()))
        } else if item.get("configMap").is_some() {
            ("configMap".to_string(), None)
        } else if item.get("secret").is_some() {
            ("secret".to_string(), None)
        } else if item.get("persistentVolumeClaim").is_some() {
            ("persistentVolumeClaim".to_string(), None)
        } else if item.get("emptyDir").is_some() {
            ("emptyDir".to_string(), None)
        } else {
            ("unknown".to_string(), None)
        };

        Some(KubeVolumeMount {
            name,
            mount_path: String::new(),
            volume_type,
            read_only: false,
            host_path,
        })
    }

    /// Enumerate Kubernetes services
    pub fn enumerate_services(&self) -> Vec<KubeService> {
        let mut cmd = self.kubectl_cmd();
        cmd.arg("get").arg("services").arg("-o").arg("json");
        if let Some(ref ns) = self.config.namespace {
            cmd.arg("-n").arg(ns);
        } else {
            cmd.arg("--all-namespaces");
        }

        let output = match cmd.output() {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let json: serde_json::Value = match serde_json::from_slice(&output.stdout) {
            Ok(v) => v,
            _ => return Vec::new(),
        };

        json.get("items")
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| self.parse_service(item))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn parse_service(&self, item: &serde_json::Value) -> Option<KubeService> {
        let metadata = item.get("metadata")?;
        let spec = item.get("spec")?;

        let name = metadata.get("name")?.as_str()?.to_string();
        let namespace = metadata
            .get("namespace")
            .and_then(|n| n.as_str())
            .unwrap_or("default")
            .to_string();

        let service_type = spec
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("ClusterIP")
            .to_string();
        let cluster_ip = spec
            .get("clusterIP")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();

        let external_ips: Vec<String> = spec
            .get("externalIPs")
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|ip| ip.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let ports: Vec<ServicePort> = spec
            .get("ports")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|p| ServicePort {
                        name: p
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string(),
                        port: p.get("port").and_then(|p| p.as_u64()).unwrap_or(0) as u16,
                        target_port: p.get("targetPort").and_then(|t| t.as_u64()).unwrap_or(0)
                            as u16,
                        protocol: p
                            .get("protocol")
                            .and_then(|p| p.as_str())
                            .unwrap_or("TCP")
                            .to_string(),
                        node_port: p.get("nodePort").and_then(|n| n.as_u64()).map(|n| n as u16),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let selector: HashMap<String, String> = spec
            .get("selector")
            .and_then(|s| s.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let labels: HashMap<String, String> = metadata
            .get("labels")
            .and_then(|l| l.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();

        Some(KubeService {
            name,
            namespace,
            service_type,
            cluster_ip,
            external_ips,
            ports,
            selector,
            labels,
        })
    }

    /// Enumerate Kubernetes deployments
    pub fn enumerate_deployments(&self) -> Vec<KubeDeployment> {
        let mut cmd = self.kubectl_cmd();
        cmd.arg("get").arg("deployments").arg("-o").arg("json");
        if let Some(ref ns) = self.config.namespace {
            cmd.arg("-n").arg(ns);
        } else {
            cmd.arg("--all-namespaces");
        }

        let output = match cmd.output() {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let json: serde_json::Value = match serde_json::from_slice(&output.stdout) {
            Ok(v) => v,
            _ => return Vec::new(),
        };

        json.get("items")
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| self.parse_deployment(item))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn parse_deployment(&self, item: &serde_json::Value) -> Option<KubeDeployment> {
        let metadata = item.get("metadata")?;
        let spec = item.get("spec")?;
        let status = item.get("status")?;

        let name = metadata.get("name")?.as_str()?.to_string();
        let namespace = metadata
            .get("namespace")
            .and_then(|n| n.as_str())
            .unwrap_or("default")
            .to_string();

        let replicas = spec.get("replicas").and_then(|r| r.as_u64()).unwrap_or(1) as u32;
        let ready_replicas = status
            .get("readyReplicas")
            .and_then(|r| r.as_u64())
            .unwrap_or(0) as u32;

        let strategy = spec
            .get("strategy")
            .and_then(|s| s.get("type"))
            .and_then(|t| t.as_str())
            .unwrap_or("RollingUpdate")
            .to_string();

        let labels: HashMap<String, String> = metadata
            .get("labels")
            .and_then(|l| l.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let selector: HashMap<String, String> = spec
            .get("selector")
            .and_then(|s| s.get("matchLabels"))
            .and_then(|m| m.as_object())
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Parse pod template
        let template = spec.get("template").and_then(|t| t.get("spec"));
        let pod_template = PodTemplateSpec {
            service_account: template
                .and_then(|s| s.get("serviceAccountName"))
                .and_then(|s| s.as_str())
                .unwrap_or("default")
                .to_string(),
            automount_sa_token: template
                .and_then(|s| s.get("automountServiceAccountToken"))
                .and_then(|b| b.as_bool())
                .unwrap_or(true),
            containers: template
                .and_then(|s| s.get("containers"))
                .and_then(|c| c.as_array())
                .map(|arr| arr.iter().filter_map(|c| self.parse_container(c)).collect())
                .unwrap_or_default(),
        };

        Some(KubeDeployment {
            name,
            namespace,
            replicas,
            ready_replicas,
            strategy,
            labels,
            selector,
            pod_template,
        })
    }

    /// Assess RBAC configuration
    pub fn assess_rbac(&self) -> KubeRbacAssessment {
        let mut assessment = KubeRbacAssessment::default();

        // Get cluster roles
        assessment.cluster_roles = self.get_cluster_roles();

        // Get namespace roles
        assessment.roles = self.get_roles();

        // Get role bindings
        assessment.bindings = self.get_role_bindings();

        // Get service accounts
        assessment.service_accounts = self.get_service_accounts();

        // Analyze RBAC findings
        assessment.findings = self.analyze_rbac(&assessment);

        assessment
    }

    fn get_cluster_roles(&self) -> Vec<KubeClusterRole> {
        let mut cmd = self.kubectl_cmd();
        cmd.arg("get").arg("clusterroles").arg("-o").arg("json");

        let output = match cmd.output() {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let json: serde_json::Value = match serde_json::from_slice(&output.stdout) {
            Ok(v) => v,
            _ => return Vec::new(),
        };

        json.get("items")
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        let name = item.get("metadata")?.get("name")?.as_str()?.to_string();
                        let rules = Self::parse_rules(item.get("rules")?);
                        Some(KubeClusterRole {
                            name,
                            rules,
                            is_aggregation: false,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn get_roles(&self) -> Vec<KubeRole> {
        let mut cmd = self.kubectl_cmd();
        cmd.arg("get")
            .arg("roles")
            .arg("--all-namespaces")
            .arg("-o")
            .arg("json");

        let output = match cmd.output() {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let json: serde_json::Value = match serde_json::from_slice(&output.stdout) {
            Ok(v) => v,
            _ => return Vec::new(),
        };

        json.get("items")
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        let metadata = item.get("metadata")?;
                        let name = metadata.get("name")?.as_str()?.to_string();
                        let namespace = metadata
                            .get("namespace")
                            .and_then(|n| n.as_str())
                            .unwrap_or("default")
                            .to_string();
                        let rules = Self::parse_rules(item.get("rules")?);
                        Some(KubeRole {
                            name,
                            namespace,
                            rules,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn parse_rules(rules_json: &serde_json::Value) -> Vec<RbacRule> {
        rules_json
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|rule| RbacRule {
                        api_groups: rule
                            .get("apiGroups")
                            .and_then(|a| a.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        resources: rule
                            .get("resources")
                            .and_then(|r| r.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        verbs: rule
                            .get("verbs")
                            .and_then(|v| v.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                        resource_names: rule
                            .get("resourceNames")
                            .and_then(|r| r.as_array())
                            .map(|a| {
                                a.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn get_role_bindings(&self) -> Vec<KubeRoleBinding> {
        let mut cmd = self.kubectl_cmd();
        cmd.arg("get")
            .arg("rolebindings")
            .arg("--all-namespaces")
            .arg("-o")
            .arg("json");

        let output = match cmd.output() {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let json: serde_json::Value = match serde_json::from_slice(&output.stdout) {
            Ok(v) => v,
            _ => return Vec::new(),
        };

        json.get("items")
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        let metadata = item.get("metadata")?;
                        let name = metadata.get("name")?.as_str()?.to_string();
                        let namespace = metadata
                            .get("namespace")
                            .and_then(|n| n.as_str())
                            .unwrap_or("default")
                            .to_string();
                        let role_ref = item
                            .get("roleRef")
                            .and_then(|r| r.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let subjects: Vec<String> = item
                            .get("subjects")
                            .and_then(|s| s.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|s| {
                                        let kind = s.get("kind")?.as_str()?;
                                        let name = s.get("name")?.as_str()?;
                                        Some(format!("{}:{}", kind, name))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        Some(KubeRoleBinding {
                            name,
                            namespace,
                            role_ref,
                            subjects,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn get_service_accounts(&self) -> Vec<KubeServiceAccount> {
        let mut cmd = self.kubectl_cmd();
        cmd.arg("get")
            .arg("serviceaccounts")
            .arg("--all-namespaces")
            .arg("-o")
            .arg("json");

        let output = match cmd.output() {
            Ok(o) if o.status.success() => o,
            _ => return Vec::new(),
        };

        let json: serde_json::Value = match serde_json::from_slice(&output.stdout) {
            Ok(v) => v,
            _ => return Vec::new(),
        };

        json.get("items")
            .and_then(|i| i.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        let metadata = item.get("metadata")?;
                        let name = metadata.get("name")?.as_str()?.to_string();
                        let namespace = metadata
                            .get("namespace")
                            .and_then(|n| n.as_str())
                            .unwrap_or("default")
                            .to_string();
                        let automount = item
                            .get("automountServiceAccountToken")
                            .and_then(|b| b.as_bool())
                            .unwrap_or(true);
                        let secrets_count = item
                            .get("secrets")
                            .and_then(|s| s.as_array())
                            .map(|a| a.len() as u32)
                            .unwrap_or(0);
                        Some(KubeServiceAccount {
                            name,
                            namespace,
                            automount_token: automount,
                            secrets_count,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn analyze_rbac(&self, assessment: &KubeRbacAssessment) -> Vec<RbacFinding> {
        let mut findings = Vec::new();

        // Check for cluster-admin bindings
        for binding in &assessment.bindings {
            if binding.role_ref == "cluster-admin" {
                findings.push(RbacFinding {
                    title: format!("cluster-admin role bound to subjects in {}", binding.namespace),
                    description: format!(
                        "The cluster-admin role grants full control over every resource. Subjects: {}",
                        binding.subjects.join(", ")
                    ),
                    severity: ContainerSeverity::High,
                    subject: binding.subjects.join(", "),
                    recommendation: "Use more restrictive roles with only required permissions.".to_string(),
                });
            }
        }

        // Check for wildcard permissions
        for role in &assessment.cluster_roles {
            for rule in &role.rules {
                if rule.verbs.contains(&"*".to_string())
                    && rule.resources.contains(&"*".to_string())
                    && rule.api_groups.contains(&"*".to_string())
                {
                    findings.push(RbacFinding {
                        title: format!("ClusterRole '{}' has wildcard permissions", role.name),
                        description: "Full wildcard access to all resources and verbs grants excessive privileges.".to_string(),
                        severity: ContainerSeverity::High,
                        subject: role.name.clone(),
                        recommendation: "Replace wildcard permissions with specific resource and verb combinations.".to_string(),
                    });
                }
            }
        }

        // Check for service accounts with automount
        let sa_with_automount: Vec<&KubeServiceAccount> = assessment
            .service_accounts
            .iter()
            .filter(|sa| sa.automount_token)
            .collect();

        if !sa_with_automount.is_empty() {
            findings.push(RbacFinding {
                title: format!("{} service accounts auto-mount API tokens", sa_with_automount.len()),
                description: "Service accounts that auto-mount tokens can expose API credentials to compromised pods.".to_string(),
                severity: ContainerSeverity::Low,
                subject: sa_with_automount.iter().map(|sa| sa.name.as_str()).collect::<Vec<_>>().join(", "),
                recommendation: "Set automountServiceAccountToken: false on service accounts and pods that don't need API access.".to_string(),
            });
        }

        // Check for secrets access
        for role in &assessment.roles {
            for rule in &role.rules {
                if rule.resources.contains(&"secrets".to_string())
                    && (rule.verbs.contains(&"get".to_string())
                        || rule.verbs.contains(&"*".to_string()))
                {
                    findings.push(RbacFinding {
                        title: format!("Role '{}' in namespace '{}' can read secrets", role.name, role.namespace),
                        description: "Roles with secrets access can read sensitive credentials and certificates.".to_string(),
                        severity: ContainerSeverity::Medium,
                        subject: format!("{}/{}", role.namespace, role.name),
                        recommendation: "Restrict secrets access to only specific resource names when possible.".to_string(),
                    });
                }
            }
        }

        findings
    }

    /// Perform security assessment on collected Kubernetes data
    pub fn assess_security(&self, results: &KubernetesResults) -> Vec<KubeSecurityFinding> {
        let mut findings = Vec::new();

        // Check pod security
        for pod in &results.pods {
            findings.extend(self.assess_pod_security(pod));
        }

        // Check deployment security
        for deployment in &results.deployments {
            findings.extend(self.assess_deployment_security(deployment));
        }

        // Check service security
        for service in &results.services {
            findings.extend(self.assess_service_security(service));
        }

        // Add RBAC findings
        if let Some(ref rbac) = results.rbac_assessment {
            for rbac_finding in &rbac.findings {
                findings.push(KubeSecurityFinding {
                    title: rbac_finding.title.clone(),
                    description: rbac_finding.description.clone(),
                    severity: rbac_finding.severity,
                    category: "rbac".to_string(),
                    namespace: String::new(),
                    resource: rbac_finding.subject.clone(),
                    recommendation: rbac_finding.recommendation.clone(),
                });
            }
        }

        findings
    }

    fn assess_pod_security(&self, pod: &KubePod) -> Vec<KubeSecurityFinding> {
        let mut findings = Vec::new();

        // Check host namespaces
        if pod.host_network {
            findings.push(KubeSecurityFinding {
                title: format!("Pod '{}' in '{}' shares host network namespace", pod.name, pod.namespace),
                description: "Pods with hostNetwork can access all host network interfaces and sniff traffic.".to_string(),
                severity: ContainerSeverity::High,
                category: "pod".to_string(),
                namespace: pod.namespace.clone(),
                resource: pod.name.clone(),
                recommendation: "Remove hostNetwork: true and use Services for network communication.".to_string(),
            });
        }

        if pod.host_pid {
            findings.push(KubeSecurityFinding {
                title: format!(
                    "Pod '{}' in '{}' shares host PID namespace",
                    pod.name, pod.namespace
                ),
                description: "Pods with hostPID can see and signal all processes on the host."
                    .to_string(),
                severity: ContainerSeverity::High,
                category: "pod".to_string(),
                namespace: pod.namespace.clone(),
                resource: pod.name.clone(),
                recommendation: "Remove hostPID: true to maintain process isolation.".to_string(),
            });
        }

        // Check privileged containers
        for container in &pod.containers {
            if container.security_context.privileged {
                findings.push(KubeSecurityFinding {
                    title: format!("Container '{}' in pod '{}' is privileged", container.name, pod.name),
                    description: "Privileged containers have full access to the host, bypassing all security boundaries.".to_string(),
                    severity: ContainerSeverity::Critical,
                    category: "container".to_string(),
                    namespace: pod.namespace.clone(),
                    resource: format!("{}/{}", pod.name, container.name),
                    recommendation: "Remove privileged: true and use specific capabilities instead.".to_string(),
                });
            }

            // Check privilege escalation
            if container.security_context.allow_privilege_escalation {
                findings.push(KubeSecurityFinding {
                    title: format!("Container '{}' allows privilege escalation", container.name),
                    description: "allowPrivilegeEscalation allows child processes to gain more privileges than parent.".to_string(),
                    severity: ContainerSeverity::Medium,
                    category: "container".to_string(),
                    namespace: pod.namespace.clone(),
                    resource: format!("{}/{}", pod.name, container.name),
                    recommendation: "Set allowPrivilegeEscalation: false in the container security context.".to_string(),
                });
            }

            // Check read-only root filesystem
            if !container.security_context.read_only_root_fs {
                findings.push(KubeSecurityFinding {
                    title: format!("Container '{}' has writable root filesystem", container.name),
                    description: "Writable root filesystems allow attackers to modify binaries and install malware.".to_string(),
                    severity: ContainerSeverity::Low,
                    category: "container".to_string(),
                    namespace: pod.namespace.clone(),
                    resource: format!("{}/{}", pod.name, container.name),
                    recommendation: "Set readOnlyRootFilesystem: true and use emptyDir volumes for writable paths.".to_string(),
                });
            }

            // Check resource limits
            if container.resources.memory_limit.is_none() {
                findings.push(KubeSecurityFinding {
                    title: format!("Container '{}' has no memory limit", container.name),
                    description: "Containers without memory limits can cause OOM conditions affecting other workloads.".to_string(),
                    severity: ContainerSeverity::Medium,
                    category: "container".to_string(),
                    namespace: pod.namespace.clone(),
                    resource: format!("{}/{}", pod.name, container.name),
                    recommendation: "Set memory limits in the container resources specification.".to_string(),
                });
            }

            if container.resources.cpu_limit.is_none() {
                findings.push(KubeSecurityFinding {
                    title: format!("Container '{}' has no CPU limit", container.name),
                    description: "Containers without CPU limits can monopolize node resources."
                        .to_string(),
                    severity: ContainerSeverity::Low,
                    category: "container".to_string(),
                    namespace: pod.namespace.clone(),
                    resource: format!("{}/{}", pod.name, container.name),
                    recommendation: "Set CPU limits in the container resources specification."
                        .to_string(),
                });
            }

            // Check for latest tag
            if container.image.ends_with(":latest") || !container.image.contains(':') {
                findings.push(KubeSecurityFinding {
                    title: format!("Container '{}' uses 'latest' tag", container.name),
                    description: "Using 'latest' tag makes deployments non-reproducible and can introduce unexpected changes.".to_string(),
                    severity: ContainerSeverity::Low,
                    category: "container".to_string(),
                    namespace: pod.namespace.clone(),
                    resource: format!("{}/{}", pod.name, container.name),
                    recommendation: "Use specific image tags or digests for reproducible deployments.".to_string(),
                });
            }

            // Check for missing probes
            if !container.liveness_probe {
                findings.push(KubeSecurityFinding {
                    title: format!("Container '{}' has no liveness probe", container.name),
                    description: "Without liveness probes, failed containers won't be automatically restarted.".to_string(),
                    severity: ContainerSeverity::Low,
                    category: "container".to_string(),
                    namespace: pod.namespace.clone(),
                    resource: format!("{}/{}", pod.name, container.name),
                    recommendation: "Add a liveness probe to detect and restart unhealthy containers.".to_string(),
                });
            }

            // Check for sensitive env vars
            let sensitive_patterns = ["PASSWORD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY"];
            for env in &container.env_vars {
                for pattern in &sensitive_patterns {
                    if env.to_uppercase().contains(pattern) {
                        findings.push(KubeSecurityFinding {
                            title: format!("Container '{}' has sensitive env var", container.name),
                            description: format!("Environment variable matching '{}' pattern found. Secrets in env vars can be exposed via kubectl describe.", pattern),
                            severity: ContainerSeverity::Medium,
                            category: "container".to_string(),
                            namespace: pod.namespace.clone(),
                            resource: format!("{}/{}", pod.name, container.name),
                            recommendation: "Use Kubernetes Secrets mounted as volumes instead of environment variables.".to_string(),
                        });
                        break;
                    }
                }
            }
        }

        // Check for host path volumes
        for volume in &pod.volumes {
            if volume.volume_type == "hostPath" {
                let severity = match volume.host_path.as_deref() {
                    Some("/") | Some("/etc") | Some("/var/run") => ContainerSeverity::Critical,
                    Some("/proc") | Some("/sys") | Some("/dev") => ContainerSeverity::High,
                    _ => ContainerSeverity::Medium,
                };
                findings.push(KubeSecurityFinding {
                    title: format!(
                        "Pod '{}' mounts host path: {:?}",
                        pod.name, volume.host_path
                    ),
                    description: format!(
                        "Host path volume '{}' mounts {} from the host.",
                        volume.name,
                        volume.host_path.as_deref().unwrap_or("unknown")
                    ),
                    severity,
                    category: "volume".to_string(),
                    namespace: pod.namespace.clone(),
                    resource: pod.name.clone(),
                    recommendation:
                        "Use PersistentVolumeClaims or emptyDir instead of hostPath mounts."
                            .to_string(),
                });
            }
        }

        // Check for default service account
        if pod.service_account == "default" {
            findings.push(KubeSecurityFinding {
                title: format!("Pod '{}' uses default service account", pod.name),
                description: "The default service account is automatically mounted and may have excessive permissions.".to_string(),
                severity: ContainerSeverity::Low,
                category: "pod".to_string(),
                namespace: pod.namespace.clone(),
                resource: pod.name.clone(),
                recommendation: "Create a dedicated service account with minimal required permissions.".to_string(),
            });
        }

        findings
    }

    fn assess_deployment_security(&self, deployment: &KubeDeployment) -> Vec<KubeSecurityFinding> {
        let mut findings = Vec::new();

        // Check for automount SA token
        if deployment.pod_template.automount_sa_token {
            findings.push(KubeSecurityFinding {
                title: format!("Deployment '{}' auto-mounts service account token", deployment.name),
                description: "Auto-mounted tokens can be used by attackers to access the Kubernetes API if a pod is compromised.".to_string(),
                severity: ContainerSeverity::Low,
                category: "deployment".to_string(),
                namespace: deployment.namespace.clone(),
                resource: deployment.name.clone(),
                recommendation: "Set automountServiceAccountToken: false in the pod spec if API access is not needed.".to_string(),
            });
        }

        findings
    }

    fn assess_service_security(&self, service: &KubeService) -> Vec<KubeSecurityFinding> {
        let mut findings = Vec::new();

        // Check for NodePort services
        if service.service_type == "NodePort" {
            findings.push(KubeSecurityFinding {
                title: format!("Service '{}' uses NodePort type", service.name),
                description: "NodePort services expose ports directly on all cluster nodes, increasing the attack surface.".to_string(),
                severity: ContainerSeverity::Medium,
                category: "service".to_string(),
                namespace: service.namespace.clone(),
                resource: service.name.clone(),
                recommendation: "Use ClusterIP with an Ingress controller instead of NodePort.".to_string(),
            });
        }

        // Check for LoadBalancer services
        if service.service_type == "LoadBalancer" {
            findings.push(KubeSecurityFinding {
                title: format!("Service '{}' uses LoadBalancer type", service.name),
                description: "LoadBalancer services create external endpoints that may be publicly accessible.".to_string(),
                severity: ContainerSeverity::Low,
                category: "service".to_string(),
                namespace: service.namespace.clone(),
                resource: service.name.clone(),
                recommendation: "Ensure LoadBalancer services have appropriate firewall rules or use internal load balancers.".to_string(),
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kube_config_default() {
        let config = KubeConfig::default();
        assert!(config.kubeconfig.is_none());
        assert!(config.context.is_none());
        assert!(config.namespace.is_none());
        assert!(config.check_rbac);
        assert!(config.check_network_policies);
        assert!(config.check_pod_security);
        assert!(config.check_secrets);
        assert_eq!(config.timeout_seconds, 30);
    }

    #[test]
    fn test_kube_scanner_creation() {
        let scanner = KubernetesScanner::with_default();
        assert!(scanner.config.kubeconfig.is_none());
    }

    #[test]
    fn test_kubernetes_results_default() {
        let results = KubernetesResults::default();
        assert!(results.pods.is_empty());
        assert!(results.services.is_empty());
        assert!(results.deployments.is_empty());
        assert!(results.security_findings.is_empty());
        assert!(!results.is_accessible);
    }

    #[test]
    fn test_assess_privileged_pod() {
        let scanner = KubernetesScanner::with_default();
        let pod = KubePod {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            containers: vec![KubeContainer {
                name: "test-container".to_string(),
                security_context: ContainerSecurityContext {
                    privileged: true,
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let findings = scanner.assess_pod_security(&pod);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Critical && f.title.contains("privileged")));
    }

    #[test]
    fn test_assess_host_network_pod() {
        let scanner = KubernetesScanner::with_default();
        let pod = KubePod {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            host_network: true,
            ..Default::default()
        };
        let findings = scanner.assess_pod_security(&pod);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::High && f.title.contains("network")));
    }

    #[test]
    fn test_assess_host_pid_pod() {
        let scanner = KubernetesScanner::with_default();
        let pod = KubePod {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            host_pid: true,
            ..Default::default()
        };
        let findings = scanner.assess_pod_security(&pod);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::High && f.title.contains("PID")));
    }

    #[test]
    fn test_assess_default_service_account() {
        let scanner = KubernetesScanner::with_default();
        let pod = KubePod {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            service_account: "default".to_string(),
            ..Default::default()
        };
        let findings = scanner.assess_pod_security(&pod);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Low
                && f.title.contains("default service account")));
    }

    #[test]
    fn test_assess_host_path_volume() {
        let scanner = KubernetesScanner::with_default();
        let pod = KubePod {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            volumes: vec![KubeVolumeMount {
                name: "host-vol".to_string(),
                mount_path: "/host".to_string(),
                volume_type: "hostPath".to_string(),
                read_only: false,
                host_path: Some("/etc".to_string()),
            }],
            ..Default::default()
        };
        let findings = scanner.assess_pod_security(&pod);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Critical && f.title.contains("host path")));
    }

    #[test]
    fn test_assess_nodeport_service() {
        let scanner = KubernetesScanner::with_default();
        let service = KubeService {
            name: "test-svc".to_string(),
            namespace: "default".to_string(),
            service_type: "NodePort".to_string(),
            ..Default::default()
        };
        let findings = scanner.assess_service_security(&service);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Medium && f.title.contains("NodePort")));
    }

    #[test]
    fn test_assess_loadbalancer_service() {
        let scanner = KubernetesScanner::with_default();
        let service = KubeService {
            name: "test-svc".to_string(),
            namespace: "default".to_string(),
            service_type: "LoadBalancer".to_string(),
            ..Default::default()
        };
        let findings = scanner.assess_service_security(&service);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Low && f.title.contains("LoadBalancer")));
    }

    #[test]
    fn test_assess_no_memory_limit() {
        let scanner = KubernetesScanner::with_default();
        let pod = KubePod {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            containers: vec![KubeContainer {
                name: "test-container".to_string(),
                resources: ContainerResources {
                    memory_limit: None,
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let findings = scanner.assess_pod_security(&pod);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Medium && f.title.contains("memory limit")));
    }

    #[test]
    fn test_assess_latest_tag() {
        let scanner = KubernetesScanner::with_default();
        let pod = KubePod {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            containers: vec![KubeContainer {
                name: "test-container".to_string(),
                image: "nginx:latest".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let findings = scanner.assess_pod_security(&pod);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Low && f.title.contains("latest")));
    }

    #[test]
    fn test_assess_deployment_automount() {
        let scanner = KubernetesScanner::with_default();
        let deployment = KubeDeployment {
            name: "test-deploy".to_string(),
            namespace: "default".to_string(),
            pod_template: PodTemplateSpec {
                automount_sa_token: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let findings = scanner.assess_deployment_security(&deployment);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Low && f.title.contains("auto-mounts")));
    }

    #[test]
    fn test_assess_privilege_escalation() {
        let scanner = KubernetesScanner::with_default();
        let pod = KubePod {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            containers: vec![KubeContainer {
                name: "test-container".to_string(),
                security_context: ContainerSecurityContext {
                    allow_privilege_escalation: true,
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let findings = scanner.assess_pod_security(&pod);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Medium
                && f.title.contains("privilege escalation")));
    }

    #[test]
    fn test_assess_writable_root_fs() {
        let scanner = KubernetesScanner::with_default();
        let pod = KubePod {
            name: "test-pod".to_string(),
            namespace: "default".to_string(),
            containers: vec![KubeContainer {
                name: "test-container".to_string(),
                security_context: ContainerSecurityContext {
                    read_only_root_fs: false,
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let findings = scanner.assess_pod_security(&pod);
        assert!(findings
            .iter()
            .any(|f| f.severity == ContainerSeverity::Low && f.title.contains("writable root")));
    }

    #[test]
    fn test_parse_rules() {
        let rules_json = serde_json::json!([
            {
                "apiGroups": [""],
                "resources": ["pods"],
                "verbs": ["get", "list", "watch"]
            }
        ]);
        let rules = KubernetesScanner::parse_rules(&rules_json);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].resources, vec!["pods"]);
        assert_eq!(rules[0].verbs.len(), 3);
    }
}
