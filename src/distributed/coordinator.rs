use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use uuid::Uuid;

/// Distributed scanning coordinator for multi-node deployments
#[allow(dead_code)]
pub struct ScanCoordinator {
    nodes: HashMap<Uuid, ScanNode>,
    job_queue: Vec<ScanJob>,
    completed_jobs: Vec<CompletedJob>,
    max_concurrent_per_node: usize,
}

/// Represents a scanning node in the distributed cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanNode {
    pub id: Uuid,
    pub address: SocketAddr,
    pub status: NodeStatus,
    pub active_jobs: usize,
    pub completed_jobs: usize,
    pub capabilities: NodeCapabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    Online,
    Busy,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub max_concurrent_scans: usize,
    pub supports_syn_scan: bool,
    pub supports_udp_scan: bool,
    pub supports_ipv6: bool,
}

/// A unit of work to be distributed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub job_id: Uuid,
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub scan_type: ScanType,
    pub assigned_to: Option<Uuid>,
    pub status: JobStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    Tcp,
    Udp,
    Syn,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Pending,
    Assigned,
    Running,
    Completed,
    Failed,
}

/// Completed job with results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedJob {
    pub job_id: Uuid,
    pub node_id: Uuid,
    pub targets_scanned: usize,
    pub ports_scanned: usize,
    pub open_ports_found: usize,
    pub duration_ms: u64,
}

impl ScanCoordinator {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            job_queue: Vec::new(),
            completed_jobs: Vec::new(),
            max_concurrent_per_node: 5,
        }
    }

    /// Register a new scanning node
    pub fn register_node(&mut self, address: SocketAddr, capabilities: NodeCapabilities) -> Uuid {
        let node_id = Uuid::new_v4();
        let node = ScanNode {
            id: node_id,
            address,
            status: NodeStatus::Online,
            active_jobs: 0,
            completed_jobs: 0,
            capabilities,
        };

        self.nodes.insert(node_id, node);
        node_id
    }

    /// Unregister a node
    pub fn unregister_node(&mut self, node_id: &Uuid) -> Result<()> {
        self.nodes
            .remove(node_id)
            .ok_or_else(|| anyhow::anyhow!("Node not found"))?;

        // Reassign any jobs from this node
        for job in &mut self.job_queue {
            if job.assigned_to == Some(*node_id) {
                job.assigned_to = None;
                job.status = JobStatus::Pending;
            }
        }

        Ok(())
    }

    /// Submit a large scan to be distributed
    pub fn submit_scan(
        &mut self,
        targets: Vec<String>,
        ports: Vec<u16>,
        scan_type: ScanType,
    ) -> Vec<Uuid> {
        // Split targets into chunks for distribution
        let chunk_size = (targets.len() / self.nodes.len().max(1)).max(1);
        let mut job_ids = Vec::new();

        for target_chunk in targets.chunks(chunk_size) {
            let job_id = Uuid::new_v4();
            let job = ScanJob {
                job_id,
                targets: target_chunk.to_vec(),
                ports: ports.clone(),
                scan_type: scan_type.clone(),
                assigned_to: None,
                status: JobStatus::Pending,
            };

            job_ids.push(job_id);
            self.job_queue.push(job);
        }

        job_ids
    }

    /// Assign pending jobs to available nodes
    pub fn assign_jobs(&mut self) -> Result<usize> {
        let mut assigned_count = 0;
        let mut node_loads: HashMap<Uuid, usize> = HashMap::new();

        // Initialize node loads
        for (id, node) in &self.nodes {
            node_loads.insert(*id, node.active_jobs);
        }

        // Collect pending jobs with their scan types
        let pending_jobs: Vec<(usize, ScanType)> = self.job_queue
            .iter()
            .enumerate()
            .filter(|(_, job)| job.status == JobStatus::Pending)
            .map(|(idx, job)| (idx, job.scan_type.clone()))
            .collect();

        // Assign jobs one by one, respecting capacity
        for (job_idx, scan_type) in pending_jobs {
            // Find available node ID with current loads
            if let Some(node_id) = self.find_available_node_with_loads(&scan_type, &node_loads) {
                if let Some(job) = self.job_queue.get_mut(job_idx) {
                    job.assigned_to = Some(node_id);
                    job.status = JobStatus::Assigned;
                    assigned_count += 1;

                    // Update temporary load
                    *node_loads.get_mut(&node_id).unwrap() += 1;
                }
            }
        }

        // Apply the assignments to actual nodes
        for (node_id, load) in node_loads {
            if let Some(node) = self.nodes.get_mut(&node_id) {
                node.active_jobs = load;
                if node.active_jobs >= node.capabilities.max_concurrent_scans {
                    node.status = NodeStatus::Busy;
                } else if node.status != NodeStatus::Offline {
                    node.status = NodeStatus::Online;
                }
            }
        }

        Ok(assigned_count)
    }

    /// Find an available node ID considering current loads
    fn find_available_node_with_loads(&self, scan_type: &ScanType, loads: &HashMap<Uuid, usize>) -> Option<Uuid> {
        let supports_scan = |node: &ScanNode| -> bool {
            match scan_type {
                ScanType::Syn => node.capabilities.supports_syn_scan,
                ScanType::Udp => node.capabilities.supports_udp_scan,
                ScanType::Tcp | ScanType::Full => true,
            }
        };

        self.nodes
            .values()
            .filter(|node| {
                let current_load = loads.get(&node.id).copied().unwrap_or(0);
                node.status != NodeStatus::Offline
                    && current_load < node.capabilities.max_concurrent_scans
                    && supports_scan(node)
            })
            .min_by_key(|node| loads.get(&node.id).copied().unwrap_or(0))
            .map(|node| node.id)
    }

    /// Check if node supports the scan type
    #[allow(dead_code)]
    fn node_supports_scan_type(&self, node: &ScanNode, scan_type: &ScanType) -> bool {
        match scan_type {
            ScanType::Syn => node.capabilities.supports_syn_scan,
            ScanType::Udp => node.capabilities.supports_udp_scan,
            ScanType::Tcp | ScanType::Full => true,
        }
    }

    /// Mark a job as completed
    pub fn complete_job(
        &mut self,
        job_id: &Uuid,
        targets_scanned: usize,
        ports_scanned: usize,
        open_ports_found: usize,
        duration_ms: u64,
    ) -> Result<()> {
        let job = self
            .job_queue
            .iter_mut()
            .find(|j| j.job_id == *job_id)
            .ok_or_else(|| anyhow::anyhow!("Job not found"))?;

        let node_id = job
            .assigned_to
            .ok_or_else(|| anyhow::anyhow!("Job not assigned"))?;

        job.status = JobStatus::Completed;

        // Update node stats
        if let Some(node) = self.nodes.get_mut(&node_id) {
            node.active_jobs = node.active_jobs.saturating_sub(1);
            node.completed_jobs += 1;

            if node.active_jobs < node.capabilities.max_concurrent_scans {
                node.status = NodeStatus::Online;
            }
        }

        // Record completion
        self.completed_jobs.push(CompletedJob {
            job_id: *job_id,
            node_id,
            targets_scanned,
            ports_scanned,
            open_ports_found,
            duration_ms,
        });

        Ok(())
    }

    /// Mark a job as failed
    pub fn fail_job(&mut self, job_id: &Uuid) -> Result<()> {
        let job = self
            .job_queue
            .iter_mut()
            .find(|j| j.job_id == *job_id)
            .ok_or_else(|| anyhow::anyhow!("Job not found"))?;

        if let Some(node_id) = job.assigned_to {
            if let Some(node) = self.nodes.get_mut(&node_id) {
                node.active_jobs = node.active_jobs.saturating_sub(1);
                if node.active_jobs < node.capabilities.max_concurrent_scans {
                    node.status = NodeStatus::Online;
                }
            }
        }

        job.status = JobStatus::Failed;
        job.assigned_to = None;

        Ok(())
    }

    /// Get cluster statistics
    pub fn get_stats(&self) -> ClusterStats {
        let total_nodes = self.nodes.len();
        let online_nodes = self
            .nodes
            .values()
            .filter(|n| n.status != NodeStatus::Offline)
            .count();

        let pending_jobs = self
            .job_queue
            .iter()
            .filter(|j| j.status == JobStatus::Pending)
            .count();

        let running_jobs = self
            .job_queue
            .iter()
            .filter(|j| j.status == JobStatus::Running || j.status == JobStatus::Assigned)
            .count();

        ClusterStats {
            total_nodes,
            online_nodes,
            pending_jobs,
            running_jobs,
            completed_jobs: self.completed_jobs.len(),
        }
    }

    /// List all nodes
    pub fn list_nodes(&self) -> Vec<&ScanNode> {
        self.nodes.values().collect()
    }

    /// Get node by ID
    pub fn get_node(&self, node_id: &Uuid) -> Option<&ScanNode> {
        self.nodes.get(node_id)
    }

    /// Update node status
    pub fn update_node_status(&mut self, node_id: &Uuid, status: NodeStatus) -> Result<()> {
        let node = self
            .nodes
            .get_mut(node_id)
            .ok_or_else(|| anyhow::anyhow!("Node not found"))?;

        node.status = status;
        Ok(())
    }
}

impl Default for ScanCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Cluster statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterStats {
    pub total_nodes: usize,
    pub online_nodes: usize,
    pub pending_jobs: usize,
    pub running_jobs: usize,
    pub completed_jobs: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_node() -> (SocketAddr, NodeCapabilities) {
        let addr = "127.0.0.1:9000".parse().unwrap();
        let caps = NodeCapabilities {
            max_concurrent_scans: 3,
            supports_syn_scan: true,
            supports_udp_scan: true,
            supports_ipv6: true,
        };
        (addr, caps)
    }

    #[test]
    fn test_register_node() {
        let mut coordinator = ScanCoordinator::new();
        let (addr, caps) = create_test_node();
        
        let node_id = coordinator.register_node(addr, caps);
        assert!(coordinator.get_node(&node_id).is_some());
        
        let stats = coordinator.get_stats();
        assert_eq!(stats.total_nodes, 1);
        assert_eq!(stats.online_nodes, 1);
    }

    #[test]
    fn test_unregister_node() {
        let mut coordinator = ScanCoordinator::new();
        let (addr, caps) = create_test_node();
        
        let node_id = coordinator.register_node(addr, caps);
        coordinator.unregister_node(&node_id).unwrap();
        
        assert!(coordinator.get_node(&node_id).is_none());
        assert_eq!(coordinator.get_stats().total_nodes, 0);
    }

    #[test]
    fn test_submit_scan() {
        let mut coordinator = ScanCoordinator::new();
        let (addr, caps) = create_test_node();
        coordinator.register_node(addr, caps);
        
        let targets = vec!["192.168.1.1".to_string(), "192.168.1.2".to_string()];
        let ports = vec![80, 443];
        
        let job_ids = coordinator.submit_scan(targets, ports, ScanType::Tcp);
        assert!(!job_ids.is_empty());
        
        let stats = coordinator.get_stats();
        assert!(stats.pending_jobs > 0);
    }

    #[test]
    fn test_assign_jobs() {
        let mut coordinator = ScanCoordinator::new();
        let (addr, caps) = create_test_node();
        coordinator.register_node(addr, caps);
        
        let targets = vec!["192.168.1.1".to_string()];
        let ports = vec![80];
        
        coordinator.submit_scan(targets, ports, ScanType::Tcp);
        let assigned = coordinator.assign_jobs().unwrap();
        
        assert_eq!(assigned, 1);
        let stats = coordinator.get_stats();
        assert_eq!(stats.pending_jobs, 0);
        assert_eq!(stats.running_jobs, 1);
    }

    #[test]
    fn test_complete_job() {
        let mut coordinator = ScanCoordinator::new();
        let (addr, caps) = create_test_node();
        coordinator.register_node(addr, caps);
        
        let job_ids = coordinator.submit_scan(
            vec!["192.168.1.1".to_string()],
            vec![80],
            ScanType::Tcp,
        );
        
        coordinator.assign_jobs().unwrap();
        coordinator.complete_job(&job_ids[0], 1, 1, 1, 100).unwrap();
        
        let stats = coordinator.get_stats();
        assert_eq!(stats.completed_jobs, 1);
    }

    #[test]
    fn test_fail_job() {
        let mut coordinator = ScanCoordinator::new();
        let (addr, caps) = create_test_node();
        coordinator.register_node(addr, caps);
        
        let job_ids = coordinator.submit_scan(
            vec!["192.168.1.1".to_string()],
            vec![80],
            ScanType::Tcp,
        );
        
        coordinator.assign_jobs().unwrap();
        coordinator.fail_job(&job_ids[0]).unwrap();
        
        // Job should be marked as failed
        let job = coordinator.job_queue.iter().find(|j| j.job_id == job_ids[0]).unwrap();
        assert_eq!(job.status, JobStatus::Failed);
    }

    #[test]
    fn test_node_capacity() {
        let mut coordinator = ScanCoordinator::new();
        let addr = "127.0.0.1:9000".parse().unwrap();
        let caps = NodeCapabilities {
            max_concurrent_scans: 2,
            supports_syn_scan: true,
            supports_udp_scan: true,
            supports_ipv6: true,
        };
        
        coordinator.register_node(addr, caps);
        
        // Submit 3 jobs
        coordinator.submit_scan(vec!["192.168.1.1".to_string()], vec![80], ScanType::Tcp);
        coordinator.submit_scan(vec!["192.168.1.2".to_string()], vec![80], ScanType::Tcp);
        coordinator.submit_scan(vec!["192.168.1.3".to_string()], vec![80], ScanType::Tcp);
        
        coordinator.assign_jobs().unwrap();
        
        // Only 2 should be assigned (node capacity)
        let stats = coordinator.get_stats();
        assert_eq!(stats.running_jobs, 2);
        assert_eq!(stats.pending_jobs, 1);
    }
}
