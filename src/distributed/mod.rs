pub mod coordinator;

pub use coordinator::{
    ScanCoordinator, ScanNode, NodeStatus, NodeCapabilities,
    ScanJob, ScanType, JobStatus, CompletedJob, ClusterStats,
};
