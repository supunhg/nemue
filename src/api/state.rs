use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

use super::models::*;

/// Application state for the API server
pub struct AppState {
    scans: HashMap<Uuid, ScanInfo>,
    start_time: Instant,
}

struct ScanInfo {
    request: ScanRequest,
    status: ScanStatus,
    results: Option<ScanResults>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            scans: HashMap::new(),
            start_time: Instant::now(),
        }
    }

    /// Create a new scan
    pub async fn create_scan(&mut self, request: ScanRequest) -> Uuid {
        let scan_id = Uuid::new_v4();
        let now = Utc::now();
        
        let status = ScanStatus {
            scan_id,
            status: ScanState::Queued,
            progress: 0.0,
            targets_total: request.targets.len(),
            targets_completed: 0,
            ports_total: request.ports.len(),
            ports_scanned: 0,
            started_at: now,
            updated_at: now,
            completed_at: None,
        };

        let scan_info = ScanInfo {
            request,
            status,
            results: None,
        };

        self.scans.insert(scan_id, scan_info);
        
        // In a real implementation, this would spawn a background task
        // to actually perform the scan
        tokio::spawn(async move {
            // Simulate scan execution
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        });

        scan_id
    }

    /// Get scan status
    pub fn get_scan_status(&self, scan_id: &Uuid) -> Option<ScanStatus> {
        self.scans.get(scan_id).map(|info| info.status.clone())
    }

    /// Get scan results
    pub fn get_scan_results(&self, scan_id: &Uuid) -> Option<ScanResults> {
        self.scans
            .get(scan_id)
            .and_then(|info| info.results.clone())
    }

    /// Cancel a running scan
    pub async fn cancel_scan(&mut self, scan_id: &Uuid) -> Result<()> {
        let scan = self
            .scans
            .get_mut(scan_id)
            .ok_or_else(|| anyhow::anyhow!("Scan not found"))?;

        if scan.status.status == ScanState::Completed {
            return Err(anyhow::anyhow!("Cannot cancel completed scan"));
        }

        scan.status.status = ScanState::Cancelled;
        scan.status.updated_at = Utc::now();
        scan.status.completed_at = Some(Utc::now());

        Ok(())
    }

    /// List all scans with pagination
    pub fn list_scans(&self, page: usize, per_page: usize) -> ScanListResponse {
        let total = self.scans.len();
        let skip = (page.saturating_sub(1)) * per_page;
        
        let scans: Vec<ScanSummary> = self
            .scans
            .values()
            .skip(skip)
            .take(per_page)
            .map(|info| ScanSummary {
                scan_id: info.status.scan_id,
                status: info.status.status.clone(),
                targets_count: info.request.targets.len(),
                ports_count: info.request.ports.len(),
                started_at: info.status.started_at,
                completed_at: info.status.completed_at,
            })
            .collect();

        ScanListResponse {
            scans,
            total,
            page,
            per_page,
        }
    }

    /// Delete a scan
    pub fn delete_scan(&mut self, scan_id: &Uuid) -> Result<()> {
        self.scans
            .remove(scan_id)
            .ok_or_else(|| anyhow::anyhow!("Scan not found"))?;
        Ok(())
    }

    /// Get server uptime
    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    /// Get count of active scans
    pub fn active_scans(&self) -> usize {
        self.scans
            .values()
            .filter(|s| s.status.status == ScanState::Running || s.status.status == ScanState::Queued)
            .count()
    }

    /// Get count of completed scans
    pub fn completed_scans(&self) -> usize {
        self.scans
            .values()
            .filter(|s| s.status.status == ScanState::Completed)
            .count()
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
