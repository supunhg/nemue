use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::time::Instant;
use uuid::Uuid;

use super::models::*;
use super::webhooks::WebhookConfig;
use super::cicd::CiCdConfig;

pub struct AppState {
    scans: HashMap<Uuid, ScanInfo>,
    webhooks: HashMap<Uuid, WebhookConfig>,
    cicd_config: CiCdConfig,
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
            webhooks: HashMap::new(),
            cicd_config: CiCdConfig::default(),
            start_time: Instant::now(),
        }
    }

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

        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        });

        scan_id
    }

    pub fn get_scan_status(&self, scan_id: &Uuid) -> Option<ScanStatus> {
        self.scans.get(scan_id).map(|info| info.status.clone())
    }

    pub fn get_scan_results(&self, scan_id: &Uuid) -> Option<ScanResults> {
        self.scans
            .get(scan_id)
            .and_then(|info| info.results.clone())
    }

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

    pub fn delete_scan(&mut self, scan_id: &Uuid) -> Result<()> {
        self.scans
            .remove(scan_id)
            .ok_or_else(|| anyhow::anyhow!("Scan not found"))?;
        Ok(())
    }

    pub fn get_stats(&self) -> ScanStats {
        let mut total_targets = 0;
        let mut total_ports = 0;
        let mut active = 0;
        let mut completed = 0;
        let mut failed = 0;
        let mut cancelled = 0;

        for info in self.scans.values() {
            total_targets += info.request.targets.len();
            total_ports += info.request.ports.len();
            match info.status.status {
                ScanState::Queued | ScanState::Running => active += 1,
                ScanState::Completed => completed += 1,
                ScanState::Failed => failed += 1,
                ScanState::Cancelled => cancelled += 1,
            }
        }

        ScanStats {
            total_scans: self.scans.len(),
            active_scans: active,
            completed_scans: completed,
            failed_scans: failed,
            cancelled_scans: cancelled,
            total_targets_scanned: total_targets,
            total_ports_scanned: total_ports,
            uptime_seconds: self.uptime().as_secs(),
        }
    }

    pub fn register_webhook(&mut self, req: RegisterWebhookRequest) -> Uuid {
        let webhook_id = Uuid::new_v4();
        let config = WebhookConfig {
            url: req.url,
            provider: req.provider,
            secret: req.secret,
            max_retries: req.max_retries,
            retry_delay_ms: 1000,
            timeout_secs: 30,
        };
        self.webhooks.insert(webhook_id, config);
        webhook_id
    }

    pub fn list_webhooks(&self) -> Vec<WebhookInfo> {
        self.webhooks
            .iter()
            .map(|(id, config)| WebhookInfo {
                webhook_id: *id,
                url: config.url.clone(),
                provider: config.provider.clone(),
                events: vec!["scan.completed".to_string(), "scan.failed".to_string()],
                created_at: Utc::now(),
            })
            .collect()
    }

    pub fn delete_webhook(&mut self, webhook_id: &Uuid) -> Result<()> {
        self.webhooks
            .remove(webhook_id)
            .ok_or_else(|| anyhow::anyhow!("Webhook not found"))?;
        Ok(())
    }

    pub fn get_webhook_config(&self, webhook_id: &Uuid) -> Option<WebhookConfig> {
        self.webhooks.get(webhook_id).cloned()
    }

    pub fn get_cicd_config(&self) -> &CiCdConfig {
        &self.cicd_config
    }

    pub fn uptime(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    pub fn active_scans(&self) -> usize {
        self.scans
            .values()
            .filter(|s| s.status.status == ScanState::Running || s.status.status == ScanState::Queued)
            .count()
    }

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
