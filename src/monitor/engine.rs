use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::time::interval;

/// Continuous monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub name: String,
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub interval_seconds: u64,
    pub alert_on_changes: bool,
    pub enable_service_detection: bool,
    pub enable_vuln_check: bool,
}

/// Monitoring session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSession {
    pub id: String,
    pub config: MonitorConfig,
    pub status: MonitorStatus,
    pub created_at: DateTime<Utc>,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub next_scan_at: Option<DateTime<Utc>>,
    pub scan_count: usize,
    pub changes_detected: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MonitorStatus {
    Running,
    Paused,
    Stopped,
}

/// Detected change between scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeDetection {
    pub timestamp: DateTime<Utc>,
    pub target: String,
    pub change_type: ChangeType,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    NewPort,
    ClosedPort,
    ServiceChanged,
    NewVulnerability,
    HostDown,
    HostUp,
}

/// Historical scan snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanSnapshot {
    timestamp: DateTime<Utc>,
    open_ports: HashMap<IpAddr, Vec<u16>>,
    services: HashMap<IpAddr, HashMap<u16, String>>,
}

/// Continuous monitoring engine
pub struct MonitorEngine {
    sessions: HashMap<String, MonitorSession>,
    history: HashMap<String, Vec<ScanSnapshot>>,
    max_history_per_session: usize,
}

impl MonitorEngine {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            history: HashMap::new(),
            max_history_per_session: 100,
        }
    }

    /// Create a new monitoring session
    pub fn create_session(&mut self, config: MonitorConfig) -> String {
        let session_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        
        let session = MonitorSession {
            id: session_id.clone(),
            config: config.clone(),
            status: MonitorStatus::Running,
            created_at: now,
            last_scan_at: None,
            next_scan_at: Some(now),
            scan_count: 0,
            changes_detected: 0,
        };

        self.sessions.insert(session_id.clone(), session);
        self.history.insert(session_id.clone(), Vec::new());

        session_id
    }

    /// Start monitoring loop for a session
    pub async fn start_monitoring(&mut self, session_id: &str) -> Result<()> {
        {
            let session = self
                .sessions
                .get_mut(session_id)
                .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

            if session.status != MonitorStatus::Stopped {
                session.status = MonitorStatus::Running;
            }
        }

        let interval_seconds = {
            let session = self.sessions.get(session_id)
                .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
            session.config.interval_seconds
        };

        let interval_duration = Duration::from_secs(interval_seconds);
        let mut ticker = interval(interval_duration);

        loop {
            ticker.tick().await;

            // Check if session still exists and is running
            let should_continue = {
                if let Some(session) = self.sessions.get(session_id) {
                    session.status == MonitorStatus::Running
                } else {
                    false
                }
            };

            if !should_continue {
                break;
            }

            // Perform scan
            self.execute_scan(session_id).await?;

            // Check for changes
            let changes = self.detect_changes(session_id)?;
            
            let alert_on_changes = {
                self.sessions.get(session_id)
                    .map(|s| s.config.alert_on_changes)
                    .unwrap_or(false)
            };

            if !changes.is_empty() && alert_on_changes {
                self.handle_changes(session_id, changes).await?;
            }

            // Update session
            if let Some(session) = self.sessions.get_mut(session_id) {
                session.last_scan_at = Some(Utc::now());
                session.next_scan_at = Some(Utc::now() + chrono::Duration::seconds(interval_seconds as i64));
                session.scan_count += 1;
            }
        }

        Ok(())
    }

    /// Execute a scan for a monitoring session
    async fn execute_scan(&mut self, session_id: &str) -> Result<()> {
        // In a real implementation, this would:
        // 1. Call the actual scanner with the configured targets/ports
        // 2. Collect results
        // 3. Store snapshot in history
        
        // For now, simulate with a snapshot
        let snapshot = ScanSnapshot {
            timestamp: Utc::now(),
            open_ports: HashMap::new(),
            services: HashMap::new(),
        };

        self.add_snapshot(session_id, snapshot)?;
        Ok(())
    }

    /// Add a snapshot to history
    fn add_snapshot(&mut self, session_id: &str, snapshot: ScanSnapshot) -> Result<()> {
        let history = self
            .history
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("History not found"))?;

        history.push(snapshot);

        // Maintain max history size
        if history.len() > self.max_history_per_session {
            history.remove(0);
        }

        Ok(())
    }

    /// Detect changes between last two scans
    fn detect_changes(&self, session_id: &str) -> Result<Vec<ChangeDetection>> {
        let history = self
            .history
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("History not found"))?;

        if history.len() < 2 {
            return Ok(Vec::new());
        }

        let previous = &history[history.len() - 2];
        let current = &history[history.len() - 1];
        let mut changes = Vec::new();

        // Compare open ports
        for (ip, current_ports) in &current.open_ports {
            let previous_ports = previous.open_ports.get(ip);
            
            if let Some(prev_ports) = previous_ports {
                // Detect new ports
                for port in current_ports {
                    if !prev_ports.contains(port) {
                        changes.push(ChangeDetection {
                            timestamp: current.timestamp,
                            target: ip.to_string(),
                            change_type: ChangeType::NewPort,
                            details: format!("New port {} opened", port),
                        });
                    }
                }

                // Detect closed ports
                for port in prev_ports {
                    if !current_ports.contains(port) {
                        changes.push(ChangeDetection {
                            timestamp: current.timestamp,
                            target: ip.to_string(),
                            change_type: ChangeType::ClosedPort,
                            details: format!("Port {} closed", port),
                        });
                    }
                }
            } else {
                // Host came online
                changes.push(ChangeDetection {
                    timestamp: current.timestamp,
                    target: ip.to_string(),
                    change_type: ChangeType::HostUp,
                    details: format!("Host came online with {} open port(s)", current_ports.len()),
                });
            }
        }

        // Detect hosts that went offline
        for (ip, _) in &previous.open_ports {
            if !current.open_ports.contains_key(ip) {
                changes.push(ChangeDetection {
                    timestamp: current.timestamp,
                    target: ip.to_string(),
                    change_type: ChangeType::HostDown,
                    details: "Host went offline".to_string(),
                });
            }
        }

        Ok(changes)
    }

    /// Handle detected changes (alerting, logging, etc.)
    async fn handle_changes(&mut self, session_id: &str, changes: Vec<ChangeDetection>) -> Result<()> {
        // In production, this would:
        // - Send alerts via email/Slack/webhook
        // - Log to database
        // - Trigger automated responses
        
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.changes_detected += changes.len();
        }

        // For now, just log
        for change in changes {
            println!(
                "[{}] Change detected: {} - {} - {}",
                change.timestamp, change.target, change.change_type as u8, change.details
            );
        }

        Ok(())
    }

    /// Pause a monitoring session
    pub fn pause_session(&mut self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

        session.status = MonitorStatus::Paused;
        Ok(())
    }

    /// Resume a paused session
    pub fn resume_session(&mut self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

        if session.status == MonitorStatus::Paused {
            session.status = MonitorStatus::Running;
        }

        Ok(())
    }

    /// Stop a monitoring session
    pub fn stop_session(&mut self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

        session.status = MonitorStatus::Stopped;
        Ok(())
    }

    /// Get session status
    pub fn get_session(&self, session_id: &str) -> Option<&MonitorSession> {
        self.sessions.get(session_id)
    }

    /// List all sessions
    pub fn list_sessions(&self) -> Vec<&MonitorSession> {
        self.sessions.values().collect()
    }

    /// Get change history for a session
    pub fn get_changes(&self, session_id: &str) -> Result<Vec<ChangeDetection>> {
        let _history = self
            .history
            .get(session_id)
            .ok_or_else(|| anyhow::anyhow!("History not found"))?;

        // Extract all changes from snapshots
        // This is simplified - in production would track changes explicitly
        Ok(Vec::new())
    }

    /// Delete a session
    pub fn delete_session(&mut self, session_id: &str) -> Result<()> {
        self.sessions
            .remove(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        self.history.remove(session_id);
        Ok(())
    }
}

impl Default for MonitorEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_session() {
        let mut engine = MonitorEngine::new();
        let config = MonitorConfig {
            name: "Test Monitor".to_string(),
            targets: vec!["192.168.1.1".to_string()],
            ports: vec![80, 443],
            interval_seconds: 60,
            alert_on_changes: true,
            enable_service_detection: false,
            enable_vuln_check: false,
        };

        let session_id = engine.create_session(config);
        assert!(engine.get_session(&session_id).is_some());
        
        let session = engine.get_session(&session_id).unwrap();
        assert_eq!(session.status, MonitorStatus::Running);
        assert_eq!(session.scan_count, 0);
    }

    #[test]
    fn test_pause_resume_session() {
        let mut engine = MonitorEngine::new();
        let config = MonitorConfig {
            name: "Test".to_string(),
            targets: vec!["192.168.1.1".to_string()],
            ports: vec![80],
            interval_seconds: 60,
            alert_on_changes: false,
            enable_service_detection: false,
            enable_vuln_check: false,
        };

        let session_id = engine.create_session(config);
        
        engine.pause_session(&session_id).unwrap();
        assert_eq!(engine.get_session(&session_id).unwrap().status, MonitorStatus::Paused);

        engine.resume_session(&session_id).unwrap();
        assert_eq!(engine.get_session(&session_id).unwrap().status, MonitorStatus::Running);
    }

    #[test]
    fn test_stop_session() {
        let mut engine = MonitorEngine::new();
        let config = MonitorConfig {
            name: "Test".to_string(),
            targets: vec!["192.168.1.1".to_string()],
            ports: vec![80],
            interval_seconds: 60,
            alert_on_changes: false,
            enable_service_detection: false,
            enable_vuln_check: false,
        };

        let session_id = engine.create_session(config);
        engine.stop_session(&session_id).unwrap();
        assert_eq!(engine.get_session(&session_id).unwrap().status, MonitorStatus::Stopped);
    }

    #[test]
    fn test_list_sessions() {
        let mut engine = MonitorEngine::new();
        let config = MonitorConfig {
            name: "Test".to_string(),
            targets: vec!["192.168.1.1".to_string()],
            ports: vec![80],
            interval_seconds: 60,
            alert_on_changes: false,
            enable_service_detection: false,
            enable_vuln_check: false,
        };

        engine.create_session(config.clone());
        engine.create_session(config);

        let sessions = engine.list_sessions();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_delete_session() {
        let mut engine = MonitorEngine::new();
        let config = MonitorConfig {
            name: "Test".to_string(),
            targets: vec!["192.168.1.1".to_string()],
            ports: vec![80],
            interval_seconds: 60,
            alert_on_changes: false,
            enable_service_detection: false,
            enable_vuln_check: false,
        };

        let session_id = engine.create_session(config);
        engine.delete_session(&session_id).unwrap();
        assert!(engine.get_session(&session_id).is_none());
    }
}
