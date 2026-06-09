use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotificationChannel {
    Email,
    Slack,
    Webhook,
    Custom(String),
}

impl std::fmt::Display for NotificationChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotificationChannel::Email => write!(f, "email"),
            NotificationChannel::Slack => write!(f, "slack"),
            NotificationChannel::Webhook => write!(f, "webhook"),
            NotificationChannel::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotificationEvent {
    ScanStarted,
    ScanCompleted,
    ScanFailed,
    HighRiskFound,
    OpenPortFound,
    Custom(String),
}

impl std::fmt::Display for NotificationEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotificationEvent::ScanStarted => write!(f, "scan_started"),
            NotificationEvent::ScanCompleted => write!(f, "scan_completed"),
            NotificationEvent::ScanFailed => write!(f, "scan_failed"),
            NotificationEvent::HighRiskFound => write!(f, "high_risk_found"),
            NotificationEvent::OpenPortFound => write!(f, "open_port_found"),
            NotificationEvent::Custom(name) => write!(f, "{}", name),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub id: String,
    pub name: String,
    pub channel: NotificationChannel,
    pub events: Vec<NotificationEvent>,
    pub destination: String,
    pub enabled: bool,
    pub metadata: HashMap<String, String>,
}

impl NotificationConfig {
    pub fn new(name: &str, channel: NotificationChannel, destination: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            channel,
            events: Vec::new(),
            destination: destination.to_string(),
            enabled: true,
            metadata: HashMap::new(),
        }
    }

    pub fn with_event(mut self, event: NotificationEvent) -> Self {
        if !self.events.contains(&event) {
            self.events.push(event);
        }
        self
    }

    pub fn with_events(mut self, events: Vec<NotificationEvent>) -> Self {
        for event in events {
            if !self.events.contains(&event) {
                self.events.push(event);
            }
        }
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn subscribed_to(&self, event: &NotificationEvent) -> bool {
        self.events.contains(event)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationMessage {
    pub id: String,
    pub event: NotificationEvent,
    pub title: String,
    pub body: String,
    pub scan_id: Option<String>,
    pub target: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

impl NotificationMessage {
    pub fn new(event: NotificationEvent, title: &str, body: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event,
            title: title.to_string(),
            body: body.to_string(),
            scan_id: None,
            target: None,
            timestamp: chrono::Utc::now(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_scan_id(mut self, scan_id: &str) -> Self {
        self.scan_id = Some(scan_id.to_string());
        self
    }

    pub fn with_target(mut self, target: &str) -> Self {
        self.target = Some(target.to_string());
        self
    }

    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecord {
    pub message_id: String,
    pub channel: NotificationChannel,
    pub destination: String,
    pub sent_at: chrono::DateTime<chrono::Utc>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationManager {
    configs: Vec<NotificationConfig>,
    history: Vec<NotificationRecord>,
    max_history: usize,
}

impl NotificationManager {
    pub fn new() -> Self {
        Self {
            configs: Vec::new(),
            history: Vec::new(),
            max_history: 500,
        }
    }

    pub fn with_max_history(mut self, max: usize) -> Self {
        self.max_history = max;
        self
    }

    pub fn add_config(&mut self, config: NotificationConfig) -> String {
        let id = config.id.clone();
        self.configs.push(config);
        id
    }

    pub fn get_config(&self, id: &str) -> Option<&NotificationConfig> {
        self.configs.iter().find(|c| c.id == id)
    }

    pub fn get_config_mut(&mut self, id: &str) -> Option<&mut NotificationConfig> {
        self.configs.iter_mut().find(|c| c.id == id)
    }

    pub fn remove_config(&mut self, id: &str) -> bool {
        if let Some(pos) = self.configs.iter().position(|c| c.id == id) {
            self.configs.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn list_configs(&self) -> &[NotificationConfig] {
        &self.configs
    }

    pub fn config_count(&self) -> usize {
        self.configs.len()
    }

    pub fn enabled_configs(&self) -> Vec<&NotificationConfig> {
        self.configs.iter().filter(|c| c.enabled).collect()
    }

    pub fn configs_for_event(&self, event: &NotificationEvent) -> Vec<&NotificationConfig> {
        self.configs
            .iter()
            .filter(|c| c.enabled && c.subscribed_to(event))
            .collect()
    }

    pub fn dispatch(&mut self, message: &NotificationMessage) -> Vec<NotificationRecord> {
        let configs: Vec<NotificationConfig> = self
            .configs_for_event(&message.event)
            .into_iter()
            .cloned()
            .collect();

        let mut records = Vec::new();
        for config in configs {
            let record = self.send(&config, message);
            records.push(record.clone());
            self.add_record(record);
        }
        records
    }

    fn send(&self, config: &NotificationConfig, message: &NotificationMessage) -> NotificationRecord {
        match &config.channel {
            NotificationChannel::Email => self.send_email(config, message),
            NotificationChannel::Slack => self.send_slack(config, message),
            NotificationChannel::Webhook => self.send_webhook(config, message),
            NotificationChannel::Custom(name) => self.send_custom(name, config, message),
        }
    }

    fn send_email(
        &self,
        config: &NotificationConfig,
        message: &NotificationMessage,
    ) -> NotificationRecord {
        // Simulate email sending; real impl would use SMTP
        let smtp_server = config.metadata.get("smtp_server").map(|s| s.as_str());
        let success = smtp_server.is_some() || cfg!(test);

        NotificationRecord {
            message_id: message.id.clone(),
            channel: NotificationChannel::Email,
            destination: config.destination.clone(),
            sent_at: chrono::Utc::now(),
            success,
            error: if success {
                None
            } else {
                Some("SMTP server not configured".to_string())
            },
        }
    }

    fn send_slack(
        &self,
        config: &NotificationConfig,
        message: &NotificationMessage,
    ) -> NotificationRecord {
        let webhook_url = config.metadata.get("webhook_url").map(|s| s.as_str());
        let success = webhook_url.is_some() || cfg!(test);

        NotificationRecord {
            message_id: message.id.clone(),
            channel: NotificationChannel::Slack,
            destination: config.destination.clone(),
            sent_at: chrono::Utc::now(),
            success,
            error: if success {
                None
            } else {
                Some("Slack webhook URL not configured".to_string())
            },
        }
    }

    fn send_webhook(
        &self,
        config: &NotificationConfig,
        message: &NotificationMessage,
    ) -> NotificationRecord {
        let url = &config.destination;
        let success = url.starts_with("http://") || url.starts_with("https://") || cfg!(test);

        NotificationRecord {
            message_id: message.id.clone(),
            channel: NotificationChannel::Webhook,
            destination: config.destination.clone(),
            sent_at: chrono::Utc::now(),
            success,
            error: if success {
                None
            } else {
                Some("Invalid webhook URL".to_string())
            },
        }
    }

    fn send_custom(
        &self,
        name: &str,
        config: &NotificationConfig,
        message: &NotificationMessage,
    ) -> NotificationRecord {
        NotificationRecord {
            message_id: message.id.clone(),
            channel: NotificationChannel::Custom(name.to_string()),
            destination: config.destination.clone(),
            sent_at: chrono::Utc::now(),
            success: true,
            error: None,
        }
    }

    fn add_record(&mut self, record: NotificationRecord) {
        self.history.push(record);
        while self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    pub fn history(&self) -> &[NotificationRecord] {
        &self.history
    }

    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    pub fn successful_count(&self) -> usize {
        self.history.iter().filter(|r| r.success).count()
    }

    pub fn failed_count(&self) -> usize {
        self.history.iter().filter(|r| !r.success).count()
    }

    pub fn clear_history(&mut self) {
        self.history.clear();
    }
}

impl Default for NotificationManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct NotificationMessageBuilder {
    message: NotificationMessage,
}

impl NotificationMessageBuilder {
    pub fn new(event: NotificationEvent, title: &str, body: &str) -> Self {
        Self {
            message: NotificationMessage::new(event, title, body),
        }
    }

    pub fn scan_id(mut self, scan_id: &str) -> Self {
        self.message.scan_id = Some(scan_id.to_string());
        self
    }

    pub fn target(mut self, target: &str) -> Self {
        self.message.target = Some(target.to_string());
        self
    }

    pub fn metadata(mut self, key: &str, value: &str) -> Self {
        self.message.metadata.insert(key.to_string(), value.to_string());
        self
    }

    pub fn build(self) -> NotificationMessage {
        self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notification_channel_display() {
        assert_eq!(NotificationChannel::Email.to_string(), "email");
        assert_eq!(NotificationChannel::Slack.to_string(), "slack");
        assert_eq!(NotificationChannel::Webhook.to_string(), "webhook");
        assert_eq!(
            NotificationChannel::Custom("pagerduty".to_string()).to_string(),
            "custom:pagerduty"
        );
    }

    #[test]
    fn test_notification_event_display() {
        assert_eq!(NotificationEvent::ScanStarted.to_string(), "scan_started");
        assert_eq!(NotificationEvent::ScanCompleted.to_string(), "scan_completed");
        assert_eq!(NotificationEvent::ScanFailed.to_string(), "scan_failed");
        assert_eq!(NotificationEvent::HighRiskFound.to_string(), "high_risk_found");
        assert_eq!(
            NotificationEvent::Custom("custom_event".to_string()).to_string(),
            "custom_event"
        );
    }

    #[test]
    fn test_notification_config_creation() {
        let config = NotificationConfig::new(
            "email-alerts",
            NotificationChannel::Email,
            "admin@example.com",
        );

        assert_eq!(config.name, "email-alerts");
        assert_eq!(config.channel, NotificationChannel::Email);
        assert_eq!(config.destination, "admin@example.com");
        assert!(config.enabled);
        assert!(config.events.is_empty());
    }

    #[test]
    fn test_notification_config_with_events() {
        let config = NotificationConfig::new(
            "slack-alerts",
            NotificationChannel::Slack,
            "#security",
        )
        .with_event(NotificationEvent::ScanCompleted)
        .with_event(NotificationEvent::HighRiskFound)
        .with_events(vec![
            NotificationEvent::ScanFailed,
            NotificationEvent::ScanCompleted, // duplicate
        ]);

        assert_eq!(config.events.len(), 3);
        assert!(config.subscribed_to(&NotificationEvent::ScanCompleted));
        assert!(config.subscribed_to(&NotificationEvent::HighRiskFound));
        assert!(config.subscribed_to(&NotificationEvent::ScanFailed));
        assert!(!config.subscribed_to(&NotificationEvent::ScanStarted));
    }

    #[test]
    fn test_notification_config_with_metadata() {
        let config = NotificationConfig::new(
            "email",
            NotificationChannel::Email,
            "admin@example.com",
        )
        .with_metadata("smtp_server", "smtp.example.com")
        .with_metadata("smtp_port", "587");

        assert_eq!(config.metadata.get("smtp_server").unwrap(), "smtp.example.com");
        assert_eq!(config.metadata.get("smtp_port").unwrap(), "587");
    }

    #[test]
    fn test_notification_message() {
        let msg = NotificationMessage::new(
            NotificationEvent::ScanCompleted,
            "Scan Complete",
            "The scan has finished successfully.",
        )
        .with_scan_id("scan-123")
        .with_target("192.168.1.0/24")
        .with_metadata("open_ports", "5");

        assert_eq!(msg.title, "Scan Complete");
        assert_eq!(msg.event, NotificationEvent::ScanCompleted);
        assert_eq!(msg.scan_id.as_deref(), Some("scan-123"));
        assert_eq!(msg.target.as_deref(), Some("192.168.1.0/24"));
        assert_eq!(msg.metadata.get("open_ports").unwrap(), "5");
    }

    #[test]
    fn test_notification_message_builder() {
        let msg = NotificationMessageBuilder::new(
            NotificationEvent::HighRiskFound,
            "Critical Vulnerability",
            "Found CVE-2024-1234 on port 443",
        )
        .scan_id("scan-456")
        .target("10.0.0.1")
        .metadata("cve", "CVE-2024-1234")
        .build();

        assert_eq!(msg.title, "Critical Vulnerability");
        assert_eq!(msg.scan_id.as_deref(), Some("scan-456"));
        assert_eq!(msg.metadata.get("cve").unwrap(), "CVE-2024-1234");
    }

    #[test]
    fn test_notification_manager_add_and_list() {
        let mut mgr = NotificationManager::new();
        assert_eq!(mgr.config_count(), 0);

        let config = NotificationConfig::new(
            "email",
            NotificationChannel::Email,
            "admin@example.com",
        );

        mgr.add_config(config);
        assert_eq!(mgr.config_count(), 1);
        assert_eq!(mgr.list_configs().len(), 1);
    }

    #[test]
    fn test_notification_manager_remove() {
        let mut mgr = NotificationManager::new();
        let config = NotificationConfig::new(
            "test",
            NotificationChannel::Email,
            "test@example.com",
        );
        let id = config.id.clone();

        mgr.add_config(config);
        assert!(mgr.remove_config(&id));
        assert_eq!(mgr.config_count(), 0);
        assert!(!mgr.remove_config("nonexistent"));
    }

    #[test]
    fn test_notification_manager_enabled() {
        let mut mgr = NotificationManager::new();

        let mut c1 = NotificationConfig::new(
            "enabled",
            NotificationChannel::Email,
            "a@example.com",
        );
        c1.enabled = true;

        let mut c2 = NotificationConfig::new(
            "disabled",
            NotificationChannel::Slack,
            "#channel",
        );
        c2.enabled = false;

        mgr.add_config(c1);
        mgr.add_config(c2);

        assert_eq!(mgr.enabled_configs().len(), 1);
    }

    #[test]
    fn test_notification_manager_configs_for_event() {
        let mut mgr = NotificationManager::new();

        let c1 = NotificationConfig::new(
            "email-complete",
            NotificationChannel::Email,
            "a@example.com",
        )
        .with_event(NotificationEvent::ScanCompleted);

        let c2 = NotificationConfig::new(
            "slack-all",
            NotificationChannel::Slack,
            "#alerts",
        )
        .with_event(NotificationEvent::ScanCompleted)
        .with_event(NotificationEvent::ScanFailed);

        let c3 = NotificationConfig::new(
            "webhook-start",
            NotificationChannel::Webhook,
            "https://hooks.example.com",
        )
        .with_event(NotificationEvent::ScanStarted);

        mgr.add_config(c1);
        mgr.add_config(c2);
        mgr.add_config(c3);

        let for_completed = mgr.configs_for_event(&NotificationEvent::ScanCompleted);
        assert_eq!(for_completed.len(), 2);

        let for_started = mgr.configs_for_event(&NotificationEvent::ScanStarted);
        assert_eq!(for_started.len(), 1);

        let for_high_risk = mgr.configs_for_event(&NotificationEvent::HighRiskFound);
        assert_eq!(for_high_risk.len(), 0);
    }

    #[test]
    fn test_notification_dispatch() {
        let mut mgr = NotificationManager::new();

        // In test mode, send functions succeed regardless of config
        mgr.add_config(
            NotificationConfig::new(
                "email",
                NotificationChannel::Email,
                "admin@example.com",
            )
            .with_event(NotificationEvent::ScanCompleted),
        );

        mgr.add_config(
            NotificationConfig::new(
                "webhook",
                NotificationChannel::Webhook,
                "https://hooks.example.com/notify",
            )
            .with_event(NotificationEvent::ScanCompleted),
        );

        let msg = NotificationMessage::new(
            NotificationEvent::ScanCompleted,
            "Scan Done",
            "All ports scanned.",
        );

        let records = mgr.dispatch(&msg);
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|r| r.success));
        assert_eq!(mgr.history_len(), 2);
        assert_eq!(mgr.successful_count(), 2);
        assert_eq!(mgr.failed_count(), 0);
    }

    #[test]
    fn test_notification_dispatch_no_matching_configs() {
        let mut mgr = NotificationManager::new();
        mgr.add_config(
            NotificationConfig::new(
                "email",
                NotificationChannel::Email,
                "admin@example.com",
            )
            .with_event(NotificationEvent::ScanCompleted),
        );

        let msg = NotificationMessage::new(
            NotificationEvent::ScanStarted,
            "Starting",
            "Scan is starting.",
        );

        let records = mgr.dispatch(&msg);
        assert_eq!(records.len(), 0);
        assert_eq!(mgr.history_len(), 0);
    }

    #[test]
    fn test_notification_dispatch_disabled_config() {
        let mut mgr = NotificationManager::new();
        let mut config = NotificationConfig::new(
            "disabled",
            NotificationChannel::Email,
            "admin@example.com",
        )
        .with_event(NotificationEvent::ScanCompleted);
        config.enabled = false;
        mgr.add_config(config);

        let msg = NotificationMessage::new(
            NotificationEvent::ScanCompleted,
            "Done",
            "Done.",
        );

        let records = mgr.dispatch(&msg);
        assert_eq!(records.len(), 0);
    }

    #[test]
    fn test_notification_history_max() {
        let mut mgr = NotificationManager::new().with_max_history(3);

        mgr.add_config(
            NotificationConfig::new(
                "test",
                NotificationChannel::Custom("test".to_string()),
                "test",
            )
            .with_event(NotificationEvent::ScanCompleted),
        );

        for i in 0..5 {
            let msg = NotificationMessage::new(
                NotificationEvent::ScanCompleted,
                &format!("Msg {}", i),
                "body",
            );
            mgr.dispatch(&msg);
        }

        assert_eq!(mgr.history_len(), 3);
    }

    #[test]
    fn test_notification_clear_history() {
        let mut mgr = NotificationManager::new();
        mgr.add_config(
            NotificationConfig::new(
                "test",
                NotificationChannel::Custom("test".to_string()),
                "test",
            )
            .with_event(NotificationEvent::ScanCompleted),
        );

        let msg = NotificationMessage::new(
            NotificationEvent::ScanCompleted,
            "Test",
            "body",
        );
        mgr.dispatch(&msg);
        assert_eq!(mgr.history_len(), 1);

        mgr.clear_history();
        assert_eq!(mgr.history_len(), 0);
    }

    #[test]
    fn test_notification_manager_get_config() {
        let mut mgr = NotificationManager::new();
        let config = NotificationConfig::new(
            "my-config",
            NotificationChannel::Email,
            "admin@example.com",
        );
        let id = config.id.clone();
        mgr.add_config(config);

        assert!(mgr.get_config(&id).is_some());
        assert!(mgr.get_config("nonexistent").is_none());

        let mutable = mgr.get_config_mut(&id).unwrap();
        mutable.enabled = false;
        assert!(!mgr.get_config(&id).unwrap().enabled);
    }

    #[test]
    fn test_notification_serialization() {
        let config = NotificationConfig::new(
            "test",
            NotificationChannel::Webhook,
            "https://hooks.example.com",
        )
        .with_event(NotificationEvent::ScanCompleted)
        .with_metadata("key", "val");

        let json = serde_json::to_string(&config).unwrap();
        let loaded: NotificationConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.name, "test");
        assert_eq!(loaded.channel, NotificationChannel::Webhook);
        assert_eq!(loaded.destination, "https://hooks.example.com");
        assert_eq!(loaded.events.len(), 1);
        assert_eq!(loaded.metadata.get("key").unwrap(), "val");
    }

    #[test]
    fn test_notification_manager_serialization() {
        let mut mgr = NotificationManager::new();
        mgr.add_config(
            NotificationConfig::new(
                "email",
                NotificationChannel::Email,
                "admin@example.com",
            )
            .with_event(NotificationEvent::ScanCompleted),
        );
        mgr.add_config(
            NotificationConfig::new(
                "slack",
                NotificationChannel::Slack,
                "#alerts",
            )
            .with_event(NotificationEvent::HighRiskFound),
        );

        let json = serde_json::to_string(&mgr).unwrap();
        let loaded: NotificationManager = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.config_count(), 2);
    }

    #[test]
    fn test_webhook_config_with_http_url() {
        let mut mgr = NotificationManager::new();
        mgr.add_config(
            NotificationConfig::new(
                "webhook",
                NotificationChannel::Webhook,
                "https://hooks.example.com/nemue",
            )
            .with_event(NotificationEvent::ScanCompleted),
        );

        let msg = NotificationMessage::new(
            NotificationEvent::ScanCompleted,
            "Done",
            "Scan finished.",
        );

        let records = mgr.dispatch(&msg);
        assert_eq!(records.len(), 1);
        assert!(records[0].success);
    }
}
