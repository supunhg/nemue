use serde::{Deserialize, Serialize};
use anyhow::{Result, Context};
use std::time::Duration;

/// Supported webhook providers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WebhookProvider {
    Slack,
    Discord,
    Teams,
    Custom,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub provider: WebhookProvider,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_retry_delay_ms")]
    pub retry_delay_ms: u64,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_max_retries() -> u32 { 3 }
fn default_retry_delay_ms() -> u64 { 1000 }
fn default_timeout_secs() -> u64 { 30 }

/// Webhook delivery status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub webhook_id: String,
    pub url: String,
    pub provider: WebhookProvider,
    pub status: DeliveryStatus,
    pub attempts: u32,
    pub response_code: Option<u16>,
    pub error_message: Option<String>,
    pub delivered_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Retrying,
}

/// Scan event payload for webhooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvent {
    pub event_type: String,
    pub scan_id: String,
    pub status: String,
    pub targets: Vec<String>,
    pub total_open_ports: usize,
    pub total_vulnerabilities: usize,
    pub risk_score: u8,
    pub timestamp: String,
    pub summary: String,
}

/// Webhook client for sending scan notifications
pub struct WebhookClient {
    http_client: reqwest::Client,
}

impl WebhookClient {
    pub fn new() -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
        Self { http_client }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("Failed to create HTTP client");
        Self { http_client }
    }

    /// Send a scan event to a webhook with retry logic
    pub async fn send(&self, config: &WebhookConfig, event: &ScanEvent) -> WebhookDelivery {
        let payload = match config.provider {
            WebhookProvider::Slack => self.build_slack_payload(event),
            WebhookProvider::Discord => self.build_discord_payload(event),
            WebhookProvider::Teams => self.build_teams_payload(event),
            WebhookProvider::Custom => self.build_custom_payload(event, config),
        };

        let mut last_error = None;
        let mut response_code = None;

        for attempt in 1..=config.max_retries.max(1) {
            match self.deliver(&config.url, &payload, config.timeout_secs).await {
                Ok(code) => {
                    response_code = Some(code);
                    if code >= 200 && code < 300 {
                        return WebhookDelivery {
                            webhook_id: uuid::Uuid::new_v4().to_string(),
                            url: config.url.clone(),
                            provider: config.provider.clone(),
                            status: DeliveryStatus::Delivered,
                            attempts: attempt,
                            response_code: Some(code),
                            error_message: None,
                            delivered_at: Some(chrono::Utc::now()),
                        };
                    }
                    last_error = Some(format!("HTTP {}: non-success status", code));
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                }
            }

            if attempt < config.max_retries {
                tokio::time::sleep(Duration::from_millis(config.retry_delay_ms * attempt as u64)).await;
            }
        }

        WebhookDelivery {
            webhook_id: uuid::Uuid::new_v4().to_string(),
            url: config.url.clone(),
            provider: config.provider.clone(),
            status: DeliveryStatus::Failed,
            attempts: config.max_retries.max(1),
            response_code,
            error_message: last_error,
            delivered_at: None,
        }
    }

    async fn deliver(&self, url: &str, payload: &serde_json::Value, timeout_secs: u64) -> Result<u16> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;

        let resp = client.post(url)
            .header("Content-Type", "application/json")
            .json(payload)
            .send()
            .await
            .context("Failed to send webhook request")?;

        Ok(resp.status().as_u16())
    }

    fn build_slack_payload(&self, event: &ScanEvent) -> serde_json::Value {
        let color = if event.total_vulnerabilities > 0 { "#ff0000" }
                    else if event.risk_score > 50 { "#ff9900" }
                    else { "#36a64f" };

        let fields = vec![
            serde_json::json!({"title": "Status", "value": event.status, "short": true}),
            serde_json::json!({"title": "Risk Score", "value": format!("{}/100", event.risk_score), "short": true}),
            serde_json::json!({"title": "Open Ports", "value": event.total_open_ports.to_string(), "short": true}),
            serde_json::json!({"title": "Vulnerabilities", "value": event.total_vulnerabilities.to_string(), "short": true}),
        ];

        serde_json::json!({
            "attachments": [{
                "color": color,
                "title": format!("Nemue Scan: {}", event.event_type),
                "text": event.summary,
                "fields": fields,
                "footer": "Nemue Security Scanner",
                "ts": chrono::Utc::now().timestamp()
            }]
        })
    }

    fn build_discord_payload(&self, event: &ScanEvent) -> serde_json::Value {
        let color = if event.total_vulnerabilities > 0 { 0xff0000 }
                    else if event.risk_score > 50 { 0xff9900 }
                    else { 0x36a64f };

        serde_json::json!({
            "embeds": [{
                "title": format!("Nemue Scan: {}", event.event_type),
                "description": event.summary,
                "color": color,
                "fields": [
                    {"name": "Scan ID", "value": event.scan_id, "inline": true},
                    {"name": "Status", "value": event.status, "inline": true},
                    {"name": "Risk Score", "value": format!("{}/100", event.risk_score), "inline": true},
                    {"name": "Open Ports", "value": event.total_open_ports.to_string(), "inline": true},
                    {"name": "Vulnerabilities", "value": event.total_vulnerabilities.to_string(), "inline": true},
                    {"name": "Targets", "value": event.targets.join(", "), "inline": false}
                ],
                "footer": {"text": "Nemue Security Scanner"},
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        })
    }

    fn build_teams_payload(&self, event: &ScanEvent) -> serde_json::Value {
        let theme_color = if event.total_vulnerabilities > 0 { "ff0000" }
                          else if event.risk_score > 50 { "ff9900" }
                          else { "36a64f" };

        let facts = vec![
            serde_json::json!({"name": "Status", "value": event.status}),
            serde_json::json!({"name": "Risk Score", "value": format!("{}/100", event.risk_score)}),
            serde_json::json!({"name": "Open Ports", "value": event.total_open_ports.to_string()}),
            serde_json::json!({"name": "Vulnerabilities", "value": event.total_vulnerabilities.to_string()}),
            serde_json::json!({"name": "Targets", "value": event.targets.join(", ")}),
        ];

        serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": theme_color,
            "summary": format!("Nemue Scan: {}", event.event_type),
            "sections": [{
                "activityTitle": format!("Nemue Scan: {}", event.event_type),
                "activitySubtitle": event.summary,
                "facts": facts,
                "markdown": true
            }]
        })
    }

    fn build_custom_payload(&self, event: &ScanEvent, config: &WebhookConfig) -> serde_json::Value {
        if let Some(ref _secret) = config.secret {
            let mut payload = serde_json::to_value(event).unwrap_or_default();
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("webhook_secret".to_string(), serde_json::Value::String(_secret.clone()));
            }
            payload
        } else {
            serde_json::to_value(event).unwrap_or_default()
        }
    }
}

impl Default for WebhookClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_config_defaults() {
        let config = WebhookConfig {
            url: "https://example.com/webhook".to_string(),
            provider: WebhookProvider::Slack,
            secret: None,
            max_retries: default_max_retries(),
            retry_delay_ms: default_retry_delay_ms(),
            timeout_secs: default_timeout_secs(),
        };
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_ms, 1000);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_slack_payload_generation() {
        let client = WebhookClient::new();
        let event = ScanEvent {
            event_type: "completed".to_string(),
            scan_id: "test-123".to_string(),
            status: "completed".to_string(),
            targets: vec!["192.168.1.1".to_string()],
            total_open_ports: 5,
            total_vulnerabilities: 2,
            risk_score: 75,
            timestamp: chrono::Utc::now().to_rfc3339(),
            summary: "Scan completed with 2 vulnerabilities found".to_string(),
        };

        let payload = client.build_slack_payload(&event);
        assert!(payload.get("attachments").is_some());
        let attachments = payload["attachments"].as_array().unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(attachments[0]["color"], "#ff0000");
    }

    #[test]
    fn test_discord_payload_generation() {
        let client = WebhookClient::new();
        let event = ScanEvent {
            event_type: "completed".to_string(),
            scan_id: "test-456".to_string(),
            status: "completed".to_string(),
            targets: vec!["10.0.0.1".to_string()],
            total_open_ports: 3,
            total_vulnerabilities: 0,
            risk_score: 30,
            timestamp: chrono::Utc::now().to_rfc3339(),
            summary: "Scan completed with no vulnerabilities".to_string(),
        };

        let payload = client.build_discord_payload(&event);
        assert!(payload.get("embeds").is_some());
        let embeds = payload["embeds"].as_array().unwrap();
        assert_eq!(embeds[0]["color"], 0x36a64f);
    }

    #[test]
    fn test_teams_payload_generation() {
        let client = WebhookClient::new();
        let event = ScanEvent {
            event_type: "completed".to_string(),
            scan_id: "test-789".to_string(),
            status: "completed".to_string(),
            targets: vec!["172.16.0.1".to_string()],
            total_open_ports: 1,
            total_vulnerabilities: 0,
            risk_score: 10,
            timestamp: chrono::Utc::now().to_rfc3339(),
            summary: "Low risk scan completed".to_string(),
        };

        let payload = client.build_teams_payload(&event);
        assert_eq!(payload["@type"], "MessageCard");
        assert_eq!(payload["themeColor"], "36a64f");
    }

    #[test]
    fn test_custom_payload_with_secret() {
        let client = WebhookClient::new();
        let event = ScanEvent {
            event_type: "started".to_string(),
            scan_id: "test-custom".to_string(),
            status: "running".to_string(),
            targets: vec!["example.com".to_string()],
            total_open_ports: 0,
            total_vulnerabilities: 0,
            risk_score: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
            summary: "Scan started".to_string(),
        };

        let config = WebhookConfig {
            url: "https://custom.example.com/hook".to_string(),
            provider: WebhookProvider::Custom,
            secret: Some("my-secret".to_string()),
            max_retries: 1,
            retry_delay_ms: 0,
            timeout_secs: 10,
        };

        let payload = client.build_custom_payload(&event, &config);
        assert_eq!(payload["webhook_secret"], "my-secret");
        assert_eq!(payload["scan_id"], "test-custom");
    }

    #[test]
    fn test_webhook_provider_serialization() {
        assert_eq!(serde_json::to_string(&WebhookProvider::Slack).unwrap(), "\"slack\"");
        assert_eq!(serde_json::to_string(&WebhookProvider::Discord).unwrap(), "\"discord\"");
        assert_eq!(serde_json::to_string(&WebhookProvider::Teams).unwrap(), "\"teams\"");
        assert_eq!(serde_json::to_string(&WebhookProvider::Custom).unwrap(), "\"custom\"");
    }

    #[test]
    fn test_scan_event_serialization() {
        let event = ScanEvent {
            event_type: "completed".to_string(),
            scan_id: "uuid-test".to_string(),
            status: "completed".to_string(),
            targets: vec!["192.168.1.1".to_string()],
            total_open_ports: 10,
            total_vulnerabilities: 3,
            risk_score: 85,
            timestamp: "2025-01-01T00:00:00Z".to_string(),
            summary: "Test scan".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: ScanEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.scan_id, "uuid-test");
        assert_eq!(deserialized.total_vulnerabilities, 3);
    }

    #[test]
    fn test_delivery_status_variants() {
        let statuses = vec![
            DeliveryStatus::Pending,
            DeliveryStatus::Delivered,
            DeliveryStatus::Failed,
            DeliveryStatus::Retrying,
        ];
        for status in statuses {
            let json = serde_json::to_string(&status).unwrap();
            let deserialized: DeliveryStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, status);
        }
    }

    #[tokio::test]
    async fn test_webhook_delivery_failure_on_bad_url() {
        let client = WebhookClient::with_timeout(Duration::from_secs(2));
        let config = WebhookConfig {
            url: "http://127.0.0.1:1/nonexistent".to_string(),
            provider: WebhookProvider::Slack,
            secret: None,
            max_retries: 1,
            retry_delay_ms: 0,
            timeout_secs: 2,
        };

        let event = ScanEvent {
            event_type: "completed".to_string(),
            scan_id: "test-fail".to_string(),
            status: "completed".to_string(),
            targets: vec![],
            total_open_ports: 0,
            total_vulnerabilities: 0,
            risk_score: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
            summary: "test".to_string(),
        };

        let delivery = client.send(&config, &event).await;
        assert_eq!(delivery.status, DeliveryStatus::Failed);
        assert!(delivery.error_message.is_some());
    }
}
