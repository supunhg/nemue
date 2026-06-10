use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum WsClientMessage {
    Subscribe {
        scan_id: String,
    },
    Unsubscribe {
        scan_id: String,
    },
    Ping,
    GetStatus {
        scan_id: String,
    },
    StreamLogs {
        scan_id: String,
        level: Option<String>,
    },
    StopStream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum WsServerMessage {
    ScanUpdate(ScanUpdate),
    LogEntry(LogEntry),
    Progress(ProgressNotification),
    Error(ErrorMessage),
    Pong,
    Subscribed { scan_id: String },
    Unsubscribed { scan_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUpdate {
    pub scan_id: String,
    pub status: String,
    pub progress: f32,
    pub targets_completed: usize,
    pub targets_total: usize,
    pub ports_scanned: usize,
    pub ports_total: usize,
    pub open_ports_found: usize,
    pub vulnerabilities_found: usize,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub scan_id: String,
    pub level: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressNotification {
    pub scan_id: String,
    pub phase: String,
    pub percent_complete: f32,
    pub current_target: Option<String>,
    pub estimated_remaining_secs: Option<u64>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub code: u16,
    pub message: String,
}

pub struct WsSession {
    pub id: Uuid,
    pub subscriptions: Vec<String>,
    pub app_state: Arc<RwLock<AppState>>,
}

impl WsSession {
    pub fn new(app_state: Arc<RwLock<AppState>>) -> Self {
        Self {
            id: Uuid::new_v4(),
            subscriptions: Vec::new(),
            app_state,
        }
    }

    pub fn handle_message(&mut self, raw: &str) -> Option<String> {
        let client_msg: WsClientMessage = match serde_json::from_str(raw) {
            Ok(msg) => msg,
            Err(_) => {
                let err = WsServerMessage::Error(ErrorMessage {
                    code: 400,
                    message: "Invalid message format".to_string(),
                });
                return Some(serde_json::to_string(&err).unwrap_or_default());
            }
        };

        match client_msg {
            WsClientMessage::Subscribe { scan_id } => {
                if !self.subscriptions.contains(&scan_id) {
                    self.subscriptions.push(scan_id.clone());
                }
                let resp = WsServerMessage::Subscribed { scan_id };
                Some(serde_json::to_string(&resp).unwrap_or_default())
            }
            WsClientMessage::Unsubscribe { scan_id } => {
                self.subscriptions.retain(|s| s != &scan_id);
                let resp = WsServerMessage::Unsubscribed { scan_id };
                Some(serde_json::to_string(&resp).unwrap_or_default())
            }
            WsClientMessage::Ping => {
                let resp = WsServerMessage::Pong;
                Some(serde_json::to_string(&resp).unwrap_or_default())
            }
            WsClientMessage::GetStatus { scan_id } => {
                let state = self.app_state.clone();
                let scan_uuid = Uuid::parse_str(&scan_id).ok();
                let rt = tokio::runtime::Runtime::new().ok()?;
                let state_ref = state;

                let result = rt.block_on(async {
                    let state = state_ref.read().await;
                    if let Some(uuid) = scan_uuid {
                        if let Some(status) = state.get_scan_status(&uuid) {
                            let update = ScanUpdate {
                                scan_id: status.scan_id.to_string(),
                                status: format!("{:?}", status.status).to_lowercase(),
                                progress: status.progress,
                                targets_completed: status.targets_completed,
                                targets_total: status.targets_total,
                                ports_scanned: status.ports_scanned,
                                ports_total: status.ports_total,
                                open_ports_found: 0,
                                vulnerabilities_found: 0,
                                timestamp: Utc::now(),
                            };
                            let msg = WsServerMessage::ScanUpdate(update);
                            return serde_json::to_string(&msg).ok();
                        } else {
                            let err = WsServerMessage::Error(ErrorMessage {
                                code: 404,
                                message: "Scan not found".to_string(),
                            });
                            return serde_json::to_string(&err).ok();
                        }
                    }
                    None
                });
                result
            }
            WsClientMessage::StreamLogs {
                scan_id: _,
                level: _,
            } => {
                let resp = WsServerMessage::LogEntry(LogEntry {
                    scan_id: "system".to_string(),
                    level: "info".to_string(),
                    message: "Log streaming connected".to_string(),
                    timestamp: Utc::now(),
                    source: "system".to_string(),
                });
                Some(serde_json::to_string(&resp).unwrap_or_default())
            }
            WsClientMessage::StopStream => {
                let resp = WsServerMessage::LogEntry(LogEntry {
                    scan_id: "system".to_string(),
                    level: "info".to_string(),
                    message: "Log streaming stopped".to_string(),
                    timestamp: Utc::now(),
                    source: "system".to_string(),
                });
                Some(serde_json::to_string(&resp).unwrap_or_default())
            }
        }
    }

    pub fn is_subscribed_to(&self, scan_id: &str) -> bool {
        self.subscriptions.contains(&scan_id.to_string())
    }
}

pub struct WsHub {
    sessions: HashMap<Uuid, WsSession>,
}

impl WsHub {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    pub fn register(&mut self, id: Uuid, session: WsSession) {
        self.sessions.insert(id, session);
    }

    pub fn unregister(&mut self, id: &Uuid) {
        self.sessions.remove(id);
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn broadcast(&self, scan_id: &str, msg: &WsServerMessage) -> Vec<(Uuid, String)> {
        let json = serde_json::to_string(msg).unwrap_or_default();
        self.sessions
            .iter()
            .filter(|(_, s)| s.is_subscribed_to(scan_id))
            .map(|(id, _)| (*id, json.clone()))
            .collect()
    }
}

impl Default for WsHub {
    fn default() -> Self {
        Self::new()
    }
}

pub fn process_ws_message(session: &mut WsSession, raw: &str) -> Option<String> {
    session.handle_message(raw)
}

pub async fn ws_handler(
    _req: HttpRequest,
    _stream: web::Payload,
    _data: web::Data<Arc<RwLock<AppState>>>,
) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "message": "WebSocket endpoint ready. Connect with a WebSocket client.",
        "endpoint": "/ws/scans",
        "protocol": "JSON messages with type/payload structure",
        "example_subscribe": {
            "type": "Subscribe",
            "payload": { "scan_id": "your-scan-uuid" }
        }
    }))
}

pub fn ws_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/ws")
            .route("", web::get().to(ws_handler))
            .route("/scans", web::get().to(ws_handler)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ws_session_new() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let session = WsSession::new(state);
        assert!(session.subscriptions.is_empty());
    }

    #[test]
    fn test_ws_session_subscribe() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let mut session = WsSession::new(state);

        let msg = r#"{"type":"Subscribe","payload":{"scan_id":"test-scan-123"}}"#;
        let response = session.handle_message(msg).unwrap();
        assert!(response.contains("Subscribed"));
        assert!(response.contains("test-scan-123"));
        assert!(session.is_subscribed_to("test-scan-123"));
    }

    #[test]
    fn test_ws_session_unsubscribe() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let mut session = WsSession::new(state);

        session.handle_message(r#"{"type":"Subscribe","payload":{"scan_id":"scan-1"}}"#);
        assert!(session.is_subscribed_to("scan-1"));

        let response = session
            .handle_message(r#"{"type":"Unsubscribe","payload":{"scan_id":"scan-1"}}"#)
            .unwrap();
        assert!(response.contains("Unsubscribed"));
        assert!(!session.is_subscribed_to("scan-1"));
    }

    #[test]
    fn test_ws_session_ping() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let mut session = WsSession::new(state);

        let response = session.handle_message(r#"{"type":"Ping"}"#).unwrap();
        assert!(response.contains("Pong"));
    }

    #[test]
    fn test_ws_session_invalid_message() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let mut session = WsSession::new(state);

        let response = session.handle_message("not json").unwrap();
        assert!(response.contains("Error"));
        assert!(response.contains("Invalid message format"));
    }

    #[test]
    fn test_ws_session_stream_logs() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let mut session = WsSession::new(state);

        let response = session
            .handle_message(
                r#"{"type":"StreamLogs","payload":{"scan_id":"scan-1","level":"info"}}"#,
            )
            .unwrap();
        assert!(response.contains("LogEntry"));
        assert!(response.contains("Log streaming connected"));
    }

    #[test]
    fn test_ws_session_stop_stream() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let mut session = WsSession::new(state);

        let response = session.handle_message(r#"{"type":"StopStream"}"#).unwrap();
        assert!(response.contains("LogEntry"));
        assert!(response.contains("Log streaming stopped"));
    }

    #[test]
    fn test_ws_hub_new() {
        let hub = WsHub::new();
        assert_eq!(hub.session_count(), 0);
    }

    #[test]
    fn test_ws_hub_default() {
        let hub = WsHub::default();
        assert_eq!(hub.session_count(), 0);
    }

    #[test]
    fn test_ws_hub_register_unregister() {
        let mut hub = WsHub::new();
        let state = Arc::new(RwLock::new(AppState::new()));
        let session = WsSession::new(state);
        let id = session.id;

        hub.register(id, session);
        assert_eq!(hub.session_count(), 1);

        hub.unregister(&id);
        assert_eq!(hub.session_count(), 0);
    }

    #[test]
    fn test_ws_hub_broadcast() {
        let mut hub = WsHub::new();
        let state = Arc::new(RwLock::new(AppState::new()));
        let mut session = WsSession::new(state);
        let id = session.id;

        session.handle_message(r#"{"type":"Subscribe","payload":{"scan_id":"scan-1"}}"#);
        hub.register(id, session);

        let update = WsServerMessage::ScanUpdate(ScanUpdate {
            scan_id: "scan-1".to_string(),
            status: "running".to_string(),
            progress: 50.0,
            targets_completed: 5,
            targets_total: 10,
            ports_scanned: 50,
            ports_total: 100,
            open_ports_found: 12,
            vulnerabilities_found: 3,
            timestamp: Utc::now(),
        });

        let messages = hub.broadcast("scan-1", &update);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].0, id);
    }

    #[test]
    fn test_ws_hub_broadcast_no_subscribers() {
        let hub = WsHub::new();
        let update = WsServerMessage::Pong;
        let messages = hub.broadcast("nonexistent", &update);
        assert!(messages.is_empty());
    }

    #[test]
    fn test_process_ws_message() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let mut session = WsSession::new(state);

        let response = process_ws_message(&mut session, r#"{"type":"Ping"}"#);
        assert!(response.is_some());
        assert!(response.unwrap().contains("Pong"));
    }

    #[test]
    fn test_ws_client_message_subscribe_serialize() {
        let msg = WsClientMessage::Subscribe {
            scan_id: "test-scan-123".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("Subscribe"));
        assert!(json.contains("test-scan-123"));
    }

    #[test]
    fn test_ws_client_message_deserialize() {
        let json = r#"{"type":"Subscribe","payload":{"scan_id":"abc-123"}}"#;
        let msg: WsClientMessage = serde_json::from_str(json).unwrap();
        match msg {
            WsClientMessage::Subscribe { scan_id } => assert_eq!(scan_id, "abc-123"),
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_ws_server_message_scan_update_serialize() {
        let update = ScanUpdate {
            scan_id: "scan-1".to_string(),
            status: "running".to_string(),
            progress: 45.5,
            targets_completed: 5,
            targets_total: 10,
            ports_scanned: 50,
            ports_total: 100,
            open_ports_found: 12,
            vulnerabilities_found: 3,
            timestamp: Utc::now(),
        };
        let msg = WsServerMessage::ScanUpdate(update);
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("ScanUpdate"));
        assert!(json.contains("45.5"));
    }

    #[test]
    fn test_ws_server_message_log_entry_serialize() {
        let log = LogEntry {
            scan_id: "scan-1".to_string(),
            level: "info".to_string(),
            message: "Port 80 open".to_string(),
            timestamp: Utc::now(),
            source: "scanner".to_string(),
        };
        let msg = WsServerMessage::LogEntry(log);
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("LogEntry"));
        assert!(json.contains("Port 80 open"));
    }

    #[test]
    fn test_ws_server_message_progress_serialize() {
        let progress = ProgressNotification {
            scan_id: "scan-1".to_string(),
            phase: "port_scanning".to_string(),
            percent_complete: 75.0,
            current_target: Some("192.168.1.1".to_string()),
            estimated_remaining_secs: Some(30),
            timestamp: Utc::now(),
        };
        let msg = WsServerMessage::Progress(progress);
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("Progress"));
        assert!(json.contains("port_scanning"));
    }

    #[test]
    fn test_ws_server_message_error_serialize() {
        let err = ErrorMessage {
            code: 404,
            message: "Scan not found".to_string(),
        };
        let msg = WsServerMessage::Error(err);
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("Error"));
        assert!(json.contains("404"));
    }

    #[test]
    fn test_ws_server_message_deserialize_roundtrip() {
        let update = ScanUpdate {
            scan_id: "scan-rt".to_string(),
            status: "completed".to_string(),
            progress: 100.0,
            targets_completed: 3,
            targets_total: 3,
            ports_scanned: 30,
            ports_total: 30,
            open_ports_found: 5,
            vulnerabilities_found: 1,
            timestamp: Utc::now(),
        };
        let msg = WsServerMessage::ScanUpdate(update);
        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: WsServerMessage = serde_json::from_str(&json).unwrap();
        match deserialized {
            WsServerMessage::ScanUpdate(u) => {
                assert_eq!(u.scan_id, "scan-rt");
                assert_eq!(u.progress, 100.0);
            }
            _ => panic!("Wrong variant"),
        }
    }

    #[test]
    fn test_scan_update_fields() {
        let update = ScanUpdate {
            scan_id: "test".to_string(),
            status: "running".to_string(),
            progress: 50.0,
            targets_completed: 5,
            targets_total: 10,
            ports_scanned: 100,
            ports_total: 200,
            open_ports_found: 15,
            vulnerabilities_found: 2,
            timestamp: Utc::now(),
        };
        assert_eq!(update.scan_id, "test");
        assert_eq!(update.open_ports_found, 15);
        assert_eq!(update.vulnerabilities_found, 2);
    }

    #[test]
    fn test_log_entry_fields() {
        let log = LogEntry {
            scan_id: "scan-log".to_string(),
            level: "warn".to_string(),
            message: "Timeout on port 443".to_string(),
            timestamp: Utc::now(),
            source: "scanner".to_string(),
        };
        assert_eq!(log.level, "warn");
        assert_eq!(log.source, "scanner");
    }

    #[test]
    fn test_progress_notification_fields() {
        let progress = ProgressNotification {
            scan_id: "scan-prog".to_string(),
            phase: "service_detection".to_string(),
            percent_complete: 60.0,
            current_target: Some("10.0.0.1".to_string()),
            estimated_remaining_secs: Some(120),
            timestamp: Utc::now(),
        };
        assert_eq!(progress.phase, "service_detection");
        assert_eq!(progress.current_target, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_ws_session_multiple_subscriptions() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let mut session = WsSession::new(state);

        session.handle_message(r#"{"type":"Subscribe","payload":{"scan_id":"scan-1"}}"#);
        session.handle_message(r#"{"type":"Subscribe","payload":{"scan_id":"scan-2"}}"#);
        session.handle_message(r#"{"type":"Subscribe","payload":{"scan_id":"scan-3"}}"#);

        assert!(session.is_subscribed_to("scan-1"));
        assert!(session.is_subscribed_to("scan-2"));
        assert!(session.is_subscribed_to("scan-3"));
        assert_eq!(session.subscriptions.len(), 3);
    }

    #[test]
    fn test_ws_session_deduplicate_subscription() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let mut session = WsSession::new(state);

        session.handle_message(r#"{"type":"Subscribe","payload":{"scan_id":"scan-1"}}"#);
        session.handle_message(r#"{"type":"Subscribe","payload":{"scan_id":"scan-1"}}"#);

        assert_eq!(session.subscriptions.len(), 1);
    }
}
