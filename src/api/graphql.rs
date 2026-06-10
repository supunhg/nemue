use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::models::*;
use super::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLRequest {
    pub query: String,
    #[serde(default)]
    pub variables: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub operation_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLResponse {
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<GraphQLError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
    pub message: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub locations: Vec<GraphQLLocation>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub path: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLLocation {
    pub line: usize,
    pub column: usize,
}

impl GraphQLResponse {
    pub fn error(message: &str) -> Self {
        Self {
            data: None,
            errors: vec![GraphQLError {
                message: message.to_string(),
                locations: vec![],
                path: vec![],
            }],
        }
    }

    pub fn success(data: serde_json::Value) -> Self {
        Self {
            data: Some(data),
            errors: vec![],
        }
    }
}

pub struct GraphQLExecutor {
    app_state: Arc<RwLock<AppState>>,
}

impl GraphQLExecutor {
    pub fn new(app_state: Arc<RwLock<AppState>>) -> Self {
        Self { app_state }
    }

    pub async fn execute(&self, request: GraphQLRequest) -> GraphQLResponse {
        let query = request.query.trim();

        if query.starts_with("query") || query.starts_with("{") {
            self.execute_query(query, request.variables).await
        } else if query.starts_with("mutation") {
            self.execute_mutation(query, request.variables).await
        } else {
            GraphQLResponse::error("Unsupported operation type")
        }
    }

    async fn execute_query(
        &self,
        query: &str,
        _variables: Option<HashMap<String, serde_json::Value>>,
    ) -> GraphQLResponse {
        if query.contains("health") || query.contains("Health") {
            return self.resolve_health().await;
        }
        if query.contains("serverInfo") || query.contains("server_info") {
            return self.resolve_server_info().await;
        }
        if query.contains("stats") || query.contains("Stats") {
            return self.resolve_stats().await;
        }
        if query.contains("scan(") || query.contains("scan(id:") {
            let scan_id = extract_id_arg(query, "scan");
            if let Some(id_str) = scan_id {
                if let Ok(uuid) = Uuid::parse_str(&id_str) {
                    return self.resolve_scan(&uuid).await;
                }
            }
        }
        if query.contains("scans") || query.contains("Scans") {
            return self.resolve_scans().await;
        }

        GraphQLResponse::error("Unknown query field")
    }

    async fn execute_mutation(
        &self,
        mutation: &str,
        variables: Option<HashMap<String, serde_json::Value>>,
    ) -> GraphQLResponse {
        if mutation.contains("startScan") || mutation.contains("start_scan") {
            let targets = extract_string_list(mutation, variables.as_ref(), "targets");
            let ports = extract_u16_list(mutation, variables.as_ref(), "ports");

            let targets = targets.unwrap_or_default();
            let ports = ports.unwrap_or(vec![80, 443]);

            if targets.is_empty() {
                return GraphQLResponse::error("At least one target is required");
            }

            let scan_req = ScanRequest {
                targets,
                ports,
                scan_type: ScanType::Tcp,
                timing: TimingTemplate::Normal,
                enable_service_detection: false,
                enable_os_detection: false,
                enable_vuln_check: false,
                enable_threat_intel: false,
            };

            let mut state = self.app_state.write().await;
            let scan_id = state.create_scan(scan_req).await;

            return GraphQLResponse::success(serde_json::json!({
                "startScan": {
                    "scanId": scan_id.to_string(),
                    "status": "queued",
                    "message": "Scan queued successfully"
                }
            }));
        }

        if mutation.contains("cancelScan") || mutation.contains("cancel_scan") {
            let scan_id_str = extract_id_arg(mutation, "cancelScan")
                .or_else(|| extract_id_arg(mutation, "cancel_scan"));

            if let Some(id_str) = scan_id_str {
                if let Ok(uuid) = Uuid::parse_str(&id_str) {
                    let mut state = self.app_state.write().await;
                    match state.cancel_scan(&uuid).await {
                        Ok(_) => {
                            return GraphQLResponse::success(serde_json::json!({
                                "cancelScan": {
                                    "scanId": uuid.to_string(),
                                    "status": "cancelled",
                                    "message": "Scan cancelled successfully"
                                }
                            }));
                        }
                        Err(e) => {
                            return GraphQLResponse::error(&e.to_string());
                        }
                    }
                }
            }
            return GraphQLResponse::error("Invalid scan ID");
        }

        if mutation.contains("deleteScan") || mutation.contains("delete_scan") {
            let scan_id_str = extract_id_arg(mutation, "deleteScan")
                .or_else(|| extract_id_arg(mutation, "delete_scan"));

            if let Some(id_str) = scan_id_str {
                if let Ok(uuid) = Uuid::parse_str(&id_str) {
                    let mut state = self.app_state.write().await;
                    match state.delete_scan(&uuid) {
                        Ok(_) => {
                            return GraphQLResponse::success(serde_json::json!({
                                "deleteScan": {
                                    "scanId": uuid.to_string(),
                                    "message": "Scan deleted successfully"
                                }
                            }));
                        }
                        Err(e) => {
                            return GraphQLResponse::error(&e.to_string());
                        }
                    }
                }
            }
            return GraphQLResponse::error("Invalid scan ID");
        }

        GraphQLResponse::error("Unknown mutation")
    }

    async fn resolve_health(&self) -> GraphQLResponse {
        let state = self.app_state.read().await;
        GraphQLResponse::success(serde_json::json!({
            "health": {
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "uptimeSeconds": state.uptime().as_secs(),
                "activeScans": state.active_scans(),
                "completedScans": state.completed_scans(),
            }
        }))
    }

    async fn resolve_scans(&self) -> GraphQLResponse {
        let state = self.app_state.read().await;
        let response = state.list_scans(1, 100);
        let scans: Vec<serde_json::Value> = response
            .scans
            .iter()
            .map(|s| {
                serde_json::json!({
                    "scanId": s.scan_id.to_string(),
                    "status": format!("{:?}", s.status).to_lowercase(),
                    "targetsCount": s.targets_count,
                    "portsCount": s.ports_count,
                    "startedAt": s.started_at.to_rfc3339(),
                    "completedAt": s.completed_at.map(|dt| dt.to_rfc3339()),
                })
            })
            .collect();

        GraphQLResponse::success(serde_json::json!({
            "scans": {
                "items": scans,
                "total": response.total,
                "page": response.page,
                "perPage": response.per_page,
            }
        }))
    }

    async fn resolve_scan(&self, scan_id: &Uuid) -> GraphQLResponse {
        let state = self.app_state.read().await;
        match state.get_scan_status(scan_id) {
            Some(status) => {
                let results = state.get_scan_results(scan_id);
                GraphQLResponse::success(serde_json::json!({
                    "scan": {
                        "scanId": status.scan_id.to_string(),
                        "status": format!("{:?}", status.status).to_lowercase(),
                        "progress": status.progress,
                        "targetsTotal": status.targets_total,
                        "targetsCompleted": status.targets_completed,
                        "portsTotal": status.ports_total,
                        "portsScanned": status.ports_scanned,
                        "startedAt": status.started_at.to_rfc3339(),
                        "updatedAt": status.updated_at.to_rfc3339(),
                        "completedAt": status.completed_at.map(|dt| dt.to_rfc3339()),
                        "results": results.map(|r| serde_json::json!({
                            "totalOpenPorts": r.total_open_ports,
                            "totalVulnerabilities": r.total_vulnerabilities,
                            "overallRiskScore": r.overall_risk_score,
                            "scanDurationMs": r.scan_duration_ms,
                        })),
                    }
                }))
            }
            None => GraphQLResponse::error("Scan not found"),
        }
    }

    async fn resolve_stats(&self) -> GraphQLResponse {
        let state = self.app_state.read().await;
        let stats = state.get_stats();
        GraphQLResponse::success(serde_json::json!({
            "stats": {
                "totalScans": stats.total_scans,
                "activeScans": stats.active_scans,
                "completedScans": stats.completed_scans,
                "failedScans": stats.failed_scans,
                "cancelledScans": stats.cancelled_scans,
                "totalTargetsScanned": stats.total_targets_scanned,
                "totalPortsScanned": stats.total_ports_scanned,
                "uptimeSeconds": stats.uptime_seconds,
            }
        }))
    }

    async fn resolve_server_info(&self) -> GraphQLResponse {
        GraphQLResponse::success(serde_json::json!({
            "serverInfo": {
                "name": "nemue",
                "version": env!("CARGO_PKG_VERSION"),
                "description": "Advanced Security Testing Framework",
                "apiVersion": "v1",
                "capabilities": [
                    "port_scanning",
                    "service_detection",
                    "os_detection",
                    "vulnerability_scanning",
                    "threat_intelligence",
                    "webhooks",
                    "cicd_integration",
                ],
            }
        }))
    }
}

fn extract_id_arg(query: &str, field_name: &str) -> Option<String> {
    let pattern = format!("{}(", field_name);
    if let Some(start) = query.find(&pattern) {
        let args_start = start + pattern.len();
        if let Some(end) = query[args_start..].find(')') {
            let args = &query[args_start..args_start + end];
            for arg in args.split(',') {
                let arg = arg.trim();
                if arg.contains("id:") {
                    let val = arg.split("id:").nth(1)?.trim();
                    let val = val.trim_matches('"').trim_matches('\'');
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

fn extract_string_list(
    query: &str,
    variables: Option<&HashMap<String, serde_json::Value>>,
    field: &str,
) -> Option<Vec<String>> {
    if let Some(vars) = variables {
        if let Some(val) = vars.get(field) {
            if let Some(arr) = val.as_array() {
                return Some(
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect(),
                );
            }
        }
    }

    let pattern = format!("{}:", field);
    if let Some(start) = query.find(&pattern) {
        let rest = &query[start + pattern.len()..];
        if let Some(bracket_start) = rest.find('[') {
            if let Some(bracket_end) = rest.find(']') {
                let inner = &rest[bracket_start + 1..bracket_end];
                let items: Vec<String> = inner
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !items.is_empty() {
                    return Some(items);
                }
            }
        }
    }

    None
}

fn extract_u16_list(
    query: &str,
    variables: Option<&HashMap<String, serde_json::Value>>,
    field: &str,
) -> Option<Vec<u16>> {
    if let Some(vars) = variables {
        if let Some(val) = vars.get(field) {
            if let Some(arr) = val.as_array() {
                return Some(
                    arr.iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u16))
                        .collect(),
                );
            }
        }
    }

    let pattern = format!("{}:", field);
    if let Some(start) = query.find(&pattern) {
        let rest = &query[start + pattern.len()..];
        if let Some(bracket_start) = rest.find('[') {
            if let Some(bracket_end) = rest.find(']') {
                let inner = &rest[bracket_start + 1..bracket_end];
                let items: Vec<u16> = inner
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').trim_matches('\''))
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if !items.is_empty() {
                    return Some(items);
                }
            }
        }
    }

    None
}

pub async fn graphql_handler(
    req: actix_web::web::Json<GraphQLRequest>,
    data: actix_web::web::Data<Arc<RwLock<AppState>>>,
) -> actix_web::HttpResponse {
    let executor = GraphQLExecutor::new(data.get_ref().clone());
    let response = executor.execute(req.into_inner()).await;
    actix_web::HttpResponse::Ok().json(response)
}

pub async fn graphql_get_handler(
    query: actix_web::web::Query<HashMap<String, String>>,
    data: actix_web::web::Data<Arc<RwLock<AppState>>>,
) -> actix_web::HttpResponse {
    let q = query.get("query").cloned().unwrap_or_default();
    let variables = query
        .get("variables")
        .and_then(|v| serde_json::from_str(v).ok());

    let request = GraphQLRequest {
        query: q,
        variables,
        operation_name: query.get("operationName").cloned(),
    };

    let executor = GraphQLExecutor::new(data.get_ref().clone());
    let response = executor.execute(request).await;
    actix_web::HttpResponse::Ok().json(response)
}

pub fn graphql_config(cfg: &mut actix_web::web::ServiceConfig) {
    cfg.service(
        actix_web::web::scope("/graphql")
            .route("", actix_web::web::post().to(graphql_handler))
            .route("", actix_web::web::get().to(graphql_get_handler)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_request_serialize() {
        let req = GraphQLRequest {
            query: "{ health { status } }".to_string(),
            variables: None,
            operation_name: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("health"));
    }

    #[test]
    fn test_graphql_request_with_variables() {
        let mut vars = HashMap::new();
        vars.insert("id".to_string(), serde_json::json!("test-123"));
        let req = GraphQLRequest {
            query: "query GetScan($id: ID!) { scan(id: $id) { status } }".to_string(),
            variables: Some(vars),
            operation_name: Some("GetScan".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("GetScan"));
    }

    #[test]
    fn test_graphql_response_success() {
        let resp = GraphQLResponse::success(serde_json::json!({"test": true}));
        assert!(resp.data.is_some());
        assert!(resp.errors.is_empty());
    }

    #[test]
    fn test_graphql_response_error() {
        let resp = GraphQLResponse::error("Something went wrong");
        assert!(resp.data.is_none());
        assert_eq!(resp.errors.len(), 1);
        assert_eq!(resp.errors[0].message, "Something went wrong");
    }

    #[test]
    fn test_graphql_error_serialize() {
        let err = GraphQLError {
            message: "Field not found".to_string(),
            locations: vec![GraphQLLocation { line: 1, column: 5 }],
            path: vec![serde_json::json!("scan")],
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("Field not found"));
        assert!(json.contains("\"line\":1"));
    }

    #[tokio::test]
    async fn test_executor_health_query() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let executor = GraphQLExecutor::new(state);
        let req = GraphQLRequest {
            query: "{ health { status version uptimeSeconds } }".to_string(),
            variables: None,
            operation_name: None,
        };
        let resp = executor.execute(req).await;
        assert!(resp.data.is_some());
        let data = resp.data.unwrap();
        assert_eq!(data["health"]["status"], "ok");
    }

    #[tokio::test]
    async fn test_executor_scans_query() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let executor = GraphQLExecutor::new(state);
        let req = GraphQLRequest {
            query: "{ scans { items total } }".to_string(),
            variables: None,
            operation_name: None,
        };
        let resp = executor.execute(req).await;
        assert!(resp.data.is_some());
        let data = resp.data.unwrap();
        assert_eq!(data["scans"]["total"], 0);
    }

    #[tokio::test]
    async fn test_executor_stats_query() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let executor = GraphQLExecutor::new(state);
        let req = GraphQLRequest {
            query: "{ stats { totalScans activeScans } }".to_string(),
            variables: None,
            operation_name: None,
        };
        let resp = executor.execute(req).await;
        assert!(resp.data.is_some());
        let data = resp.data.unwrap();
        assert_eq!(data["stats"]["totalScans"], 0);
    }

    #[tokio::test]
    async fn test_executor_server_info_query() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let executor = GraphQLExecutor::new(state);
        let req = GraphQLRequest {
            query: "{ serverInfo { name version } }".to_string(),
            variables: None,
            operation_name: None,
        };
        let resp = executor.execute(req).await;
        assert!(resp.data.is_some());
        let data = resp.data.unwrap();
        assert_eq!(data["serverInfo"]["name"], "nemue");
    }

    #[tokio::test]
    async fn test_executor_unknown_query() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let executor = GraphQLExecutor::new(state);
        let req = GraphQLRequest {
            query: "{ unknownField }".to_string(),
            variables: None,
            operation_name: None,
        };
        let resp = executor.execute(req).await;
        assert!(!resp.errors.is_empty());
    }

    #[tokio::test]
    async fn test_executor_start_scan_mutation() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let executor = GraphQLExecutor::new(state);
        let req = GraphQLRequest {
            query: r#"mutation { startScan(targets: ["192.168.1.1"], ports: [80, 443]) { scanId status } }"#.to_string(),
            variables: None,
            operation_name: None,
        };
        let resp = executor.execute(req).await;
        assert!(resp.data.is_some());
        let data = resp.data.unwrap();
        assert_eq!(data["startScan"]["status"], "queued");
    }

    #[tokio::test]
    async fn test_executor_start_scan_no_targets() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let executor = GraphQLExecutor::new(state);
        let req = GraphQLRequest {
            query: r#"mutation { startScan(targets: [], ports: [80]) { scanId } }"#.to_string(),
            variables: None,
            operation_name: None,
        };
        let resp = executor.execute(req).await;
        assert!(!resp.errors.is_empty());
    }

    #[tokio::test]
    async fn test_executor_scan_by_id() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let scan_id = {
            let mut s = state.write().await;
            let req = ScanRequest {
                targets: vec!["10.0.0.1".to_string()],
                ports: vec![80],
                scan_type: ScanType::Tcp,
                timing: TimingTemplate::Normal,
                enable_service_detection: false,
                enable_os_detection: false,
                enable_vuln_check: false,
                enable_threat_intel: false,
            };
            s.create_scan(req).await
        };

        let executor = GraphQLExecutor::new(state);
        let query = format!(
            r#"{{ scan(id: "{}") {{ scanId status progress }} }}"#,
            scan_id
        );
        let req = GraphQLRequest {
            query,
            variables: None,
            operation_name: None,
        };
        let resp = executor.execute(req).await;
        assert!(resp.data.is_some());
        let data = resp.data.unwrap();
        assert_eq!(data["scan"]["scanId"], scan_id.to_string());
    }

    #[tokio::test]
    async fn test_executor_scan_not_found() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let executor = GraphQLExecutor::new(state);
        let req = GraphQLRequest {
            query: r#"{ scan(id: "00000000-0000-0000-0000-000000000000") { scanId } }"#.to_string(),
            variables: None,
            operation_name: None,
        };
        let resp = executor.execute(req).await;
        assert!(!resp.errors.is_empty());
    }

    #[test]
    fn test_extract_id_arg() {
        let query = r#"{ scan(id: "abc-123") { status } }"#;
        let id = extract_id_arg(query, "scan");
        assert_eq!(id, Some("abc-123".to_string()));
    }

    #[test]
    fn test_extract_string_list_from_query() {
        let query = r#"mutation { startScan(targets: ["a.com", "b.com"], ports: [80]) }"#;
        let targets = extract_string_list(query, None, "targets");
        assert_eq!(
            targets,
            Some(vec!["a.com".to_string(), "b.com".to_string()])
        );
    }

    #[test]
    fn test_extract_u16_list_from_query() {
        let query = r#"mutation { startScan(targets: ["a.com"], ports: [80, 443, 8080]) }"#;
        let ports = extract_u16_list(query, None, "ports");
        assert_eq!(ports, Some(vec![80, 443, 8080]));
    }

    #[test]
    fn test_extract_string_list_from_variables() {
        let mut vars = HashMap::new();
        vars.insert("targets".to_string(), serde_json::json!(["x.com", "y.com"]));
        let result = extract_string_list("query", Some(&vars), "targets");
        assert_eq!(result, Some(vec!["x.com".to_string(), "y.com".to_string()]));
    }

    #[test]
    fn test_graphql_response_serialize() {
        let resp = GraphQLResponse::success(serde_json::json!({"health": {"status": "ok"}}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("health"));
        assert!(!json.contains("errors"));
    }

    #[test]
    fn test_graphql_response_error_serialize() {
        let resp = GraphQLResponse::error("test error");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("test error"));
        assert!(json.contains("errors"));
    }

    #[test]
    fn test_unsupported_operation() {
        let state = Arc::new(RwLock::new(AppState::new()));
        let executor = GraphQLExecutor::new(state);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resp = rt.block_on(async {
            let req = GraphQLRequest {
                query: "subscription { scanUpdates }".to_string(),
                variables: None,
                operation_name: None,
            };
            executor.execute(req).await
        });
        assert!(!resp.errors.is_empty());
    }
}
