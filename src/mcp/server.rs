// MCP Server implementation for Nemue
// Exposes network scanning tools via Model Context Protocol

use rmcp::{
    handler::server::ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, Content,
        Implementation, ListToolsResult, PaginatedRequestParams, ServerInfo,
    },
    service::RequestContext,
    RoleServer,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::scanner::ScanEngine;

pub struct NemueMcpServer {
    engine: Arc<Mutex<ScanEngine>>,
}

impl NemueMcpServer {
    pub fn new() -> anyhow::Result<Self> {
        let engine = ScanEngine::new(1000, 1000)?;
        Ok(Self {
            engine: Arc::new(Mutex::new(engine)),
        })
    }

    pub fn with_engine(engine: ScanEngine) -> Self {
        Self {
            engine: Arc::new(Mutex::new(engine)),
        }
    }
}

impl ServerHandler for NemueMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: Default::default(),
            server_info: Implementation {
                name: "nemue".into(),
                title: Some("Nemue Network Scanner".into()),
                version: env!("CARGO_PKG_VERSION").into(),
                description: Some("Advanced network security scanner with MCP support".into()),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "Nemue network scanner. Use nemue_scan for full scans, nemue_quick_scan for fast reconnaissance.".into()
            ),
        }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, rmcp::ErrorData>> + Send {
        let tools = super::tools::get_tools();
        std::future::ready(Ok(ListToolsResult {
            meta: None,
            next_cursor: None,
            tools,
        }))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, rmcp::ErrorData>> + Send {
        let engine = self.engine.clone();
        async move {
            let args = request.arguments
                .map(|m| serde_json::Value::Object(m))
                .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
            let name = request.name.to_string();
            match name.as_str() {
                "nemue_scan" => handle_scan(&engine, &args).await,
                "nemue_quick_scan" => handle_quick_scan(&engine, &args).await,
                "nemue_service_detect" => handle_service_detect(&engine, &args).await,
                "nemue_os_detect" => handle_os_detect(&engine, &args).await,
                "nemue_ssl_check" => handle_ssl_check(&args).await,
                "nemue_host_discovery" => handle_host_discovery(&args).await,

                "nemue_vuln_scan" => handle_vuln_scan(&engine, &args).await,
                _ => Err(rmcp::ErrorData::method_not_found::<rmcp::model::CallToolRequestMethod>()),
            }
        }
    }
}

fn text_result(text: String) -> CallToolResult {
    CallToolResult::success(vec![Content::text(text)])
}

fn json_result(value: Value) -> CallToolResult {
    match serde_json::to_string_pretty(&value) {
        Ok(s) => text_result(s),
        Err(e) => text_result(format!("JSON error: {}", e)),
    }
}

fn error_result(msg: String) -> CallToolResult {
    CallToolResult::error(vec![Content::text(msg)])
}

async fn handle_scan(engine: &Arc<Mutex<ScanEngine>>, args: &Value) -> Result<CallToolResult, rmcp::ErrorData> {
    let target = args["target"].as_str()
        .ok_or_else(|| rmcp::ErrorData::invalid_params("target required", None))?;
    let ports = args["ports"].as_str().unwrap_or("top-1000");
    let scan_type = args["scan_type"].as_str().unwrap_or("connect");

    let engine = engine.lock().await;
    match engine.scan(target, ports, scan_type).await {
        Ok(results) => {
            let open_ports: Vec<Value> = results.results.iter()
                .filter(|r| r.state == crate::scanner::PortState::Open)
                .map(|r| json!({"port": r.port, "protocol": r.protocol.to_string(), "service": r.service}))
                .collect();
            Ok(json_result(json!({
                "scan_id": uuid::Uuid::new_v4().to_string(),
                "target": target,
                "port_count": results.port_count,
                "open_ports": open_ports,
                "scan_duration_ms": (results.scan_end - results.scan_start).num_milliseconds(),
            })))
        }
        Err(e) => Ok(error_result(format!("Scan failed: {}", e))),
    }
}

async fn handle_quick_scan(engine: &Arc<Mutex<ScanEngine>>, args: &Value) -> Result<CallToolResult, rmcp::ErrorData> {
    let target = args["target"].as_str()
        .ok_or_else(|| rmcp::ErrorData::invalid_params("target required", None))?;
    let top = args["top_ports"].as_u64().unwrap_or(100);

    let engine = engine.lock().await;
    match engine.scan(target, &format!("top-{}", top), "connect").await {
        Ok(results) => {
            let open: Vec<Value> = results.results.iter()
                .filter(|r| r.state == crate::scanner::PortState::Open)
                .map(|r| json!({"port": r.port, "service": r.service}))
                .collect();
            Ok(json_result(json!({
                "target": target,
                "open_ports": open,
                "scan_duration_ms": (results.scan_end - results.scan_start).num_milliseconds(),
            })))
        }
        Err(e) => Ok(error_result(format!("Quick scan failed: {}", e))),
    }
}

async fn handle_service_detect(engine: &Arc<Mutex<ScanEngine>>, args: &Value) -> Result<CallToolResult, rmcp::ErrorData> {
    let target = args["target"].as_str()
        .ok_or_else(|| rmcp::ErrorData::invalid_params("target required", None))?;
    let ports = args["ports"].as_str()
        .ok_or_else(|| rmcp::ErrorData::invalid_params("ports required", None))?;

    let engine = engine.lock().await;
    match engine.scan(target, ports, "connect").await {
        Ok(results) => {
            let services: Vec<Value> = results.results.iter()
                .filter(|r| r.state == crate::scanner::PortState::Open)
                .map(|r| json!({"port": r.port, "service": r.service, "service_info": r.service_info}))
                .collect();
            Ok(json_result(json!({"target": target, "services": services})))
        }
        Err(e) => Ok(error_result(format!("Service detection failed: {}", e))),
    }
}

async fn handle_os_detect(engine: &Arc<Mutex<ScanEngine>>, args: &Value) -> Result<CallToolResult, rmcp::ErrorData> {
    let target = args["target"].as_str()
        .ok_or_else(|| rmcp::ErrorData::invalid_params("target required", None))?;

    let engine = engine.lock().await;
    match engine.scan(target, "top-20", "connect").await {
        Ok(results) => Ok(json_result(json!({
            "target": target,
            "os_fingerprints": results.os_fingerprints,
        }))),
        Err(e) => Ok(error_result(format!("OS detection failed: {}", e))),
    }
}

async fn handle_ssl_check(args: &Value) -> Result<CallToolResult, rmcp::ErrorData> {
    let target = args["target"].as_str()
        .ok_or_else(|| rmcp::ErrorData::invalid_params("target required", None))?;
    let port = args["port"].as_u64().unwrap_or(443) as u16;

    let target_ip: std::net::IpAddr = target.parse()
        .map_err(|_| rmcp::ErrorData::invalid_params("invalid IP address", None))?;
    let config = crate::ssl::SslConfig {
        target: target_ip,
        port,
        timeout: std::time::Duration::from_secs(10),
        check_vulnerabilities: true,
        enumerate_ciphers: false,
        validate_certificates: true,
    };
    let ssl_scanner = crate::ssl::SslScanner::new(config);
    match ssl_scanner.scan().await {
        Ok(result) => {
            let val = serde_json::to_value(&result).unwrap_or(json!({"error": "serialization failed"}));
            Ok(json_result(val))
        }
        Err(e) => Ok(error_result(format!("SSL check failed: {}", e))),
    }
}

async fn handle_host_discovery(args: &Value) -> Result<CallToolResult, rmcp::ErrorData> {
    let target = args["target"].as_str()
        .ok_or_else(|| rmcp::ErrorData::invalid_params("target required", None))?;

    let engine = ScanEngine::new(1000, 1000)
        .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;

    match engine.scan(target, "22,80,443", "connect").await {
        Ok(results) => {
            let hosts: Vec<Value> = results.results.iter()
                .filter(|r| r.state == crate::scanner::PortState::Open)
                .map(|r| json!({"host": r.target, "port": r.port}))
                .collect();
            Ok(json_result(json!({"target": target, "alive_hosts": hosts})))
        }
        Err(e) => Ok(error_result(format!("Host discovery failed: {}", e))),
    }
}

async fn handle_vuln_scan(engine: &Arc<Mutex<ScanEngine>>, args: &Value) -> Result<CallToolResult, rmcp::ErrorData> {
    let target = args["target"].as_str()
        .ok_or_else(|| rmcp::ErrorData::invalid_params("target required", None))?;
    let ports = args["ports"].as_str().unwrap_or("top-1000");

    let engine = engine.lock().await;
    match engine.scan(target, ports, "connect").await {
        Ok(results) => {
            let open: Vec<Value> = results.results.iter()
                .filter(|r| r.state == crate::scanner::PortState::Open)
                .map(|r| json!({"port": r.port, "service": r.service}))
                .collect();
            Ok(json_result(json!({
                "target": target,
                "open_ports": open,
                "total_scanned": results.port_count,
            })))
        }
        Err(e) => Ok(error_result(format!("Vuln scan failed: {}", e))),
    }
}

