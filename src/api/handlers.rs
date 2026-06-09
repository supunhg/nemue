use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::models::*;
use super::state::AppState;

pub async fn health(data: web::Data<Arc<RwLock<AppState>>>) -> impl Responder {
    let state = data.read().await;
    let response = HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.uptime().as_secs(),
        active_scans: state.active_scans(),
        completed_scans: state.completed_scans(),
    };
    HttpResponse::Ok().json(response)
}

pub async fn server_info() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "name": "nemue",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Advanced Security Testing Framework",
        "capabilities": [
            "port_scanning",
            "service_detection",
            "os_detection",
            "vulnerability_scanning",
            "threat_intelligence",
            "webhooks",
            "cicd_integration",
            "siem_integration"
        ],
        "api_version": "v1",
        "documentation": "/openapi.json"
    }))
}

pub async fn scan_stats(data: web::Data<Arc<RwLock<AppState>>>) -> impl Responder {
    let state = data.read().await;
    let stats = state.get_stats();
    HttpResponse::Ok().json(stats)
}

pub async fn start_scan(
    req: web::Json<ScanRequest>,
    data: web::Data<Arc<RwLock<AppState>>>,
) -> impl Responder {
    if req.targets.is_empty() {
        let error = ApiError::bad_request("At least one target is required");
        return HttpResponse::BadRequest().json(error);
    }

    if req.ports.is_empty() {
        let error = ApiError::bad_request("At least one port is required");
        return HttpResponse::BadRequest().json(error);
    }

    let mut state = data.write().await;
    let scan_id = state.create_scan(req.into_inner()).await;

    HttpResponse::Accepted().json(serde_json::json!({
        "scan_id": scan_id,
        "status": "queued",
        "message": "Scan queued successfully"
    }))
}

pub async fn get_scan_status(
    scan_id: web::Path<Uuid>,
    data: web::Data<Arc<RwLock<AppState>>>,
) -> impl Responder {
    let state = data.read().await;

    match state.get_scan_status(&scan_id) {
        Some(status) => HttpResponse::Ok().json(status),
        None => {
            let error = ApiError::not_found("Scan not found");
            HttpResponse::NotFound().json(error)
        }
    }
}

pub async fn get_scan_results(
    scan_id: web::Path<Uuid>,
    data: web::Data<Arc<RwLock<AppState>>>,
) -> impl Responder {
    let state = data.read().await;

    match state.get_scan_results(&scan_id) {
        Some(results) => HttpResponse::Ok().json(results),
        None => {
            let error = ApiError::not_found("Scan results not found");
            HttpResponse::NotFound().json(error)
        }
    }
}

pub async fn cancel_scan(
    scan_id: web::Path<Uuid>,
    data: web::Data<Arc<RwLock<AppState>>>,
) -> impl Responder {
    let mut state = data.write().await;

    match state.cancel_scan(&scan_id).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "scan_id": scan_id.to_string(),
            "status": "cancelled",
            "message": "Scan cancelled successfully"
        })),
        Err(e) => {
            let error = ApiError::bad_request(&e.to_string());
            HttpResponse::BadRequest().json(error)
        }
    }
}

pub async fn list_scans(
    query: web::Query<PaginationQuery>,
    data: web::Data<Arc<RwLock<AppState>>>,
) -> impl Responder {
    let state = data.read().await;
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20).min(100);

    let response = state.list_scans(page, per_page);
    HttpResponse::Ok().json(response)
}

pub async fn delete_scan(
    scan_id: web::Path<Uuid>,
    data: web::Data<Arc<RwLock<AppState>>>,
) -> impl Responder {
    let mut state = data.write().await;

    match state.delete_scan(&scan_id) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "scan_id": scan_id.to_string(),
            "message": "Scan deleted successfully"
        })),
        Err(e) => {
            let error = ApiError::not_found(&e.to_string());
            HttpResponse::NotFound().json(error)
        }
    }
}

pub async fn register_webhook(
    req: web::Json<RegisterWebhookRequest>,
    data: web::Data<Arc<RwLock<AppState>>>,
) -> impl Responder {
    if req.url.is_empty() {
        return HttpResponse::BadRequest().json(ApiError::bad_request("Webhook URL is required"));
    }

    let mut state = data.write().await;
    let webhook_id = state.register_webhook(req.into_inner());

    HttpResponse::Created().json(serde_json::json!({
        "webhook_id": webhook_id,
        "message": "Webhook registered successfully"
    }))
}

pub async fn list_webhooks(data: web::Data<Arc<RwLock<AppState>>>) -> impl Responder {
    let state = data.read().await;
    let webhooks = state.list_webhooks();
    HttpResponse::Ok().json(serde_json::json!({
        "webhooks": webhooks,
        "total": webhooks.len()
    }))
}

pub async fn delete_webhook(
    webhook_id: web::Path<Uuid>,
    data: web::Data<Arc<RwLock<AppState>>>,
) -> impl Responder {
    let mut state = data.write().await;

    match state.delete_webhook(&webhook_id) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "webhook_id": webhook_id.to_string(),
            "message": "Webhook deleted successfully"
        })),
        Err(e) => HttpResponse::NotFound().json(ApiError::not_found(&e.to_string())),
    }
}

pub async fn test_webhook(
    webhook_id: web::Path<Uuid>,
    data: web::Data<Arc<RwLock<AppState>>>,
) -> impl Responder {
    let state = data.read().await;

    match state.get_webhook_config(&webhook_id) {
        Some(config) => {
            let client = super::webhooks::WebhookClient::new();
            let test_event = super::webhooks::ScanEvent {
                event_type: "test".to_string(),
                scan_id: "test-ping".to_string(),
                status: "test".to_string(),
                targets: vec!["test.example.com".to_string()],
                total_open_ports: 0,
                total_vulnerabilities: 0,
                risk_score: 0,
                timestamp: chrono::Utc::now().to_rfc3339(),
                summary: "Webhook test delivery from Nemue".to_string(),
            };

            let delivery = client.send(&config, &test_event).await;
            HttpResponse::Ok().json(delivery)
        }
        None => HttpResponse::NotFound().json(ApiError::not_found("Webhook not found")),
    }
}

pub async fn get_cicd_config(data: web::Data<Arc<RwLock<AppState>>>) -> impl Responder {
    let state = data.read().await;
    let config = state.get_cicd_config();
    HttpResponse::Ok().json(config)
}

pub async fn evaluate_cicd(
    req: web::Json<CiCdEvaluateRequest>,
    data: web::Data<Arc<RwLock<AppState>>>,
) -> impl Responder {
    let state = data.read().await;
    let config = state.get_cicd_config().clone();
    let runner = super::cicd::CiCdRunner::new(config);

    let result = runner.evaluate(
        &req.scan_id,
        req.targets_scanned,
        req.total_open_ports,
        req.total_vulnerabilities,
        req.risk_score,
    );

    HttpResponse::Ok().json(result)
}

pub async fn openapi_spec() -> impl Responder {
    let spec = serde_json::json!({
        "openapi": "3.0.3",
        "info": {
            "title": "Nemue Security Scanner API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "REST API for the Nemue Advanced Security Testing Framework",
            "license": { "name": "MIT" }
        },
        "servers": [
            { "url": "http://localhost:8080", "description": "Local server" }
        ],
        "paths": {
            "/health": {
                "get": {
                    "tags": ["system"],
                    "summary": "Health check",
                    "operationId": "healthCheck",
                    "responses": {
                        "200": {
                            "description": "Server is healthy",
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/HealthResponse" } } }
                        }
                    }
                }
            },
            "/api/v1/info": {
                "get": {
                    "tags": ["system"],
                    "summary": "Server information and capabilities",
                    "operationId": "serverInfo",
                    "responses": { "200": { "description": "Server info" } }
                }
            },
            "/api/v1/stats": {
                "get": {
                    "tags": ["system"],
                    "summary": "Aggregated scan statistics",
                    "operationId": "scanStats",
                    "responses": { "200": { "description": "Statistics" } }
                }
            },
            "/api/v1/scans": {
                "post": {
                    "tags": ["scans"],
                    "summary": "Start a new scan",
                    "operationId": "startScan",
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ScanRequest" } } }
                    },
                    "responses": {
                        "202": { "description": "Scan queued" },
                        "400": { "description": "Invalid request" }
                    }
                },
                "get": {
                    "tags": ["scans"],
                    "summary": "List all scans",
                    "operationId": "listScans",
                    "parameters": [
                        { "name": "page", "in": "query", "schema": { "type": "integer", "default": 1 } },
                        { "name": "per_page", "in": "query", "schema": { "type": "integer", "default": 20 } }
                    ],
                    "responses": { "200": { "description": "Scan list" } }
                }
            },
            "/api/v1/scans/{scan_id}": {
                "get": {
                    "tags": ["scans"],
                    "summary": "Get scan status",
                    "operationId": "getScanStatus",
                    "parameters": [
                        { "name": "scan_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
                    ],
                    "responses": {
                        "200": { "description": "Scan status" },
                        "404": { "description": "Scan not found" }
                    }
                },
                "delete": {
                    "tags": ["scans"],
                    "summary": "Delete a scan",
                    "operationId": "deleteScan",
                    "parameters": [
                        { "name": "scan_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
                    ],
                    "responses": {
                        "200": { "description": "Scan deleted" },
                        "404": { "description": "Scan not found" }
                    }
                }
            },
            "/api/v1/scans/{scan_id}/results": {
                "get": {
                    "tags": ["scans"],
                    "summary": "Get scan results",
                    "operationId": "getScanResults",
                    "parameters": [
                        { "name": "scan_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
                    ],
                    "responses": {
                        "200": { "description": "Scan results" },
                        "404": { "description": "Results not found" }
                    }
                }
            },
            "/api/v1/scans/{scan_id}/cancel": {
                "post": {
                    "tags": ["scans"],
                    "summary": "Cancel a running scan",
                    "operationId": "cancelScan",
                    "parameters": [
                        { "name": "scan_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
                    ],
                    "responses": {
                        "200": { "description": "Scan cancelled" },
                        "400": { "description": "Cannot cancel" }
                    }
                }
            },
            "/api/v1/webhooks": {
                "post": {
                    "tags": ["webhooks"],
                    "summary": "Register a webhook",
                    "operationId": "registerWebhook",
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/RegisterWebhookRequest" } } }
                    },
                    "responses": { "201": { "description": "Webhook registered" } }
                },
                "get": {
                    "tags": ["webhooks"],
                    "summary": "List registered webhooks",
                    "operationId": "listWebhooks",
                    "responses": { "200": { "description": "Webhook list" } }
                }
            },
            "/api/v1/webhooks/{webhook_id}": {
                "delete": {
                    "tags": ["webhooks"],
                    "summary": "Delete a webhook",
                    "operationId": "deleteWebhook",
                    "parameters": [
                        { "name": "webhook_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
                    ],
                    "responses": { "200": { "description": "Webhook deleted" } }
                }
            },
            "/api/v1/webhooks/{webhook_id}/test": {
                "post": {
                    "tags": ["webhooks"],
                    "summary": "Send test delivery to webhook",
                    "operationId": "testWebhook",
                    "parameters": [
                        { "name": "webhook_id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }
                    ],
                    "responses": { "200": { "description": "Delivery result" } }
                }
            },
            "/api/v1/cicd/config": {
                "get": {
                    "tags": ["cicd"],
                    "summary": "Get CI/CD integration configuration",
                    "operationId": "getCiCdConfig",
                    "responses": { "200": { "description": "CI/CD config" } }
                }
            },
            "/api/v1/cicd/evaluate": {
                "post": {
                    "tags": ["cicd"],
                    "summary": "Evaluate scan results for CI/CD pipeline",
                    "operationId": "evaluateCiCd",
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/CiCdEvaluateRequest" } } }
                    },
                    "responses": { "200": { "description": "CI/CD evaluation result" } }
                }
            }
        },
        "components": {
            "schemas": {
                "ScanRequest": {
                    "type": "object",
                    "required": ["targets", "ports"],
                    "properties": {
                        "targets": { "type": "array", "items": { "type": "string" } },
                        "ports": { "type": "array", "items": { "type": "integer" } },
                        "scan_type": { "type": "string", "enum": ["tcp", "udp", "syn", "connect"] },
                        "timing": { "type": "string", "enum": ["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"] },
                        "enable_service_detection": { "type": "boolean" },
                        "enable_os_detection": { "type": "boolean" },
                        "enable_vuln_check": { "type": "boolean" },
                        "enable_threat_intel": { "type": "boolean" }
                    }
                },
                "HealthResponse": {
                    "type": "object",
                    "properties": {
                        "status": { "type": "string" },
                        "version": { "type": "string" },
                        "uptime_seconds": { "type": "integer" },
                        "active_scans": { "type": "integer" },
                        "completed_scans": { "type": "integer" }
                    }
                },
                "RegisterWebhookRequest": {
                    "type": "object",
                    "required": ["url", "provider"],
                    "properties": {
                        "url": { "type": "string" },
                        "provider": { "type": "string", "enum": ["slack", "discord", "teams", "custom"] },
                        "secret": { "type": "string" },
                        "max_retries": { "type": "integer" }
                    }
                },
                "CiCdEvaluateRequest": {
                    "type": "object",
                    "required": ["scan_id"],
                    "properties": {
                        "scan_id": { "type": "string" },
                        "targets_scanned": { "type": "integer" },
                        "total_open_ports": { "type": "integer" },
                        "total_vulnerabilities": { "type": "integer" },
                        "risk_score": { "type": "integer" }
                    }
                }
            }
        }
    });

    HttpResponse::Ok().json(spec)
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
}
