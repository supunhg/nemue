use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::models::*;
use super::state::AppState;

/// Health check endpoint
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

/// Start a new scan
pub async fn start_scan(
    req: web::Json<ScanRequest>,
    data: web::Data<Arc<RwLock<AppState>>>,
) -> impl Responder {
    // Validate request
    if req.targets.is_empty() {
        let error = ApiError::bad_request("At least one target is required");
        return HttpResponse::BadRequest().json(error);
    }

    if req.ports.is_empty() {
        let error = ApiError::bad_request("At least one port is required");
        return HttpResponse::BadRequest().json(error);
    }

    let mut state = data.write().await;
    
    // Create new scan
    let scan_id = state.create_scan(req.into_inner()).await;
    
    HttpResponse::Accepted().json(serde_json::json!({
        "scan_id": scan_id,
        "status": "queued",
        "message": "Scan queued successfully"
    }))
}

/// Get scan status
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

/// Get scan results
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

/// Cancel a running scan
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

/// List all scans
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

/// Delete a scan and its results
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

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<usize>,
    pub per_page: Option<usize>,
}
