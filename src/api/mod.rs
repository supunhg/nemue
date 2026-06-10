use actix_web::{web, App, HttpServer};
use actix_cors::Cors;
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod models;
pub mod handlers;
pub mod state;
pub mod auth;
pub mod webhooks;
pub mod cicd;
pub mod security;
pub mod websocket;
pub mod graphql;
pub mod versioning;
pub mod docs;
pub mod rate_limit;
pub mod cache;
pub mod pagination;
pub mod filtering;

use state::AppState;

/// Start the REST API server with all endpoints
pub async fn start_server(bind_addr: &str) -> std::io::Result<()> {
    let app_state = Arc::new(RwLock::new(AppState::new()));

    println!("🚀 Starting Nemue API server on http://{}", bind_addr);
    println!("📚 API Endpoints:");
    println!("   GET    /health                         - Health check");
    println!("   GET    /api/v1/info                     - Server info & capabilities");
    println!("   POST   /api/v1/scans                    - Start new scan");
    println!("   GET    /api/v1/scans                    - List all scans");
    println!("   GET    /api/v1/scans/:id                - Get scan status");
    println!("   GET    /api/v1/scans/:id/results        - Get scan results");
    println!("   POST   /api/v1/scans/:id/cancel         - Cancel scan");
    println!("   DELETE /api/v1/scans/:id                 - Delete scan");
    println!("   GET    /api/v1/stats                     - Aggregated statistics");
    println!("   POST   /api/v1/webhooks                 - Register webhook");
    println!("   GET    /api/v1/webhooks                 - List webhooks");
    println!("   DELETE /api/v1/webhooks/:id              - Delete webhook");
    println!("   POST   /api/v1/webhooks/:id/test         - Test webhook");
    println!("   GET    /api/v1/cicd/config              - Get CI/CD config");
    println!("   POST   /api/v1/cicd/evaluate            - Evaluate CI/CD results");
    println!("   WS     /ws/scans                        - WebSocket real-time updates");
    println!("   POST   /graphql                          - GraphQL endpoint");
    println!("   GET    /graphql                          - GraphQL playground");
    println!("   GET    /api/versions                     - API version info");
    println!("   GET    /openapi.json                     - OpenAPI specification");
    println!("   GET    /docs                             - Interactive API documentation");
    println!("   GET    /docs/examples                    - Code examples");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(actix_web::middleware::Logger::default())
            .wrap(cors)
            .route("/health", web::get().to(handlers::health))
            .route("/openapi.json", web::get().to(docs::openapi_spec_handler))
            .route("/api/versions", web::get().to(handlers::api_versions))
            .configure(websocket::ws_config)
            .configure(graphql::graphql_config)
            .configure(docs::docs_config)
            .service(
                web::scope("/api/v1")
                    .route("/info", web::get().to(handlers::server_info))
                    .route("/stats", web::get().to(handlers::scan_stats))
                    .route("/scans", web::post().to(handlers::start_scan))
                    .route("/scans", web::get().to(handlers::list_scans))
                    .route("/scans/{scan_id}", web::get().to(handlers::get_scan_status))
                    .route("/scans/{scan_id}/results", web::get().to(handlers::get_scan_results))
                    .route("/scans/{scan_id}/cancel", web::post().to(handlers::cancel_scan))
                    .route("/scans/{scan_id}", web::delete().to(handlers::delete_scan))
                    .route("/webhooks", web::post().to(handlers::register_webhook))
                    .route("/webhooks", web::get().to(handlers::list_webhooks))
                    .route("/webhooks/{webhook_id}", web::delete().to(handlers::delete_webhook))
                    .route("/webhooks/{webhook_id}/test", web::post().to(handlers::test_webhook))
                    .route("/cicd/config", web::get().to(handlers::get_cicd_config))
                    .route("/cicd/evaluate", web::post().to(handlers::evaluate_cicd))
            )
    })
    .bind(bind_addr)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use models::*;

    #[actix_web::test]
    async fn test_health_endpoint() {
        let app_state = Arc::new(RwLock::new(AppState::new()));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state))
                .route("/health", web::get().to(handlers::health)),
        )
        .await;

        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_start_scan_endpoint() {
        let app_state = Arc::new(RwLock::new(AppState::new()));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state))
                .route("/scans", web::post().to(handlers::start_scan)),
        )
        .await;

        let scan_req = ScanRequest {
            targets: vec!["192.168.1.1".to_string()],
            ports: vec![80, 443],
            scan_type: ScanType::Tcp,
            timing: TimingTemplate::Normal,
            enable_service_detection: false,
            enable_os_detection: false,
            enable_vuln_check: false,
            enable_threat_intel: false,
        };

        let req = test::TestRequest::post()
            .uri("/scans")
            .set_json(&scan_req)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 202); // Accepted
    }

    #[actix_web::test]
    async fn test_scan_not_found() {
        let app_state = Arc::new(RwLock::new(AppState::new()));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state))
                .route("/scans/{scan_id}", web::get().to(handlers::get_scan_status)),
        )
        .await;

        let fake_uuid = uuid::Uuid::new_v4();
        let req = test::TestRequest::get()
            .uri(&format!("/scans/{}", fake_uuid))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 404); // Not Found
    }

    #[actix_web::test]
    async fn test_server_info_endpoint() {
        let app_state = Arc::new(RwLock::new(AppState::new()));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state))
                .route("/info", web::get().to(handlers::server_info)),
        )
        .await;

        let req = test::TestRequest::get().uri("/info").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_stats_endpoint() {
        let app_state = Arc::new(RwLock::new(AppState::new()));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state))
                .route("/stats", web::get().to(handlers::scan_stats)),
        )
        .await;

        let req = test::TestRequest::get().uri("/stats").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_openapi_endpoint() {
        let app_state = Arc::new(RwLock::new(AppState::new()));
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(app_state))
                .route("/openapi.json", web::get().to(handlers::openapi_spec)),
        )
        .await;

        let req = test::TestRequest::get().uri("/openapi.json").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[tokio::test]
    async fn test_app_state_create_scan() {
        let mut state = AppState::new();
        let request = ScanRequest {
            targets: vec!["192.168.1.1".to_string()],
            ports: vec![80],
            scan_type: ScanType::Tcp,
            timing: TimingTemplate::Normal,
            enable_service_detection: false,
            enable_os_detection: false,
            enable_vuln_check: false,
            enable_threat_intel: false,
        };

        let scan_id = state.create_scan(request).await;
        let status = state.get_scan_status(&scan_id);
        assert!(status.is_some());
        assert_eq!(status.unwrap().status, ScanState::Queued);
    }

    #[tokio::test]
    async fn test_app_state_cancel_scan() {
        let mut state = AppState::new();
        let request = ScanRequest {
            targets: vec!["192.168.1.1".to_string()],
            ports: vec![80],
            scan_type: ScanType::Tcp,
            timing: TimingTemplate::Normal,
            enable_service_detection: false,
            enable_os_detection: false,
            enable_vuln_check: false,
            enable_threat_intel: false,
        };

        let scan_id = state.create_scan(request).await;
        let result = state.cancel_scan(&scan_id).await;
        assert!(result.is_ok());

        let status = state.get_scan_status(&scan_id).unwrap();
        assert_eq!(status.status, ScanState::Cancelled);
    }

    #[tokio::test]
    async fn test_app_state_list_scans() {
        let mut state = AppState::new();

        for i in 0..5 {
            let request = ScanRequest {
                targets: vec![format!("192.168.1.{}", i)],
                ports: vec![80],
                scan_type: ScanType::Tcp,
                timing: TimingTemplate::Normal,
                enable_service_detection: false,
                enable_os_detection: false,
                enable_vuln_check: false,
                enable_threat_intel: false,
            };
            state.create_scan(request).await;
        }

        let response = state.list_scans(1, 3);
        assert_eq!(response.total, 5);
        assert_eq!(response.scans.len(), 3);
        assert_eq!(response.per_page, 3);
    }

    #[tokio::test]
    async fn test_app_state_stats() {
        let mut state = AppState::new();

        let request = ScanRequest {
            targets: vec!["10.0.0.1".to_string()],
            ports: vec![80, 443],
            scan_type: ScanType::Tcp,
            timing: TimingTemplate::Normal,
            enable_service_detection: false,
            enable_os_detection: false,
            enable_vuln_check: false,
            enable_threat_intel: false,
        };
        state.create_scan(request).await;

        let stats = state.get_stats();
        assert_eq!(stats.total_scans, 1);
    }
}
