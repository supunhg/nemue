use actix_web::{test, web, App};
use nemue::api::{handlers, models::*, state::AppState};
use std::sync::Arc;
use tokio::sync::RwLock;

fn create_test_app_state() -> Arc<RwLock<AppState>> {
    Arc::new(RwLock::new(AppState::new()))
}

#[actix_web::test]
async fn test_health_endpoint_returns_200() {
    let app_state = create_test_app_state();
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
async fn test_server_info_returns_capabilities() {
    let app_state = create_test_app_state();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(app_state))
            .route("/info", web::get().to(handlers::server_info)),
    )
    .await;

    let req = test::TestRequest::get().uri("/info").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.get("version").is_some());
}

#[actix_web::test]
async fn test_start_scan_returns_202() {
    let app_state = create_test_app_state();
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
    assert_eq!(resp.status(), 202);
}

#[actix_web::test]
async fn test_list_scans_returns_paginated() {
    let app_state = create_test_app_state();
    {
        let mut state = app_state.write().await;
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
    }

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(app_state))
            .route("/scans", web::get().to(handlers::list_scans)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/scans?page=1&per_page=3")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_get_nonexistent_scan_returns_404() {
    let app_state = create_test_app_state();
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
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_scan_lifecycle_create_cancel() {
    let app_state = create_test_app_state();

    let scan_id;
    {
        let mut state = app_state.write().await;
        let request = ScanRequest {
            targets: vec!["10.0.0.1".to_string()],
            ports: vec![80],
            scan_type: ScanType::Tcp,
            timing: TimingTemplate::Normal,
            enable_service_detection: false,
            enable_os_detection: false,
            enable_vuln_check: false,
            enable_threat_intel: false,
        };
        scan_id = state.create_scan(request).await;
    }

    {
        let state = app_state.read().await;
        let status = state.get_scan_status(&scan_id);
        assert!(status.is_some());
        assert_eq!(status.unwrap().status, ScanState::Queued);
    }

    {
        let mut state = app_state.write().await;
        let result = state.cancel_scan(&scan_id).await;
        assert!(result.is_ok());
    }

    {
        let state = app_state.read().await;
        let status = state.get_scan_status(&scan_id).unwrap();
        assert_eq!(status.status, ScanState::Cancelled);
    }
}

#[actix_web::test]
async fn test_stats_endpoint_returns_aggregates() {
    let app_state = create_test_app_state();
    {
        let mut state = app_state.write().await;
        for i in 0..3 {
            let request = ScanRequest {
                targets: vec![format!("10.0.0.{}", i)],
                ports: vec![80, 443],
                scan_type: ScanType::Tcp,
                timing: TimingTemplate::Normal,
                enable_service_detection: false,
                enable_os_detection: false,
                enable_vuln_check: false,
                enable_threat_intel: false,
            };
            state.create_scan(request).await;
        }
    }

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(app_state))
            .route("/stats", web::get().to(handlers::scan_stats)),
    )
    .await;

    let req = test::TestRequest::get().uri("/stats").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.get("total_scans").is_some());
}

#[actix_web::test]
async fn test_app_state_list_scans_pagination() {
    let mut state = AppState::new();

    for i in 0..10 {
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

    let page1 = state.list_scans(1, 3);
    assert_eq!(page1.total, 10);
    assert_eq!(page1.scans.len(), 3);
    assert_eq!(page1.page, 1);
    assert_eq!(page1.per_page, 3);

    let page2 = state.list_scans(2, 3);
    assert_eq!(page2.scans.len(), 3);
    assert_eq!(page2.page, 2);

    let page4 = state.list_scans(4, 3);
    assert_eq!(page4.scans.len(), 1);
}

#[actix_web::test]
async fn test_app_state_stats() {
    let mut state = AppState::new();

    for i in 0..5 {
        let request = ScanRequest {
            targets: vec![format!("10.0.0.{}", i)],
            ports: vec![80, 443, 8080],
            scan_type: ScanType::Tcp,
            timing: TimingTemplate::Normal,
            enable_service_detection: false,
            enable_os_detection: false,
            enable_vuln_check: false,
            enable_threat_intel: false,
        };
        state.create_scan(request).await;
    }

    let stats = state.get_stats();
    assert_eq!(stats.total_scans, 5);
    assert_eq!(stats.active_scans, 5);
    assert_eq!(stats.completed_scans, 0);
}
