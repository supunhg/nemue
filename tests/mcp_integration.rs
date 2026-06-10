use nemue::mcp::NemueMcpServer;
use rmcp::handler::server::ServerHandler;

#[test]
fn test_mcp_server_creation() {
    let server = NemueMcpServer::new();
    assert!(server.is_ok());
}

#[test]
fn test_mcp_server_info() {
    let server = NemueMcpServer::new().unwrap();
    let info = server.get_info();

    assert_eq!(info.server_info.name, "nemue");
    assert!(info.server_info.description.is_some());
    assert!(info.instructions.is_some());
}

#[test]
fn test_mcp_server_version() {
    let server = NemueMcpServer::new().unwrap();
    let info = server.get_info();

    assert_eq!(info.server_info.version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn test_mcp_server_title() {
    let server = NemueMcpServer::new().unwrap();
    let info = server.get_info();

    assert_eq!(info.server_info.title, Some("Nemue Network Scanner".into()));
}

#[test]
fn test_mcp_tool_names() {
    let tools = nemue::mcp::tools::get_tools();
    let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();

    assert!(names.contains(&"nemue_scan".to_string()));
    assert!(names.contains(&"nemue_quick_scan".to_string()));
    assert!(names.contains(&"nemue_service_detect".to_string()));
    assert!(names.contains(&"nemue_os_detect".to_string()));
    assert!(names.contains(&"nemue_ssl_check".to_string()));
    assert!(names.contains(&"nemue_host_discovery".to_string()));
    assert!(names.contains(&"nemue_vuln_scan".to_string()));
}

#[test]
fn test_mcp_tool_descriptions() {
    let tools = nemue::mcp::tools::get_tools();

    for tool in &tools {
        assert!(tool.description.is_some(), "Tool {} has no description", tool.name);
        assert!(!tool.description.as_ref().unwrap().is_empty(), "Tool {} has empty description", tool.name);
    }
}

#[test]
fn test_mcp_tool_input_schemas() {
    let tools = nemue::mcp::tools::get_tools();

    for tool in &tools {
        assert!(!tool.input_schema.is_empty(), "Tool {} has empty input schema", tool.name);
    }
}
