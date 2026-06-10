// MCP Tool definitions for Nemue

use rmcp::model::Tool;
use serde_json::json;

fn make_tool(name: &'static str, description: &'static str, schema: serde_json::Value) -> Tool {
    let schema_obj = match schema {
        serde_json::Value::Object(obj) => obj,
        _ => serde_json::Map::new(),
    };
    Tool::new(name, description, std::sync::Arc::new(schema_obj))
}

pub fn get_tools() -> Vec<Tool> {
    vec![
        make_tool("nemue_scan",
            "Full port scan with service detection. Scans target(s) for open ports, identifies services, and performs OS fingerprinting.",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host, IP, CIDR, or comma-separated list"},
                    "ports": {"type": "string", "description": "Ports: 'top-1000', '1-65535', '22,80,443'. Default: top-1000"},
                    "scan_type": {"type": "string", "enum": ["connect", "syn", "udp"], "description": "Scan type. Default: connect"}
                },
                "required": ["target"]
            }),
        ),
        make_tool("nemue_quick_scan",
            "Fast scan of top N most common ports. Ideal for quick reconnaissance.",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host or IP"},
                    "top_ports": {"type": "integer", "description": "Number of top ports to scan. Default: 100"}
                },
                "required": ["target"]
            }),
        ),
        make_tool("nemue_service_detect",
            "Detect services and versions on specific ports.",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host or IP"},
                    "ports": {"type": "string", "description": "Ports to check (e.g. '22,80,443')"}
                },
                "required": ["target", "ports"]
            }),
        ),
        make_tool("nemue_os_detect",
            "Detect operating system via TCP/IP stack fingerprinting.",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host or IP"}
                },
                "required": ["target"]
            }),
        ),
        make_tool("nemue_ssl_check",
            "Analyze SSL/TLS configuration. Checks certificate, cipher suites, protocol versions.",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host or IP"},
                    "port": {"type": "integer", "description": "Port to check. Default: 443"}
                },
                "required": ["target"]
            }),
        ),
        make_tool("nemue_host_discovery",
            "Discover alive hosts on a network by testing common ports.",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP, CIDR, or range"}
                },
                "required": ["target"]
            }),
        ),

        make_tool("nemue_vuln_scan",
            "Scan for known vulnerabilities on open ports. Matches services against CVE database.",
            json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host or IP"},
                    "ports": {"type": "string", "description": "Ports to scan. Default: top-1000"}
                },
                "required": ["target"]
            }),
        ),
    ]
}
