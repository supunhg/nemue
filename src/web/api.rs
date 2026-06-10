// API Discovery and Testing
// Discovers REST/GraphQL APIs and performs basic security testing

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// API endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APIEndpoint {
    pub url: String,
    pub method: String,
    pub api_type: APIType,
    pub auth_required: bool,
    pub parameters: Vec<APIParameter>,
    pub response_format: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum APIType {
    REST,
    GraphQL,
    SOAP,
    WebSocket,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APIParameter {
    pub name: String,
    pub param_type: ParameterType,
    pub required: bool,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterType {
    Query,
    Path,
    Header,
    Body,
}

/// API discovery engine
pub struct APIDiscovery;

impl APIDiscovery {
    /// Discover APIs from JavaScript files
    pub fn discover_from_js(js_content: &str) -> Vec<APIEndpoint> {
        let mut endpoints = Vec::new();

        // Look for fetch() calls
        endpoints.extend(Self::extract_fetch_calls(js_content));

        // Look for axios calls
        endpoints.extend(Self::extract_axios_calls(js_content));

        // Look for jQuery AJAX
        endpoints.extend(Self::extract_jquery_ajax(js_content));

        endpoints
    }

    /// Discover APIs from network traffic patterns
    pub fn discover_from_headers(headers: &HashMap<String, String>) -> Option<APIType> {
        // Check Content-Type for API indicators
        if let Some(content_type) = headers
            .get("content-type")
            .or_else(|| headers.get("Content-Type"))
        {
            if content_type.contains("application/json") {
                return Some(APIType::REST);
            } else if content_type.contains("application/graphql") {
                return Some(APIType::GraphQL);
            } else if content_type.contains("application/soap+xml") {
                return Some(APIType::SOAP);
            }
        }

        // Check for GraphQL specific headers
        if headers.contains_key("x-graphql") {
            return Some(APIType::GraphQL);
        }

        None
    }

    /// Test API endpoint for common vulnerabilities
    pub async fn test_endpoint(endpoint: &APIEndpoint) -> Vec<APIVulnerability> {
        let mut vulns = Vec::new();

        // Check for missing authentication
        if !endpoint.auth_required {
            vulns.push(APIVulnerability {
                severity: VulnerabilitySeverity::Medium,
                issue_type: "Missing Authentication".to_string(),
                description: "API endpoint accessible without authentication".to_string(),
                endpoint: endpoint.url.clone(),
            });
        }

        // TODO: Implement more security tests
        // - SQL injection in parameters
        // - NoSQL injection
        // - Mass assignment
        // - Rate limiting
        // - IDOR (Insecure Direct Object Reference)

        vulns
    }

    /// Extract fetch() API calls from JavaScript
    fn extract_fetch_calls(js: &str) -> Vec<APIEndpoint> {
        let mut endpoints = Vec::new();

        // Simple pattern matching for fetch('url')
        // TODO: Implement proper JavaScript AST parsing

        for line in js.lines() {
            if line.contains("fetch(") {
                // Extract URL from fetch call
                if let Some(url) = Self::extract_url_from_call(line, "fetch(") {
                    endpoints.push(APIEndpoint {
                        url,
                        method: "GET".to_string(),
                        api_type: APIType::REST,
                        auth_required: line.contains("Authorization") || line.contains("Bearer"),
                        parameters: vec![],
                        response_format: Some("json".to_string()),
                    });
                }
            }
        }

        endpoints
    }

    /// Extract axios API calls from JavaScript
    fn extract_axios_calls(js: &str) -> Vec<APIEndpoint> {
        let mut endpoints = Vec::new();

        // Look for axios.get(), axios.post(), etc.
        let methods = ["get", "post", "put", "delete", "patch"];

        for method in &methods {
            let pattern = format!("axios.{}(", method);
            for line in js.lines() {
                if line.contains(&pattern) {
                    if let Some(url) = Self::extract_url_from_call(line, &pattern) {
                        endpoints.push(APIEndpoint {
                            url,
                            method: method.to_uppercase(),
                            api_type: APIType::REST,
                            auth_required: line.contains("headers"),
                            parameters: vec![],
                            response_format: Some("json".to_string()),
                        });
                    }
                }
            }
        }

        endpoints
    }

    /// Extract jQuery AJAX calls
    fn extract_jquery_ajax(_js: &str) -> Vec<APIEndpoint> {
        let endpoints = Vec::new();

        // Look for $.ajax({ url: '...' })
        // TODO: Implement proper extraction

        endpoints
    }

    /// Extract URL from function call
    fn extract_url_from_call(line: &str, pattern: &str) -> Option<String> {
        if let Some(pos) = line.find(pattern) {
            let after = &line[pos + pattern.len()..];

            // Find quoted URL
            if let Some(quote_start) = after.find(['"', '\'']) {
                let quote_char = after.chars().nth(quote_start).unwrap();
                let url_start = quote_start + 1;

                if let Some(quote_end) = after[url_start..].find(quote_char) {
                    return Some(after[url_start..url_start + quote_end].to_string());
                }
            }
        }
        None
    }
}

/// API vulnerability finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APIVulnerability {
    pub severity: VulnerabilitySeverity,
    pub issue_type: String,
    pub description: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_rest_from_headers() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());

        let api_type = APIDiscovery::discover_from_headers(&headers);
        assert_eq!(api_type, Some(APIType::REST));
    }

    #[test]
    fn test_discover_graphql_from_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "Content-Type".to_string(),
            "application/graphql".to_string(),
        );

        let api_type = APIDiscovery::discover_from_headers(&headers);
        assert_eq!(api_type, Some(APIType::GraphQL));
    }

    #[test]
    fn test_extract_fetch_calls() {
        let js = r#"
            fetch('https://api.example.com/users');
            const data = await fetch('/api/posts', { method: 'POST' });
        "#;

        let endpoints = APIDiscovery::extract_fetch_calls(js);
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].url, "https://api.example.com/users");
    }

    #[test]
    fn test_extract_axios_calls() {
        let js = r#"
            axios.get('/api/users');
            axios.post('https://api.example.com/posts', data);
        "#;

        let endpoints = APIDiscovery::extract_axios_calls(js);
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].method, "GET");
        assert_eq!(endpoints[1].method, "POST");
    }
}
