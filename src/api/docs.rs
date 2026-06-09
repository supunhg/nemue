use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: ApiInfo,
    pub servers: Vec<Server>,
    pub paths: HashMap<String, PathItem>,
    pub components: Option<Components>,
    pub tags: Vec<Tag>,
    pub external_docs: Option<ExternalDocs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiInfo {
    pub title: String,
    pub version: String,
    pub description: String,
    pub contact: Option<Contact>,
    pub license: Option<License>,
    #[serde(rename = "termsOfService")]
    pub terms_of_service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub name: Option<String>,
    pub url: Option<String>,
    pub email: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct License {
    pub name: String,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub url: String,
    pub description: String,
    #[serde(rename = "variables")]
    pub variables: Option<HashMap<String, ServerVariable>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerVariable {
    pub default_value: String,
    pub description: Option<String>,
    #[serde(rename = "enum")]
    pub enum_values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "externalDocs")]
    pub external_docs: Option<ExternalDocs>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalDocs {
    pub url: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathItem {
    pub get: Option<Operation>,
    pub post: Option<Operation>,
    pub put: Option<Operation>,
    pub delete: Option<Operation>,
    pub patch: Option<Operation>,
    pub parameters: Option<Vec<Parameter>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub tags: Vec<String>,
    pub summary: String,
    #[serde(rename = "operationId")]
    pub operation_id: String,
    pub description: Option<String>,
    pub parameters: Option<Vec<Parameter>>,
    #[serde(rename = "requestBody")]
    pub request_body: Option<RequestBody>,
    pub responses: HashMap<String, Response>,
    pub deprecated: Option<bool>,
    pub security: Option<Vec<SecurityRequirement>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub in_location: String,
    pub description: Option<String>,
    pub required: Option<bool>,
    pub schema: Option<Schema>,
    pub deprecated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBody {
    pub description: Option<String>,
    pub required: Option<bool>,
    pub content: HashMap<String, MediaType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaType {
    pub schema: Option<Schema>,
    pub example: Option<serde_json::Value>,
    pub examples: Option<HashMap<String, Example>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Example {
    pub summary: Option<String>,
    pub description: Option<String>,
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub description: String,
    pub content: Option<HashMap<String, MediaType>>,
    pub headers: Option<HashMap<String, Header>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub description: Option<String>,
    pub schema: Option<Schema>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Schema {
    #[serde(rename = "type")]
    pub schema_type: Option<String>,
    pub format: Option<String>,
    pub description: Option<String>,
    pub properties: Option<HashMap<String, Schema>>,
    pub required: Option<Vec<String>>,
    pub items: Option<Box<Schema>>,
    #[serde(rename = "enum")]
    pub enum_values: Option<Vec<String>>,
    pub example: Option<serde_json::Value>,
    #[serde(rename = "default")]
    pub default_value: Option<serde_json::Value>,
    #[serde(rename = "$ref")]
    pub reference: Option<String>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub nullable: Option<bool>,
}

pub type SecurityRequirement = HashMap<String, Vec<String>>;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Components {
    pub schemas: Option<HashMap<String, Schema>>,
    pub security_schemes: Option<HashMap<String, SecurityScheme>>,
    pub responses: Option<HashMap<String, Response>>,
    pub parameters: Option<HashMap<String, Parameter>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityScheme {
    #[serde(rename = "type")]
    pub scheme_type: String,
    pub description: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "in")]
    pub in_location: Option<String>,
    pub scheme: Option<String>,
    #[serde(rename = "bearerFormat")]
    pub bearer_format: Option<String>,
    pub flows: Option<OAuthFlows>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthFlows {
    pub authorization_code: Option<OAuthFlow>,
    pub client_credentials: Option<OAuthFlow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthFlow {
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub refresh_url: Option<String>,
    pub scopes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeExample {
    pub language: String,
    pub label: String,
    pub source: String,
}

pub struct OpenApiBuilder;

impl OpenApiBuilder {
    pub fn build_spec() -> OpenApiSpec {
        OpenApiSpec {
            openapi: "3.0.3".to_string(),
            info: ApiInfo {
                title: "Nemue Security Scanner API".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                description: "REST API for the Nemue Advanced Security Testing Framework. \
                    Provides endpoints for managing security scans, retrieving results, \
                    configuring webhooks, and integrating with CI/CD pipelines.".to_string(),
                contact: Some(Contact {
                    name: Some("Nemue Project".to_string()),
                    url: Some("https://github.com/tabea/Nemue".to_string()),
                    email: None,
                }),
                license: Some(License {
                    name: "MIT".to_string(),
                    url: Some("https://opensource.org/licenses/MIT".to_string()),
                }),
                terms_of_service: None,
            },
            servers: vec![
                Server {
                    url: "http://localhost:8080".to_string(),
                    description: "Local development server".to_string(),
                    variables: None,
                },
                Server {
                    url: "https://api.nemue.dev".to_string(),
                    description: "Production server".to_string(),
                    variables: None,
                },
            ],
            tags: vec![
                Tag {
                    name: "system".to_string(),
                    description: Some("System health and information endpoints".to_string()),
                    external_docs: None,
                },
                Tag {
                    name: "scans".to_string(),
                    description: Some("Security scan management".to_string()),
                    external_docs: None,
                },
                Tag {
                    name: "webhooks".to_string(),
                    description: Some("Webhook registration and management".to_string()),
                    external_docs: None,
                },
                Tag {
                    name: "cicd".to_string(),
                    description: Some("CI/CD pipeline integration".to_string()),
                    external_docs: None,
                },
            ],
            paths: Self::build_paths(),
            components: Some(Self::build_components()),
            external_docs: Some(ExternalDocs {
                url: "https://docs.nemue.dev".to_string(),
                description: Some("Full documentation".to_string()),
            }),
        }
    }

    fn build_paths() -> HashMap<String, PathItem> {
        let mut paths = HashMap::new();

        paths.insert("/health".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["system".to_string()],
                summary: "Health check".to_string(),
                operation_id: "healthCheck".to_string(),
                description: Some("Returns server health status, uptime, and active scan counts".to_string()),
                parameters: None,
                request_body: None,
                responses: Self::responses_with("200", "Server is healthy", "HealthResponse"),
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v1/info".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["system".to_string()],
                summary: "Server information and capabilities".to_string(),
                operation_id: "serverInfo".to_string(),
                description: Some("Returns server name, version, and supported capabilities".to_string()),
                parameters: None,
                request_body: None,
                responses: Self::responses_with("200", "Server info", "ServerInfo"),
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v1/stats".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["system".to_string()],
                summary: "Aggregated scan statistics".to_string(),
                operation_id: "scanStats".to_string(),
                description: Some("Returns aggregated statistics across all scans".to_string()),
                parameters: None,
                request_body: None,
                responses: Self::responses_with("200", "Statistics", "ScanStats"),
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v1/scans".to_string(), PathItem {
            post: Some(Operation {
                tags: vec!["scans".to_string()],
                summary: "Start a new scan".to_string(),
                operation_id: "startScan".to_string(),
                description: Some("Queues a new security scan with the specified targets and options".to_string()),
                parameters: None,
                request_body: Some(RequestBody {
                    description: Some("Scan configuration".to_string()),
                    required: Some(true),
                    content: {
                        let mut m = HashMap::new();
                        m.insert("application/json".to_string(), MediaType {
                            schema: Some(Self::schema_ref("ScanRequest")),
                            example: Some(serde_json::json!({
                                "targets": ["192.168.1.0/24"],
                                "ports": [22, 80, 443],
                                "scan_type": "tcp",
                                "timing": "normal",
                                "enable_service_detection": true,
                                "enable_os_detection": false,
                                "enable_vuln_check": true,
                                "enable_threat_intel": false
                            })),
                            examples: None,
                        });
                        m
                    },
                }),
                responses: {
                    let mut r = HashMap::new();
                    r.insert("202".to_string(), Response {
                        description: "Scan queued successfully".to_string(),
                        content: Some(Self::json_content("ScanQueued")),
                        headers: None,
                    });
                    r.insert("400".to_string(), Response {
                        description: "Invalid request".to_string(),
                        content: Some(Self::json_content("ApiError")),
                        headers: None,
                    });
                    r
                },
                deprecated: None,
                security: Some(vec![{
                    let mut s = HashMap::new();
                    s.insert("apiKey".to_string(), vec![]);
                    s
                }]),
            }),
            get: Some(Operation {
                tags: vec!["scans".to_string()],
                summary: "List all scans".to_string(),
                operation_id: "listScans".to_string(),
                description: Some("Returns a paginated list of all scans".to_string()),
                parameters: Some(vec![
                    Parameter {
                        name: "page".to_string(),
                        in_location: "query".to_string(),
                        description: Some("Page number".to_string()),
                        required: Some(false),
                        schema: Some(Schema {
                            schema_type: Some("integer".to_string()),
                            default_value: Some(serde_json::json!(1)),
                            minimum: Some(1.0),
                            ..Default::default()
                        }),
                        deprecated: None,
                    },
                    Parameter {
                        name: "per_page".to_string(),
                        in_location: "query".to_string(),
                        description: Some("Items per page (max 100)".to_string()),
                        required: Some(false),
                        schema: Some(Schema {
                            schema_type: Some("integer".to_string()),
                            default_value: Some(serde_json::json!(20)),
                            minimum: Some(1.0),
                            maximum: Some(100.0),
                            ..Default::default()
                        }),
                        deprecated: None,
                    },
                ]),
                request_body: None,
                responses: Self::responses_with("200", "Scan list", "ScanListResponse"),
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v1/scans/{scan_id}".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["scans".to_string()],
                summary: "Get scan status".to_string(),
                operation_id: "getScanStatus".to_string(),
                description: Some("Returns the current status and progress of a scan".to_string()),
                parameters: Some(vec![Self::uuid_param("scan_id", "Scan ID")]),
                request_body: None,
                responses: {
                    let mut r = HashMap::new();
                    r.insert("200".to_string(), Response {
                        description: "Scan status".to_string(),
                        content: Some(Self::json_content("ScanStatus")),
                        headers: None,
                    });
                    r.insert("404".to_string(), Response {
                        description: "Scan not found".to_string(),
                        content: Some(Self::json_content("ApiError")),
                        headers: None,
                    });
                    r
                },
                deprecated: None,
                security: None,
            }),
            delete: Some(Operation {
                tags: vec!["scans".to_string()],
                summary: "Delete a scan".to_string(),
                operation_id: "deleteScan".to_string(),
                description: Some("Deletes a scan and its results".to_string()),
                parameters: Some(vec![Self::uuid_param("scan_id", "Scan ID")]),
                request_body: None,
                responses: {
                    let mut r = HashMap::new();
                    r.insert("200".to_string(), Response {
                        description: "Scan deleted".to_string(),
                        content: None,
                        headers: None,
                    });
                    r.insert("404".to_string(), Response {
                        description: "Scan not found".to_string(),
                        content: Some(Self::json_content("ApiError")),
                        headers: None,
                    });
                    r
                },
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v1/scans/{scan_id}/results".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["scans".to_string()],
                summary: "Get scan results".to_string(),
                operation_id: "getScanResults".to_string(),
                description: Some("Returns detailed scan results including ports, services, and vulnerabilities".to_string()),
                parameters: Some(vec![Self::uuid_param("scan_id", "Scan ID")]),
                request_body: None,
                responses: {
                    let mut r = HashMap::new();
                    r.insert("200".to_string(), Response {
                        description: "Scan results".to_string(),
                        content: Some(Self::json_content("ScanResults")),
                        headers: None,
                    });
                    r.insert("404".to_string(), Response {
                        description: "Results not found".to_string(),
                        content: Some(Self::json_content("ApiError")),
                        headers: None,
                    });
                    r
                },
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v1/scans/{scan_id}/cancel".to_string(), PathItem {
            post: Some(Operation {
                tags: vec!["scans".to_string()],
                summary: "Cancel a running scan".to_string(),
                operation_id: "cancelScan".to_string(),
                description: Some("Cancels a queued or running scan".to_string()),
                parameters: Some(vec![Self::uuid_param("scan_id", "Scan ID")]),
                request_body: None,
                responses: {
                    let mut r = HashMap::new();
                    r.insert("200".to_string(), Response {
                        description: "Scan cancelled".to_string(),
                        content: None,
                        headers: None,
                    });
                    r.insert("400".to_string(), Response {
                        description: "Cannot cancel".to_string(),
                        content: Some(Self::json_content("ApiError")),
                        headers: None,
                    });
                    r
                },
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v1/webhooks".to_string(), PathItem {
            post: Some(Operation {
                tags: vec!["webhooks".to_string()],
                summary: "Register a webhook".to_string(),
                operation_id: "registerWebhook".to_string(),
                description: Some("Registers a new webhook endpoint for scan notifications".to_string()),
                parameters: None,
                request_body: Some(RequestBody {
                    description: Some("Webhook configuration".to_string()),
                    required: Some(true),
                    content: Self::json_content_map("RegisterWebhookRequest"),
                }),
                responses: Self::responses_with("201", "Webhook registered", "WebhookCreated"),
                deprecated: None,
                security: None,
            }),
            get: Some(Operation {
                tags: vec!["webhooks".to_string()],
                summary: "List registered webhooks".to_string(),
                operation_id: "listWebhooks".to_string(),
                description: Some("Returns all registered webhooks".to_string()),
                parameters: None,
                request_body: None,
                responses: Self::responses_with("200", "Webhook list", "WebhookList"),
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v1/webhooks/{webhook_id}".to_string(), PathItem {
            delete: Some(Operation {
                tags: vec!["webhooks".to_string()],
                summary: "Delete a webhook".to_string(),
                operation_id: "deleteWebhook".to_string(),
                description: Some("Removes a registered webhook".to_string()),
                parameters: Some(vec![Self::uuid_param("webhook_id", "Webhook ID")]),
                request_body: None,
                responses: Self::responses_simple("200", "Webhook deleted"),
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v1/webhooks/{webhook_id}/test".to_string(), PathItem {
            post: Some(Operation {
                tags: vec!["webhooks".to_string()],
                summary: "Send test delivery to webhook".to_string(),
                operation_id: "testWebhook".to_string(),
                description: Some("Sends a test payload to the webhook endpoint".to_string()),
                parameters: Some(vec![Self::uuid_param("webhook_id", "Webhook ID")]),
                request_body: None,
                responses: Self::responses_with("200", "Delivery result", "WebhookDelivery"),
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v1/cicd/config".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["cicd".to_string()],
                summary: "Get CI/CD integration configuration".to_string(),
                operation_id: "getCiCdConfig".to_string(),
                description: Some("Returns the current CI/CD integration settings".to_string()),
                parameters: None,
                request_body: None,
                responses: Self::responses_with("200", "CI/CD config", "CiCdConfig"),
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v1/cicd/evaluate".to_string(), PathItem {
            post: Some(Operation {
                tags: vec!["cicd".to_string()],
                summary: "Evaluate scan results for CI/CD pipeline".to_string(),
                operation_id: "evaluateCiCd".to_string(),
                description: Some("Evaluates scan results against CI/CD thresholds and returns pass/fail".to_string()),
                parameters: None,
                request_body: Some(RequestBody {
                    description: Some("Evaluation parameters".to_string()),
                    required: Some(true),
                    content: Self::json_content_map("CiCdEvaluateRequest"),
                }),
                responses: Self::responses_with("200", "Evaluation result", "CiCdResult"),
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths.insert("/api/v2/scans".to_string(), PathItem {
            get: Some(Operation {
                tags: vec!["scans".to_string()],
                summary: "List all scans (v2)".to_string(),
                operation_id: "listScansV2".to_string(),
                description: Some("Returns scans with enhanced filtering and sorting".to_string()),
                parameters: Some(vec![
                    Parameter {
                        name: "page".to_string(),
                        in_location: "query".to_string(),
                        description: Some("Page number".to_string()),
                        required: Some(false),
                        schema: Some(Schema {
                            schema_type: Some("integer".to_string()),
                            default_value: Some(serde_json::json!(1)),
                            ..Default::default()
                        }),
                        deprecated: None,
                    },
                    Parameter {
                        name: "per_page".to_string(),
                        in_location: "query".to_string(),
                        description: Some("Items per page".to_string()),
                        required: Some(false),
                        schema: Some(Schema {
                            schema_type: Some("integer".to_string()),
                            default_value: Some(serde_json::json!(20)),
                            ..Default::default()
                        }),
                        deprecated: None,
                    },
                    Parameter {
                        name: "status".to_string(),
                        in_location: "query".to_string(),
                        description: Some("Filter by status".to_string()),
                        required: Some(false),
                        schema: Some(Schema {
                            schema_type: Some("string".to_string()),
                            enum_values: Some(vec![
                                "queued".to_string(),
                                "running".to_string(),
                                "completed".to_string(),
                                "failed".to_string(),
                                "cancelled".to_string(),
                            ]),
                            ..Default::default()
                        }),
                        deprecated: None,
                    },
                    Parameter {
                        name: "sort_by".to_string(),
                        in_location: "query".to_string(),
                        description: Some("Sort field".to_string()),
                        required: Some(false),
                        schema: Some(Schema {
                            schema_type: Some("string".to_string()),
                            enum_values: Some(vec![
                                "started_at".to_string(),
                                "updated_at".to_string(),
                                "status".to_string(),
                            ]),
                            ..Default::default()
                        }),
                        deprecated: None,
                    },
                ]),
                request_body: None,
                responses: Self::responses_with("200", "Scan list", "ScanListResponse"),
                deprecated: None,
                security: None,
            }),
            ..Default::default()
        });

        paths
    }

    fn build_components() -> Components {
        let mut schemas = HashMap::new();

        schemas.insert("ScanRequest".to_string(), Schema {
            schema_type: Some("object".to_string()),
            required: Some(vec!["targets".to_string(), "ports".to_string()]),
            properties: Some({
                let mut p = HashMap::new();
                p.insert("targets".to_string(), Schema {
                    schema_type: Some("array".to_string()),
                    items: Some(Box::new(Schema {
                        schema_type: Some("string".to_string()),
                        ..Default::default()
                    })),
                    description: Some("Target hosts or CIDR ranges".to_string()),
                    ..Default::default()
                });
                p.insert("ports".to_string(), Schema {
                    schema_type: Some("array".to_string()),
                    items: Some(Box::new(Schema {
                        schema_type: Some("integer".to_string()),
                        ..Default::default()
                    })),
                    description: Some("Ports to scan".to_string()),
                    ..Default::default()
                });
                p.insert("scan_type".to_string(), Schema {
                    schema_type: Some("string".to_string()),
                    enum_values: Some(vec![
                        "tcp".to_string(), "udp".to_string(),
                        "syn".to_string(), "connect".to_string(),
                    ]),
                    default_value: Some(serde_json::json!("tcp")),
                    ..Default::default()
                });
                p.insert("timing".to_string(), Schema {
                    schema_type: Some("string".to_string()),
                    enum_values: Some(vec![
                        "paranoid".to_string(), "sneaky".to_string(), "polite".to_string(),
                        "normal".to_string(), "aggressive".to_string(), "insane".to_string(),
                    ]),
                    default_value: Some(serde_json::json!("normal")),
                    ..Default::default()
                });
                p.insert("enable_service_detection".to_string(), Schema {
                    schema_type: Some("boolean".to_string()),
                    default_value: Some(serde_json::json!(false)),
                    ..Default::default()
                });
                p.insert("enable_os_detection".to_string(), Schema {
                    schema_type: Some("boolean".to_string()),
                    default_value: Some(serde_json::json!(false)),
                    ..Default::default()
                });
                p.insert("enable_vuln_check".to_string(), Schema {
                    schema_type: Some("boolean".to_string()),
                    default_value: Some(serde_json::json!(false)),
                    ..Default::default()
                });
                p.insert("enable_threat_intel".to_string(), Schema {
                    schema_type: Some("boolean".to_string()),
                    default_value: Some(serde_json::json!(false)),
                    ..Default::default()
                });
                p
            }),
            description: Some("Scan request configuration".to_string()),
            ..Default::default()
        });

        schemas.insert("HealthResponse".to_string(), Schema {
            schema_type: Some("object".to_string()),
            properties: Some({
                let mut p = HashMap::new();
                p.insert("status".to_string(), Schema {
                    schema_type: Some("string".to_string()),
                    example: Some(serde_json::json!("ok")),
                    ..Default::default()
                });
                p.insert("version".to_string(), Schema {
                    schema_type: Some("string".to_string()),
                    ..Default::default()
                });
                p.insert("uptime_seconds".to_string(), Schema {
                    schema_type: Some("integer".to_string()),
                    ..Default::default()
                });
                p.insert("active_scans".to_string(), Schema {
                    schema_type: Some("integer".to_string()),
                    ..Default::default()
                });
                p.insert("completed_scans".to_string(), Schema {
                    schema_type: Some("integer".to_string()),
                    ..Default::default()
                });
                p
            }),
            ..Default::default()
        });

        schemas.insert("ApiError".to_string(), Schema {
            schema_type: Some("object".to_string()),
            properties: Some({
                let mut p = HashMap::new();
                p.insert("error".to_string(), Schema {
                    schema_type: Some("string".to_string()),
                    ..Default::default()
                });
                p.insert("message".to_string(), Schema {
                    schema_type: Some("string".to_string()),
                    ..Default::default()
                });
                p.insert("status_code".to_string(), Schema {
                    schema_type: Some("integer".to_string()),
                    ..Default::default()
                });
                p
            }),
            ..Default::default()
        });

        schemas.insert("RegisterWebhookRequest".to_string(), Schema {
            schema_type: Some("object".to_string()),
            required: Some(vec!["url".to_string(), "provider".to_string()]),
            properties: Some({
                let mut p = HashMap::new();
                p.insert("url".to_string(), Schema {
                    schema_type: Some("string".to_string()),
                    format: Some("uri".to_string()),
                    ..Default::default()
                });
                p.insert("provider".to_string(), Schema {
                    schema_type: Some("string".to_string()),
                    enum_values: Some(vec![
                        "slack".to_string(), "discord".to_string(),
                        "teams".to_string(), "custom".to_string(),
                    ]),
                    ..Default::default()
                });
                p.insert("secret".to_string(), Schema {
                    schema_type: Some("string".to_string()),
                    nullable: Some(true),
                    ..Default::default()
                });
                p.insert("max_retries".to_string(), Schema {
                    schema_type: Some("integer".to_string()),
                    default_value: Some(serde_json::json!(3)),
                    ..Default::default()
                });
                p
            }),
            ..Default::default()
        });

        schemas.insert("CiCdEvaluateRequest".to_string(), Schema {
            schema_type: Some("object".to_string()),
            required: Some(vec!["scan_id".to_string()]),
            properties: Some({
                let mut p = HashMap::new();
                p.insert("scan_id".to_string(), Schema {
                    schema_type: Some("string".to_string()),
                    ..Default::default()
                });
                p.insert("targets_scanned".to_string(), Schema {
                    schema_type: Some("integer".to_string()),
                    ..Default::default()
                });
                p.insert("total_open_ports".to_string(), Schema {
                    schema_type: Some("integer".to_string()),
                    ..Default::default()
                });
                p.insert("total_vulnerabilities".to_string(), Schema {
                    schema_type: Some("integer".to_string()),
                    ..Default::default()
                });
                p.insert("risk_score".to_string(), Schema {
                    schema_type: Some("integer".to_string()),
                    minimum: Some(0.0),
                    maximum: Some(100.0),
                    ..Default::default()
                });
                p
            }),
            ..Default::default()
        });

        Components {
            schemas: Some(schemas),
            security_schemes: Some({
                let mut s = HashMap::new();
                s.insert("apiKey".to_string(), SecurityScheme {
                    scheme_type: "apiKey".to_string(),
                    description: Some("API key authentication".to_string()),
                    name: Some("X-API-Key".to_string()),
                    in_location: Some("header".to_string()),
                    scheme: None,
                    bearer_format: None,
                    flows: None,
                });
                s.insert("bearerAuth".to_string(), SecurityScheme {
                    scheme_type: "http".to_string(),
                    description: Some("Bearer token authentication".to_string()),
                    name: None,
                    in_location: None,
                    scheme: Some("bearer".to_string()),
                    bearer_format: Some("JWT".to_string()),
                    flows: None,
                });
                s
            }),
            responses: None,
            parameters: None,
        }
    }

    fn responses_simple(code: &str, desc: &str) -> HashMap<String, Response> {
        let mut r = HashMap::new();
        r.insert(code.to_string(), Response {
            description: desc.to_string(),
            content: None,
            headers: None,
        });
        r
    }

    fn responses_with(code: &str, desc: &str, schema_ref: &str) -> HashMap<String, Response> {
        let mut r = HashMap::new();
        r.insert(code.to_string(), Response {
            description: desc.to_string(),
            content: Some(Self::json_content(schema_ref)),
            headers: None,
        });
        r
    }

    fn json_content(schema_ref: &str) -> HashMap<String, MediaType> {
        let mut m = HashMap::new();
        m.insert("application/json".to_string(), MediaType {
            schema: Some(Self::schema_ref(schema_ref)),
            example: None,
            examples: None,
        });
        m
    }

    fn json_content_map(schema_ref: &str) -> HashMap<String, MediaType> {
        Self::json_content(schema_ref)
    }

    fn schema_ref(name: &str) -> Schema {
        Schema {
            reference: Some(format!("#/components/schemas/{}", name)),
            ..Default::default()
        }
    }

    fn uuid_param(name: &str, desc: &str) -> Parameter {
        Parameter {
            name: name.to_string(),
            in_location: "path".to_string(),
            description: Some(desc.to_string()),
            required: Some(true),
            schema: Some(Schema {
                schema_type: Some("string".to_string()),
                format: Some("uuid".to_string()),
                ..Default::default()
            }),
            deprecated: None,
        }
    }
}

pub fn get_code_examples() -> Vec<CodeExample> {
    vec![
        CodeExample {
            language: "bash".to_string(),
            label: "Start a scan (curl)".to_string(),
            source: r#"curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.0/24"],
    "ports": [22, 80, 443],
    "scan_type": "tcp",
    "timing": "normal",
    "enable_service_detection": true,
    "enable_vuln_check": true
  }'"#.to_string(),
        },
        CodeExample {
            language: "python".to_string(),
            label: "Start a scan (Python)".to_string(),
            source: r#"import requests

response = requests.post("http://localhost:8080/api/v1/scans", json={
    "targets": ["192.168.1.0/24"],
    "ports": [22, 80, 443],
    "scan_type": "tcp",
    "timing": "normal",
    "enable_service_detection": True,
    "enable_vuln_check": True
})

scan = response.json()
print(f"Scan ID: {scan['scan_id']}")"#.to_string(),
        },
        CodeExample {
            language: "javascript".to_string(),
            label: "Start a scan (JavaScript)".to_string(),
            source: r#"const response = await fetch("http://localhost:8080/api/v1/scans", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    targets: ["192.168.1.0/24"],
    ports: [22, 80, 443],
    scan_type: "tcp",
    timing: "normal",
    enable_service_detection: true,
    enable_vuln_check: true
  })
});

const scan = await response.json();
console.log(`Scan ID: ${scan.scan_id}`);"#.to_string(),
        },
        CodeExample {
            language: "javascript".to_string(),
            label: "WebSocket connection".to_string(),
            source: r#"const ws = new WebSocket("ws://localhost:8080/ws/scans");

ws.onopen = () => {
  ws.send(JSON.stringify({
    type: "Subscribe",
    payload: { scan_id: "your-scan-id" }
  }));
};

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === "ScanUpdate") {
    console.log(`Progress: ${msg.payload.progress}%`);
  }
};"#.to_string(),
        },
        CodeExample {
            language: "graphql".to_string(),
            label: "GraphQL query".to_string(),
            source: r#"query {
  scans {
    items {
      scanId
      status
      targetsCount
      startedAt
    }
    total
  }
}"#.to_string(),
        },
    ]
}

pub async fn openapi_spec_handler() -> actix_web::HttpResponse {
    let spec = OpenApiBuilder::build_spec();
    actix_web::HttpResponse::Ok().json(spec)
}

pub async fn api_docs_handler() -> actix_web::HttpResponse {
    let html = r#"<!DOCTYPE html>
<html>
<head><title>Nemue API Documentation</title></head>
<body>
<h1>Nemue Security Scanner API</h1>
<p>Interactive API documentation. View the <a href="/openapi.json">OpenAPI spec</a>.</p>
<h2>Endpoints</h2>
<ul>
<li><a href="/openapi.json">OpenAPI 3.0 Specification (JSON)</a></li>
<li><a href="/api/v1/info">Server Info</a></li>
<li><a href="/health">Health Check</a></li>
</ul>
<h2>Code Examples</h2>
<p>See <code>/docs/examples</code> for code examples in multiple languages.</p>
</body>
</html>"#;
    actix_web::HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

pub async fn code_examples_handler() -> actix_web::HttpResponse {
    let examples = get_code_examples();
    actix_web::HttpResponse::Ok().json(examples)
}

pub fn docs_config(cfg: &mut actix_web::web::ServiceConfig) {
    cfg.route("/docs", actix_web::web::get().to(api_docs_handler))
       .route("/docs/examples", actix_web::web::get().to(code_examples_handler));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_builder_builds_spec() {
        let spec = OpenApiBuilder::build_spec();
        assert_eq!(spec.openapi, "3.0.3");
        assert_eq!(spec.info.title, "Nemue Security Scanner API");
        assert!(!spec.paths.is_empty());
    }

    #[test]
    fn test_openapi_spec_has_health_path() {
        let spec = OpenApiBuilder::build_spec();
        assert!(spec.paths.contains_key("/health"));
    }

    #[test]
    fn test_openapi_spec_has_scans_paths() {
        let spec = OpenApiBuilder::build_spec();
        assert!(spec.paths.contains_key("/api/v1/scans"));
        assert!(spec.paths.contains_key("/api/v1/scans/{scan_id}"));
        assert!(spec.paths.contains_key("/api/v1/scans/{scan_id}/results"));
        assert!(spec.paths.contains_key("/api/v1/scans/{scan_id}/cancel"));
    }

    #[test]
    fn test_openapi_spec_has_webhook_paths() {
        let spec = OpenApiBuilder::build_spec();
        assert!(spec.paths.contains_key("/api/v1/webhooks"));
        assert!(spec.paths.contains_key("/api/v1/webhooks/{webhook_id}"));
    }

    #[test]
    fn test_openapi_spec_has_cicd_paths() {
        let spec = OpenApiBuilder::build_spec();
        assert!(spec.paths.contains_key("/api/v1/cicd/config"));
        assert!(spec.paths.contains_key("/api/v1/cicd/evaluate"));
    }

    #[test]
    fn test_openapi_spec_has_v2_scans() {
        let spec = OpenApiBuilder::build_spec();
        assert!(spec.paths.contains_key("/api/v2/scans"));
    }

    #[test]
    fn test_openapi_spec_has_components() {
        let spec = OpenApiBuilder::build_spec();
        let components = spec.components.unwrap();
        let schemas = components.schemas.unwrap();
        assert!(schemas.contains_key("ScanRequest"));
        assert!(schemas.contains_key("HealthResponse"));
        assert!(schemas.contains_key("ApiError"));
    }

    #[test]
    fn test_openapi_spec_has_security_schemes() {
        let spec = OpenApiBuilder::build_spec();
        let components = spec.components.unwrap();
        let schemes = components.security_schemes.unwrap();
        assert!(schemes.contains_key("apiKey"));
        assert!(schemes.contains_key("bearerAuth"));
    }

    #[test]
    fn test_openapi_spec_has_tags() {
        let spec = OpenApiBuilder::build_spec();
        let tag_names: Vec<&str> = spec.tags.iter().map(|t| t.name.as_str()).collect();
        assert!(tag_names.contains(&"system"));
        assert!(tag_names.contains(&"scans"));
        assert!(tag_names.contains(&"webhooks"));
        assert!(tag_names.contains(&"cicd"));
    }

    #[test]
    fn test_openapi_spec_has_servers() {
        let spec = OpenApiBuilder::build_spec();
        assert!(!spec.servers.is_empty());
        assert!(spec.servers.iter().any(|s| s.url.contains("localhost")));
    }

    #[test]
    fn test_openapi_spec_serialize() {
        let spec = OpenApiBuilder::build_spec();
        let json = serde_json::to_string(&spec).unwrap();
        assert!(json.contains("3.0.3"));
        assert!(json.contains("Nemue Security Scanner API"));
    }

    #[test]
    fn test_openapi_spec_serialize_pretty() {
        let spec = OpenApiBuilder::build_spec();
        let json = serde_json::to_string_pretty(&spec).unwrap();
        assert!(json.contains("openapi"));
        assert!(json.contains("paths"));
        assert!(json.contains("components"));
    }

    #[test]
    fn test_scan_request_schema_has_required_fields() {
        let spec = OpenApiBuilder::build_spec();
        let components = spec.components.unwrap();
        let schemas = components.schemas.unwrap();
        let scan_req = schemas.get("ScanRequest").unwrap();
        let required = scan_req.required.as_ref().unwrap();
        assert!(required.contains(&"targets".to_string()));
        assert!(required.contains(&"ports".to_string()));
    }

    #[test]
    fn test_health_path_has_get_operation() {
        let spec = OpenApiBuilder::build_spec();
        let health = spec.paths.get("/health").unwrap();
        assert!(health.get.is_some());
        let op = health.get.as_ref().unwrap();
        assert_eq!(op.operation_id, "healthCheck");
        assert!(op.tags.contains(&"system".to_string()));
    }

    #[test]
    fn test_scans_path_has_post_and_get() {
        let spec = OpenApiBuilder::build_spec();
        let scans = spec.paths.get("/api/v1/scans").unwrap();
        assert!(scans.post.is_some());
        assert!(scans.get.is_some());
    }

    #[test]
    fn test_code_examples_count() {
        let examples = get_code_examples();
        assert!(examples.len() >= 4);
    }

    #[test]
    fn test_code_examples_have_languages() {
        let examples = get_code_examples();
        let languages: Vec<&str> = examples.iter().map(|e| e.language.as_str()).collect();
        assert!(languages.contains(&"bash"));
        assert!(languages.contains(&"python"));
        assert!(languages.contains(&"javascript"));
        assert!(languages.contains(&"graphql"));
    }

    #[test]
    fn test_code_examples_serialize() {
        let examples = get_code_examples();
        let json = serde_json::to_string(&examples).unwrap();
        assert!(json.contains("curl"));
        assert!(json.contains("requests.post"));
    }

    #[test]
    fn test_schema_ref() {
        let schema = OpenApiBuilder::schema_ref("TestSchema");
        assert_eq!(schema.reference, Some("#/components/schemas/TestSchema".to_string()));
    }

    #[test]
    fn test_uuid_param() {
        let param = OpenApiBuilder::uuid_param("scan_id", "Scan ID");
        assert_eq!(param.name, "scan_id");
        assert_eq!(param.in_location, "path");
        assert_eq!(param.required, Some(true));
    }

    #[test]
    fn test_api_info_has_contact() {
        let spec = OpenApiBuilder::build_spec();
        assert!(spec.info.contact.is_some());
        let contact = spec.info.contact.unwrap();
        assert_eq!(contact.name, Some("Nemue Project".to_string()));
    }

    #[test]
    fn test_api_info_has_license() {
        let spec = OpenApiBuilder::build_spec();
        assert!(spec.info.license.is_some());
        let license = spec.info.license.unwrap();
        assert_eq!(license.name, "MIT");
    }

    #[test]
    fn test_external_docs() {
        let spec = OpenApiBuilder::build_spec();
        assert!(spec.external_docs.is_some());
        let ext = spec.external_docs.unwrap();
        assert!(ext.url.contains("docs.nemue.dev"));
    }

    #[test]
    fn test_path_item_default() {
        let item = PathItem::default();
        assert!(item.get.is_none());
        assert!(item.post.is_none());
        assert!(item.delete.is_none());
    }

    #[test]
    fn test_components_default() {
        let components = Components::default();
        assert!(components.schemas.is_none());
        assert!(components.security_schemes.is_none());
    }
}
