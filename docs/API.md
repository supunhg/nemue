# Nemue REST API Documentation

## Overview

The Nemue REST API provides programmatic access to the security scanning framework. It supports scan management, webhook notifications, CI/CD integration, and SIEM forwarding.

**Base URL:** `http://localhost:8080`
**API Version:** v1
**Content-Type:** `application/json`

## Authentication

The API supports authentication via API keys. Pass the key using one of:

- **Header:** `Authorization: Bearer <api-key>`
- **Header:** `X-API-Key: <api-key>`
- **Query parameter:** `?api_key=<api-key>`

When no API keys are configured, all endpoints are accessible without authentication.

## Rate Limiting

Requests are rate-limited per API key (or IP address). Default limits:

- 100 requests per 60-second window
- Returns `429 Too Many Requests` when exceeded
- Response includes `X-RateLimit-Remaining` header

---

## Endpoints

### System

#### Health Check

```
GET /health
```

Returns server health status and basic metrics.

**Response (200):**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "uptime_seconds": 3600,
  "active_scans": 2,
  "completed_scans": 15
}
```

#### Server Info

```
GET /api/v1/info
```

Returns server capabilities and API version.

**Response (200):**
```json
{
  "name": "nemue",
  "version": "0.1.0",
  "capabilities": ["port_scanning", "service_detection", "webhooks", "cicd_integration"],
  "api_version": "v1"
}
```

#### Scan Statistics

```
GET /api/v1/stats
```

Returns aggregated statistics across all scans.

**Response (200):**
```json
{
  "total_scans": 42,
  "active_scans": 3,
  "completed_scans": 35,
  "failed_scans": 2,
  "cancelled_scans": 2,
  "total_targets_scanned": 150,
  "total_ports_scanned": 42000,
  "uptime_seconds": 86400
}
```

---

### Scans

#### Start Scan

```
POST /api/v1/scans
```

**Request Body:**
```json
{
  "targets": ["192.168.1.1", "10.0.0.0/24"],
  "ports": [22, 80, 443, 8080],
  "scan_type": "tcp",
  "timing": "normal",
  "enable_service_detection": true,
  "enable_os_detection": false,
  "enable_vuln_check": true,
  "enable_threat_intel": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| targets | string[] | Yes | IP addresses or CIDR ranges |
| ports | integer[] | Yes | Ports to scan |
| scan_type | string | No | `tcp`, `udp`, `syn`, `connect` (default: `tcp`) |
| timing | string | No | `paranoid`, `sneaky`, `polite`, `normal`, `aggressive`, `insane` |
| enable_service_detection | boolean | No | Detect services on open ports |
| enable_os_detection | boolean | No | Attempt OS fingerprinting |
| enable_vuln_check | boolean | No | Check for known vulnerabilities |
| enable_threat_intel | boolean | No | Query threat intelligence databases |

**Response (202):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "Scan queued successfully"
}
```

#### List Scans

```
GET /api/v1/scans?page=1&per_page=20
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| page | integer | 1 | Page number |
| per_page | integer | 20 | Results per page (max 100) |

**Response (200):**
```json
{
  "scans": [
    {
      "scan_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "completed",
      "targets_count": 2,
      "ports_count": 1000,
      "started_at": "2025-01-01T00:00:00Z",
      "completed_at": "2025-01-01T00:05:30Z"
    }
  ],
  "total": 42,
  "page": 1,
  "per_page": 20
}
```

#### Get Scan Status

```
GET /api/v1/scans/{scan_id}
```

**Response (200):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "progress": 45.5,
  "targets_total": 2,
  "targets_completed": 1,
  "ports_total": 1000,
  "ports_scanned": 450,
  "started_at": "2025-01-01T00:00:00Z",
  "updated_at": "2025-01-01T00:02:30Z",
  "completed_at": null
}
```

#### Get Scan Results

```
GET /api/v1/scans/{scan_id}/results
```

**Response (200):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "targets": [
    {
      "target": "192.168.1.1",
      "ip": "192.168.1.1",
      "status": "up",
      "open_ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "service": {
            "name": "http",
            "version": "2.4.41",
            "product": "Apache httpd",
            "confidence": 95
          }
        }
      ],
      "vulnerabilities": [
        {
          "cve_id": "CVE-2024-1234",
          "severity": "high",
          "cvss_score": 8.5,
          "description": "Remote code execution in Apache"
        }
      ],
      "risk_score": 75
    }
  ],
  "total_open_ports": 3,
  "total_vulnerabilities": 1,
  "overall_risk_score": 75,
  "scan_duration_ms": 330000
}
```

#### Cancel Scan

```
POST /api/v1/scans/{scan_id}/cancel
```

**Response (200):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "cancelled",
  "message": "Scan cancelled successfully"
}
```

#### Delete Scan

```
DELETE /api/v1/scans/{scan_id}
```

**Response (200):**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Scan deleted successfully"
}
```

---

### Webhooks

#### Register Webhook

```
POST /api/v1/webhooks
```

**Request Body:**
```json
{
  "url": "https://hooks.slack.com/services/T00/B00/xxx",
  "provider": "slack",
  "secret": null,
  "max_retries": 3,
  "events": ["scan.completed", "scan.failed"]
}
```

**Supported Providers:** `slack`, `discord`, `teams`, `custom`

**Response (201):**
```json
{
  "webhook_id": "660e8400-e29b-41d4-a716-446655440000",
  "message": "Webhook registered successfully"
}
```

#### List Webhooks

```
GET /api/v1/webhooks
```

**Response (200):**
```json
{
  "webhooks": [
    {
      "webhook_id": "660e8400-e29b-41d4-a716-446655440000",
      "url": "https://hooks.slack.com/services/...",
      "provider": "slack",
      "events": ["scan.completed", "scan.failed"],
      "created_at": "2025-01-01T00:00:00Z"
    }
  ],
  "total": 1
}
```

#### Delete Webhook

```
DELETE /api/v1/webhooks/{webhook_id}
```

#### Test Webhook

```
POST /api/v1/webhooks/{webhook_id}/test
```

Sends a test event to the webhook and returns the delivery result.

---

### CI/CD Integration

#### Get CI/CD Config

```
GET /api/v1/cicd/config
```

**Response (200):**
```json
{
  "platform": "generic",
  "fail_on_vuln": false,
  "risk_threshold": 80,
  "max_open_ports": null,
  "output_format": "text"
}
```

#### Evaluate CI/CD Results

```
POST /api/v1/cicd/evaluate
```

**Request Body:**
```json
{
  "scan_id": "scan-123",
  "targets_scanned": 5,
  "total_open_ports": 12,
  "total_vulnerabilities": 2,
  "risk_score": 75
}
```

**Response (200):**
```json
{
  "scan_id": "scan-123",
  "passed": true,
  "exit_code": 0,
  "targets_scanned": 5,
  "total_open_ports": 12,
  "total_vulnerabilities": 2,
  "risk_score": 75,
  "failures": [],
  "warnings": ["Risk score 75 is elevated but below threshold"],
  "report": "=== Nemue CI/CD Scan Report ===\n..."
}
```

**Exit Codes:**
| Code | Meaning |
|------|---------|
| 0 | Success - no issues |
| 1 | Vulnerabilities found (when `fail_on_vuln: true`) |
| 2 | Risk score exceeded threshold |
| 3 | Open ports exceeded maximum |
| 4 | Scan error |

---

### OpenAPI Specification

```
GET /openapi.json
```

Returns the full OpenAPI 3.0 specification for the API.

---

## SIEM Integration

Nemue can forward scan results to SIEM systems in multiple formats:

### Supported Formats

| Format | Description |
|--------|-------------|
| **CEF** | Common Event Format (ArcSight) |
| **LEEF** | Log Event Extended Format (QRadar) |
| **JSON** | Raw JSON for generic ingestion |
| **Syslog** | RFC 5424 syslog messages |

### Supported SIEM Systems

- **ElasticSearch** - Direct index ingestion
- **Syslog** - UDP/TCP syslog forwarding
- **HTTP endpoints** - Generic webhook-style delivery

### Configuration

```rust
let config = SiemConfig {
    format: SiemFormat::Cef,
    elasticsearch_url: Some("http://localhost:9200".to_string()),
    elasticsearch_index: Some("nemue-scans".to_string()),
    auth_token: Some("your-token".to_string()),
    ..Default::default()
};
```

---

## CI/CD Usage Examples

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    nemue scan ${{ env.TARGET }} --ports top1000 --output json > results.json
    nemue cicd evaluate --input results.json --fail-on-vuln --risk-threshold 70
```

### GitLab CI

```yaml
security_scan:
  script:
    - nemue scan $TARGET --ports top1000 --output json > results.json
    - nemue cicd evaluate --input results.json --format gitlabci
  artifacts:
    reports:
      dotenv: scan_results.env
```

### Jenkins Pipeline

```groovy
stage('Security Scan') {
    steps {
        sh 'nemue scan ${TARGET} --ports top1000 --output json > results.json'
        sh 'nemue cicd evaluate --input results.json --format json'
    }
    post {
        always {
            archiveArtifacts 'results.json'
        }
    }
}
```

---

## Integrations

Nemue integrates with external ticketing and incident management systems to automatically create tickets from vulnerability findings.

### Jira Integration

Create and update Jira issues from scan findings.

**Configuration:**
```rust
use nemue::integrations::JiraConfig;

let config = JiraConfig {
    base_url: "https://your-org.atlassian.net".to_string(),
    email: "security@your-org.com".to_string(),
    api_token: std::env::var("JIRA_API_TOKEN").unwrap(),
    project_key: "SEC".to_string(),
    default_assignee: Some("security-team".to_string()),
    default_labels: vec!["automated".to_string()],
    custom_field_mappings: HashMap::new(),
};
```

**Severity to Priority Mapping:**

| Nemue Severity | Jira Priority |
|---------------|---------------|
| Critical | Highest |
| High | High |
| Medium | Medium |
| Low | Low |
| Info | Lowest |

**Features:**
- Create issues from vulnerability findings with full details (CVE IDs, evidence, remediation)
- Update existing issues with new findings
- Transition issues through workflow states
- Custom field mapping for organizational requirements

**Example:**
```rust
use nemue::integrations::{JiraClient, JiraConfig};

let client = JiraClient::new(config);
let issue = client.create_issue_from_finding(&vuln_result);
let issue_key = client.create_issue(&issue).await?;
```

---

### ServiceNow Integration

Create incidents and change requests from scan findings.

**Configuration:**
```rust
use nemue::integrations::ServiceNowConfig;

let config = ServiceNowConfig {
    instance_url: "https://dev.service-now.com".to_string(),
    username: "admin".to_string(),
    password: std::env::var("SNOW_PASSWORD").unwrap(),
    assignment_group: Some("Security Team".to_string()),
    caller_id: Some("nemue-service".to_string()),
    default_cmdb_ci: Some("web-server-01".to_string()),
    custom_table: None,
    custom_fields: HashMap::new(),
};
```

**Severity to Priority Mapping:**

| Nemue Severity | ServiceNow Priority | Impact |
|---------------|-------------------|--------|
| Critical | 1 - Critical | High |
| High | 2 - High | High |
| Medium | 3 - Moderate | Medium |
| Low | 4 - Low | Low |
| Info | 5 - Planning | Low |

**Features:**
- Create incidents from vulnerability findings
- Create change requests for remediation tracking
- Map findings to CMDB configuration items
- Custom table support for organizational workflows
- Custom field mapping

**Example:**
```rust
use nemue::integrations::{ServiceNowClient, ServiceNowConfig};

let client = ServiceNowClient::new(config);

// Create incident
let incident = client.create_incident_from_finding(&vuln_result);
let incident_number = client.create_incident(&incident).await?;

// Create change request
let change = client.create_change_from_finding(&vuln_result);
let change_number = client.create_change_request(&change).await?;
```

---

### PagerDuty Integration

Trigger incidents for critical and high-severity findings.

**Configuration:**
```rust
use nemue::integrations::PagerDutyConfig;

let config = PagerDutyConfig {
    routing_key: std::env::var("PD_ROUTING_KEY").unwrap(),
    api_token: std::env::var("PD_API_TOKEN").unwrap(),
    service_id: "service-id".to_string(),
    escalation_policy_id: Some("policy-id".to_string()),
    default_urgency: "high".to_string(),
    auto_acknowledge: false,
    auto_resolve: false,
};
```

**Severity Mapping:**

| Nemue Severity | PagerDuty Severity | Urgency |
|---------------|-------------------|---------|
| Critical | critical | high |
| High | error | high |
| Medium | warning | default |
| Low/Info | info | default |

**Features:**
- Trigger incidents via Events API v2 for critical findings
- Configure escalation policies per severity level
- Deduplication keys prevent duplicate incidents
- Acknowledge and resolve incidents programmatically
- Custom urgency based on severity

**Example:**
```rust
use nemue::integrations::{PagerDutyClient, PagerDutyConfig};

let client = PagerDutyClient::new(config);
let incident = client.create_incident_from_finding(&vuln_result);
let dedup_key = client.trigger_incident(&incident).await?;

// Later, acknowledge or resolve
client.acknowledge_incident(&dedup_key).await?;
client.resolve_incident(&dedup_key).await?;
```

---

### GitHub Issues Integration

Create GitHub issues from scan findings with labels and milestones.

**Configuration:**
```rust
use nemue::integrations::GitHubConfig;

let config = GitHubConfig {
    token: std::env::var("GITHUB_TOKEN").unwrap(),
    owner: "myorg".to_string(),
    repo: "security-reports".to_string(),
    default_labels: vec!["auto-generated".to_string()],
    default_assignees: vec!["security-lead".to_string()],
    default_milestone: Some(5),
    project_board_id: None,
    project_column_id: None,
};
```

**Labels Applied:**

| Label | Description |
|-------|-------------|
| `security` | All findings |
| `vulnerability` | All findings |
| `severity:critical` | Critical severity |
| `severity:high` | High severity |
| `severity:medium` | Medium severity |
| `severity:low` | Low severity |
| `severity:info` | Info severity |

**Features:**
- Create issues with rich Markdown formatting (tables, code blocks, links)
- Automatic label assignment by severity
- Milestone assignment for tracking
- Project board integration
- Assignee management

**Example:**
```rust
use nemue::integrations::{GitHubClient, GitHubConfig};

let client = GitHubClient::new(config);
let issue = client.create_issue_from_finding(&vuln_result);
let issue_number = client.create_issue(&issue).await?;

// Add to project board
client.add_to_project(
    &format!("https://api.github.com/repos/myorg/security-reports/issues/{}", issue_number),
    column_id,
).await?;
```

---

### Integration Module Structure

```
src/integrations/
├── mod.rs           # Module exports
├── jira.rs          # Jira integration
├── servicenow.rs    # ServiceNow integration
├── pagerduty.rs     # PagerDuty integration
└── github.rs        # GitHub Issues integration
```
