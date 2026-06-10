use actix_web::dev::ServiceRequest;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    pub keys: HashMap<String, ApiKeyInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub rotation_history: Vec<RotationEntry>,
    #[serde(default)]
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationEntry {
    pub rotated_at: String,
    pub reason: String,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiKeyConfig {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub fn add_key(&mut self, key: String, name: String, scopes: Vec<String>) {
        self.keys.insert(
            key,
            ApiKeyInfo {
                name,
                enabled: true,
                scopes,
                created_at: Some(Utc::now().to_rfc3339()),
                expires_at: None,
                rotation_history: Vec::new(),
                last_used_at: None,
            },
        );
    }

    pub fn add_key_with_expiry(
        &mut self,
        key: String,
        name: String,
        scopes: Vec<String>,
        expires_at: DateTime<Utc>,
    ) {
        self.keys.insert(
            key,
            ApiKeyInfo {
                name,
                enabled: true,
                scopes,
                created_at: Some(Utc::now().to_rfc3339()),
                expires_at: Some(expires_at.to_rfc3339()),
                rotation_history: Vec::new(),
                last_used_at: None,
            },
        );
    }

    pub fn validate(&self, key: &str) -> Option<&ApiKeyInfo> {
        self.keys.get(key).filter(|info| {
            if !info.enabled {
                return false;
            }
            if let Some(expires) = &info.expires_at {
                if let Ok(expiry) = DateTime::parse_from_rfc3339(expires) {
                    if Utc::now() > expiry.with_timezone(&Utc) {
                        return false;
                    }
                }
            }
            true
        })
    }

    pub fn rotate_key(&mut self, old_key: &str, new_key: String) -> Result<(), String> {
        if let Some(mut info) = self.keys.remove(old_key) {
            let entry = RotationEntry {
                rotated_at: Utc::now().to_rfc3339(),
                reason: "Key rotation".to_string(),
            };
            info.rotation_history.push(entry);
            self.keys.insert(new_key, info);
            Ok(())
        } else {
            Err("Key not found".to_string())
        }
    }

    pub fn disable_key(&mut self, key: &str) -> Result<(), String> {
        if let Some(info) = self.keys.get_mut(key) {
            info.enabled = false;
            Ok(())
        } else {
            Err("Key not found".to_string())
        }
    }

    pub fn record_usage(&mut self, key: &str) {
        if let Some(info) = self.keys.get_mut(key) {
            info.last_used_at = Some(Utc::now().to_rfc3339());
        }
    }

    pub fn keys_expiring_within(&self, duration: Duration) -> Vec<(&String, &ApiKeyInfo)> {
        let cutoff = Utc::now() + duration;
        self.keys
            .iter()
            .filter(|(_, info)| {
                if let Some(expires) = &info.expires_at {
                    if let Ok(expiry) = DateTime::parse_from_rfc3339(expires) {
                        return expiry.with_timezone(&Utc) <= cutoff;
                    }
                }
                false
            })
            .collect()
    }
}

/// JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

impl JwtClaims {
    pub fn new(
        subject: String,
        issuer: String,
        audience: String,
        scopes: Vec<String>,
        ttl_seconds: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            sub: subject,
            iss: issuer,
            aud: audience,
            exp: now.timestamp() + ttl_seconds,
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            scopes,
            metadata: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(&scope.to_string()) || self.scopes.contains(&"*".to_string())
    }
}

/// Simple JWT token encoder/decoder (base64url, no external crate needed for basic use)
pub struct JwtService {
    secret: Vec<u8>,
    issuer: String,
    default_ttl: i64,
}

impl JwtService {
    pub fn new(secret: &[u8], issuer: String, default_ttl: i64) -> Self {
        Self {
            secret: secret.to_vec(),
            issuer,
            default_ttl,
        }
    }

    pub fn create_token(&self, subject: &str, scopes: Vec<String>) -> Result<String, String> {
        let claims = JwtClaims::new(
            subject.to_string(),
            self.issuer.clone(),
            "nemue-api".to_string(),
            scopes,
            self.default_ttl,
        );
        self.encode(&claims)
    }

    pub fn create_token_with_ttl(
        &self,
        subject: &str,
        scopes: Vec<String>,
        ttl: i64,
    ) -> Result<String, String> {
        let claims = JwtClaims::new(
            subject.to_string(),
            self.issuer.clone(),
            "nemue-api".to_string(),
            scopes,
            ttl,
        );
        self.encode(&claims)
    }

    pub fn validate_token(&self, token: &str) -> Result<JwtClaims, String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid JWT format".to_string());
        }

        let payload =
            base64url_decode(parts[1]).map_err(|_| "Invalid JWT payload encoding".to_string())?;

        let claims: JwtClaims =
            serde_json::from_slice(&payload).map_err(|_| "Invalid JWT claims".to_string())?;

        if claims.is_expired() {
            return Err("Token expired".to_string());
        }

        let expected_sig = self.sign(parts[0], parts[1]);
        let provided_sig =
            base64url_decode(parts[2]).map_err(|_| "Invalid JWT signature encoding".to_string())?;

        if expected_sig != provided_sig {
            return Err("Invalid JWT signature".to_string());
        }

        Ok(claims)
    }

    fn encode(&self, claims: &JwtClaims) -> Result<String, String> {
        let header = base64url_encode(b"{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        let payload =
            serde_json::to_vec(claims).map_err(|e| format!("Failed to serialize claims: {}", e))?;
        let payload_b64 = base64url_encode(&payload);
        let signature = self.sign(&header, &payload_b64);
        let sig_b64 = base64url_encode(&signature);
        Ok(format!("{}.{}.{}", header, payload_b64, sig_b64))
    }

    fn sign(&self, header: &str, payload: &str) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        header.hash(&mut hasher);
        payload.hash(&mut hasher);
        self.secret.hash(&mut hasher);
        let hash = hasher.finish();

        hash.to_be_bytes().to_vec()
    }
}

/// OAuth2 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Config {
    pub client_id: String,
    pub client_secret: String,
    pub authorization_url: String,
    pub token_url: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

impl OAuth2Config {
    pub fn new(
        client_id: String,
        client_secret: String,
        authorization_url: String,
        token_url: String,
        redirect_uri: String,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            authorization_url,
            token_url,
            redirect_uri,
            scopes,
        }
    }

    pub fn authorization_url_with_state(&self, state: &str) -> String {
        let scopes = self.scopes.join("%20");
        format!(
            "{}?client_id={}&redirect_uri={}&scope={}&state={}&response_type=code",
            self.authorization_url,
            urlencoding(&self.client_id),
            urlencoding(&self.redirect_uri),
            scopes,
            urlencoding(state)
        )
    }
}

/// OAuth2 token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

/// OAuth2 token exchange handler
pub struct OAuth2Client {
    config: OAuth2Config,
    http_client: reqwest::Client,
}

impl OAuth2Client {
    pub fn new(config: OAuth2Config) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }

    pub async fn exchange_code(&self, code: &str) -> Result<OAuth2TokenResponse, String> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.config.redirect_uri),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let response = self
            .http_client
            .post(&self.config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Token exchange failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!(
                "Token exchange returned status: {}",
                response.status()
            ));
        }

        response
            .json::<OAuth2TokenResponse>()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))
    }

    pub async fn refresh_token(&self, refresh_token: &str) -> Result<OAuth2TokenResponse, String> {
        let params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let response = self
            .http_client
            .post(&self.config.token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Token refresh failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!(
                "Token refresh returned status: {}",
                response.status()
            ));
        }

        response
            .json::<OAuth2TokenResponse>()
            .await
            .map_err(|e| format!("Failed to parse refresh response: {}", e))
    }
}

/// Session management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub scopes: Vec<String>,
    pub is_valid: bool,
}

impl Session {
    pub fn new(user_id: String, scopes: Vec<String>, ttl: Duration) -> Self {
        let now = Utc::now();
        Self {
            session_id: Uuid::new_v4().to_string(),
            user_id,
            created_at: now,
            last_activity: now,
            expires_at: now + ttl,
            ip_address: None,
            user_agent: None,
            scopes,
            is_valid: true,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    pub fn invalidate(&mut self) {
        self.is_valid = false;
    }
}

pub struct SessionManager {
    sessions: RwLock<HashMap<String, Session>>,
    session_ttl: Duration,
    max_sessions_per_user: usize,
}

impl SessionManager {
    pub fn new(session_ttl: Duration, max_sessions_per_user: usize) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            session_ttl,
            max_sessions_per_user,
        }
    }

    pub fn create_session(
        &self,
        user_id: &str,
        scopes: Vec<String>,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> Result<Session, String> {
        let mut sessions = self.sessions.write().map_err(|e| e.to_string())?;

        let user_sessions: Vec<_> = sessions
            .values()
            .filter(|s| s.user_id == user_id && !s.is_expired() && s.is_valid)
            .collect();

        if user_sessions.len() >= self.max_sessions_per_user {
            return Err("Maximum sessions per user exceeded".to_string());
        }

        let mut session = Session::new(user_id.to_string(), scopes, self.session_ttl);
        session.ip_address = ip;
        session.user_agent = user_agent;
        let session_id = session.session_id.clone();
        sessions.insert(session_id, session.clone());

        Ok(session)
    }

    pub fn get_session(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read().ok()?;
        sessions
            .get(session_id)
            .cloned()
            .filter(|s| !s.is_expired() && s.is_valid)
    }

    pub fn touch_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().map_err(|e| e.to_string())?;
        if let Some(session) = sessions.get_mut(session_id) {
            if session.is_expired() || !session.is_valid {
                return Err("Session expired or invalid".to_string());
            }
            session.touch();
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    pub fn invalidate_session(&self, session_id: &str) -> Result<(), String> {
        let mut sessions = self.sessions.write().map_err(|e| e.to_string())?;
        if let Some(session) = sessions.get_mut(session_id) {
            session.invalidate();
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    pub fn invalidate_user_sessions(&self, user_id: &str) -> usize {
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        let mut count = 0;
        for session in sessions.values_mut() {
            if session.user_id == user_id && session.is_valid {
                session.invalidate();
                count += 1;
            }
        }
        count
    }

    pub fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().unwrap_or_else(|e| e.into_inner());
        let before = sessions.len();
        sessions.retain(|_, s| !s.is_expired() && s.is_valid);
        before - sessions.len()
    }

    pub fn active_sessions(&self) -> usize {
        let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        sessions
            .values()
            .filter(|s| !s.is_expired() && s.is_valid)
            .count()
    }

    pub fn user_sessions(&self, user_id: &str) -> Vec<Session> {
        let sessions = self.sessions.read().unwrap_or_else(|e| e.into_inner());
        sessions
            .values()
            .filter(|s| s.user_id == user_id && !s.is_expired() && s.is_valid)
            .cloned()
            .collect()
    }
}

/// Rate limiter state per API key or IP
#[derive(Debug)]
pub struct RateLimiterState {
    requests: HashMap<String, Vec<DateTime<Utc>>>,
    max_requests: u64,
    window_secs: u64,
}

impl RateLimiterState {
    pub fn new(max_requests: u64, window_secs: u64) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests,
            window_secs,
        }
    }

    pub fn check_and_record(&mut self, key: &str) -> bool {
        let now = Utc::now();
        let window = chrono::Duration::seconds(self.window_secs as i64);
        let cutoff = now - window;

        let entries = self.requests.entry(key.to_string()).or_default();
        entries.retain(|t| *t > cutoff);

        if entries.len() as u64 >= self.max_requests {
            return false;
        }

        entries.push(now);
        true
    }

    pub fn remaining(&self, key: &str) -> u64 {
        let now = Utc::now();
        let window = chrono::Duration::seconds(self.window_secs as i64);
        let cutoff = now - window;

        match self.requests.get(key) {
            Some(entries) => {
                let count = entries.iter().filter(|t| **t > cutoff).count() as u64;
                self.max_requests.saturating_sub(count)
            }
            None => self.max_requests,
        }
    }
}

/// Extract bearer token or X-API-Key header from request
pub fn extract_api_key(req: &ServiceRequest) -> Option<String> {
    if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if auth_str.starts_with("Bearer ") {
                return Some(auth_str[7..].to_string());
            }
        }
    }

    if let Some(api_key) = req.headers().get("X-API-Key") {
        if let Ok(key) = api_key.to_str() {
            return Some(key.to_string());
        }
    }

    if let Some(query) = req.uri().query() {
        for param in query.split('&') {
            if let Some((k, v)) = param.split_once('=') {
                if k == "api_key" {
                    return Some(v.to_string());
                }
            }
        }
    }

    None
}

fn base64url_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        }
    }
    result
}

fn base64url_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.replace('-', "+").replace('_', "/");
    let padded = match input.len() % 4 {
        0 => input,
        n => format!("{}{}", input, "=".repeat(4 - n)),
    };

    let mut result = Vec::new();
    for chunk in padded.as_bytes().chunks(4) {
        if chunk.len() < 2 {
            return Err("Invalid base64".to_string());
        }
        let a = char_to_sextet(chunk[0])? as u32;
        let b = char_to_sextet(chunk[1])? as u32;
        let c = if chunk.len() > 2 && chunk[2] != b'=' {
            char_to_sextet(chunk[2])? as u32
        } else {
            0
        };
        let d = if chunk.len() > 3 && chunk[3] != b'=' {
            char_to_sextet(chunk[3])? as u32
        } else {
            0
        };

        let triple = (a << 18) | (b << 12) | (c << 6) | d;
        result.push((triple >> 16) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            result.push((triple >> 8) as u8);
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            result.push(triple as u8);
        }
    }
    Ok(result)
}

fn char_to_sextet(c: u8) -> Result<u8, String> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' | b'-' => Ok(62),
        b'/' | b'_' => Ok(63),
        _ => Err(format!("Invalid base64 character: {}", c as char)),
    }
}

fn urlencoding(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_config_validation() {
        let mut config = ApiKeyConfig::new();
        config.add_key(
            "test-key-123".to_string(),
            "Test Key".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );

        assert!(config.validate("test-key-123").is_some());
        assert!(config.validate("invalid-key").is_none());
    }

    #[test]
    fn test_api_key_disabled() {
        let mut config = ApiKeyConfig::new();
        config.add_key("disabled-key".to_string(), "Disabled".to_string(), vec![]);
        config.keys.get_mut("disabled-key").unwrap().enabled = false;

        assert!(config.validate("disabled-key").is_none());
    }

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiterState::new(5, 60);
        assert!(limiter.check_and_record("user1"));
        assert!(limiter.check_and_record("user1"));
        assert!(limiter.check_and_record("user1"));
        assert_eq!(limiter.remaining("user1"), 2);
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let mut limiter = RateLimiterState::new(3, 60);
        assert!(limiter.check_and_record("user2"));
        assert!(limiter.check_and_record("user2"));
        assert!(limiter.check_and_record("user2"));
        assert!(!limiter.check_and_record("user2"));
        assert_eq!(limiter.remaining("user2"), 0);
    }

    #[test]
    fn test_rate_limiter_independent_keys() {
        let mut limiter = RateLimiterState::new(2, 60);
        assert!(limiter.check_and_record("userA"));
        assert!(limiter.check_and_record("userA"));
        assert!(!limiter.check_and_record("userA"));

        assert!(limiter.check_and_record("userB"));
        assert_eq!(limiter.remaining("userB"), 1);
    }

    #[test]
    fn test_rate_limiter_unknown_key_has_full_quota() {
        let limiter = RateLimiterState::new(100, 60);
        assert_eq!(limiter.remaining("unknown"), 100);
    }

    #[test]
    fn test_jwt_claims_creation() {
        let claims = JwtClaims::new(
            "user1".to_string(),
            "nemue".to_string(),
            "api".to_string(),
            vec!["read".to_string()],
            3600,
        );
        assert!(!claims.is_expired());
        assert!(claims.has_scope("read"));
        assert!(!claims.has_scope("write"));
    }

    #[test]
    fn test_jwt_claims_wildcard_scope() {
        let claims = JwtClaims::new(
            "admin".to_string(),
            "nemue".to_string(),
            "api".to_string(),
            vec!["*".to_string()],
            3600,
        );
        assert!(claims.has_scope("anything"));
    }

    #[test]
    fn test_jwt_service_create_and_validate() {
        let service = JwtService::new(b"test-secret", "nemue".to_string(), 3600);
        let token = service
            .create_token("user1", vec!["read".to_string()])
            .unwrap();

        let claims = service.validate_token(&token).unwrap();
        assert_eq!(claims.sub, "user1");
        assert!(claims.has_scope("read"));
    }

    #[test]
    fn test_jwt_service_rejects_expired() {
        let service = JwtService::new(b"test-secret", "nemue".to_string(), -1);
        let token = service
            .create_token("user1", vec!["read".to_string()])
            .unwrap();
        assert!(service.validate_token(&token).is_err());
    }

    #[test]
    fn test_jwt_service_rejects_tampered() {
        let service = JwtService::new(b"test-secret", "nemue".to_string(), 3600);
        let token = service
            .create_token("user1", vec!["read".to_string()])
            .unwrap();
        let tampered = format!("{}X", token);
        assert!(service.validate_token(&tampered).is_err());
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_session_creation() {
        let session = Session::new(
            "user1".to_string(),
            vec!["read".to_string()],
            Duration::hours(1),
        );
        assert!(!session.is_expired());
        assert!(session.is_valid);
    }

    #[test]
    fn test_session_manager_create_and_get() {
        let manager = SessionManager::new(Duration::hours(1), 5);
        let session = manager
            .create_session(
                "user1",
                vec!["read".to_string()],
                Some("127.0.0.1".to_string()),
                None,
            )
            .unwrap();

        let retrieved = manager.get_session(&session.session_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user1");
    }

    #[test]
    fn test_session_manager_invalidate() {
        let manager = SessionManager::new(Duration::hours(1), 5);
        let session = manager.create_session("user1", vec![], None, None).unwrap();

        manager.invalidate_session(&session.session_id).unwrap();
        assert!(manager.get_session(&session.session_id).is_none());
    }

    #[test]
    fn test_session_manager_max_per_user() {
        let manager = SessionManager::new(Duration::hours(1), 2);
        let _s1 = manager.create_session("user1", vec![], None, None).unwrap();
        let _s2 = manager.create_session("user1", vec![], None, None).unwrap();
        assert!(manager.create_session("user1", vec![], None, None).is_err());
    }

    #[test]
    fn test_session_manager_cleanup() {
        let manager = SessionManager::new(Duration::hours(1), 5);
        let session = manager.create_session("user1", vec![], None, None).unwrap();
        assert_eq!(manager.active_sessions(), 1);

        manager.invalidate_session(&session.session_id).unwrap();
        let cleaned = manager.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert_eq!(manager.active_sessions(), 0);
    }

    #[test]
    fn test_session_manager_invalidate_user() {
        let manager = SessionManager::new(Duration::hours(1), 5);
        let _s1 = manager.create_session("user1", vec![], None, None).unwrap();
        let _s2 = manager.create_session("user1", vec![], None, None).unwrap();
        let _s3 = manager.create_session("user2", vec![], None, None).unwrap();

        let invalidated = manager.invalidate_user_sessions("user1");
        assert_eq!(invalidated, 2);
        assert_eq!(manager.active_sessions(), 1);
    }

    #[test]
    fn test_api_key_rotation() {
        let mut config = ApiKeyConfig::new();
        config.add_key(
            "old-key".to_string(),
            "Test".to_string(),
            vec!["read".to_string()],
        );

        config.rotate_key("old-key", "new-key".to_string()).unwrap();
        assert!(config.validate("old-key").is_none());
        assert!(config.validate("new-key").is_some());
    }

    #[test]
    fn test_api_key_with_expiry() {
        let mut config = ApiKeyConfig::new();
        config.add_key_with_expiry(
            "expiring-key".to_string(),
            "Expiring".to_string(),
            vec![],
            Utc::now() - Duration::hours(1),
        );

        assert!(config.validate("expiring-key").is_none());
    }

    #[test]
    fn test_api_key_disable() {
        let mut config = ApiKeyConfig::new();
        config.add_key("key1".to_string(), "Test".to_string(), vec![]);
        assert!(config.validate("key1").is_some());

        config.disable_key("key1").unwrap();
        assert!(config.validate("key1").is_none());
    }

    #[test]
    fn test_oauth2_authorization_url() {
        let config = OAuth2Config::new(
            "client123".to_string(),
            "secret".to_string(),
            "https://auth.example.com/authorize".to_string(),
            "https://auth.example.com/token".to_string(),
            "https://app.example.com/callback".to_string(),
            vec!["read".to_string(), "write".to_string()],
        );

        let url = config.authorization_url_with_state("random-state");
        assert!(url.contains("client_id=client123"));
        assert!(url.contains("state=random-state"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn test_urlencoding() {
        assert_eq!(urlencoding("hello world"), "hello%20world");
        assert_eq!(urlencoding("test@example"), "test%40example");
        assert_eq!(urlencoding("safe-chars_123"), "safe-chars_123");
    }
}
