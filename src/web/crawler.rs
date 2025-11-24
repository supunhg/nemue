// Web Crawler Implementation
// Recursive web spider for discovering pages, links, and resources

use anyhow::{Result, Context};
use std::collections::{HashSet, VecDeque, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use reqwest::{Client, header};

use super::{CrawlerConfig, WebResource, FormInfo, FormInput, HttpMethod};

/// Web crawler state
pub struct CrawlerState {
    visited: HashSet<String>,
    queue: VecDeque<(String, usize)>, // (URL, depth)
    results: Vec<WebResource>,
}

impl CrawlerState {
    pub fn new() -> Self {
        Self {
            visited: HashSet::new(),
            queue: VecDeque::new(),
            results: Vec::new(),
        }
    }

    pub fn add_url(&mut self, url: String, depth: usize) {
        if !self.visited.contains(&url) && depth <= 10 {
            self.queue.push_back((url, depth));
        }
    }

    pub fn mark_visited(&mut self, url: String) {
        self.visited.insert(url);
    }

    pub fn add_result(&mut self, resource: WebResource) {
        self.results.push(resource);
    }

    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty()
    }

    pub fn pop_url(&mut self) -> Option<(String, usize)> {
        self.queue.pop_front()
    }

    pub fn get_results(&self) -> &[WebResource] {
        &self.results
    }
}

/// Recursive web crawler
pub struct Crawler {
    config: CrawlerConfig,
    state: Arc<Mutex<CrawlerState>>,
    client: Client,
}

impl Crawler {
    pub fn new(config: CrawlerConfig) -> Self {
        let client = Client::builder()
            .user_agent(&config.user_agent)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .unwrap();

        Self {
            config,
            state: Arc::new(Mutex::new(CrawlerState::new())),
            client,
        }
    }

    /// Start crawling from a seed URL
    pub async fn crawl(&self, seed_url: &str) -> Result<Vec<WebResource>> {
        let mut state = self.state.lock().await;
        state.add_url(seed_url.to_string(), 0);
        drop(state);

        while let Some((url, depth)) = {
            let mut state = self.state.lock().await;
            state.pop_url()
        } {
            if depth > self.config.max_depth {
                continue;
            }

            // Check if we've reached max pages
            let page_count = {
                let state = self.state.lock().await;
                state.results.len()
            };

            if page_count >= self.config.max_pages {
                break;
            }

            // Fetch and process the page
            if let Ok(resource) = self.fetch_page(&url, depth).await {
                let mut state = self.state.lock().await;
                state.mark_visited(url.clone());
                
                // Extract and queue links for recursive crawling
                for link in &resource.links {
                    if self.should_follow_link(&url, link) {
                        state.add_url(link.clone(), depth + 1);
                    }
                }
                
                state.add_result(resource);
            }
        }

        let state = self.state.lock().await;
        Ok(state.get_results().to_vec())
    }

    /// Fetch a single page
    async fn fetch_page(&self, url: &str, depth: usize) -> Result<WebResource> {
        let start = std::time::Instant::now();
        
        let response = self.client
            .get(url)
            .send()
            .await
            .context("Failed to fetch page")?;

        let status_code = response.status().as_u16();
        let response_time_ms = start.elapsed().as_millis() as u64;

        // Extract headers
        let mut headers = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.to_string(), value_str.to_string());
            }
        }

        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let content_length = response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        let body = response.text().await.unwrap_or_default();

        // Extract title
        let title = Self::extract_title(&body);

        // Extract links
        let links = Self::extract_links(&body, url);

        // Extract forms
        let forms = Self::extract_forms(&body);

        Ok(WebResource {
            url: url.to_string(),
            method: HttpMethod::GET,
            status_code,
            content_type,
            content_length: content_length.or(Some(body.len())),
            response_time_ms,
            headers,
            title,
            links,
            forms,
            depth,
        })
    }

    /// Determine if a link should be followed
    fn should_follow_link(&self, current_url: &str, link: &str) -> bool {
        // Don't follow external links unless configured
        if !self.config.follow_external {
            if !link.starts_with(current_url) && link.starts_with("http") {
                return false;
            }
        }

        // Skip common non-HTML resources
        let skip_extensions = [
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
            ".css", ".js", ".woff", ".woff2", ".ttf", ".pdf", ".zip"
        ];

        for ext in &skip_extensions {
            if link.ends_with(ext) {
                return false;
            }
        }

        true
    }

    /// Extract links from HTML content
    pub fn extract_links(html: &str, base_url: &str) -> Vec<String> {
        let mut links = Vec::new();
        
        // Matches href="..." and href='...'
        let href_pattern = regex::Regex::new(r#"href\s*=\s*["']([^"']+)["']"#).unwrap();
        let src_pattern = regex::Regex::new(r#"src\s*=\s*["']([^"']+)["']"#).unwrap();

        for pattern in [&href_pattern, &src_pattern] {
            for cap in pattern.captures_iter(html) {
                if let Some(link_match) = cap.get(1) {
                    let mut link = link_match.as_str().to_string();
                    
                    // Convert relative URLs to absolute
                    if link.starts_with('/') {
                        if let Ok(base) = url::Url::parse(base_url) {
                            if let Some(domain) = base.host_str() {
                                let scheme = base.scheme();
                                link = format!("{}://{}{}", scheme, domain, link);
                            }
                        }
                    } else if !link.starts_with("http") && !link.starts_with("//") {
                        if let Ok(base) = url::Url::parse(base_url) {
                            if let Ok(joined) = base.join(&link) {
                                link = joined.to_string();
                            }
                        }
                    }
                    
                    // Skip anchors, javascript, and mailto
                    if !link.starts_with('#') && !link.starts_with("javascript:") && !link.starts_with("mailto:") {
                        links.push(link);
                    }
                }
            }
        }

        links.sort();
        links.dedup();
        links
    }

    /// Extract forms from HTML content
    pub fn extract_forms(html: &str) -> Vec<FormInfo> {
        let mut forms = Vec::new();
        let form_re = regex::Regex::new(r#"(?is)<form[^>]*>(.*?)</form>"#).unwrap();
        
        for form_cap in form_re.captures_iter(html) {
            if let Some(form_content) = form_cap.get(0) {
                let form_html = form_content.as_str();
                
                let action = regex::Regex::new(r#"action\s*=\s*["']([^"']*)["']"#)
                    .unwrap()
                    .captures(form_html)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                let method = regex::Regex::new(r#"method\s*=\s*["']([^"']*)["']"#)
                    .unwrap()
                    .captures(form_html)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_uppercase())
                    .unwrap_or_else(|| "GET".to_string());

                let mut inputs = Vec::new();
                let input_re = regex::Regex::new(r#"(?is)<input[^>]*>"#).unwrap();
                
                for input_match in input_re.find_iter(form_html) {
                    let input_html = input_match.as_str();
                    
                    let name = regex::Regex::new(r#"name\s*=\s*["']([^"']*)["']"#)
                        .unwrap()
                        .captures(input_html)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default();

                    let input_type = regex::Regex::new(r#"type\s*=\s*["']([^"']*)["']"#)
                        .unwrap()
                        .captures(input_html)
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_else(|| "text".to_string());

                    let required = input_html.to_lowercase().contains("required");

                    if !name.is_empty() {
                        inputs.push(FormInput {
                            name,
                            input_type,
                            required,
                        });
                    }
                }

                forms.push(FormInfo {
                    action,
                    method,
                    inputs,
                });
            }
        }

        forms
    }

    /// Extract title from HTML
    fn extract_title(html: &str) -> Option<String> {
        regex::Regex::new(r#"(?is)<title[^>]*>(.*?)</title>"#)
            .unwrap()
            .captures(html)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawler_state_creation() {
        let state = CrawlerState::new();
        assert!(!state.has_pending());
        assert_eq!(state.get_results().len(), 0);
    }

    #[test]
    fn test_add_and_pop_url() {
        let mut state = CrawlerState::new();
        state.add_url("http://example.com".to_string(), 0);
        assert!(state.has_pending());
        
        let (url, depth) = state.pop_url().unwrap();
        assert_eq!(url, "http://example.com");
        assert_eq!(depth, 0);
    }

    #[test]
    fn test_visited_tracking() {
        let mut state = CrawlerState::new();
        state.mark_visited("http://example.com".to_string());
        state.add_url("http://example.com".to_string(), 0);
        assert!(!state.has_pending());
    }

    #[tokio::test]
    async fn test_crawler_creation() {
        let config = CrawlerConfig::default();
        let crawler = Crawler::new(config);
        assert_eq!(crawler.config.max_depth, 3);
    }

    #[test]
    fn test_extract_links() {
        let html = r##"
            <html>
                <a href="https://example.com/page1">Page 1</a>
                <a href='/page2'>Page 2</a>
                <a href="page3.html">Page 3</a>
                <img src="/image.png">
                <a href="#anchor">Anchor</a>
                <a href="javascript:void(0)">JS</a>
            </html>
        "##;
        
        let links = Crawler::extract_links(html, "https://example.com");
        assert!(links.contains(&"https://example.com/page1".to_string()));
        assert!(links.contains(&"https://example.com/page2".to_string()));
        assert!(!links.iter().any(|l| l.contains("javascript:")));
        assert!(!links.iter().any(|l| l.starts_with('#')));
    }

    #[test]
    fn test_extract_forms() {
        let html = r##"
            <form action="/login" method="POST">
                <input type="text" name="username" required>
                <input type="password" name="password" required>
                <input type="submit" value="Login">
            </form>
            <form action="/search">
                <input name="q" type="text">
            </form>
        "##;
        
        let forms = Crawler::extract_forms(html);
        assert_eq!(forms.len(), 2);
        
        let login_form = &forms[0];
        assert_eq!(login_form.action, "/login");
        assert_eq!(login_form.method, "POST");
        assert_eq!(login_form.inputs.len(), 2); // Only named inputs (username, password)
        assert!(login_form.inputs.iter().any(|i| i.name == "username" && i.required));
        assert!(login_form.inputs.iter().any(|i| i.name == "password" && i.required));
    }

    #[test]
    fn test_extract_title() {
        let html = r##"
            <html>
                <head><title>Test Page Title</title></head>
                <body>Content</body>
            </html>
        "##;
        
        let title = Crawler::extract_title(html);
        assert_eq!(title, Some("Test Page Title".to_string()));
    }

    #[test]
    fn test_extract_links_relative_urls() {
        let html = r##"
            <a href="about.html">About</a>
            <a href="/contact">Contact</a>
            <a href="https://external.com">External</a>
        "##;
        
        let links = Crawler::extract_links(html, "https://example.com/blog/");
        assert!(links.iter().any(|l| l.contains("example.com/blog/about.html")));
        assert!(links.contains(&"https://example.com/contact".to_string()));
        assert!(links.contains(&"https://external.com".to_string()));
    }

    #[test]
    fn test_extract_forms_no_method() {
        let html = r##"
            <form action="/search">
                <input name="q" type="search">
            </form>
        "##;
        
        let forms = Crawler::extract_forms(html);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].method, "GET"); // Default method
    }
}
