// Technology Fingerprinting
// Identifies web technologies, frameworks, CMS, and JavaScript libraries

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Detected technology information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    pub name: String,
    pub category: TechnologyCategory,
    pub version: Option<String>,
    pub confidence: f32, // 0.0 to 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TechnologyCategory {
    WebServer,
    Framework,
    CMS,
    ProgrammingLanguage,
    JavaScript,
    Analytics,
    CDN,
    Database,
    Cache,
    Security,
    Other,
}

/// Technology fingerprinting engine
pub struct TechnologyFingerprinter;

impl TechnologyFingerprinter {
    /// Detect technologies from HTTP headers and HTML body
    pub fn detect(headers: &HashMap<String, String>, body: &str) -> Vec<Technology> {
        let mut technologies = Vec::new();

        technologies.extend(Self::detect_from_headers(headers));
        technologies.extend(Self::detect_from_body(body));
        technologies.extend(Self::detect_from_meta_tags(body));
        technologies.extend(Self::detect_from_scripts(body));

        technologies
    }

    /// Detect technologies from HTTP response headers
    fn detect_from_headers(headers: &HashMap<String, String>) -> Vec<Technology> {
        let mut techs = Vec::new();

        // Web servers
        if let Some(server) = headers.get("server").or_else(|| headers.get("Server")) {
            if server.contains("nginx") {
                techs.push(Technology {
                    name: "nginx".to_string(),
                    category: TechnologyCategory::WebServer,
                    version: Self::extract_version(server, "nginx/"),
                    confidence: 1.0,
                });
            } else if server.contains("Apache") {
                techs.push(Technology {
                    name: "Apache".to_string(),
                    category: TechnologyCategory::WebServer,
                    version: Self::extract_version(server, "Apache/"),
                    confidence: 1.0,
                });
            } else if server.contains("Microsoft-IIS") {
                techs.push(Technology {
                    name: "Microsoft IIS".to_string(),
                    category: TechnologyCategory::WebServer,
                    version: Self::extract_version(server, "Microsoft-IIS/"),
                    confidence: 1.0,
                });
            } else if server.contains("cloudflare") {
                techs.push(Technology {
                    name: "Cloudflare".to_string(),
                    category: TechnologyCategory::CDN,
                    version: None,
                    confidence: 1.0,
                });
            }
        }

        // X-Powered-By header
        if let Some(powered_by) = headers
            .get("x-powered-by")
            .or_else(|| headers.get("X-Powered-By"))
        {
            if powered_by.contains("PHP") {
                techs.push(Technology {
                    name: "PHP".to_string(),
                    category: TechnologyCategory::ProgrammingLanguage,
                    version: Self::extract_version(powered_by, "PHP/"),
                    confidence: 1.0,
                });
            } else if powered_by.contains("ASP.NET") {
                techs.push(Technology {
                    name: "ASP.NET".to_string(),
                    category: TechnologyCategory::Framework,
                    version: None,
                    confidence: 1.0,
                });
            } else if powered_by.contains("Express") {
                techs.push(Technology {
                    name: "Express.js".to_string(),
                    category: TechnologyCategory::Framework,
                    version: None,
                    confidence: 0.9,
                });
            }
        }

        // CDN detection
        if headers.contains_key("cf-ray") || headers.contains_key("CF-RAY") {
            techs.push(Technology {
                name: "Cloudflare".to_string(),
                category: TechnologyCategory::CDN,
                version: None,
                confidence: 1.0,
            });
        }

        if headers.contains_key("x-amz-cf-id") {
            techs.push(Technology {
                name: "Amazon CloudFront".to_string(),
                category: TechnologyCategory::CDN,
                version: None,
                confidence: 1.0,
            });
        }

        techs
    }

    /// Detect technologies from HTML body
    fn detect_from_body(body: &str) -> Vec<Technology> {
        let mut techs = Vec::new();

        // WordPress
        if body.contains("/wp-content/") || body.contains("/wp-includes/") {
            techs.push(Technology {
                name: "WordPress".to_string(),
                category: TechnologyCategory::CMS,
                version: None,
                confidence: 0.95,
            });
        }

        // Joomla
        if body.contains("/media/jui/") || body.contains("Joomla!") {
            techs.push(Technology {
                name: "Joomla".to_string(),
                category: TechnologyCategory::CMS,
                version: None,
                confidence: 0.95,
            });
        }

        // Drupal
        if body.contains("Drupal.settings") || body.contains("/sites/default/files") {
            techs.push(Technology {
                name: "Drupal".to_string(),
                category: TechnologyCategory::CMS,
                version: None,
                confidence: 0.95,
            });
        }

        // Laravel
        if body.contains("laravel_session") || body.contains("csrf-token") {
            techs.push(Technology {
                name: "Laravel".to_string(),
                category: TechnologyCategory::Framework,
                version: None,
                confidence: 0.7,
            });
        }

        // Django
        if body.contains("csrfmiddlewaretoken") {
            techs.push(Technology {
                name: "Django".to_string(),
                category: TechnologyCategory::Framework,
                version: None,
                confidence: 0.8,
            });
        }

        // React
        if body.contains("__REACT_") || body.contains("react-root") {
            techs.push(Technology {
                name: "React".to_string(),
                category: TechnologyCategory::JavaScript,
                version: None,
                confidence: 0.85,
            });
        }

        // Vue.js
        if body.contains("v-cloak") || body.contains("data-v-") {
            techs.push(Technology {
                name: "Vue.js".to_string(),
                category: TechnologyCategory::JavaScript,
                version: None,
                confidence: 0.85,
            });
        }

        // Angular
        if body.contains("ng-app") || body.contains("ng-controller") {
            techs.push(Technology {
                name: "Angular".to_string(),
                category: TechnologyCategory::JavaScript,
                version: None,
                confidence: 0.85,
            });
        }

        techs
    }

    /// Detect technologies from meta tags
    fn detect_from_meta_tags(body: &str) -> Vec<Technology> {
        let mut techs = Vec::new();

        // Generator meta tag
        if let Some(generator) = Self::extract_meta_content(body, "generator") {
            if generator.contains("WordPress") {
                let version = Self::extract_version(&generator, "WordPress ");
                techs.push(Technology {
                    name: "WordPress".to_string(),
                    category: TechnologyCategory::CMS,
                    version,
                    confidence: 1.0,
                });
            } else if generator.contains("Drupal") {
                let version = Self::extract_version(&generator, "Drupal ");
                techs.push(Technology {
                    name: "Drupal".to_string(),
                    category: TechnologyCategory::CMS,
                    version,
                    confidence: 1.0,
                });
            }
        }

        techs
    }

    /// Detect technologies from script tags
    fn detect_from_scripts(body: &str) -> Vec<Technology> {
        let mut techs = Vec::new();

        // jQuery
        if body.contains("jquery.min.js") || body.contains("jquery.js") {
            techs.push(Technology {
                name: "jQuery".to_string(),
                category: TechnologyCategory::JavaScript,
                version: None,
                confidence: 1.0,
            });
        }

        // Bootstrap
        if body.contains("bootstrap.min.js") || body.contains("bootstrap.css") {
            techs.push(Technology {
                name: "Bootstrap".to_string(),
                category: TechnologyCategory::JavaScript,
                version: None,
                confidence: 1.0,
            });
        }

        // Google Analytics
        if body.contains("google-analytics.com/analytics.js") || body.contains("gtag.js") {
            techs.push(Technology {
                name: "Google Analytics".to_string(),
                category: TechnologyCategory::Analytics,
                version: None,
                confidence: 1.0,
            });
        }

        techs
    }

    /// Extract version number from a string
    fn extract_version(text: &str, prefix: &str) -> Option<String> {
        if let Some(pos) = text.find(prefix) {
            let after_prefix = &text[pos + prefix.len()..];
            let version: String = after_prefix
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();

            if !version.is_empty() {
                return Some(version);
            }
        }
        None
    }

    /// Extract content from meta tag
    fn extract_meta_content(body: &str, name: &str) -> Option<String> {
        // Regex-based extraction
        let pattern = format!("name=\"{}\"", name);
        if let Some(pos) = body.find(&pattern) {
            if let Some(content_start) = body[pos..].find("content=\"") {
                let content_pos = pos + content_start + 9; // 9 = length of 'content="'
                if let Some(content_end) = body[content_pos..].find('"') {
                    return Some(body[content_pos..content_pos + content_end].to_string());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_nginx_from_header() {
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "nginx/1.18.0".to_string());

        let techs = TechnologyFingerprinter::detect_from_headers(&headers);
        assert!(!techs.is_empty());
        assert_eq!(techs[0].name, "nginx");
        assert_eq!(techs[0].version, Some("1.18.0".to_string()));
    }

    #[test]
    fn test_detect_php_from_header() {
        let mut headers = HashMap::new();
        headers.insert("X-Powered-By".to_string(), "PHP/7.4.3".to_string());

        let techs = TechnologyFingerprinter::detect_from_headers(&headers);
        assert!(!techs.is_empty());
        assert_eq!(techs[0].name, "PHP");
    }

    #[test]
    fn test_detect_wordpress_from_body() {
        let body =
            "<html><body><link href='/wp-content/themes/twentytwenty/style.css'/></body></html>";

        let techs = TechnologyFingerprinter::detect_from_body(body);
        assert!(!techs.is_empty());
        assert_eq!(techs[0].name, "WordPress");
    }

    #[test]
    fn test_extract_version() {
        let result = TechnologyFingerprinter::extract_version("nginx/1.18.0 (Ubuntu)", "nginx/");
        assert_eq!(result, Some("1.18.0".to_string()));
    }
}
