// Form Detection and Analysis
// Identifies HTML forms, input fields, and potential security issues

use serde::{Deserialize, Serialize};

use super::FormInfo;

/// Input field information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputField {
    pub name: String,
    pub input_type: String,
    pub value: Option<String>,
    pub required: bool,
    pub max_length: Option<usize>,
}

/// Form security issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FormSecurityIssue {
    MissingCSRFProtection,
    NoHTTPS,
    AutocompleteEnabled,
    PasswordInURL,
    WeakValidation,
}

/// Form analyzer
pub struct FormAnalyzer;

impl FormAnalyzer {
    /// Extract all forms from HTML
    pub fn extract_forms(_html: &str, _page_url: &str) -> Vec<FormInfo> {
        // TODO: Implement proper HTML parsing
        // For now, return placeholder
        vec![]
    }

    /// Analyze form for security issues
    pub fn analyze_security(form: &FormInfo, is_https: bool) -> Vec<FormSecurityIssue> {
        let mut issues = Vec::new();

        // Check for HTTPS
        if !is_https && Self::contains_sensitive_fields(form) {
            issues.push(FormSecurityIssue::NoHTTPS);
        }

        // Check for CSRF token
        if !Self::has_csrf_token(form) && !Self::is_get_form(form) {
            issues.push(FormSecurityIssue::MissingCSRFProtection);
        }

        // Check for autocomplete on sensitive fields
        if Self::has_autocomplete_on_password(form) {
            issues.push(FormSecurityIssue::AutocompleteEnabled);
        }

        issues
    }

    /// Check if form contains sensitive fields (password, credit card, etc.)
    fn contains_sensitive_fields(form: &FormInfo) -> bool {
        let sensitive_patterns = ["password", "passwd", "pwd", "credit", "card", "cvv", "ssn"];

        form.inputs.iter().any(|input| {
            sensitive_patterns.iter().any(|pattern| {
                input.name.to_lowercase().contains(pattern)
                    || input.input_type.to_lowercase().contains(pattern)
            })
        })
    }

    /// Check if form has CSRF token field
    fn has_csrf_token(form: &FormInfo) -> bool {
        let csrf_patterns = [
            "csrf",
            "token",
            "_token",
            "authenticity_token",
            "csrfmiddlewaretoken",
        ];

        form.inputs.iter().any(|input| {
            csrf_patterns
                .iter()
                .any(|pattern| input.name.to_lowercase().contains(pattern))
        })
    }

    /// Check if form uses GET method
    fn is_get_form(form: &FormInfo) -> bool {
        form.method.to_uppercase() == "GET"
    }

    /// Check if autocomplete is enabled on password fields
    fn has_autocomplete_on_password(form: &FormInfo) -> bool {
        form.inputs.iter().any(|input| {
            input.input_type.to_lowercase() == "password"
                && input.name.to_lowercase().contains("autocomplete")
        })
    }

    /// Extract input fields from form HTML
    pub fn extract_inputs(_form_html: &str) -> Vec<InputField> {
        // TODO: Implement proper HTML parsing
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::super::FormInput;
    use super::*;

    #[test]
    fn test_contains_sensitive_fields() {
        let form = FormInfo {
            action: "/login".to_string(),
            method: "POST".to_string(),
            inputs: vec![
                FormInput {
                    name: "username".to_string(),
                    input_type: "text".to_string(),
                    required: true,
                },
                FormInput {
                    name: "password".to_string(),
                    input_type: "password".to_string(),
                    required: true,
                },
            ],
        };

        assert!(FormAnalyzer::contains_sensitive_fields(&form));
    }

    #[test]
    fn test_has_csrf_token() {
        let form_with_token = FormInfo {
            action: "/submit".to_string(),
            method: "POST".to_string(),
            inputs: vec![FormInput {
                name: "csrf_token".to_string(),
                input_type: "hidden".to_string(),
                required: false,
            }],
        };

        assert!(FormAnalyzer::has_csrf_token(&form_with_token));

        let form_without_token = FormInfo {
            action: "/submit".to_string(),
            method: "POST".to_string(),
            inputs: vec![FormInput {
                name: "data".to_string(),
                input_type: "text".to_string(),
                required: false,
            }],
        };

        assert!(!FormAnalyzer::has_csrf_token(&form_without_token));
    }

    #[test]
    fn test_analyze_security_no_https() {
        let form = FormInfo {
            action: "/login".to_string(),
            method: "POST".to_string(),
            inputs: vec![FormInput {
                name: "password".to_string(),
                input_type: "password".to_string(),
                required: true,
            }],
        };

        let issues = FormAnalyzer::analyze_security(&form, false);
        assert!(issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::NoHTTPS)));
    }

    #[test]
    fn test_analyze_security_missing_csrf() {
        let form = FormInfo {
            action: "/submit".to_string(),
            method: "POST".to_string(),
            inputs: vec![FormInput {
                name: "data".to_string(),
                input_type: "text".to_string(),
                required: false,
            }],
        };

        let issues = FormAnalyzer::analyze_security(&form, true);
        assert!(issues
            .iter()
            .any(|i| matches!(i, FormSecurityIssue::MissingCSRFProtection)));
    }
}
