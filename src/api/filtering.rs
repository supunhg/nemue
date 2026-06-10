use serde::Deserialize;
use std::collections::HashMap;

/// Common query parameters for filtering, sorting, field selection, and search
#[derive(Debug, Clone, Deserialize)]
pub struct FilterQuery {
    /// Comma-separated field list to include in the response (sparse fieldset)
    pub fields: Option<String>,
    /// Sort specification: `field` (ascending) or `-field` (descending), comma-separated
    pub sort: Option<String>,
    /// Free-text search query
    pub search: Option<String>,
}

/// Parsed and validated filter parameters
#[derive(Debug, Clone)]
pub struct ParsedFilter {
    pub fields: Vec<String>,
    pub sort_fields: Vec<SortField>,
    pub search: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SortField {
    pub field: String,
    pub ascending: bool,
}

impl ParsedFilter {
    pub fn parse(query: &FilterQuery) -> Self {
        let fields = query
            .fields
            .as_ref()
            .map(|f| {
                f.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let sort_fields = query
            .sort
            .as_ref()
            .map(|s| {
                s.split(',')
                    .map(|part| {
                        let part = part.trim();
                        if let Some(field) = part.strip_prefix('-') {
                            SortField {
                                field: field.to_string(),
                                ascending: false,
                            }
                        } else {
                            SortField {
                                field: part.to_string(),
                                ascending: true,
                            }
                        }
                    })
                    .filter(|sf| !sf.field.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        ParsedFilter {
            fields,
            sort_fields,
            search: query.search.clone(),
        }
    }

    /// Returns true if a given field name was requested in `fields`
    pub fn wants_field(&self, field: &str) -> bool {
        self.fields.is_empty() || self.fields.iter().any(|f| f == field)
    }

    /// Check if a string matches the search query (case-insensitive substring)
    pub fn matches_search(&self, text: &str) -> bool {
        match &self.search {
            Some(q) if !q.is_empty() => text.to_lowercase().contains(&q.to_lowercase()),
            _ => true,
        }
    }
}

/// Apply field selection to a JSON value, keeping only the requested fields.
/// If no fields were requested the value is returned unchanged.
pub fn apply_field_selection(value: &serde_json::Value, fields: &[String]) -> serde_json::Value {
    if fields.is_empty() {
        return value.clone();
    }

    match value {
        serde_json::Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for field in fields {
                if let Some(v) = map.get(field) {
                    result.insert(field.clone(), v.clone());
                }
            }
            serde_json::Value::Object(result)
        }
        other => other.clone(),
    }
}

/// Apply field selection to each item in a JSON array
pub fn apply_field_selection_to_array(
    items: &[serde_json::Value],
    fields: &[String],
) -> Vec<serde_json::Value> {
    if fields.is_empty() {
        return items.to_vec();
    }
    items
        .iter()
        .map(|item| apply_field_selection(item, fields))
        .collect()
}

/// Sort a mutable slice of JSON values by the given sort fields.
/// Values that lack a sort field are placed at the end.
pub fn sort_json_values(items: &mut [serde_json::Value], sort_fields: &[SortField]) {
    if sort_fields.is_empty() {
        return;
    }

    items.sort_by(|a, b| {
        for sf in sort_fields {
            let va = a.get(&sf.field);
            let vb = b.get(&sf.field);
            let ord = compare_json_values(va, vb);
            let ord = if sf.ascending { ord } else { ord.reverse() };
            if ord != std::cmp::Ordering::Equal {
                return ord;
            }
        }
        std::cmp::Ordering::Equal
    });
}

fn compare_json_values(
    a: Option<&serde_json::Value>,
    b: Option<&serde_json::Value>,
) -> std::cmp::Ordering {
    match (a, b) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(a), Some(b)) => match (a, b) {
            (serde_json::Value::Number(na), serde_json::Value::Number(nb)) => na
                .as_f64()
                .unwrap_or(0.0)
                .partial_cmp(&nb.as_f64().unwrap_or(0.0))
                .unwrap_or(std::cmp::Ordering::Equal),
            (serde_json::Value::String(sa), serde_json::Value::String(sb)) => sa.cmp(sb),
            (serde_json::Value::Bool(ba), serde_json::Value::Bool(bb)) => ba.cmp(bb),
            _ => std::cmp::Ordering::Equal,
        },
    }
}

/// Validate that the requested sort fields are in the allowed set
pub fn validate_sort_fields(sort_fields: &[SortField], allowed: &[&str]) -> Result<(), String> {
    for sf in sort_fields {
        if !allowed.contains(&sf.field.as_str()) {
            return Err(format!(
                "Cannot sort by field '{}'. Allowed: {:?}",
                sf.field, allowed
            ));
        }
    }
    Ok(())
}

/// Validate that the requested fields are in the allowed set
pub fn validate_fields(fields: &[String], allowed: &[&str]) -> Result<(), String> {
    for f in fields {
        if !allowed.contains(&f.as_str()) {
            return Err(format!("Unknown field '{}'. Allowed: {:?}", f, allowed));
        }
    }
    Ok(())
}

/// Extract extra key=value filter parameters from a query string map
/// (all params that are not `fields`, `sort`, `search`, `cursor`, `limit`, `page`, `per_page`)
pub fn extract_extra_filters(params: &HashMap<String, String>) -> HashMap<String, String> {
    let reserved = [
        "fields", "sort", "search", "cursor", "limit", "page", "per_page",
    ];
    params
        .iter()
        .filter(|(k, _)| !reserved.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_empty() {
        let q = FilterQuery {
            fields: None,
            sort: None,
            search: None,
        };
        let f = ParsedFilter::parse(&q);
        assert!(f.fields.is_empty());
        assert!(f.sort_fields.is_empty());
        assert!(f.search.is_none());
    }

    #[test]
    fn test_parse_fields() {
        let q = FilterQuery {
            fields: Some("name,status,port".to_string()),
            sort: None,
            search: None,
        };
        let f = ParsedFilter::parse(&q);
        assert_eq!(f.fields, vec!["name", "status", "port"]);
    }

    #[test]
    fn test_parse_sort() {
        let q = FilterQuery {
            fields: None,
            sort: Some("-created_at,name".to_string()),
            search: None,
        };
        let f = ParsedFilter::parse(&q);
        assert_eq!(f.sort_fields.len(), 2);
        assert_eq!(f.sort_fields[0].field, "created_at");
        assert!(!f.sort_fields[0].ascending);
        assert_eq!(f.sort_fields[1].field, "name");
        assert!(f.sort_fields[1].ascending);
    }

    #[test]
    fn test_wants_field() {
        let q = FilterQuery {
            fields: Some("name,status".to_string()),
            sort: None,
            search: None,
        };
        let f = ParsedFilter::parse(&q);
        assert!(f.wants_field("name"));
        assert!(f.wants_field("status"));
        assert!(!f.wants_field("port"));
    }

    #[test]
    fn test_wants_field_empty_means_all() {
        let q = FilterQuery {
            fields: None,
            sort: None,
            search: None,
        };
        let f = ParsedFilter::parse(&q);
        assert!(f.wants_field("anything"));
    }

    #[test]
    fn test_matches_search() {
        let q = FilterQuery {
            fields: None,
            sort: None,
            search: Some("web".to_string()),
        };
        let f = ParsedFilter::parse(&q);
        assert!(f.matches_search("My Web Server"));
        assert!(!f.matches_search("Database"));
    }

    #[test]
    fn test_matches_search_empty() {
        let q = FilterQuery {
            fields: None,
            sort: None,
            search: None,
        };
        let f = ParsedFilter::parse(&q);
        assert!(f.matches_search("anything"));
    }

    #[test]
    fn test_field_selection() {
        let item = json!({"name": "scan1", "status": "running", "secret": "hidden"});
        let result = apply_field_selection(&item, &["name".into(), "status".into()]);
        assert_eq!(result, json!({"name": "scan1", "status": "running"}));
    }

    #[test]
    fn test_field_selection_empty() {
        let item = json!({"name": "scan1"});
        let result = apply_field_selection(&item, &[]);
        assert_eq!(result, item);
    }

    #[test]
    fn test_sort_json_values() {
        let mut items = vec![
            json!({"name": "b", "port": 80}),
            json!({"name": "a", "port": 443}),
            json!({"name": "c", "port": 22}),
        ];
        sort_json_values(
            &mut items,
            &[SortField {
                field: "name".to_string(),
                ascending: true,
            }],
        );
        assert_eq!(items[0]["name"], "a");
        assert_eq!(items[1]["name"], "b");
        assert_eq!(items[2]["name"], "c");
    }

    #[test]
    fn test_sort_descending() {
        let mut items = vec![
            json!({"port": 22}),
            json!({"port": 443}),
            json!({"port": 80}),
        ];
        sort_json_values(
            &mut items,
            &[SortField {
                field: "port".to_string(),
                ascending: false,
            }],
        );
        assert_eq!(items[0]["port"], 443);
        assert_eq!(items[1]["port"], 80);
        assert_eq!(items[2]["port"], 22);
    }

    #[test]
    fn test_validate_sort_fields() {
        let fields = vec![SortField {
            field: "name".to_string(),
            ascending: true,
        }];
        assert!(validate_sort_fields(&fields, &["name", "status"]).is_ok());

        let bad = vec![SortField {
            field: "secret".to_string(),
            ascending: true,
        }];
        assert!(validate_sort_fields(&bad, &["name", "status"]).is_err());
    }

    #[test]
    fn test_validate_fields() {
        assert!(validate_fields(&["name".into()], &["name", "status"]).is_ok());
        assert!(validate_fields(&["bad".into()], &["name", "status"]).is_err());
    }

    #[test]
    fn test_extract_extra_filters() {
        let mut params = HashMap::new();
        params.insert("status".to_string(), "running".to_string());
        params.insert("sort".to_string(), "name".to_string());
        params.insert("page".to_string(), "1".to_string());

        let extras = extract_extra_filters(&params);
        assert_eq!(extras.len(), 1);
        assert_eq!(extras.get("status").unwrap(), "running");
    }

    #[test]
    fn test_apply_field_selection_to_array() {
        let items = vec![json!({"name": "a", "x": 1}), json!({"name": "b", "x": 2})];
        let result = apply_field_selection_to_array(&items, &["name".into()]);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], json!({"name": "a"}));
    }
}
