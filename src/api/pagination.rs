use serde::{Deserialize, Serialize};

/// Query parameters for cursor-based pagination
#[derive(Debug, Clone, Deserialize)]
pub struct CursorQuery {
    /// Opaque cursor returned from a previous response
    pub cursor: Option<String>,
    /// Number of items per page (capped at `max_page_size`)
    pub limit: Option<usize>,
}

/// Metadata included in every paginated response
#[derive(Debug, Clone, Serialize)]
pub struct PaginationMeta {
    /// Cursor to pass as `?cursor=` to get the next page
    pub next_cursor: Option<String>,
    /// Cursor to pass to get the previous page (if available)
    pub prev_cursor: Option<String>,
    /// Number of items returned in this page
    pub count: usize,
    /// Total number of items across all pages
    pub total: usize,
}

/// A paginated response wrapper
#[derive(Debug, Clone, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub pagination: PaginationMeta,
}

/// Link header values for RFC 8288 compliance
#[derive(Debug, Clone)]
pub struct LinkHeaders {
    pub next: Option<String>,
    pub prev: Option<String>,
    pub first: String,
    pub last: String,
}

impl LinkHeaders {
    pub fn to_header_value(&self) -> String {
        let mut parts = Vec::new();
        parts.push(format!("<{}>; rel=\"first\"", self.first));
        parts.push(format!("<{}>; rel=\"last\"", self.last));
        if let Some(ref next) = self.next {
            parts.push(format!("<{}>; rel=\"next\"", next));
        }
        if let Some(ref prev) = self.prev {
            parts.push(format!("<{}>; rel=\"prev\"", prev));
        }
        parts.join(", ")
    }
}

/// Configuration for pagination behaviour
#[derive(Debug, Clone)]
pub struct PaginationConfig {
    pub default_page_size: usize,
    pub max_page_size: usize,
}

impl Default for PaginationConfig {
    fn default() -> Self {
        Self {
            default_page_size: 20,
            max_page_size: 100,
        }
    }
}

/// Cursor encoder/decoder – cursors are simply base64-encoded indices
/// so the storage layer stays opaque to the caller.
pub struct CursorCodec;

impl CursorCodec {
    pub fn encode(index: usize) -> String {
        base64_simple_encode(index)
    }

    pub fn decode(cursor: &str) -> Option<usize> {
        base64_simple_decode(cursor)
    }
}

/// Compute pagination metadata and slice items from a pre-sorted list.
///
/// `items` must already be sorted in the desired order. The function applies
/// the cursor offset and limit, then returns the page along with metadata.
pub fn paginate<T: Clone + Serialize>(
    items: &[T],
    cursor: Option<&str>,
    config: &PaginationConfig,
) -> PaginatedResponse<T> {
    let limit = config.default_page_size.min(config.max_page_size);
    let offset = cursor
        .and_then(CursorCodec::decode)
        .unwrap_or(0)
        .min(items.len());

    let page: Vec<T> = items
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect();

    let page_count = page.len();
    let next_offset = offset + page_count;
    let next_cursor = if next_offset < items.len() {
        Some(CursorCodec::encode(next_offset))
    } else {
        None
    };

    let prev_cursor = if offset > 0 {
        let prev = offset.saturating_sub(limit);
        Some(CursorCodec::encode(prev))
    } else {
        None
    };

    PaginatedResponse {
        data: page,
        pagination: PaginationMeta {
            next_cursor,
            prev_cursor,
            count: page_count,
            total: items.len(),
        },
    }
}

/// Build Link headers for a request path
pub fn build_link_headers(
    base_path: &str,
    meta: &PaginationMeta,
    limit: usize,
) -> LinkHeaders {
    let first = format!("{}?limit={}", base_path, limit);
    let last_offset = if meta.total > 0 {
        ((meta.total - 1) / limit) * limit
    } else {
        0
    };
    let last = format!("{}?cursor={}&limit={}", base_path, CursorCodec::encode(last_offset), limit);

    let next = meta.next_cursor.as_ref().map(|c| {
        format!("{}?cursor={}&limit={}", base_path, c, limit)
    });
    let prev = meta.prev_cursor.as_ref().map(|c| {
        format!("{}?cursor={}&limit={}", base_path, c, limit)
    });

    LinkHeaders {
        next,
        prev,
        first,
        last,
    }
}

const BASE64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 4 + 2) / 3);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(BASE64_ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(BASE64_ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64_ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(BASE64_ALPHABET[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(input.len() * 3 / 4);
    let mut accum: u32 = 0;
    let mut bits: u32 = 0;
    for byte in input.bytes() {
        let val = BASE64_ALPHABET.iter().position(|&b| b == byte)? as u32;
        accum = (accum << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buf.push((accum >> bits) as u8);
        }
    }
    Some(buf)
}

fn base64_simple_encode(value: usize) -> String {
    let bytes = value.to_be_bytes();
    let trimmed = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    base64_encode(&bytes[trimmed..])
}

fn base64_simple_decode(encoded: &str) -> Option<usize> {
    let bytes = base64_decode(encoded)?;
    if bytes.len() > std::mem::size_of::<usize>() {
        return None;
    }
    let mut buf = [0u8; std::mem::size_of::<usize>()];
    buf[std::mem::size_of::<usize>() - bytes.len()..].copy_from_slice(&bytes);
    Some(usize::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor_roundtrip() {
        for v in [0usize, 1, 42, 255, 1024, 65535, usize::MAX] {
            let encoded = CursorCodec::encode(v);
            let decoded = CursorCodec::decode(&encoded);
            assert_eq!(decoded, Some(v), "roundtrip failed for {}", v);
        }
    }

    #[test]
    fn test_paginate_first_page() {
        let items: Vec<i32> = (0..50).collect();
        let config = PaginationConfig {
            default_page_size: 10,
            max_page_size: 100,
        };
        let resp = paginate(&items, None, &config);
        assert_eq!(resp.data.len(), 10);
        assert_eq!(resp.data[0], 0);
        assert_eq!(resp.pagination.count, 10);
        assert_eq!(resp.pagination.total, 50);
        assert!(resp.pagination.next_cursor.is_some());
        assert!(resp.pagination.prev_cursor.is_none());
    }

    #[test]
    fn test_paginate_second_page() {
        let items: Vec<i32> = (0..50).collect();
        let config = PaginationConfig {
            default_page_size: 10,
            max_page_size: 100,
        };
        let first = paginate(&items, None, &config);
        let cursor = first.pagination.next_cursor.unwrap();
        let second = paginate(&items, Some(&cursor), &config);
        assert_eq!(second.data[0], 10);
        assert_eq!(second.data.len(), 10);
        assert!(second.pagination.prev_cursor.is_some());
    }

    #[test]
    fn test_paginate_last_page() {
        let items: Vec<i32> = (0..25).collect();
        let config = PaginationConfig {
            default_page_size: 10,
            max_page_size: 100,
        };
        let cursor = CursorCodec::encode(20);
        let resp = paginate(&items, Some(&cursor), &config);
        assert_eq!(resp.data.len(), 5);
        assert_eq!(resp.data, vec![20, 21, 22, 23, 24]);
        assert!(resp.pagination.next_cursor.is_none());
    }

    #[test]
    fn test_paginate_empty() {
        let items: Vec<i32> = vec![];
        let config = PaginationConfig::default();
        let resp = paginate(&items, None, &config);
        assert!(resp.data.is_empty());
        assert_eq!(resp.pagination.total, 0);
        assert!(resp.pagination.next_cursor.is_none());
    }

    #[test]
    fn test_paginate_limit_capped() {
        let items: Vec<i32> = (0..200).collect();
        let config = PaginationConfig {
            default_page_size: 200,
            max_page_size: 50,
        };
        let resp = paginate(&items, None, &config);
        assert_eq!(resp.data.len(), 50);
    }

    #[test]
    fn test_link_headers() {
        let meta = PaginationMeta {
            next_cursor: Some("abc".to_string()),
            prev_cursor: None,
            count: 10,
            total: 50,
        };
        let links = build_link_headers("/api/v1/scans", &meta, 10);
        let header = links.to_header_value();
        assert!(header.contains("rel=\"first\""));
        assert!(header.contains("rel=\"last\""));
        assert!(header.contains("rel=\"next\""));
        assert!(!header.contains("rel=\"prev\""));
    }

    #[test]
    fn test_link_headers_no_next() {
        let meta = PaginationMeta {
            next_cursor: None,
            prev_cursor: Some("0".to_string()),
            count: 5,
            total: 25,
        };
        let links = build_link_headers("/api/v1/scans", &meta, 10);
        let header = links.to_header_value();
        assert!(!header.contains("rel=\"next\""));
        assert!(header.contains("rel=\"prev\""));
    }

    #[test]
    fn test_cursor_codec_invalid() {
        assert!(CursorCodec::decode("!!!").is_none());
    }
}
