use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;

use super::intensity::{MatchPattern, ProbeProtocol, ProbeRarity, ServiceProbe, VersionInfo};
use super::probes::ProbeDatabase;

#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

#[derive(Debug, Clone, Default)]
pub struct NmapVersionInfo {
    pub product: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub device_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NmapMatch {
    pub service: String,
    pub pattern: String,
    pub version_info: NmapVersionInfo,
    pub case_insensitive: bool,
    pub dot_all: bool,
}

#[derive(Debug, Clone, Default)]
pub struct NmapProbe {
    pub name: String,
    pub protocol: String,
    pub data: Vec<u8>,
    pub rarity: u8,
    pub fallback: Option<String>,
    pub ports: Vec<u16>,
    pub sslports: Vec<u16>,
    pub matches: Vec<NmapMatch>,
    pub softmatches: Vec<NmapMatch>,
}

#[derive(Debug, Clone, Default)]
pub struct NmapProbeFile {
    pub probes: Vec<NmapProbe>,
    pub exclude_tcp: Vec<PortRange>,
    pub exclude_udp: Vec<PortRange>,
}

impl NmapProbeFile {
    pub fn parse(path: &str) -> Result<Self> {
        let content = fs::read_to_string(Path::new(path))
            .map_err(|e| anyhow!("Failed to read nmap-service-probes file '{}': {}", path, e))?;
        Self::parse_str(&content)
    }

    pub fn parse_str(content: &str) -> Result<Self> {
        let mut file = NmapProbeFile::default();
        let mut current_probe: Option<NmapProbe> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("Exclude ") {
                parse_exclude(line, &mut file)?;
            } else if line.starts_with("Probe ") {
                if let Some(probe) = current_probe.take() {
                    file.probes.push(probe);
                }
                current_probe = Some(parse_probe_line(line)?);
            } else if line.starts_with("match ") || line.starts_with("softmatch ") {
                if let Some(ref mut probe) = current_probe {
                    let nmap_match = parse_match_line(line)?;
                    if line.starts_with("softmatch ") {
                        probe.softmatches.push(nmap_match);
                    } else {
                        probe.matches.push(nmap_match);
                    }
                }
            } else if let Some(ref mut probe) = current_probe {
                parse_probe_option(line, probe)?;
            }
        }

        if let Some(probe) = current_probe {
            file.probes.push(probe);
        }

        Ok(file)
    }
}

fn parse_exclude(line: &str, file: &mut NmapProbeFile) -> Result<()> {
    let rest = line.strip_prefix("Exclude ").unwrap().trim();
    let (proto_spec, ports_str) = rest
        .split_once(':')
        .ok_or_else(|| anyhow!("Invalid Exclude format: {}", line))?;

    let ranges = parse_port_ranges(ports_str)?;
    match proto_spec {
        "T" => file.exclude_tcp.extend(ranges),
        "U" => file.exclude_udp.extend(ranges),
        _ => return Err(anyhow!("Unknown Exclude protocol: {}", proto_spec)),
    }
    Ok(())
}

fn parse_port_ranges(s: &str) -> Result<Vec<PortRange>> {
    let mut ranges = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start_s, end_s)) = part.split_once('-') {
            let start: u16 = start_s.parse().map_err(|_| anyhow!("Invalid port: {}", start_s))?;
            let end: u16 = end_s.parse().map_err(|_| anyhow!("Invalid port: {}", end_s))?;
            ranges.push(PortRange { start, end });
        } else {
            let port: u16 = part.parse().map_err(|_| anyhow!("Invalid port: {}", part))?;
            ranges.push(PortRange { start: port, end: port });
        }
    }
    Ok(ranges)
}

fn parse_probe_line(line: &str) -> Result<NmapProbe> {
    let rest = line.strip_prefix("Probe ").unwrap();
    let parts: Vec<&str> = rest.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err(anyhow!("Invalid Probe line: {}", line));
    }

    let protocol = parts[0].to_string();
    let name = parts[1].to_string();

    let data_str = parts[2].trim();
    let data = parse_probe_data(data_str)?;

    Ok(NmapProbe {
        name,
        protocol,
        data,
        ..Default::default()
    })
}

fn parse_probe_data(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() < 2 {
        return Ok(Vec::new());
    }

    let first = s.chars().next().unwrap();
    let last = s.chars().last().unwrap();

    if (first == 'q' || first == 'Q') && s.len() >= 3 {
        let delimiter = s.chars().nth(1).unwrap();
        let close_delimiter = match delimiter {
            '|' => '|',
            '/' => '/',
            '#' => '#',
            _ => return Err(anyhow!("Unsupported probe data delimiter: {}", delimiter)),
        };

        if last != close_delimiter {
            return Err(anyhow!("Mismatched probe data delimiters"));
        }

        let inner = &s[2..s.len() - 1];
        return unhex(inner.as_bytes());
    }

    unhex(s.as_bytes())
}

fn unhex(data: &[u8]) -> Result<Vec<u8>> {
    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if i + 3 < data.len() && data[i] == b'\\' && data[i + 1] == b'x' {
            let hi = hex_val(data[i + 2])?;
            let lo = hex_val(data[i + 3])?;
            result.push((hi << 4) | lo);
            i += 4;
        } else if i + 1 < data.len() && data[i] == b'\\' {
            match data[i + 1] {
                b'n' => result.push(b'\n'),
                b'r' => result.push(b'\r'),
                b't' => result.push(b'\t'),
                b'0' => result.push(0),
                b'\\' => result.push(b'\\'),
                other => {
                    result.push(b'\\');
                    result.push(other);
                }
            }
            i += 2;
        } else {
            result.push(data[i]);
            i += 1;
        }
    }
    Ok(result)
}

fn hex_val(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(anyhow!("Invalid hex character: {}", b as char)),
    }
}

fn parse_match_line(line: &str) -> Result<NmapMatch> {
    let (is_soft, rest) = if line.starts_with("softmatch ") {
        (true, line.strip_prefix("softmatch ").unwrap())
    } else {
        (false, line.strip_prefix("match ").unwrap())
    };

    let parts: Vec<&str> = rest.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid match line: {}", line));
    }

    let service = parts[0].to_string();
    let pattern_part = parts[1].trim();

    let (pattern, case_insensitive, dot_all) = parse_match_pattern(pattern_part)?;

    let version_info = parse_version_info_from_line(line);

    Ok(NmapMatch {
        service,
        pattern,
        version_info,
        case_insensitive,
        dot_all,
    })
}

fn parse_match_pattern(s: &str) -> Result<(String, bool, bool)> {
    let s = s.trim();
    if s.len() < 3 || !s.starts_with('m') {
        return Err(anyhow!("Invalid match pattern: {}", s));
    }

    let delimiter = s.chars().nth(1).unwrap();
    let close_delimiter = match delimiter {
        '|' => '|',
        '/' => '/',
        '#' => '#',
        _ => return Err(anyhow!("Unsupported pattern delimiter: {}", delimiter)),
    };

    let close_pos = find_closing_delimiter(s, 2, delimiter, close_delimiter)?;
    let pattern = &s[2..close_pos];

    let flags = &s[close_pos + 1..];
    let case_insensitive = flags.contains('i');
    let dot_all = flags.contains('s');

    Ok((pattern.to_string(), case_insensitive, dot_all))
}

fn find_closing_delimiter(s: &str, start: usize, open: char, close: char) -> Result<usize> {
    let bytes = s.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == close as u8 {
            if i + 1 < bytes.len() && bytes[i + 1] == close as u8 {
                i += 2;
                continue;
            }
            return Ok(i);
        }
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        i += 1;
    }
    Err(anyhow!("Unterminated pattern: {}", s))
}

fn parse_version_info_from_line(line: &str) -> NmapVersionInfo {
    let mut info = NmapVersionInfo::default();

    if let Some(idx) = line.find(" p/") {
        let rest = &line[idx + 3..];
        if let Some(end) = find_template_close(rest) {
            info.product = Some(rest[..end].to_string());
        }
    }

    if let Some(idx) = line.find(" v/") {
        let rest = &line[idx + 3..];
        if let Some(end) = find_template_close(rest) {
            info.version = Some(rest[..end].to_string());
        }
    }

    if let Some(idx) = line.find(" i/") {
        let rest = &line[idx + 3..];
        if let Some(end) = find_template_close(rest) {
            info.info = Some(rest[..end].to_string());
        }
    }

    if let Some(idx) = line.find(" h/") {
        let rest = &line[idx + 3..];
        if let Some(end) = find_template_close(rest) {
            info.hostname = Some(rest[..end].to_string());
        }
    }

    if let Some(idx) = line.find(" o/") {
        let rest = &line[idx + 3..];
        if let Some(end) = find_template_close(rest) {
            info.os = Some(rest[..end].to_string());
        }
    }

    if let Some(idx) = line.find(" d/") {
        let rest = &line[idx + 3..];
        if let Some(end) = find_template_close(rest) {
            info.device_type = Some(rest[..end].to_string());
        }
    }

    info
}

fn find_template_close(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && (i == 0 || bytes[i - 1] != b'\\') {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn parse_probe_option(line: &str, probe: &mut NmapProbe) -> Result<()> {
    let line = line.trim();
    if let Some(val) = line.strip_prefix("rarity ") {
        probe.rarity = val.trim().parse().map_err(|_| anyhow!("Invalid rarity: {}", val))?;
    } else if let Some(val) = line.strip_prefix("fallback ") {
        probe.fallback = Some(val.trim().to_string());
    } else if let Some(val) = line.strip_prefix("ports ") {
        probe.ports = parse_port_list(val)?;
    } else if let Some(val) = line.strip_prefix("sslports ") {
        probe.sslports = parse_port_list(val)?;
    } else if line.starts_with("totalwaitms ")
        || line.starts_with("tcpwrappedms ")
        || line.starts_with("waitms ")
    {
        // Ignored
    } else {
        // Unknown option, skip
    }
    Ok(())
}

fn parse_port_list(s: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start_s, end_s)) = part.split_once('-') {
            let start: u16 = start_s.parse().map_err(|_| anyhow!("Invalid port: {}", start_s))?;
            let end: u16 = end_s.parse().map_err(|_| anyhow!("Invalid port: {}", end_s))?;
            for p in start..=end {
                ports.push(p);
            }
        } else {
            let port: u16 = part.parse().map_err(|_| anyhow!("Invalid port: {}", part))?;
            ports.push(port);
        }
    }
    Ok(ports)
}

fn rarity_to_enum(r: u8) -> ProbeRarity {
    match r {
        1 => ProbeRarity::VeryCommon,
        2..=3 => ProbeRarity::Common,
        4..=6 => ProbeRarity::Moderate,
        7..=8 => ProbeRarity::Uncommon,
        _ => ProbeRarity::Rare,
    }
}

fn convert_version_info(ni: &NmapVersionInfo) -> VersionInfo {
    VersionInfo {
        product: ni.product.clone(),
        version_template: ni.version.clone(),
        info: ni.info.clone(),
        hostname: ni.hostname.clone(),
        os: ni.os.clone(),
        cpe: None,
        device_type: ni.device_type.clone(),
    }
}

impl NmapProbe {
    pub fn merge_into(&self, db: &mut ProbeDatabase) {
        let protocol = match self.protocol.as_str() {
            "TCP" => ProbeProtocol::Tcp,
            "UDP" => ProbeProtocol::Udp,
            _ => ProbeProtocol::Tcp,
        };

        let rarity = rarity_to_enum(self.rarity);

        let mut service_probe = ServiceProbe::new(self.name.clone(), protocol)
            .with_data(self.data.clone())
            .with_rarity(rarity);

        if let Some(ref fallback_name) = self.fallback {
            service_probe = service_probe.with_fallback_name(fallback_name);
        }

        for nm in &self.matches {
            let mp = MatchPattern {
                service: nm.service.clone(),
                pattern_str: nm.pattern.clone(),
                version_info: convert_version_info(&nm.version_info),
                is_softmatch: false,
                case_insensitive: nm.case_insensitive,
            };
            service_probe = service_probe.with_match(mp);
        }

        for nm in &self.softmatches {
            let mp = MatchPattern {
                service: nm.service.clone(),
                pattern_str: nm.pattern.clone(),
                version_info: convert_version_info(&nm.version_info),
                is_softmatch: true,
                case_insensitive: nm.case_insensitive,
            };
            service_probe = service_probe.with_softmatch(mp);
        }

        let mut all_ports = self.ports.clone();
        all_ports.extend_from_slice(&self.sslports);

        db.add_probe(service_probe, &all_ports);
    }
}

pub fn substitute_version_template(template: &str, captures: &[String]) -> String {
    let mut result = template.to_string();

    if captures.len() > 1 {
        for i in (1..captures.len()).rev() {
            result = result.replace(&format!("${{{}}}", i), &captures[i]);
            result = result.replace(&format!("${}", i), &captures[i]);
        }
    }

    result = result.replace("$I", "{ip}");
    result = result.replace("$H", "{hostname}");
    result = result.replace("$P", "{port}");

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_probe_definitions() {
        let input = r#"
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
Probe TCP NULL q||
Probe UDP DNSVersionBindReq q|\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00|
"#;
        let file = NmapProbeFile::parse_str(input).unwrap();
        assert_eq!(file.probes.len(), 3);

        assert_eq!(file.probes[0].name, "GetRequest");
        assert_eq!(file.probes[0].protocol, "TCP");
        assert_eq!(file.probes[0].data, b"GET / HTTP/1.0\r\n\r\n");

        assert_eq!(file.probes[1].name, "NULL");
        assert_eq!(file.probes[1].protocol, "TCP");
        assert!(file.probes[1].data.is_empty());

        assert_eq!(file.probes[2].name, "DNSVersionBindReq");
        assert_eq!(file.probes[2].protocol, "UDP");
        assert_eq!(file.probes[2].data, &[0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_parse_match_patterns() {
        let input = r#"
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
match http m|^HTTP/1\.[01] \d\d\d| p/Apache httpd/
match http m|Server: Apache/([\d.]+)| p/Apache httpd/ v/$1/
match ssh m|^SSH-([\d.]+)-OpenSSH_([\d.p]+)| p/OpenSSH/ v/$2/ i/protocol $1/
softmatch http m|^HTTP/|
"#;
        let file = NmapProbeFile::parse_str(input).unwrap();
        assert_eq!(file.probes.len(), 1);

        let probe = &file.probes[0];
        assert_eq!(probe.matches.len(), 3);
        assert_eq!(probe.softmatches.len(), 1);

        assert_eq!(probe.matches[0].service, "http");
        assert_eq!(probe.matches[0].pattern, r"^HTTP/1\.[01] \d\d\d");
        assert_eq!(probe.matches[0].version_info.product, Some("Apache httpd".to_string()));

        assert_eq!(probe.matches[1].version_info.version, Some("$1".to_string()));

        assert_eq!(probe.matches[2].version_info.product, Some("OpenSSH".to_string()));
        assert_eq!(probe.matches[2].version_info.version, Some("$2".to_string()));
        assert_eq!(probe.matches[2].version_info.info, Some("protocol $1".to_string()));

        assert_eq!(probe.softmatches[0].service, "http");
        assert_eq!(probe.softmatches[0].pattern, r"^HTTP/");
    }

    #[test]
    fn test_parse_exclude_directives() {
        let input = r#"
Exclude T:9100
Exclude U:30000-40000
Exclude T:111,113
"#;
        let file = NmapProbeFile::parse_str(input).unwrap();
        assert_eq!(file.exclude_tcp.len(), 3);
        assert_eq!(file.exclude_udp.len(), 1);

        assert_eq!(file.exclude_tcp[0].start, 9100);
        assert_eq!(file.exclude_tcp[0].end, 9100);
        assert_eq!(file.exclude_udp[0].start, 30000);
        assert_eq!(file.exclude_udp[0].end, 40000);
        assert_eq!(file.exclude_tcp[1].start, 111);
        assert_eq!(file.exclude_tcp[1].end, 111);
        assert_eq!(file.exclude_tcp[2].start, 113);
        assert_eq!(file.exclude_tcp[2].end, 113);
    }

    #[test]
    fn test_hex_escape_handling() {
        let input = r#"
Probe TCP test q|\x41\x42\x43|
"#;
        let file = NmapProbeFile::parse_str(input).unwrap();
        assert_eq!(file.probes[0].data, b"ABC");

        let input2 = r#"
Probe TCP test2 q|\x00\x0a\x0d|
"#;
        let file2 = NmapProbeFile::parse_str(input2).unwrap();
        assert_eq!(file2.probes[0].data, &[0x00, 0x0a, 0x0d]);

        let input3 = r#"
Probe TCP test3 q|\x48\x65\x6c\x6c\x6f|
"#;
        let file3 = NmapProbeFile::parse_str(input3).unwrap();
        assert_eq!(file3.probes[0].data, b"Hello");
    }

    #[test]
    fn test_version_template_substitution() {
        let captures = vec![
            "SSH-2.0-OpenSSH_8.9".to_string(),
            "2.0".to_string(),
            "8.9".to_string(),
        ];

        let result = substitute_version_template("protocol $1", &captures);
        assert_eq!(result, "protocol 2.0");

        let result2 = substitute_version_template("$2", &captures);
        assert_eq!(result2, "8.9");

        let result3 = substitute_version_template("${1} - ${2}", &captures);
        assert_eq!(result3, "2.0 - 8.9");
    }

    #[test]
    fn test_probe_options() {
        let input = r#"
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
fallback NULL
ports 80,443,8080-8090
sslports 443,8443
"#;
        let file = NmapProbeFile::parse_str(input).unwrap();
        let probe = &file.probes[0];
        assert_eq!(probe.rarity, 1);
        assert_eq!(probe.fallback, Some("NULL".to_string()));
        assert!(probe.ports.contains(&80));
        assert!(probe.ports.contains(&443));
        assert!(probe.ports.contains(&8080));
        assert!(probe.ports.contains(&8090));
        assert_eq!(probe.ports.len(), 13);
        assert!(probe.sslports.contains(&443));
        assert!(probe.sslports.contains(&8443));
    }

    #[test]
    fn test_pattern_delimiters() {
        let input = r#"
Probe TCP test q|test|
match http m|^HTTP/1.0| p/Test/
match http m|Server: (.*)| p/Test/ v/$1/
"#;
        let file = NmapProbeFile::parse_str(input).unwrap();
        assert_eq!(file.probes[0].matches.len(), 2);
    }

    #[test]
    fn test_merge_into_probe_database() {
        let input = r#"
Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80,443
match http m|^HTTP/| p/Apache httpd/
softmatch http m|^HTTP/|
"#;
        let file = NmapProbeFile::parse_str(input).unwrap();
        let mut db = ProbeDatabase::new();
        let initial_count = db.all_probes().len();

        file.probes[0].merge_into(&mut db);

        assert_eq!(db.all_probes().len(), initial_count + 1);
    }
}
