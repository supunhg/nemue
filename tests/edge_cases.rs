// Edge Case Tests for Nemue Scanner
// Testing boundary conditions, error handling, and unusual inputs

use nemue::scanner::{PortParser, TargetParser, ScanType, TimingTemplate};
use nemue::script::ScriptArgs;
use std::net::IpAddr;

#[test]
fn test_port_parser_edge_cases() {
    // Empty string
    assert!(PortParser::parse("").is_err());
    
    // Invalid characters
    assert!(PortParser::parse("abc").is_err());
    assert!(PortParser::parse("80,abc,443").is_err());
    
    // Out of range
    assert!(PortParser::parse("0").is_err());
    assert!(PortParser::parse("65536").is_err());
    assert!(PortParser::parse("80,99999").is_err());
    
    // Invalid ranges
    assert!(PortParser::parse("100-50").is_err()); // Reversed range
    assert!(PortParser::parse("80-80").is_ok()); // Single port range (valid)
    assert!(PortParser::parse("-100").is_err()); // Missing start
    assert!(PortParser::parse("100-").is_err()); // Missing end
    
    // Boundary values
    assert!(PortParser::parse("1").is_ok()); // Min port
    assert!(PortParser::parse("65535").is_ok()); // Max port
    assert!(PortParser::parse("1-65535").is_ok()); // Full range
    
    // Whitespace handling
    assert!(PortParser::parse(" 80 ").is_ok());
    assert!(PortParser::parse("80 , 443").is_ok());
    assert!(PortParser::parse(" 80 - 100 ").is_ok());
    
    // Duplicates
    let ports = PortParser::parse("80,80,80").unwrap();
    assert!(ports.iter().any(|p| p.value() == 80));
    
    // Mixed valid and invalid
    assert!(PortParser::parse("80,invalid,443").is_err());
}

#[test]
fn test_target_parser_edge_cases() {
    // Empty string
    assert!(TargetParser::parse("").is_err());
    
    // Invalid IP addresses
    assert!(TargetParser::parse("256.1.1.1").is_err());
    assert!(TargetParser::parse("192.168.1").is_err());
    assert!(TargetParser::parse("192.168.1.1.1").is_err());
    
    // Invalid CIDR notation
    assert!(TargetParser::parse("192.168.1.0/33").is_err()); // Invalid mask
    assert!(TargetParser::parse("192.168.1.0/").is_err()); // Missing mask
    assert!(TargetParser::parse("/24").is_err()); // Missing IP
    
    // Valid boundary cases
    assert!(TargetParser::parse("0.0.0.0").is_ok());
    assert!(TargetParser::parse("255.255.255.255").is_ok());
    assert!(TargetParser::parse("192.168.1.0/32").is_ok()); // Single host
    // Note: /0 generates too many IPs and causes overflow in tests
    
    // IPv6 edge cases
    assert!(TargetParser::parse("::1").is_ok()); // Loopback
    assert!(TargetParser::parse("::").is_ok()); // All zeros
    assert!(TargetParser::parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").is_ok());
    
    // Invalid IPv6
    assert!(TargetParser::parse("gggg::1").is_err());
    assert!(TargetParser::parse("::::::").is_err());
}

#[test]
fn test_scan_type_edge_cases() {
    // Verify all scan types can be created
    let types = vec![
        ScanType::Syn,
        ScanType::Connect,
        ScanType::Ack,
        ScanType::Udp,
        ScanType::Null,
        ScanType::Fin,
        ScanType::Xmas,
    ];
    
    for scan_type in types {
        // Should not panic
        let _type_name = format!("{:?}", scan_type);
    }
}

#[test]
fn test_timing_template_edge_cases() {
    // All valid template numbers
    for i in 0..=5 {
        let template = TimingTemplate::from_number(i);
        assert!(template.is_some());
        
        // Config should be valid
        let config = template.unwrap().to_config();
        assert!(config.min_rtt_timeout.as_millis() > 0);
        assert!(config.max_rtt_timeout >= config.min_rtt_timeout);
        assert!(config.initial_rtt_timeout >= config.min_rtt_timeout);
        assert!(config.max_retries > 0);
    }
    
    // Invalid template numbers
    assert!(TimingTemplate::from_number(6).is_none());
    assert!(TimingTemplate::from_number(100).is_none());
}

#[test]
fn test_timing_config_validation() {
    use nemue::scanner::TimingConfig;
    use std::time::Duration;
    
    // Invalid: min > max
    let mut config = TimingConfig {
        min_rtt_timeout: Duration::from_millis(1000),
        max_rtt_timeout: Duration::from_millis(100),
        initial_rtt_timeout: Duration::from_millis(500),
        max_retries: 3,
        host_timeout: Duration::from_secs(5),
        scan_delay: Duration::from_millis(0),
        max_scan_delay: Duration::from_millis(1000),
        min_parallelism: 1,
        max_parallelism: 100,
        min_hostgroup: 1,
        max_hostgroup: 100,
        min_rate: 0,
        max_rate: 1000,
    };
    config.validate();
    assert!(config.min_rtt_timeout <= config.max_rtt_timeout);
    
    // Invalid: min = 0
    let mut config = TimingConfig {
        min_rtt_timeout: Duration::from_millis(0),
        max_rtt_timeout: Duration::from_millis(1000),
        initial_rtt_timeout: Duration::from_millis(500),
        max_retries: 3,
        host_timeout: Duration::from_secs(5),
        scan_delay: Duration::from_millis(0),
        max_scan_delay: Duration::from_millis(1000),
        min_parallelism: 1,
        max_parallelism: 100,
        min_hostgroup: 1,
        max_hostgroup: 100,
        min_rate: 0,
        max_rate: 1000,
    };
    config.validate();
    assert!(config.min_rtt_timeout.as_millis() >= 1);
    
    // Valid config unchanged
    let original = TimingConfig {
        min_rtt_timeout: Duration::from_millis(100),
        max_rtt_timeout: Duration::from_millis(1000),
        initial_rtt_timeout: Duration::from_millis(500),
        max_retries: 3,
        host_timeout: Duration::from_secs(5),
        scan_delay: Duration::from_millis(0),
        max_scan_delay: Duration::from_millis(1000),
        min_parallelism: 1,
        max_parallelism: 100,
        min_hostgroup: 1,
        max_hostgroup: 100,
        min_rate: 0,
        max_rate: 1000,
    };
    let mut config = original.clone();
    config.validate();
    assert_eq!(config.min_rtt_timeout, original.min_rtt_timeout);
    assert_eq!(config.max_rtt_timeout, original.max_rtt_timeout);
}

#[test]
fn test_script_args_edge_cases() {
    // Empty string
    assert!(ScriptArgs::parse("").is_err());
    
    // Only whitespace
    assert!(ScriptArgs::parse("   ").is_err());
    
    // Missing value
    assert!(ScriptArgs::parse("key=").is_err());
    assert!(ScriptArgs::parse("key").is_err());
    
    // Missing key
    assert!(ScriptArgs::parse("=value").is_err());
    
    // Special characters in values (quoted)
    let args = ScriptArgs::parse(r#"msg="hello, world!""#).unwrap();
    assert_eq!(args.get("msg"), Some(&"hello, world!".to_string()));
    
    let args = ScriptArgs::parse(r#"url='http://example.com/path?q=1&p=2'"#).unwrap();
    assert_eq!(args.get("url"), Some(&"http://example.com/path?q=1&p=2".to_string()));
    
    // Unicode in values
    let args = ScriptArgs::parse("msg=Hello世界").unwrap();
    assert_eq!(args.get("msg"), Some(&"Hello世界".to_string()));
    
    // Empty quoted string
    let args = ScriptArgs::parse(r#"msg="""#).unwrap();
    assert_eq!(args.get("msg"), Some(&"".to_string()));
    
    // Multiple separators (semicolon takes precedence)
    let args = ScriptArgs::parse("a=1;b=2").unwrap();
    assert_eq!(args.get("a"), Some(&"1".to_string()));
    assert_eq!(args.get("b"), Some(&"2".to_string()));
    
    // Comma separator
    let args = ScriptArgs::parse("c=3,d=4").unwrap();
    assert_eq!(args.get("c"), Some(&"3".to_string()));
    assert_eq!(args.get("d"), Some(&"4".to_string()));
    
    // Trailing separator
    let args = ScriptArgs::parse("a=1,b=2,").unwrap();
    assert_eq!(args.get("a"), Some(&"1".to_string()));
    assert_eq!(args.get("b"), Some(&"2".to_string()));
}

#[test]
fn test_script_args_merge_edge_cases() {
    // Merging with empty
    let mut args1 = ScriptArgs::parse("a=1").unwrap();
    let args2 = ScriptArgs::new();
    args1.merge(args2);
    assert_eq!(args1.get("a"), Some(&"1".to_string()));
    
    // Merging empty with filled
    let mut args1 = ScriptArgs::new();
    let args2 = ScriptArgs::parse("b=2").unwrap();
    args1.merge(args2);
    assert_eq!(args1.get("b"), Some(&"2".to_string()));
    
    // Conflicting keys (second wins)
    let mut args1 = ScriptArgs::parse("key=value1").unwrap();
    let args2 = ScriptArgs::parse("key=value2").unwrap();
    args1.merge(args2);
    assert_eq!(args1.get("key"), Some(&"value2".to_string()));
}

#[test]
fn test_ip_addr_parsing_edge_cases() {
    // Valid IPs
    assert!("0.0.0.0".parse::<IpAddr>().is_ok());
    assert!("255.255.255.255".parse::<IpAddr>().is_ok());
    assert!("127.0.0.1".parse::<IpAddr>().is_ok());
    
    // Invalid IPs
    assert!("256.1.1.1".parse::<IpAddr>().is_err());
    assert!("1.1.1".parse::<IpAddr>().is_err());
    assert!("1.1.1.1.1".parse::<IpAddr>().is_err());
    assert!("a.b.c.d".parse::<IpAddr>().is_err());
    
    // IPv6
    assert!("::1".parse::<IpAddr>().is_ok());
    assert!("::".parse::<IpAddr>().is_ok());
    assert!("fe80::1".parse::<IpAddr>().is_ok());
    assert!("2001:db8::1".parse::<IpAddr>().is_ok());
}

#[test]
fn test_large_input_handling() {
    // Large number of ports
    let mut port_str = String::new();
    for i in 1..=1000 {
        if i > 1 {
            port_str.push(',');
        }
        port_str.push_str(&i.to_string());
    }
    let result = PortParser::parse(&port_str);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1000);
    
    // Very long single value
    let long_value = "x".repeat(10000);
    let input = format!("key={}", long_value);
    let args = ScriptArgs::parse(&input);
    assert!(args.is_ok());
}

#[test]
fn test_concurrent_parsing() {
    use std::thread;
    
    // Spawn multiple threads parsing simultaneously
    let handles: Vec<_> = (1..=10)
        .map(|i| {
            thread::spawn(move || {
                let port_str = format!("{}-{}", i * 100, (i + 1) * 100);
                PortParser::parse(&port_str)
            })
        })
        .collect();
    
    // All should succeed
    for handle in handles {
        assert!(handle.join().unwrap().is_ok());
    }
}

#[test]
fn test_memory_safety() {
    // Create and drop many objects rapidly
    for _ in 0..1000 {
        let _ = PortParser::parse("80,443,8080");
        let _ = TargetParser::parse("192.168.1.0/24");
        let _ = ScriptArgs::parse("a=1,b=2,c=3");
        let _ = TimingTemplate::Aggressive.to_config();
    }
    // Should not leak memory or crash
}

#[test]
fn test_special_network_addresses() {
    // Loopback
    assert!(TargetParser::parse("127.0.0.1").is_ok());
    assert!(TargetParser::parse("::1").is_ok());
    
    // Broadcast
    assert!(TargetParser::parse("255.255.255.255").is_ok());
    
    // Multicast
    assert!(TargetParser::parse("224.0.0.1").is_ok());
    assert!(TargetParser::parse("ff02::1").is_ok());
    
    // Link-local
    assert!(TargetParser::parse("169.254.0.1").is_ok());
    assert!(TargetParser::parse("fe80::1").is_ok());
    
    // Private ranges
    assert!(TargetParser::parse("10.0.0.1").is_ok());
    assert!(TargetParser::parse("172.16.0.1").is_ok());
    assert!(TargetParser::parse("192.168.0.1").is_ok());
}

#[test]
fn test_error_message_quality() {
    // Errors should be informative
    let result = PortParser::parse("99999");
    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(!error.is_empty());
    
    let result = TargetParser::parse("invalid.ip");
    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(!error.is_empty());
    
    let result = ScriptArgs::parse("invalid");
    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(!error.is_empty());
}

#[test]
fn test_string_ownership() {
    // Test that string ownership is handled correctly
    let input = String::from("80,443");
    let result = PortParser::parse(&input);
    assert!(result.is_ok());
    // input should still be valid
    assert_eq!(input, "80,443");
    
    // Same with target parsing
    let input = String::from("192.168.1.0/24");
    let result = TargetParser::parse(&input);
    assert!(result.is_ok());
    assert_eq!(input, "192.168.1.0/24");
}

#[test]
fn test_null_and_empty_handling() {
    // Empty collections
    let args = ScriptArgs::new();
    let lua_table = args.to_lua_table();
    assert_eq!(lua_table, "{}");
    
    // Zero-length strings after trim
    let result = PortParser::parse("   ");
    assert!(result.is_err());
}

#[test]
fn test_numeric_edge_cases() {
    // Port number boundaries
    assert!(PortParser::parse("1").is_ok());
    assert!(PortParser::parse("65535").is_ok());
    assert!(PortParser::parse("0").is_err());
    assert!(PortParser::parse("65536").is_err());
    
    // Negative numbers
    assert!(PortParser::parse("-1").is_err());
    assert!(PortParser::parse("80,-1").is_err());
    
    // Very large numbers
    assert!(PortParser::parse("999999999").is_err());
}
