use nemue::scanner::{PortParser, TargetParser};

#[test]
fn test_port_parser_single() {
    let ports = PortParser::parse("80").unwrap();
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].value(), 80);
}

#[test]
fn test_port_parser_range() {
    let ports = PortParser::parse("1-10").unwrap();
    assert_eq!(ports.len(), 10);
}

#[test]
fn test_port_parser_mixed() {
    let ports = PortParser::parse("22,80,443,8000-8003").unwrap();
    assert_eq!(ports.len(), 7);
}

#[test]
fn test_target_parser_single_ip() {
    let targets = TargetParser::parse("192.168.1.1").unwrap();
    assert_eq!(targets.len(), 1);
}

#[test]
fn test_target_parser_cidr() {
    let targets = TargetParser::parse("192.168.1.0/30").unwrap();
    assert_eq!(targets.len(), 4);
}

#[test]
fn test_invalid_port() {
    let result = PortParser::parse("0");
    assert!(result.is_err());
}

#[test]
fn test_invalid_ip() {
    let result = TargetParser::parse("invalid.ip.address");
    assert!(result.is_err());
}
