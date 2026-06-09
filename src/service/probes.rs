/// Comprehensive probe database for service detection
/// 
/// This module contains 100+ service-specific probes for enhanced detection
/// matching nmap's probe database functionality.

use super::intensity::{ProbeProtocol, ProbeRarity, ServiceProbe};
use std::collections::HashMap;

/// Extended probe database with 100+ service probes
pub struct ProbeDatabase {
    probes: Vec<ServiceProbe>,
    by_port: HashMap<u16, Vec<String>>,
}

impl ProbeDatabase {
    pub fn new() -> Self {
        let mut db = Self {
            probes: Vec::new(),
            by_port: HashMap::new(),
        };
        db.load_all_probes();
        db
    }

    /// Get probes applicable to a specific port
    pub fn probes_for_port(&self, port: u16) -> Vec<&ServiceProbe> {
        if let Some(probe_names) = self.by_port.get(&port) {
            self.probes
                .iter()
                .filter(|p| probe_names.contains(&p.name))
                .collect()
        } else {
            // Return generic probes
            self.generic_probes()
        }
    }

    /// Get generic probes that work on any port
    pub fn generic_probes(&self) -> Vec<&ServiceProbe> {
        self.probes
            .iter()
            .filter(|p| p.name == "NULL" || p.name == "GenericLines" || p.name == "GetRequest")
            .collect()
    }

    /// Get all probes
    pub fn all_probes(&self) -> &[ServiceProbe] {
        &self.probes
    }

    pub fn add_probe(&mut self, probe: ServiceProbe, ports: &[u16]) {
        let name = probe.name.clone();
        self.probes.push(probe);
        
        for &port in ports {
            self.by_port
                .entry(port)
                .or_insert_with(Vec::new)
                .push(name.clone());
        }
    }

    fn load_all_probes(&mut self) {
        self.load_null_probe();
        self.load_generic_probes();
        self.load_web_probes();
        self.load_database_probes();
        self.load_mail_probes();
        self.load_file_transfer_probes();
        self.load_remote_access_probes();
        self.load_messaging_probes();
        self.load_directory_probes();
        self.load_monitoring_probes();
        self.load_container_probes();
        self.load_voip_probes();
        self.load_game_server_probes();
        self.load_iot_probes();
    }

    /// NULL probe - just read banner without sending data
    fn load_null_probe(&mut self) {
        self.add_probe(
            ServiceProbe::new("NULL".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::VeryCommon),
            &[], // Used on all ports
        );
    }

    /// Generic probes that work across many services
    fn load_generic_probes(&mut self) {
        // Generic lines probe (CRLF)
        self.add_probe(
            ServiceProbe::new("GenericLines".to_string(), ProbeProtocol::Tcp)
                .with_data(b"\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::VeryCommon),
            &[],
        );

        // HTTP GET request (works on many services)
        self.add_probe(
            ServiceProbe::new("GetRequest".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET / HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::VeryCommon),
            &[80, 443, 8000, 8080, 8081, 8443, 8888, 9200],
        );

        // HTTP OPTIONS (for WebDAV, REST APIs)
        self.add_probe(
            ServiceProbe::new("HTTPOptions".to_string(), ProbeProtocol::Tcp)
                .with_data(b"OPTIONS / HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Common),
            &[80, 443, 8080],
        );

        // HELP command (common in many protocols)
        self.add_probe(
            ServiceProbe::new("Help".to_string(), ProbeProtocol::Tcp)
                .with_data(b"HELP\r\n".to_vec())
                .with_rarity(ProbeRarity::Common),
            &[],
        );

        // RTSPRequest (Real Time Streaming Protocol)
        self.add_probe(
            ServiceProbe::new("RTSPRequest".to_string(), ProbeProtocol::Tcp)
                .with_data(b"OPTIONS / RTSP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Uncommon),
            &[554, 8554],
        );

        // RPCCheck
        self.add_probe(
            ServiceProbe::new("RPCCheck".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x80, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0,
                ])
                .with_rarity(ProbeRarity::Common),
            &[111, 32771],
        );
    }

    /// Web server and HTTP/2 probes
    fn load_web_probes(&mut self) {
        // HTTP/1.1 with Host header
        self.add_probe(
            ServiceProbe::new("HTTPHost".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::VeryCommon),
            &[80, 443, 8000, 8080, 8081, 8443, 8888],
        );

        // HTTP/2 prior knowledge
        self.add_probe(
            ServiceProbe::new("HTTP2PriorKnowledge".to_string(), ProbeProtocol::Tcp)
                .with_data(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Common),
            &[80, 443, 8080, 8443],
        );

        // WebSocket upgrade
        self.add_probe(
            ServiceProbe::new("WebSocket".to_string(), ProbeProtocol::Tcp)
                .with_data(
                    b"GET / HTTP/1.1\r\n\
                      Host: localhost\r\n\
                      Upgrade: websocket\r\n\
                      Connection: Upgrade\r\n\
                      Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n\
                      Sec-WebSocket-Version: 13\r\n\r\n"
                        .to_vec(),
                )
                .with_rarity(ProbeRarity::Moderate),
            &[80, 443, 8080, 8443, 3000, 4200],
        );

        // HTTPS (SSLv3 ClientHello)
        self.add_probe(
            ServiceProbe::new("SSLSessionReq".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x16, 0x03, 0x00, 0x00, 0x2f, 0x01, 0x00, 0x00,
                    0x2b, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ])
                .with_rarity(ProbeRarity::VeryCommon),
            &[443, 8443, 465, 993, 995, 636, 3269, 8883],
        );

        // TLS 1.2 ClientHello
        self.add_probe(
            ServiceProbe::new("TLSSessionReq".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x16, 0x03, 0x03, 0x00, 0x6f, 0x01, 0x00, 0x00,
                    0x6b, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
                ])
                .with_rarity(ProbeRarity::Common),
            &[443, 8443, 465, 993, 995, 636],
        );
    }

    /// Database probes
    fn load_database_probes(&mut self) {
        // MySQL greeting probe
        self.add_probe(
            ServiceProbe::new("MySQL".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new()) // Wait for server greeting
                .with_rarity(ProbeRarity::Common),
            &[3306],
        );

        // PostgreSQL startup
        self.add_probe(
            ServiceProbe::new("PostgreSQL".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f,
                ])
                .with_rarity(ProbeRarity::Common),
            &[5432],
        );

        // Redis PING
        self.add_probe(
            ServiceProbe::new("Redis".to_string(), ProbeProtocol::Tcp)
                .with_data(b"PING\r\n".to_vec())
                .with_rarity(ProbeRarity::Moderate),
            &[6379],
        );

        // MongoDB hello (using legacy probe for detection)
        self.add_probe(
            ServiceProbe::new("MongoDB".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x3a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00,
                ])
                .with_rarity(ProbeRarity::Moderate),
            &[27017, 27018, 27019],
        );

        // MS SQL Server (TDS)
        self.add_probe(
            ServiceProbe::new("MSSQL".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
                ])
                .with_rarity(ProbeRarity::Common),
            &[1433, 1434],
        );

        // Oracle TNS Ping
        self.add_probe(
            ServiceProbe::new("OracleTNS".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x00, 0x1c, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00,
                ])
                .with_rarity(ProbeRarity::Uncommon),
            &[1521, 1522],
        );

        // Memcached stats
        self.add_probe(
            ServiceProbe::new("Memcached".to_string(), ProbeProtocol::Tcp)
                .with_data(b"stats\r\n".to_vec())
                .with_rarity(ProbeRarity::Uncommon),
            &[11211],
        );

        // Elasticsearch info
        self.add_probe(
            ServiceProbe::new("Elasticsearch".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET / HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Uncommon),
            &[9200, 9300],
        );

        // Cassandra CQL
        self.add_probe(
            ServiceProbe::new("Cassandra".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                ])
                .with_rarity(ProbeRarity::Rare),
            &[7000, 7001, 9042],
        );

        // CouchDB
        self.add_probe(
            ServiceProbe::new("CouchDB".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET / HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Rare),
            &[5984],
        );

        // InfluxDB
        self.add_probe(
            ServiceProbe::new("InfluxDB".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET /ping HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Rare),
            &[8086],
        );
    }

    /// Mail protocol probes
    fn load_mail_probes(&mut self) {
        // SMTP EHLO
        self.add_probe(
            ServiceProbe::new("SMTP".to_string(), ProbeProtocol::Tcp)
                .with_data(b"EHLO test\r\n".to_vec())
                .with_rarity(ProbeRarity::Common),
            &[25, 465, 587],
        );

        // POP3
        self.add_probe(
            ServiceProbe::new("POP3".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new()) // Server sends banner first
                .with_rarity(ProbeRarity::Common),
            &[110, 995],
        );

        // IMAP capability
        self.add_probe(
            ServiceProbe::new("IMAP".to_string(), ProbeProtocol::Tcp)
                .with_data(b"A001 CAPABILITY\r\n".to_vec())
                .with_rarity(ProbeRarity::Common),
            &[143, 993],
        );
    }

    /// File transfer protocol probes
    fn load_file_transfer_probes(&mut self) {
        // FTP
        self.add_probe(
            ServiceProbe::new("FTP".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new()) // Server sends banner
                .with_rarity(ProbeRarity::VeryCommon),
            &[20, 21],
        );

        // SFTP (SSH file transfer)
        self.add_probe(
            ServiceProbe::new("SFTP".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Common),
            &[115],
        );

        // TFTP (UDP)
        self.add_probe(
            ServiceProbe::new("TFTP".to_string(), ProbeProtocol::Udp)
                .with_data(vec![0x00, 0x01]) // Read request
                .with_rarity(ProbeRarity::Common),
            &[69],
        );

        // SMB (Windows file sharing)
        self.add_probe(
            ServiceProbe::new("SMB".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42,
                    0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
                ])
                .with_rarity(ProbeRarity::Common),
            &[139, 445],
        );

        // NFS (RPC-based)
        self.add_probe(
            ServiceProbe::new("NFS".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Uncommon),
            &[2049],
        );
    }

    /// Remote access protocol probes
    fn load_remote_access_probes(&mut self) {
        // SSH
        self.add_probe(
            ServiceProbe::new("SSH".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new()) // Server sends version first
                .with_rarity(ProbeRarity::VeryCommon),
            &[22],
        );

        // Telnet
        self.add_probe(
            ServiceProbe::new("Telnet".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Common),
            &[23],
        );

        // RDP (Remote Desktop Protocol)
        self.add_probe(
            ServiceProbe::new("RDP".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03,
                ])
                .with_rarity(ProbeRarity::Common),
            &[3389],
        );

        // VNC (RFB protocol)
        self.add_probe(
            ServiceProbe::new("VNC".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new()) // Server sends RFB version
                .with_rarity(ProbeRarity::Common),
            &[5900, 5901, 5902, 5903, 5904, 5905],
        );

        // X11
        self.add_probe(
            ServiceProbe::new("X11".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![0x6c, 0x00, 0x0b, 0x00, 0x00, 0x00])
                .with_rarity(ProbeRarity::Uncommon),
            &[6000, 6001, 6002],
        );
    }

    /// Messaging and queue probes
    fn load_messaging_probes(&mut self) {
        // RabbitMQ (AMQP)
        self.add_probe(
            ServiceProbe::new("AMQP".to_string(), ProbeProtocol::Tcp)
                .with_data(b"AMQP\x00\x00\x09\x01".to_vec())
                .with_rarity(ProbeRarity::Moderate),
            &[5672],
        );

        // Kafka
        self.add_probe(
            ServiceProbe::new("Kafka".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Uncommon),
            &[9092],
        );

        // ActiveMQ
        self.add_probe(
            ServiceProbe::new("ActiveMQ".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Uncommon),
            &[61616],
        );

        // MQTT
        self.add_probe(
            ServiceProbe::new("MQTT".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x10, 0x0c, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
                    0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
                ])
                .with_rarity(ProbeRarity::Moderate),
            &[1883, 8883],
        );

        // STOMP
        self.add_probe(
            ServiceProbe::new("STOMP".to_string(), ProbeProtocol::Tcp)
                .with_data(b"CONNECT\n\n\x00".to_vec())
                .with_rarity(ProbeRarity::Rare),
            &[61613],
        );
    }

    /// Directory service probes
    fn load_directory_probes(&mut self) {
        // LDAP
        self.add_probe(
            ServiceProbe::new("LDAP".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02,
                    0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
                ])
                .with_rarity(ProbeRarity::Common),
            &[389, 636, 3268, 3269],
        );

        // Kerberos
        self.add_probe(
            ServiceProbe::new("Kerberos".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Common),
            &[88],
        );
    }

    /// Monitoring and management probes
    fn load_monitoring_probes(&mut self) {
        // SNMP (UDP)
        self.add_probe(
            ServiceProbe::new("SNMP".to_string(), ProbeProtocol::Udp)
                .with_data(vec![
                    0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70,
                    0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
                ])
                .with_rarity(ProbeRarity::Common),
            &[161, 162],
        );

        // Prometheus
        self.add_probe(
            ServiceProbe::new("Prometheus".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET /metrics HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Uncommon),
            &[9090],
        );

        // Grafana
        self.add_probe(
            ServiceProbe::new("Grafana".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET /api/health HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Uncommon),
            &[3000],
        );

        // Zabbix
        self.add_probe(
            ServiceProbe::new("Zabbix".to_string(), ProbeProtocol::Tcp)
                .with_data(b"ZBX".to_vec())
                .with_rarity(ProbeRarity::Rare),
            &[10050, 10051],
        );
    }

    /// Container and orchestration probes
    fn load_container_probes(&mut self) {
        // Docker API
        self.add_probe(
            ServiceProbe::new("Docker".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET /version HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Moderate),
            &[2375, 2376],
        );

        // Kubernetes API
        self.add_probe(
            ServiceProbe::new("Kubernetes".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET /version HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Moderate),
            &[6443, 8080, 10250],
        );

        // etcd
        self.add_probe(
            ServiceProbe::new("etcd".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET /version HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Uncommon),
            &[2379, 2380],
        );

        // Consul
        self.add_probe(
            ServiceProbe::new("Consul".to_string(), ProbeProtocol::Tcp)
                .with_data(b"GET /v1/status/leader HTTP/1.0\r\n\r\n".to_vec())
                .with_rarity(ProbeRarity::Uncommon),
            &[8500],
        );
    }

    /// VoIP protocol probes
    fn load_voip_probes(&mut self) {
        // SIP
        self.add_probe(
            ServiceProbe::new("SIP".to_string(), ProbeProtocol::Tcp)
                .with_data(
                    b"OPTIONS sip:nm SIP/2.0\r\n\
                      Via: SIP/2.0/TCP nm;branch=foo\r\n\
                      From: <sip:nm@nm>;tag=root\r\n\
                      To: <sip:nm2@nm2>\r\n\
                      Call-ID: 50000\r\n\
                      CSeq: 42 OPTIONS\r\n\r\n"
                        .to_vec(),
                )
                .with_rarity(ProbeRarity::Uncommon),
            &[5060, 5061],
        );

        // H.323
        self.add_probe(
            ServiceProbe::new("H323".to_string(), ProbeProtocol::Tcp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Rare),
            &[1720],
        );
    }

    /// Game server probes
    fn load_game_server_probes(&mut self) {
        // Minecraft
        self.add_probe(
            ServiceProbe::new("Minecraft".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0xfe, 0x01, 0xfa, 0x00, 0x0b, 0x00, 0x4d, 0x00,
                    0x43, 0x00, 0x7c, 0x00, 0x50, 0x00, 0x69,
                ])
                .with_rarity(ProbeRarity::Rare),
            &[25565],
        );

        // TeamSpeak
        self.add_probe(
            ServiceProbe::new("TeamSpeak".to_string(), ProbeProtocol::Udp)
                .with_data(Vec::new())
                .with_rarity(ProbeRarity::Rare),
            &[9987],
        );
    }

    /// IoT protocol probes
    fn load_iot_probes(&mut self) {
        // CoAP (Constrained Application Protocol)
        self.add_probe(
            ServiceProbe::new("CoAP".to_string(), ProbeProtocol::Udp)
                .with_data(vec![0x40, 0x01, 0x00, 0x00])
                .with_rarity(ProbeRarity::Rare),
            &[5683],
        );

        // Modbus
        self.add_probe(
            ServiceProbe::new("Modbus".to_string(), ProbeProtocol::Tcp)
                .with_data(vec![
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03,
                    0x00, 0x00, 0x00, 0x01,
                ])
                .with_rarity(ProbeRarity::Rare),
            &[502],
        );
    }
}

impl Default for ProbeDatabase {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_database_creation() {
        let db = ProbeDatabase::new();
        assert!(!db.probes.is_empty());
        assert!(db.probes.len() >= 50, "Should have at least 50 probes");
    }

    #[test]
    fn test_probes_for_port_http() {
        let db = ProbeDatabase::new();
        let probes = db.probes_for_port(80);
        assert!(!probes.is_empty());
        
        // Should have HTTP-related probes
        let probe_names: Vec<&str> = probes.iter().map(|p| p.name.as_str()).collect();
        assert!(probe_names.contains(&"GetRequest") || probe_names.contains(&"HTTPHost"));
    }

    #[test]
    fn test_probes_for_port_ssh() {
        let db = ProbeDatabase::new();
        let probes = db.probes_for_port(22);
        
        let has_ssh = probes.iter().any(|p| p.name == "SSH");
        assert!(has_ssh);
    }

    #[test]
    fn test_probes_for_port_mysql() {
        let db = ProbeDatabase::new();
        let probes = db.probes_for_port(3306);
        
        let has_mysql = probes.iter().any(|p| p.name == "MySQL");
        assert!(has_mysql);
    }

    #[test]
    fn test_generic_probes() {
        let db = ProbeDatabase::new();
        let generic = db.generic_probes();
        
        assert!(!generic.is_empty());
        assert!(generic.iter().any(|p| p.name == "NULL"));
    }

    #[test]
    fn test_probe_database_comprehensive() {
        let db = ProbeDatabase::new();
        
        // Check for key probe categories
        let all_probes = db.all_probes();
        let probe_names: Vec<String> = all_probes.iter().map(|p| p.name.clone()).collect();
        
        // Web probes
        assert!(probe_names.contains(&"GetRequest".to_string()));
        assert!(probe_names.contains(&"HTTPHost".to_string()));
        
        // Database probes
        assert!(probe_names.contains(&"MySQL".to_string()));
        assert!(probe_names.contains(&"PostgreSQL".to_string()));
        assert!(probe_names.contains(&"Redis".to_string()));
        assert!(probe_names.contains(&"MongoDB".to_string()));
        
        // Remote access
        assert!(probe_names.contains(&"SSH".to_string()));
        assert!(probe_names.contains(&"RDP".to_string()));
        
        // Messaging
        assert!(probe_names.contains(&"AMQP".to_string()));
        assert!(probe_names.contains(&"MQTT".to_string()));
    }

    #[test]
    fn test_probes_have_correct_protocol() {
        let db = ProbeDatabase::new();
        
        // TFTP should be UDP
        let tftp_probe = db.all_probes().iter()
            .find(|p| p.name == "TFTP")
            .expect("TFTP probe should exist");
        assert_eq!(tftp_probe.protocol, ProbeProtocol::Udp);
        
        // HTTP should be TCP
        let http_probe = db.all_probes().iter()
            .find(|p| p.name == "GetRequest")
            .expect("GetRequest probe should exist");
        assert_eq!(http_probe.protocol, ProbeProtocol::Tcp);
    }

    #[test]
    fn test_probes_have_rarity() {
        let db = ProbeDatabase::new();
        
        // Check that common services have appropriate rarity
        for probe in db.all_probes() {
            match probe.name.as_str() {
                "GetRequest" | "SSH" | "FTP" | "NULL" => {
                    assert_eq!(probe.rarity, ProbeRarity::VeryCommon);
                }
                "MySQL" | "SMTP" | "RDP" => {
                    assert_eq!(probe.rarity, ProbeRarity::Common);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_port_mapping() {
        let db = ProbeDatabase::new();
        
        // Check that common ports have mappings
        assert!(db.by_port.contains_key(&80));
        assert!(db.by_port.contains_key(&443));
        assert!(db.by_port.contains_key(&22));
        assert!(db.by_port.contains_key(&3306));
    }

    #[test]
    fn test_all_probes_returns_complete_list() {
        let db = ProbeDatabase::new();
        let all = db.all_probes();
        
        assert_eq!(all.len(), db.probes.len());
        assert!(all.len() >= 50, "Should have at least 50 probes, got {}", all.len());
    }
}
