// Service version detection signatures database
// Based on Nmap nmap-service-probes format patterns

use super::intensity::{MatchPattern, VersionInfo};

/// Create a match pattern with version extraction
fn m(service: &str, pattern: &str, product: &str, version: Option<&str>) -> MatchPattern {
    MatchPattern {
        service: service.to_string(),
        pattern_str: pattern.to_string(),
        version_info: VersionInfo {
            product: Some(product.to_string()),
            version_template: version.map(|v| v.to_string()),
            ..Default::default()
        },
        is_softmatch: false,
        case_insensitive: false,
    }
}

/// Create a case-insensitive match pattern
#[allow(dead_code)]
fn mi(service: &str, pattern: &str, product: &str, version: Option<&str>) -> MatchPattern {
    MatchPattern {
        service: service.to_string(),
        pattern_str: pattern.to_string(),
        version_info: VersionInfo {
            product: Some(product.to_string()),
            version_template: version.map(|v| v.to_string()),
            ..Default::default()
        },
        is_softmatch: false,
        case_insensitive: true,
    }
}

/// Create a softmatch pattern (lower confidence)
fn sm(service: &str, pattern: &str) -> MatchPattern {
    MatchPattern {
        service: service.to_string(),
        pattern_str: pattern.to_string(),
        version_info: VersionInfo::default(),
        is_softmatch: true,
        case_insensitive: false,
    }
}

/// Get all HTTP server signatures
pub fn http_signatures() -> Vec<MatchPattern> {
    vec![
        // Apache
        m("http", r"Server: Apache/(\d+\.\d+\.\d+)", "Apache httpd", Some("$1")),
        m("http", r"Server: Apache/(\d+\.\d+)", "Apache httpd", Some("$1")),
        m("http", r"Server: Apache$", "Apache httpd", None),
        m("http", r"Server: Apache-Coyote/(\d+\.\d+\.\d+)", "Apache Tomcat Coyote", Some("$1")),
        
        // Nginx
        m("http", r"Server: nginx/(\d+\.\d+\.\d+)", "nginx", Some("$1")),
        m("http", r"Server: nginx/(\d+\.\d+)", "nginx", Some("$1")),
        m("http", r"Server: nginx$", "nginx", None),
        m("http", r"Server: openresty/(\d+\.\d+\.\d+)", "OpenResty", Some("$1")),
        
        // Microsoft IIS
        m("http", r"Server: Microsoft-IIS/(\d+\.\d+)", "Microsoft IIS httpd", Some("$1")),
        m("http", r"Server: Microsoft-IIS/(\d+\.\d+)", "Microsoft IIS", Some("$1")),
        
        // Lighttpd
        m("http", r"Server: lighttpd/(\d+\.\d+\.\d+)", "lighttpd", Some("$1")),
        m("http", r"Server: lighttpd/(\d+\.\d+)", "lighttpd", Some("$1")),
        
        // LiteSpeed
        m("http", r"Server: LiteSpeed/(\d+)", "LiteSpeed httpd", Some("$1")),
        m("http", r"Server: OpenLiteSpeed/(\d+\.\d+)", "OpenLiteSpeed", Some("$1")),
        
        // Caddy
        m("http", r"Server: Caddy", "Caddy httpd", None),
        m("http", r"Server: Caddy/(\d+\.\d+\.\d+)", "Caddy httpd", Some("$1")),
        
        // Envoy
        m("http", r"Server: envoy", "Envoy proxy", None),
        m("http", r"Server: envoy/(\d+\.\d+\.\d+)", "Envoy proxy", Some("$1")),
        
        // HAProxy
        m("http", r"Server: HAProxy", "HAProxy", None),
        
        // Traefik
        m("http", r"Server: Traefik", "Traefik", None),
        
        // Jetty
        m("http", r"Server: Jetty\((\d+\.\d+\.\d+)", "Jetty", Some("$1")),
        
        // Gunicorn
        m("http", r"Server: gunicorn/(\d+\.\d+\.\d+)", "Gunicorn", Some("$1")),
        
        // uvicorn
        m("http", r"Server: uvicorn", "uvicorn", None),
        
        // Werkzeug
        m("http", r"Server: Werkzeug/(\d+\.\d+\.\d+)", "Werkzeug httpd", Some("$1")),
        
        // Tornado
        m("http", r"Server: TornadoServer/(\d+\.\d+)", "Tornado httpd", Some("$1")),
        
        // CherryPy
        m("http", r"Server: CherryPy/(\d+\.\d+\.\d+)", "CherryPy httpd", Some("$1")),
        
        // Apache Tomcat
        m("http", r"Server: Apache-Coyote", "Apache Tomcat", None),
        m("http", r"Server: Apache Tomcat/(\d+\.\d+)", "Apache Tomcat", Some("$1")),
        
        // WebLogic
        m("http", r"Server: WebLogic", "Oracle WebLogic Server", None),
        
        // JBoss/WildFly
        m("http", r"Server: JBoss", "JBoss", None),
        m("http", r"Server: WildFly", "WildFly", None),
        
        // WebSphere
        m("http", r"Server: WebSphere", "IBM WebSphere", None),
        
        // GlassFish
        m("http", r"Server: GlassFish Server", "GlassFish", None),
        
        // Golang net/http
        m("http", r"Server: Go-httpd/(\d+\.\d+)", "Go httpd", Some("$1")),
        
        // Python
        m("http", r"Server: BaseHTTP/(\d+\.\d+) Python/(\d+\.\d+\.\d+)", "Python BaseHTTP", Some("$2")),
        
        // Ruby
        m("http", r"Server: WEBrick/(\d+\.\d+\.\d+)", "WEBrick", Some("$1")),
        m("http", r"Server: Puma (\d+\.\d+\.\d+)", "Puma", Some("$1")),
        
        // Node.js
        m("http", r"X-Powered-By: Express", "Node.js Express", None),
        
        // PHP
        m("http", r"X-Powered-By: PHP/(\d+\.\d+\.\d+)", "PHP", Some("$1")),
        m("http", r"X-Powered-By: PHP/(\d+\.\d+)", "PHP", Some("$1")),
        
        // ASP.NET
        m("http", r"X-Powered-By: ASP\.NET", "ASP.NET", None),
        m("http", r"X-AspNet-Version: (\d+\.\d+\.\d+)", "ASP.NET", Some("$1")),
        
        // Django
        m("http", r"X-Frame-Options: DENY.*Server: WSGIServer", "Django", None),
        
        // Rails
        m("http", r"X-Powered-By: Phusion Passenger", "Phusion Passenger", None),
        
        // Cloudflare
        m("http", r"Server: cloudflare", "Cloudflare httpd", None),
        m("http", r"Server: Cloudflare", "Cloudflare httpd", None),
        
        // Akamai
        m("http", r"Server: AkamaiGHost", "Akamai httpd", None),
        
        // Varnish
        m("http", r"Via:.*varnish", "Varnish cache", None),
        m("http", r"X-Varnish: \d+", "Varnish cache", None),
        
        // Squid
        m("http", r"Server: squid/(\d+\.\d+)", "Squid http proxy", Some("$1")),
        
        // Softmatches
        sm("http", r"^HTTP/\d\.\d \d\d\d"),
    ]
}

/// Get all SSH signatures
pub fn ssh_signatures() -> Vec<MatchPattern> {
    vec![
        m("ssh", r"SSH-2.0-OpenSSH_([\d.p]+)", "OpenSSH", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+)", "OpenSSH", Some("$1")),
        m("ssh", r"SSH-1.99-OpenSSH_([\d.p]+)", "OpenSSH", Some("$1")),
        m("ssh", r"SSH-2.0-dropbear_([\d]+)", "Dropbear SSH", Some("$1")),
        m("ssh", r"SSH-2.0-libssh[_ ]([\d.]+)", "libssh", Some("$1")),
        m("ssh", r"SSH-2.0-libssh-([\d.]+)", "libssh", Some("$1")),
        m("ssh", r"SSH-2.0-Cisco-([\d.]+)", "Cisco SSH", Some("$1")),
        m("ssh", r"SSH-2.0-ROSSSH", "MikroTik SSH", None),
        m("ssh", r"SSH-2.0-MikroTik", "MikroTik SSH", None),
        m("ssh", r"SSH-2.0-AsyncSSH_([\d.]+)", "AsyncSSH", Some("$1")),
        m("ssh", r"SSH-2.0-PuTTY_Release_([\d.]+)", "PuTTY SSH", Some("$1")),
        m("ssh", r"SSH-2.0-Windows Power", "Microsoft Windows SSH", None),
        m("ssh", r"SSH-2.0-paramiko_([\d.]+)", "Paramiko SSH", Some("$1")),
        m("ssh", r"SSH-2.0-Go", "Go SSH", None),
        m("ssh", r"SSH-2.0-JSCH-([\d.]+)", "JSch SSH", Some("$1")),
        m("ssh", r"SSH-2.0-Apache-SSHD-([\d.]+)", "Apache SSHD", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) FreeBSD", "OpenSSH (FreeBSD)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) Ubuntu", "OpenSSH (Ubuntu)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) Debian", "OpenSSH (Debian)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) RHEL", "OpenSSH (RHEL)", Some("$1")),
        sm("ssh", r"^SSH-"),
    ]
}

/// Get all FTP signatures
pub fn ftp_signatures() -> Vec<MatchPattern> {
    vec![
        m("ftp", r"220.*ProFTPD (\d+\.\d+\.\d+)", "ProFTPD", Some("$1")),
        m("ftp", r"220.*ProFTPD", "ProFTPD", None),
        m("ftp", r"220.*vsFTPd (\d+\.\d+\.\d+)", "vsftpd", Some("$1")),
        m("ftp", r"220.*vsFTPd", "vsftpd", None),
        m("ftp", r"220.*Pure-FTPd", "Pure-FTPd", None),
        m("ftp", r"220.*FileZilla Server (\d+)", "FileZilla Server", Some("$1")),
        m("ftp", r"220.*FileZilla Server", "FileZilla Server", None),
        m("ftp", r"220.*Microsoft FTP Service", "Microsoft ftpd", None),
        m("ftp", r"220.*Serv-U FTP Server (\d+)", "Serv-U FTP Server", Some("$1")),
        m("ftp", r"220.*Serv-U FTP Server", "Serv-U FTP Server", None),
        m("ftp", r"220.*WU-ftpd", "WU-FTPD", None),
        m("ftp", r"220.*wu-ftpd", "WU-FTPD", None),
        m("ftp", r"220.*NcFTPd (\d+)", "NcFTPd", Some("$1")),
        m("ftp", r"220.*bftpd", "bftpd", None),
        m("ftp", r"220.* glftpd", "glFTPd", None),
        m("ftp", r"220.*Pure-FTPd", "Pure-FTPd", None),
        m("ftp", r"220.*Titan FTP Server", "Titan FTP Server", None),
        m("ftp", r"220.*CrushFTP", "CrushFTP", None),
        sm("ftp", r"^220[- ].*FTP"),
        sm("ftp", r"^220[- ]"),
    ]
}

/// Get all SMTP signatures
pub fn smtp_signatures() -> Vec<MatchPattern> {
    vec![
        m("smtp", r"220.*Postfix", "Postfix smtpd", None),
        m("smtp", r"220.*ESMTP Exim (\d+)", "Exim smtpd", Some("$1")),
        m("smtp", r"220.*ESMTP Exim", "Exim smtpd", None),
        m("smtp", r"220.*Microsoft ESMTP MAIL Service", "Microsoft ESMTP", None),
        m("smtp", r"220.*Sendmail (\d+)", "Sendmail", Some("$1")),
        m("smtp", r"220.*Sendmail", "Sendmail", None),
        m("smtp", r"220.*ESMTP Sendmail", "Sendmail", None),
        m("smtp", r"220.*OpenSMTPD", "OpenSMTPD", None),
        m("smtp", r"220.*Exchange", "Microsoft Exchange", None),
        m("smtp", r"220.*hMailServer", "hMailServer", None),
        m("smtp", r"220.*MailEnable", "MailEnable", None),
        m("smtp", r"220.*XMail", "XMail", None),
        m("smtp", r"220.*Zimbra", "Zimbra", None),
        m("smtp", r"220.*Dovecot", "Dovecot", None),
        sm("smtp", r"^220[- ].*ESMTP"),
        sm("smtp", r"^220[- ].*SMTP"),
    ]
}

/// Get all DNS signatures
pub fn dns_signatures() -> Vec<MatchPattern> {
    vec![
        m("dns", r"version\.bind.*BIND (\d+\.\d+\.\d+)", "ISC BIND", Some("$1")),
        m("dns", r"version\.bind.*BIND (\d+\.\d+)", "ISC BIND", Some("$1")),
        m("dns", r"version\.bind.*BIND", "ISC BIND", None),
        m("dns", r"version\.bind.*dnsmasq-([\d.]+)", "dnsmasq", Some("$1")),
        m("dns", r"version\.bind.*dnsmasq", "dnsmasq", None),
        m("dns", r"version\.bind.*Microsoft DNS", "Microsoft DNS", None),
        m("dns", r"version\.bind.*Unbound (\d+\.\d+\.\d+)", "Unbound", Some("$1")),
        m("dns", r"version\.bind.*PowerDNS", "PowerDNS", None),
        m("dns", r"version\.bind.*Knot DNS", "Knot DNS", None),
        m("dns", r"version\.bind.*NSD", "NSD", None),
    ]
}

/// Get all database signatures
pub fn database_signatures() -> Vec<MatchPattern> {
    vec![
        // MySQL
        m("mysql", r"(\d+\.\d+\.\d+)-MariaDB", "MariaDB", Some("$1")),
        m("mysql", r"(\d+\.\d+\.\d+)-log", "MySQL", Some("$1")),
        m("mysql", r"(\d+\.\d+\.\d+)", "MySQL", Some("$1")),
        m("mysql", r"mysql_native_password", "MySQL", None),
        
        // PostgreSQL
        m("postgres", r"PostgreSQL (\d+\.\d+\.\d+)", "PostgreSQL", Some("$1")),
        m("postgres", r"PostgreSQL (\d+\.\d+)", "PostgreSQL", Some("$1")),
        
        // Redis
        m("redis", r"redis_version:(\d+\.\d+\.\d+)", "Redis", Some("$1")),
        m("redis", r"redis_version:(\d+\.\d+)", "Redis", Some("$1")),
        m("redis", r"Redis server", "Redis", None),
        
        // MongoDB
        m("mongodb", r"mongodb", "MongoDB", None),
        m("mongodb", r"mongo", "MongoDB", None),
        
        // MSSQL
        m("ms-sql-s", r"Microsoft SQL Server", "Microsoft SQL Server", None),
        
        // Oracle
        m("oracle-tns", r"Oracle", "Oracle TNS", None),
        
        // Elasticsearch
        m("elasticsearch", r"elasticsearch", "Elasticsearch", None),
        m("elasticsearch", r"cluster_name.*elasticsearch", "Elasticsearch", None),
        
        // Cassandra
        m("cassandra", r"Cassandra", "Apache Cassandra", None),
        
        // CouchDB
        m("couchdb", r"couchdb", "CouchDB", None),
        m("couchdb", r"CouchDB", "CouchDB", None),
    ]
}

/// Get all web application signatures
pub fn webapp_signatures() -> Vec<MatchPattern> {
    vec![
        // WordPress
        m("http", r"wp-content", "WordPress", None),
        m("http", r"wp-login\.php", "WordPress", None),
        m("http", r"wp-includes", "WordPress", None),
        
        // Joomla
        m("http", r"/administrator/", "Joomla", None),
        m("http", r"Joomla!", "Joomla", None),
        
        // Drupal
        m("http", r"Drupal/(\d+\.\d+)", "Drupal", Some("$1")),
        m("http", r"drupal", "Drupal", None),
        
        // Laravel
        m("http", r"laravel_session", "Laravel", None),
        
        // Django
        m("http", r"csrfmiddlewaretoken", "Django", None),
        
        // React/Angular/Vue
        m("http", r"react", "React", None),
        m("http", r"angular", "Angular", None),
        m("http", r"vue\.js", "Vue.js", None),
        
        // jQuery
        m("http", r"jquery[/-](\d+\.\d+\.\d+)", "jQuery", Some("$1")),
        
        // Bootstrap
        m("http", r"bootstrap[/-](\d+\.\d+\.\d+)", "Bootstrap", Some("$1")),
    ]
}

/// Get all container/infrastructure signatures
pub fn container_signatures() -> Vec<MatchPattern> {
    vec![
        // Docker
        m("docker", r"Docker", "Docker", None),
        
        // Kubernetes
        m("kubernetes", r"Kubernetes", "Kubernetes", None),
        m("kubernetes", r"k8s", "Kubernetes", None),
        
        // etcd
        m("etcd", r"etcd", "etcd", None),
        
        // Consul
        m("consul", r"Consul", "Consul", None),
        
        // Vault
        m("vault", r"Vault", "HashiCorp Vault", None),
        
        // Prometheus
        m("prometheus", r"Prometheus", "Prometheus", None),
        
        // Grafana
        m("grafana", r"Grafana", "Grafana", None),
        
        // Jenkins
        m("jenkins", r"Jenkins", "Jenkins", None),
        
        // GitLab
        m("gitlab", r"GitLab", "GitLab", None),
        
        // Nexus
        m("nexus", r"Nexus Repository", "Sonatype Nexus", None),
    ]
}

/// Get all mail server signatures
pub fn mail_signatures() -> Vec<MatchPattern> {
    vec![
        // Dovecot
        m("imap", r"Dovecot", "Dovecot", None),
        m("imap", r"IMAP.*Dovecot", "Dovecot", None),
        m("pop3", r"Dovecot", "Dovecot", None),
        
        // Courier
        m("imap", r"Courier-IMAP", "Courier IMAP", None),
        
        // Cyrus
        m("imap", r"Cyrus IMAP", "Cyrus IMAP", None),
        
        // UW-IMAP
        m("imap", r"UW-IMAP", "UW-IMAP", None),
        
        // Exchange
        m("imap", r"Microsoft Exchange", "Microsoft Exchange IMAP", None),
        m("pop3", r"Microsoft Exchange", "Microsoft Exchange POP3", None),
    ]
}

/// Get all proxy/load balancer signatures
pub fn proxy_signatures() -> Vec<MatchPattern> {
    vec![
        m("http", r"X-Served-By:.*cache-", "Varnish cache", None),
        m("http", r"X-Cache:.*HIT", "Caching proxy", None),
        m("http", r"X-Forwarded-For:", "Reverse proxy", None),
        m("http", r"X-Real-IP:", "Reverse proxy", None),
    ]
}

/// Get all network equipment signatures
pub fn network_signatures() -> Vec<MatchPattern> {
    vec![
        // Cisco
        m("ssh", r"Cisco-", "Cisco SSH", None),
        m("telnet", r"Cisco", "Cisco IOS", None),
        m("telnet", r"User Access Verification", "Cisco", None),
        
        // Juniper
        m("ssh", r"Juniper", "Juniper SSH", None),
        m("telnet", r"Juniper", "Juniper Junos", None),
        
        // MikroTik
        m("ssh", r"ROSSSH", "MikroTik SSH", None),
        m("ssh", r"MikroTik", "MikroTik SSH", None),
        m("telnet", r"MikroTik", "MikroTik RouterOS", None),
        
        // Huawei
        m("ssh", r"Huawei", "Huawei SSH", None),
        m("telnet", r"Huawei", "Huawei VRP", None),
        
        // Fortinet
        m("ssh", r"Fortinet", "Fortinet FortiOS", None),
        m("https", r"FortiGate", "Fortinet FortiGate", None),
        
        // Palo Alto
        m("ssh", r"Palo Alto", "Palo Alto PAN-OS", None),
        
        // Arista
        m("ssh", r"Arista", "Arista EOS", None),
        
        // Dell
        m("ssh", r"Dell", "Dell Networking OS", None),
        
        // HP/Aruba
        m("ssh", r"HP", "HP ProCurve", None),
        m("ssh", r"Aruba", "ArubaOS", None),
    ]
}

/// Get all printer signatures
pub fn printer_signatures() -> Vec<MatchPattern> {
    vec![
        // HP JetDirect
        m("http", r"HP LaserJet", "HP LaserJet", None),
        m("http", r"HP Color LaserJet", "HP Color LaserJet", None),
        m("http", r"HP OfficeJet", "HP OfficeJet", None),
        m("http", r"JetDirect", "HP JetDirect", None),
        m("printer", r"HP JetDirect", "HP JetDirect", None),
        
        // Canon
        m("http", r"Canon", "Canon printer", None),
        m("http", r"imageRUNNER", "Canon imageRUNNER", None),
        
        // Epson
        m("http", r"Epson", "Epson printer", None),
        
        // Brother
        m("http", r"Brother", "Brother printer", None),
        
        // Xerox
        m("http", r"Xerox", "Xerox printer", None),
        m("http", r"WorkCentre", "Xerox WorkCentre", None),
        
        // Ricoh
        m("http", r"Ricoh", "Ricoh printer", None),
        
        // Lexmark
        m("http", r"Lexmark", "Lexmark printer", None),
        
        // Samsung
        m("http", r"Samsung.*printer", "Samsung printer", None),
        
        // Kyocera
        m("http", r"Kyocera", "Kyocera printer", None),
    ]
}

/// Get all VPN signatures
pub fn vpn_signatures() -> Vec<MatchPattern> {
    vec![
        // OpenVPN
        m("openvpn", r"OpenVPN", "OpenVPN", None),
        
        // WireGuard
        m("wireguard", r"WireGuard", "WireGuard", None),
        
        // IPSec/IKE
        m("isakmp", r"IKE", "IKE/IPSec", None),
        
        // PPTP
        m("pptp", r"PPTP", "PPTP VPN", None),
        
        // L2TP
        m("l2tp", r"L2TP", "L2TP VPN", None),
        
        // Cisco AnyConnect
        m("https", r"AnyConnect", "Cisco AnyConnect", None),
        
        // GlobalProtect
        m("https", r"GlobalProtect", "Palo Alto GlobalProtect", None),
        
        // FortiClient
        m("https", r"FortiClient", "Fortinet FortiClient", None),
    ]
}

/// Get all IoT signatures
pub fn iot_signatures() -> Vec<MatchPattern> {
    vec![
        // MQTT brokers
        m("mqtt", r"mosquitto", "Mosquitto MQTT", None),
        m("mqtt", r"MQTT", "MQTT Broker", None),
        m("mqtt", r"EMQ", "EMQ X", None),
        
        // CoAP
        m("coap", r"CoAP", "CoAP server", None),
        
        // Modbus
        m("modbus", r"Modbus", "Modbus device", None),
        
        // BACnet
        m("bacnet", r"BACnet", "BACnet device", None),
        
        // SNMP
        m("snmp", r"SNMP", "SNMP agent", None),
        
        // IP cameras
        m("http", r"Hikvision", "Hikvision camera", None),
        m("http", r"Dahua", "Dahua camera", None),
        m("http", r"Axis.*camera", "Axis camera", None),
        
        // Smart home
        m("http", r"Home Assistant", "Home Assistant", None),
        m("http", r"OpenHAB", "OpenHAB", None),
    ]
}

/// Get all game server signatures
pub fn game_signatures() -> Vec<MatchPattern> {
    vec![
        // Minecraft
        m("minecraft", r"Minecraft", "Minecraft Server", None),
        m("minecraft", r"MCServer", "Minecraft Server", None),
        
        // Steam
        m("steam", r"Steam", "Steam Server", None),
        
        // TeamSpeak
        m("teamspeak", r"TeamSpeak", "TeamSpeak Server", None),
        
        // Mumble
        m("mumble", r"Mumble", "Mumble Server", None),
        
        // Discord (bot)
        m("discord", r"Discord", "Discord Bot", None),
    ]
}

/// Get all monitoring signatures
pub fn monitoring_signatures() -> Vec<MatchPattern> {
    vec![
        // Prometheus
        m("prometheus", r"Prometheus", "Prometheus", None),
        m("http", r"prometheus", "Prometheus", None),
        
        // Grafana
        m("grafana", r"Grafana", "Grafana", None),
        m("http", r"grafana", "Grafana", None),
        
        // Zabbix
        m("zabbix", r"Zabbix", "Zabbix", None),
        m("http", r"zabbix", "Zabbix", None),
        
        // Nagios
        m("nagios", r"Nagios", "Nagios", None),
        m("http", r"nagios", "Nagios", None),
        
        // Datadog
        m("datadog", r"Datadog", "Datadog Agent", None),
        
        // New Relic
        m("newrelic", r"New Relic", "New Relic Agent", None),
        
        // Elastic Stack
        m("elasticsearch", r"elasticsearch", "Elasticsearch", None),
        m("logstash", r"logstash", "Logstash", None),
        m("kibana", r"kibana", "Kibana", None),
    ]
}

/// Get all CI/CD signatures
pub fn cicd_signatures() -> Vec<MatchPattern> {
    vec![
        // Jenkins
        m("jenkins", r"Jenkins", "Jenkins", None),
        m("http", r"jenkins", "Jenkins", None),
        
        // GitLab
        m("gitlab", r"GitLab", "GitLab", None),
        m("http", r"gitlab", "GitLab", None),
        
        // GitHub Enterprise
        m("github", r"GitHub Enterprise", "GitHub Enterprise", None),
        
        // Nexus
        m("nexus", r"Nexus Repository", "Sonatype Nexus", None),
        
        // Artifactory
        m("artifactory", r"Artifactory", "JFrog Artifactory", None),
        
        // SonarQube
        m("sonarqube", r"SonarQube", "SonarQube", None),
        
        // Harbor
        m("harbor", r"Harbor", "Harbor Registry", None),
    ]
}

/// Get all signatures combined
pub fn all_signatures() -> Vec<MatchPattern> {
    let mut sigs = Vec::new();
    sigs.extend(http_signatures());
    sigs.extend(ssh_signatures());
    sigs.extend(ftp_signatures());
    sigs.extend(smtp_signatures());
    sigs.extend(dns_signatures());
    sigs.extend(database_signatures());
    sigs.extend(webapp_signatures());
    sigs.extend(container_signatures());
    sigs.extend(mail_signatures());
    sigs.extend(proxy_signatures());
    sigs.extend(network_signatures());
    sigs.extend(printer_signatures());
    sigs.extend(vpn_signatures());
    sigs.extend(iot_signatures());
    sigs.extend(game_signatures());
    sigs.extend(monitoring_signatures());
    sigs.extend(cicd_signatures());
    sigs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_signatures_count() {
        let sigs = http_signatures();
        assert!(sigs.len() >= 30, "Expected at least 30 HTTP signatures, got {}", sigs.len());
    }

    #[test]
    fn test_ssh_signatures_count() {
        let sigs = ssh_signatures();
        assert!(sigs.len() >= 15, "Expected at least 15 SSH signatures, got {}", sigs.len());
    }

    #[test]
    fn test_ftp_signatures_count() {
        let sigs = ftp_signatures();
        assert!(sigs.len() >= 15, "Expected at least 15 FTP signatures, got {}", sigs.len());
    }

    #[test]
    fn test_smtp_signatures_count() {
        let sigs = smtp_signatures();
        assert!(sigs.len() >= 10, "Expected at least 10 SMTP signatures, got {}", sigs.len());
    }

    #[test]
    fn test_all_signatures_count() {
        let sigs = all_signatures();
        assert!(sigs.len() >= 200, "Expected at least 200 total signatures, got {}", sigs.len());
    }

    #[test]
    fn test_match_pattern_try_match() {
        let pattern = m("ssh", r"SSH-2.0-OpenSSH_([\d.p]+)", "OpenSSH", Some("$1"));
        let data = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
        let caps = pattern.try_match(data);
        assert!(caps.is_some());
        let caps = caps.unwrap();
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[1], "8.9p1");
    }

    #[test]
    fn test_match_pattern_case_insensitive() {
        let pattern = mi("http", r"server: nginx/(\d+\.\d+)", "nginx", Some("$1"));
        let data = b"HTTP/1.1 200 OK\r\nServer: Nginx/1.24.0\r\n\r\n";
        let caps = pattern.try_match(data);
        assert!(caps.is_some());
    }

    #[test]
    fn test_version_substitution() {
        let caps = vec!["SSH-2.0-OpenSSH_8.9p1".to_string(), "8.9p1".to_string()];
        let version = MatchPattern::substitute_template("$1", &caps);
        assert_eq!(version, "8.9p1");
    }

    #[test]
    fn test_softmatch_pattern() {
        let pattern = sm("http", r"^HTTP/\d\.\d \d\d\d");
        let data = b"HTTP/1.1 200 OK\r\n\r\n";
        assert!(pattern.try_match(data).is_some());
    }
}
