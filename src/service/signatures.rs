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
        m("http", r"Server: Tengine/(\d+\.\d+\.\d+)", "Tengine", Some("$1")),
        
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
        m("http", r"Server: Python/(\d+\.\d+)", "Python httpd", Some("$1")),
        
        // Ruby
        m("http", r"Server: WEBrick/(\d+\.\d+\.\d+)", "WEBrick", Some("$1")),
        m("http", r"Server: Puma (\d+\.\d+\.\d+)", "Puma", Some("$1")),
        m("http", r"Server: Unicorn", "Unicorn", None),
        m("http", r"Server: Thin", "Thin", None),
        
        // Node.js
        m("http", r"X-Powered-By: Express", "Node.js Express", None),
        m("http", r"Server: Node\.js/(\d+\.\d+\.\d+)", "Node.js", Some("$1")),
        m("http", r"Server: Fastify", "Fastify", None),
        m("http", r"Server: Koa", "Koa", None),
        m("http", r"Server: Hapi", "Hapi", None),
        
        // PHP
        m("http", r"X-Powered-By: PHP/(\d+\.\d+\.\d+)", "PHP", Some("$1")),
        m("http", r"X-Powered-By: PHP/(\d+\.\d+)", "PHP", Some("$1")),
        
        // ASP.NET
        m("http", r"X-Powered-By: ASP\.NET", "ASP.NET", None),
        m("http", r"X-AspNet-Version: (\d+\.\d+\.\d+)", "ASP.NET", Some("$1")),
        m("http", r"X-AspNetMvc-Version: (\d+\.\d+)", "ASP.NET MVC", Some("$1")),
        
        // Django
        m("http", r"X-Frame-Options: DENY.*Server: WSGIServer", "Django", None),
        m("http", r"csrfmiddlewaretoken", "Django", None),
        
        // Rails
        m("http", r"X-Powered-By: Phusion Passenger", "Phusion Passenger", None),
        m("http", r"Server: Phusion Passenger", "Phusion Passenger", None),
        
        // Cloudflare
        m("http", r"Server: cloudflare", "Cloudflare httpd", None),
        m("http", r"Server: Cloudflare", "Cloudflare httpd", None),
        m("http", r"CF-RAY:", "Cloudflare httpd", None),
        
        // Akamai
        m("http", r"Server: AkamaiGHost", "Akamai httpd", None),
        m("http", r"X-Akamai-Transformed:", "Akamai httpd", None),
        
        // Fastly
        m("http", r"X-Served-By: cache-.*\.fastly\.net", "Fastly CDN", None),
        m("http", r"Via:.*varnish", "Varnish cache", None),
        m("http", r"X-Varnish: \d+", "Varnish cache", None),
        
        // Squid
        m("http", r"Server: squid/(\d+\.\d+)", "Squid http proxy", Some("$1")),
        
        // Varnish
        m("http", r"Via:.*varnish", "Varnish cache", None),
        m("http", r"X-Varnish: \d+", "Varnish cache", None),
        
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
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) CentOS", "OpenSSH (CentOS)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) SUSE", "OpenSSH (SUSE)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) FreeBSD", "OpenSSH (FreeBSD)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) NetBSD", "OpenSSH (NetBSD)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) OpenBSD", "OpenSSH (OpenBSD)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) Apple", "OpenSSH (macOS)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*QNAP", "OpenSSH (QNAP NAS)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*Synology", "OpenSSH (Synology NAS)", Some("$1")),
        m("ssh", r"SSH-2.0-ROSSSH", "MikroTik SSH", None),
        m("ssh", r"SSH-2.0-ROSSSH.*MikroTik", "MikroTik SSH", None),
        m("ssh", r"SSH-2.0-Cisco-", "Cisco SSH", None),
        m("ssh", r"SSH-2.0-Huawei", "Huawei SSH", None),
        m("ssh", r"SSH-2.0-Fortinet", "Fortinet SSH", None),
        m("ssh", r"SSH-2.0-Arista", "Arista SSH", None),
        m("ssh", r"SSH-2.0-HP", "HP SSH", None),
        m("ssh", r"SSH-2.0-OpenSSH", "OpenSSH", None),
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

/// Get additional HTTP framework signatures
pub fn http_frameworks_signatures() -> Vec<MatchPattern> {
    vec![
        // Vert.x
        m("http", r"Server: Vert\.x-Web/(\d+\.\d+\.\d+)", "Vert.x-Web", Some("$1")),
        m("http", r"Server: Vert\.x HTTP Server", "Vert.x HTTP Server", None),
        m("http", r"X-Powered-By: Vert\.x", "Vert.x", None),

        // Undertow
        m("http", r"Server: Undertow/(\d+\.\d+\.\d+)", "Undertow", Some("$1")),
        m("http", r"Server: Undertow", "Undertow", None),
        m("http", r"X-Powered-By: Undertow", "Undertow", None),

        // Netty
        m("http", r"Server: Netty/(\d+\.\d+\.\d+)", "Netty HTTP", Some("$1")),
        m("http", r"Server: Netty", "Netty HTTP", None),
        m("http", r"X-Powered-By: Netty", "Netty HTTP", None),

        // Resin
        m("http", r"Server: Resin/(\d+\.\d+\.\d+)", "Caucho Resin", Some("$1")),
        m("http", r"Server: Resin", "Caucho Resin", None),

        // Zope
        m("http", r"Server: Zope/(\d+\.\d+\.\d+)", "Zope", Some("$1")),
        m("http", r"Server: Zope", "Zope", None),
        m("http", r"X-Powered-By: Zope", "Zope", None),

        // Web2py
        m("http", r"X-Powered-By: web2py", "web2py", None),
        m("http", r"web2py\.js", "web2py", None),

        // Bottle
        m("http", r"Server: Bottle/(\d+\.\d+\.\d+)", "Bottle", Some("$1")),
        m("http", r"Server: Bottle", "Bottle", None),
        m("http", r"X-Powered-By: Bottle", "Bottle", None),

        // Flask
        m("http", r"Server: Werkzeug/(\d+\.\d+\.\d+) Python/(\d+\.\d+\.\d+)", "Flask", Some("$1")),
        m("http", r"X-Powered-By: Flask", "Flask", None),

        // FastAPI
        m("http", r"Server: uvicorn/(\d+\.\d+\.\d+)", "FastAPI/uvicorn", Some("$1")),
        m("http", r"X-Powered-By: FastAPI", "FastAPI", None),

        // Falcon
        m("http", r"X-Powered-By: Falcon", "Falcon", None),

        // Sanic
        m("http", r"Server: Sanic/(\d+\.\d+\.\d+)", "Sanic", Some("$1")),
        m("http", r"Server: Sanic", "Sanic", None),

        // Tornado (extra)
        m("http", r"Server: TornadoServer", "Tornado", None),

        // Twisted
        m("http", r"Server: TwistedWeb/(\d+\.\d+\.\d+)", "Twisted Web", Some("$1")),
        m("http", r"Server: TwistedWeb", "Twisted Web", None),

        // Cowboy (Erlang)
        m("http", r"Server: Cowboy/(\d+\.\d+\.\d+)", "Cowboy", Some("$1")),
        m("http", r"Server: Cowboy", "Cowboy", None),

        // Mochiweb
        m("http", r"Server: MochiWeb/(\d+\.\d+)", "MochiWeb", Some("$1")),
        m("http", r"Server: MochiWeb", "MochiWeb", None),

        // Yaws
        m("http", r"Server: Yaws/(\d+\.\d+\.\d+)", "Yaws", Some("$1")),
        m("http", r"Server: Yaws", "Yaws", None),

        // Mojolicious
        m("http", r"X-Powered-By: Mojolicious", "Mojolicious", None),

        // Dancer
        m("http", r"X-Powered-By: Perl Dancer", "Perl Dancer", None),
        m("http", r"X-Powered-By: Dancer2", "Dancer2", None),

        // Sinatra
        m("http", r"X-Powered-By: Sinatra", "Sinatra", None),

        // Rack
        m("http", r"X-Powered-By: Rack", "Rack", None),

        // Starlette
        m("http", r"Server: Starlette", "Starlette", None),

        // AIOHTTP
        m("http", r"Server: Python/(\d+\.\d+) aiohttp/(\d+\.\d+\.\d+)", "aiohttp", Some("$2")),

        // Apache Struts
        m("http", r"X-Powered-By: Struts", "Apache Struts", None),

        // Grails
        m("http", r"X-Powered-By: Grails", "Grails", None),

        // Play Framework
        m("http", r"X-Powered-By: Play Framework", "Play Framework", None),
        m("http", r"Server: Play", "Play Framework", None),

        // Akka HTTP
        m("http", r"Server: akka-http/(\d+\.\d+\.\d+)", "Akka HTTP", Some("$1")),
        m("http", r"Server: akka-http", "Akka HTTP", None),

        // Hapi (extra)
        m("http", r"Server: hapi", "hapi", None),

        // Koa (extra)
        m("http", r"X-Powered-By: Koa", "Koa", None),

        // NestJS
        m("http", r"X-Powered-By: NestJS", "NestJS", None),
    ]
}

/// Get additional CDN signatures
pub fn cdn_signatures() -> Vec<MatchPattern> {
    vec![
        // KeyCDN
        m("http", r"Server: keycdn-engine", "KeyCDN", None),
        m("http", r"X-Edge-Location:.*keycdn", "KeyCDN", None),

        // StackPath
        m("http", r"Server: StackPath", "StackPath CDN", None),
        m("http", r"X-CDN: StackPath", "StackPath CDN", None),
        m("http", r"X-HW:.*stackpathcdn", "StackPath CDN", None),

        // Sucuri
        m("http", r"Server: Sucuri/Cloudproxy", "Sucuri WAF", None),
        m("http", r"X-Sucuri-ID:", "Sucuri WAF", None),
        m("http", r"X-Sucuri-Cache:", "Sucuri CDN", None),

        // Incapsula/Imperva
        m("http", r"Server: Incapsula", "Imperva Incapsula", None),
        m("http", r"X-CDN: Incapsula", "Imperva Incapsula", None),
        m("http", r"incap_ses", "Imperva Incapsula", None),
        m("http", r"visid_incap_", "Imperva Incapsula", None),

        // BelugaCDN
        m("http", r"Server: BelugaCDN", "BelugaCDN", None),

        // BunnyCDN
        m("http", r"Server: BunnyCDN", "BunnyCDN", None),
        m("http", r"CDN-PullZone:.*bunnycdn", "BunnyCDN", None),

        // CacheFly
        m("http", r"Server: CFS ", "CacheFly CDN", None),

        // Limelight
        m("http", r"Server: Limelight", "Limelight CDN", None),

        // MaxCDN/bootstrapcdn
        m("http", r"Server: NetDNA", "MaxCDN", None),

        // Rackspace CDN
        m("http", r"X-Trans-Id:.*cdn", "Rackspace CDN", None),
    ]
}

/// Get additional reverse proxy signatures
pub fn reverse_proxy_signatures() -> Vec<MatchPattern> {
    vec![
        // Pound
        m("http", r"Server: Pound", "Pound proxy", None),
        m("http", r"X-Pound:", "Pound proxy", None),

        // Nginx variants
        m("http", r"Server: nginx/(\d+\.\d+\.\d+).*mod", "nginx (modified)", Some("$1")),
        m("http", r"Server: nginx-unit/(\d+\.\d+\.\d+)", "NGINX Unit", Some("$1")),
        m("http", r"Server: Unit/(\d+\.\d+\.\d+)", "NGINX Unit", Some("$1")),
        m("http", r"Server: Nginx", "nginx", None),

        // Varnish variants
        m("http", r"Server: Varnish/(\d+\.\d+\.\d+)", "Varnish", Some("$1")),
        m("http", r"Via:.*varnish/(\d+\.\d+)", "Varnish", Some("$1")),

        // Apache Traffic Server
        m("http", r"Server: ATS/(\d+\.\d+\.\d+)", "Apache Traffic Server", Some("$1")),
        m("http", r"Server: ApacheTrafficServer", "Apache Traffic Server", None),
        m("http", r"Via:.*ApacheTrafficServer", "Apache Traffic Server", None),

        // Envoy variants
        m("http", r"Server: envoy/(\d+\.\d+\.\d+)", "Envoy proxy", Some("$1")),
        m("http", r"x-envoy-upstream-service-time:", "Envoy proxy", None),

        // Traefik variants
        m("http", r"Server: Traefik/(\d+\.\d+\.\d+)", "Traefik", Some("$1")),

        // Linkerd
        m("http", r"Server: linkerd", "Linkerd proxy", None),
        m("http", r"l5d-dst-override:", "Linkerd proxy", None),

        // Caddy variants
        m("http", r"Server: Caddy/(\d+\.\d+)", "Caddy", Some("$1")),

        // AWS ALB
        m("http", r"Server: awselb", "AWS ELB", None),
        m("http", r"X-Amzn-Trace-Id:", "AWS load balancer", None),

        // GCP Load Balancer
        m("http", r"Via:.*google", "Google Cloud LB", None),
        m("http", r"Server: Google Frontend", "Google Frontend", None),

        // Azure Application Gateway
        m("http", r"Server: Microsoft-Azure-Application-Gateway", "Azure App GW", None),
    ]
}

/// Get API gateway signatures
pub fn api_gateway_signatures() -> Vec<MatchPattern> {
    vec![
        // Kong
        m("http", r"Server: kong/(\d+\.\d+\.\d+)", "Kong Gateway", Some("$1")),
        m("http", r"Server: kong", "Kong Gateway", None),
        m("http", r"X-Kong-.*:", "Kong Gateway", None),

        // Apigee
        m("http", r"X-Apigee-.*:", "Apigee", None),
        m("http", r"Server: Apigee", "Apigee", None),

        // AWS API Gateway
        m("http", r"Server: apigateway", "AWS API Gateway", None),
        m("http", r"x-amzn-RequestId:", "AWS API Gateway", None),
        m("http", r"x-amz-apigw-id:", "AWS API Gateway", None),

        // Tyk
        m("http", r"Server: Tyk", "Tyk Gateway", None),
        m("http", r"X-Tyk-.*:", "Tyk Gateway", None),

        // Ambassador
        m("http", r"Server: Ambassador", "Ambassador Gateway", None),

        // Express Gateway
        m("http", r"X-Powered-By: Express Gateway", "Express Gateway", None),

        // Zuul
        m("http", r"X-Zuul-.*:", "Netflix Zuul", None),

        // Azure API Management
        m("http", r"Server: Azure-API-Management", "Azure API Management", None),

        // Gravitee
        m("http", r"X-Gravitee-.*:", "Gravitee Gateway", None),

        // WSO2
        m("http", r"Server: WSO2", "WSO2 Gateway", None),
    ]
}

/// Get additional SSH vendor signatures
pub fn ssh_vendor_signatures() -> Vec<MatchPattern> {
    vec![
        // Brocade
        m("ssh", r"SSH-2.0-Brocade", "Brocade SSH", None),
        m("ssh", r"SSH-2.0-.*brocade", "Brocade SSH", None),

        // Extreme Networks
        m("ssh", r"SSH-2.0-Extreme Networks", "Extreme Networks SSH", None),
        m("ssh", r"SSH-2.0-ExtremeXOS", "Extreme Networks SSH", None),

        // Aruba Networks
        m("ssh", r"SSH-2.0-ArubaOS", "ArubaOS SSH", None),
        m("ssh", r"SSH-2.0-Aruba", "Aruba SSH", None),

        // Ruckus
        m("ssh", r"SSH-2.0-Ruckus", "Ruckus SSH", None),
        m("ssh", r"SSH-2.0-SZ", "Ruckus SmartZone SSH", None),

        // Ubiquiti
        m("ssh", r"SSH-2.0-Ubiquiti", "Ubiquiti SSH", None),
        m("ssh", r"SSH-2.0-EdgeRouter", "Ubiquiti EdgeRouter SSH", None),

        // Dell Networking (extra)
        m("ssh", r"SSH-2.0-OpenSSH_.*Dell", "Dell Networking SSH", None),
        m("ssh", r"SSH-2.0-Dell", "Dell SSH", None),

        // Juniper (extra)
        m("ssh", r"SSH-2.0-Junos", "Juniper Junos SSH", None),

        // Arista (extra)
        m("ssh", r"SSH-2.0-Arista.*EOS", "Arista EOS SSH", None),

        // Cisco (extra)
        m("ssh", r"SSH-2.0-Cisco-.*NX-OS", "Cisco NX-OS SSH", None),
        m("ssh", r"SSH-2.0-Cisco-.*ASA", "Cisco ASA SSH", None),

        // Huawei (extra)
        m("ssh", r"SSH-2.0-OpenSSH_.*HUAWEI", "Huawei SSH", None),
        m("ssh", r"SSH-2.0-SSH_.*VRP", "Huawei VRP SSH", None),

        // ZTE
        m("ssh", r"SSH-2.0-ZTE", "ZTE SSH", None),

        // TP-Link
        m("ssh", r"SSH-2.0-TP-LINK", "TP-Link SSH", None),

        // Netgear
        m("ssh", r"SSH-2.0-Netgear", "Netgear SSH", None),

        // Linksys
        m("ssh", r"SSH-2.0-Linksys", "Linksys SSH", None),

        // SonicWall
        m("ssh", r"SSH-2.0-SonicWall", "SonicWall SSH", None),
    ]
}

/// Get additional SSH OS variant signatures
pub fn ssh_os_signatures() -> Vec<MatchPattern> {
    vec![
        // AlmaLinux
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) AlmaLinux", "OpenSSH (AlmaLinux)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*alma", "OpenSSH (AlmaLinux)", Some("$1")),

        // Rocky Linux
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) Rocky", "OpenSSH (Rocky Linux)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*rocky", "OpenSSH (Rocky Linux)", Some("$1")),

        // Amazon Linux
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*amzn", "OpenSSH (Amazon Linux)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) Amazon", "OpenSSH (Amazon Linux)", Some("$1")),

        // Oracle Linux
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*Oracle", "OpenSSH (Oracle Linux)", Some("$1")),
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*el.*uek", "OpenSSH (Oracle UEK)", Some("$1")),

        // Arch Linux
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*arch", "OpenSSH (Arch Linux)", Some("$1")),

        // Gentoo
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*gentoo", "OpenSSH (Gentoo)", Some("$1")),

        // Alpine
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*alpine", "OpenSSH (Alpine Linux)", Some("$1")),

        // Manjaro
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*manjaro", "OpenSSH (Manjaro)", Some("$1")),

        // Fedora
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*fc\d+", "OpenSSH (Fedora)", Some("$1")),

        // CloudLinux
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*cloudlinux", "OpenSSH (CloudLinux)", Some("$1")),

        // AIX
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*aix", "OpenSSH (AIX)", Some("$1")),

        // HP-UX
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*HP-UX", "OpenSSH (HP-UX)", Some("$1")),

        // Solaris
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*SunOS", "OpenSSH (Solaris)", Some("$1")),
        m("ssh", r"SSH-2.0-Sun_SSH_([\d.]+)", "Sun SSH", Some("$1")),

        // SmartOS
        m("ssh", r"SSH-2.0-OpenSSH_([\d.]+) .*joyent", "OpenSSH (SmartOS/Joyent)", Some("$1")),
    ]
}

/// Get additional FTP server signatures
pub fn ftp_extended_signatures() -> Vec<MatchPattern> {
    vec![
        // glFTPd
        m("ftp", r"220.*glFTPd (\d+\.\d+\.\d+)", "glFTPd", Some("$1")),
        m("ftp", r"220.*glFTPd", "glFTPd", None),

        // RaidenFTPD
        m("ftp", r"220.*RaidenFTPD (\d+\.\d+\.\d+)", "RaidenFTPD", Some("$1")),
        m("ftp", r"220.*RaidenFTPD", "RaidenFTPD", None),
        m("ftp", r"220.*Raiden FTPD", "RaidenFTPD", None),

        // Cerberus FTP
        m("ftp", r"220.*Cerberus FTP Server (\d+\.\d+)", "Cerberus FTP", Some("$1")),
        m("ftp", r"220.*Cerberus FTP", "Cerberus FTP", None),

        // CrushFTP
        m("ftp", r"220.*CrushFTP (\d+\.\d+)", "CrushFTP", Some("$1")),
        m("ftp", r"220.*CrushFTP", "CrushFTP", None),

        // Wing FTP
        m("ftp", r"220.*Wing FTP Server (\d+\.\d+)", "Wing FTP", Some("$1")),
        m("ftp", r"220.*Wing FTP Server", "Wing FTP", None),

        // Gene6
        m("ftp", r"220.*Gene6 FTP Server", "Gene6 FTP", None),

        // War FTP Daemon
        m("ftp", r"220.*WarFTPd (\d+\.\d+)", "War FTP Daemon", Some("$1")),
        m("ftp", r"220.*WarFTPd", "War FTP Daemon", None),

        // BulletProof FTP
        m("ftp", r"220.*BPFTP Server", "BulletProof FTP", None),

        // ioFTPD
        m("ftp", r"220.*ioFTPD", "ioFTPD", None),

        // DrFTPD
        m("ftp", r"220.*DrFTPD", "DrFTPD", None),

        // Pure-FTPd variants
        m("ftp", r"220.*Pure-FTPd (\d+\.\d+)", "Pure-FTPd", Some("$1")),

        // ProFTPD variants
        m("ftp", r"220.*ProFTPD (\d+\.\d+) ", "ProFTPD", Some("$1")),
        m("ftp", r"220.*ProFTPD.*Debian", "ProFTPD (Debian)", None),
        m("ftp", r"220.*ProFTPD.*Ubuntu", "ProFTPD (Ubuntu)", None),

        // vsftpd variants
        m("ftp", r"220.*vsFTPd (\d+\.\d+\.\d+).*Ubuntu", "vsftpd (Ubuntu)", Some("$1")),
        m("ftp", r"220.*vsFTPd (\d+\.\d+\.\d+).*Debian", "vsftpd (Debian)", Some("$1")),

        // FileZilla variants
        m("ftp", r"220.*FileZilla Server (\d+\.\d+\.\d+)", "FileZilla Server", Some("$1")),

        // Golden FTP
        m("ftp", r"220.*Golden FTP Server", "Golden FTP", None),

        // Baby FTP
        m("ftp", r"220.*Baby FTP Server", "Baby FTP", None),

        // Quick 'n Easy FTP
        m("ftp", r"220.*Quick.*Easy FTP", "Quick 'n Easy FTP", None),

        // SurgeFTP
        m("ftp", r"220.*SurgeFTP (\d+\.\d+)", "SurgeFTP", Some("$1")),
        m("ftp", r"220.*SurgeFTP", "SurgeFTP", None),
    ]
}

/// Get additional SMTP server signatures
pub fn smtp_extended_signatures() -> Vec<MatchPattern> {
    vec![
        // CommuniGate Pro
        m("smtp", r"220.*CommuniGate Pro (\d+\.\d+)", "CommuniGate Pro", Some("$1")),
        m("smtp", r"220.*CommuniGate Pro", "CommuniGate Pro", None),
        m("smtp", r"220.*CommuniGate", "CommuniGate Pro", None),

        // IceWarp
        m("smtp", r"220.*IceWarp (\d+\.\d+)", "IceWarp", Some("$1")),
        m("smtp", r"220.*IceWarp", "IceWarp", None),

        // Merak Mail Server
        m("smtp", r"220.*Merak (\d+\.\d+)", "Merak Mail Server", Some("$1")),
        m("smtp", r"220.*Merak", "Merak Mail Server", None),
        m("smtp", r"220.*MerakMail", "Merak Mail Server", None),

        // Kerio Connect
        m("smtp", r"220.*Kerio Connect (\d+\.\d+)", "Kerio Connect", Some("$1")),
        m("smtp", r"220.*Kerio Connect", "Kerio Connect", None),
        m("smtp", r"220.*Kerio MailServer", "Kerio Connect", None),

        // Office 365 / Exchange Online
        m("smtp", r"220.*\.outlook\.com", "Microsoft 365 SMTP", None),
        m("smtp", r"220.*\.protection\.outlook\.com", "Microsoft 365 SMTP", None),
        m("smtp", r"220.*Exchange Online", "Microsoft 365 SMTP", None),

        // Google Workspace
        m("smtp", r"220.*\.google\.com ESMTP", "Google Workspace SMTP", None),
        m("smtp", r"220.*smtp\.google\.com", "Google Workspace SMTP", None),

        // Amazon SES
        m("smtp", r"220.*email-smtp\.amazonaws\.com", "Amazon SES", None),

        // Mailgun
        m("smtp", r"220.*Mailgun", "Mailgun SMTP", None),

        // SendGrid
        m("smtp", r"220.*SendGrid", "SendGrid SMTP", None),

        // Postfix variants
        m("smtp", r"220.*Postfix \((\d+\.\d+\.\d+)\)", "Postfix", Some("$1")),
        m("smtp", r"220.*Postfix.*Ubuntu", "Postfix (Ubuntu)", None),
        m("smtp", r"220.*Postfix.*Debian", "Postfix (Debian)", None),

        // Exim variants
        m("smtp", r"220.*Exim (\d+\.\d+\.\d+)", "Exim", Some("$1")),
        m("smtp", r"220.*Exim.*Debian", "Exim (Debian)", None),

        // Courier MTA
        m("smtp", r"220.*Courier", "Courier MTA", None),

        // qmail
        m("smtp", r"220.*ESMTP qmail", "qmail", None),
        m("smtp", r"220.*qmail", "qmail", None),

        // Citadel
        m("smtp", r"220.*Citadel", "Citadel", None),

        // Haraka
        m("smtp", r"220.*Haraka", "Haraka SMTP", None),

        // Zone MTA
        m("smtp", r"220.*Zone-MTA", "Zone-MTA", None),

        // MessageSystems
        m("smtp", r"220.*Momentum", "Momentum MTA", None),
    ]
}

/// Get additional database signatures
pub fn database_extended_signatures() -> Vec<MatchPattern> {
    vec![
        // CockroachDB
        m("postgres", r"CockroachDB", "CockroachDB", None),
        m("postgres", r"cockroach", "CockroachDB", None),

        // TiDB
        m("mysql", r"TiDB", "TiDB", None),
        m("mysql", r"tidb-server", "TiDB", None),

        // ScyllaDB
        m("cassandra", r"Scylla", "ScyllaDB", None),
        m("cassandra", r"scylla", "ScyllaDB", None),

        // ClickHouse
        m("clickhouse", r"ClickHouse", "ClickHouse", None),
        m("http", r"X-ClickHouse-Summary:", "ClickHouse", None),
        m("clickhouse", r"ClickHouse server", "ClickHouse", None),

        // InfluxDB
        m("influxdb", r"InfluxDB", "InfluxDB", None),
        m("http", r"X-Influxdb-Build:", "InfluxDB", None),
        m("http", r"X-Influxdb-Version:", "InfluxDB", None),

        // TimescaleDB
        m("postgres", r"timescaledb", "TimescaleDB", None),
        m("postgres", r"TimescaleDB", "TimescaleDB", None),

        // SQLite (via HTTP services)
        m("http", r"X-Powered-By: SQLite", "SQLite", None),

        // Firebird
        m("firebird", r"Firebird", "Firebird", None),
        m("gds-db", r"Firebird", "Firebird", None),
        m("firebird", r"Firebird/(\d+\.\d+\.\d+)", "Firebird", Some("$1")),

        // Informix
        m("informix", r"Informix", "IBM Informix", None),
        m("drda", r"Informix", "IBM Informix", None),

        // Sybase/SAP ASE
        m("sybase", r"Sybase", "SAP ASE", None),
        m("sybase", r"Adaptive Server", "SAP ASE", None),

        // Couchbase
        m("couchbase", r"Couchbase", "Couchbase", None),
        m("memcached", r"Couchbase", "Couchbase", None),
        m("http", r"X-Couchbase", "Couchbase", None),

        // Neo4j
        m("neo4j", r"Neo4j", "Neo4j", None),
        m("http", r"X-Neo4j", "Neo4j", None),
        m("bolt", r"Neo4j", "Neo4j", None),

        // ArangoDB
        m("arangodb", r"ArangoDB", "ArangoDB", None),
        m("http", r"X-ArangoDB", "ArangoDB", None),

        // RethinkDB
        m("rethinkdb", r"RethinkDB", "RethinkDB", None),
        m("http", r"X-RethinkDB", "RethinkDB", None),

        // Memcached
        m("memcached", r"memcached", "Memcached", None),
        m("memcached", r"Memcached", "Memcached", None),

        // Aerospike
        m("aerospike", r"Aerospike", "Aerospike", None),

        // RavenDB
        m("ravendb", r"RavenDB", "RavenDB", None),
        m("http", r"RavenDB", "RavenDB", None),

        // OrientDB
        m("orientdb", r"OrientDB", "OrientDB", None),
        m("http", r"X-OrientDB", "OrientDB", None),

        // Valkey
        m("redis", r"valkey", "Valkey", None),
        m("redis", r"Valkey", "Valkey", None),
    ]
}

/// Get additional web application signatures
pub fn webapp_extended_signatures() -> Vec<MatchPattern> {
    vec![
        // Magento
        m("http", r"X-Magento-Cache-Control:", "Magento", None),
        m("http", r"X-Magento-Tags:", "Magento", None),
        m("http", r"magento", "Magento", None),
        m("http", r"/static/frontend/.*Magento", "Magento", None),
        m("http", r"mage/cookies", "Magento", None),

        // Shopify
        m("http", r"X-Shopify-Stage:", "Shopify", None),
        m("http", r"Server: Shopify", "Shopify", None),
        m("http", r"cdn\.shopify\.com", "Shopify", None),

        // Wix
        m("http", r"X-Wix-.*:", "Wix", None),
        m("http", r"Server: Pepyaka", "Wix", None),
        m("http", r"wix\.com", "Wix", None),

        // Squarespace
        m("http", r"X-Squarespace-.*:", "Squarespace", None),
        m("http", r"Server: Squarespace", "Squarespace", None),
        m("http", r"squarespace-cdn", "Squarespace", None),

        // Ghost CMS
        m("http", r"X-Ghost-.*:", "Ghost CMS", None),
        m("http", r"ghost/", "Ghost CMS", None),
        m("http", r"X-Powered-By: Ghost", "Ghost CMS", None),

        // Spring Boot
        m("http", r"X-Application-Context:", "Spring Boot", None),
        m("http", r"/actuator/health", "Spring Boot Actuator", None),
        m("http", r"/actuator/info", "Spring Boot Actuator", None),
        m("http", r"Whitelabel Error Page", "Spring Boot", None),

        // Micronaut
        m("http", r"X-Micronaut-.*:", "Micronaut", None),
        m("http", r"Server: Micronaut", "Micronaut", None),

        // Quarkus
        m("http", r"X-Powered-By: Quarkus", "Quarkus", None),
        m("http", r"Server: Quarkus", "Quarkus", None),

        // Express variants
        m("http", r"X-Powered-By: Express/(\d+\.\d+\.\d+)", "Express.js", Some("$1")),
        m("http", r"Server: Express", "Express.js", None),

        // Next.js
        m("http", r"x-nextjs-page:", "Next.js", None),
        m("http", r"x-nextjs-cache:", "Next.js", None),
        m("http", r"X-Powered-By: Next\.js", "Next.js", None),
        m("http", r"_next/static", "Next.js", None),

        // Nuxt.js
        m("http", r"X-Powered-By: Nuxt", "Nuxt.js", None),
        m("http", r"nuxt/", "Nuxt.js", None),
        m("http", r"_nuxt/", "Nuxt.js", None),

        // Gatsby
        m("http", r"X-Gatsby-.*:", "Gatsby", None),
        m("http", r"Server: Gatsby", "Gatsby", None),

        // SvelteKit
        m("http", r"X-Powered-By: SvelteKit", "SvelteKit", None),
        m("http", r"Server: SvelteKit", "SvelteKit", None),
        m("http", r"_app/immutable", "SvelteKit", None),

        // Remix
        m("http", r"X-Remix-.*:", "Remix", None),
        m("http", r"Server: Remix", "Remix", None),

        // Astro
        m("http", r"X-Powered-By: Astro", "Astro", None),

        // Hugo
        m("http", r"Server: Hugo", "Hugo", None),
        m("http", r"X-Powered-By: Hugo", "Hugo", None),

        // Jekyll
        m("http", r"X-Powered-By: Jekyll", "Jekyll", None),

        // TYPO3
        m("http", r"X-TYPO3-.*:", "TYPO3", None),
        m("http", r"typo3", "TYPO3", None),

        // PrestaShop
        m("http", r"X-Powered-By: PrestaShop", "PrestaShop", None),
        m("http", r"prestashop", "PrestaShop", None),

        // Moodle
        m("http", r"X-Powered-By: Moodle", "Moodle", None),
        m("http", r"/theme/yui_combo", "Moodle", None),

        // MediaWiki
        m("http", r"X-Powered-By: MediaWiki", "MediaWiki", None),
        m("http", r"mediawiki", "MediaWiki", None),
        m("http", r"wgCanonicalNamespace", "MediaWiki", None),

        // Confluence
        m("http", r"X-Confluence-.*:", "Atlassian Confluence", None),
        m("http", r"confluence", "Atlassian Confluence", None),

        // Jira
        m("http", r"X-AREQUESTID:", "Atlassian Jira", None),
        m("http", r"ajs-version-number", "Atlassian Jira", None),

        // phpMyAdmin
        m("http", r"phpMyAdmin", "phpMyAdmin", None),
        m("http", r"pma_", "phpMyAdmin", None),

        // Roundcube
        m("http", r"X-Roundcube-.*:", "Roundcube", None),
        m("http", r"roundcube", "Roundcube", None),

        // Grafana (extra)
        m("http", r"grafana-session", "Grafana", None),
        m("http", r"X-Grafana-.*:", "Grafana", None),

        // Matomo
        m("http", r"matomo", "Matomo", None),
        m("http", r"X-Matomo-.*:", "Matomo", None),

        // Odoo
        m("http", r"X-Odoo-.*:", "Odoo", None),
        m("http", r"Server: Odoo", "Odoo", None),

        // GitLab (extra)
        m("http", r"_gitlab_session", "GitLab", None),
        m("http", r"X-Gitlab-.*:", "GitLab", None),

        // Gitea
        m("http", r"X-Powered-By: Gitea", "Gitea", None),
        m("http", r"_i_like_gitea", "Gitea", None),

        // Gogs
        m("http", r"X-Powered-By: Gogs", "Gogs", None),
        m("http", r"_gogs_session", "Gogs", None),

        // Redmine
        m("http", r"X-Powered-By: Redmine", "Redmine", None),
        m("http", r"redmine", "Redmine", None),

        // Bugzilla
        m("http", r"X-Bugzilla-.*:", "Bugzilla", None),
        m("http", r"bugzilla", "Bugzilla", None),

        // Trac
        m("http", r"X-Powered-By: Trac", "Trac", None),
        m("http", r"trac/", "Trac", None),
    ]
}

/// Get additional network equipment signatures
pub fn network_extended_signatures() -> Vec<MatchPattern> {
    vec![
        // Check Point
        m("ssh", r"SSH-2.0-Check Point", "Check Point SSH", None),
        m("ssh", r"SSH-2.0-OpenSSH_.*check", "Check Point SSH", None),
        m("https", r"Server: Check Point", "Check Point Gateway", None),

        // Sophos
        m("ssh", r"SSH-2.0-Sophos", "Sophos SSH", None),
        m("http", r"Server: Sophos", "Sophos", None),
        m("https", r"Sophos", "Sophos", None),

        // SonicWall (extra)
        m("http", r"Server: SonicWALL", "SonicWall", None),
        m("https", r"SonicWall", "SonicWall", None),
        m("http", r"X-SonicWall", "SonicWall", None),

        // Ubiquiti (extra)
        m("http", r"Server: Ubiquiti", "Ubiquiti", None),
        m("http", r"UBNT", "Ubiquiti", None),

        // Cisco Meraki
        m("http", r"Server: Meraki", "Cisco Meraki", None),
        m("https", r"X-Meraki", "Cisco Meraki", None),

        // Zyxel
        m("ssh", r"SSH-2.0-Zyxel", "Zyxel SSH", None),
        m("telnet", r"ZyXEL", "Zyxel", None),

        // Netgear (extra)
        m("telnet", r"Netgear", "Netgear", None),
        m("http", r"Server: NETGEAR", "Netgear", None),

        // DrayTek
        m("ssh", r"SSH-2.0-DrayTek", "DrayTek SSH", None),
        m("telnet", r"DrayTek", "DrayTek", None),

        // Barracuda
        m("ssh", r"SSH-2.0-Barracuda", "Barracuda SSH", None),
        m("http", r"Server: Barracuda", "Barracuda", None),

        // Citrix NetScaler
        m("ssh", r"SSH-2.0-NetScaler", "Citrix NetScaler SSH", None),
        m("http", r"Server: NetScaler", "Citrix NetScaler", None),
        m("http", r"ns_af=", "Citrix NetScaler", None),

        // F5 BIG-IP
        m("ssh", r"SSH-2.0-OpenSSH.*f5", "F5 BIG-IP SSH", None),
        m("http", r"Server: BigIP", "F5 BIG-IP", None),
        m("http", r"X-Cnection: close", "F5 BIG-IP", None),
        m("http", r"BIGipServer", "F5 BIG-IP", None),

        // A10 Networks
        m("ssh", r"SSH-2.0-A10", "A10 Networks SSH", None),

        // Brocade (extra)
        m("telnet", r"Brocade", "Brocade", None),

        // Extreme Networks (extra)
        m("telnet", r"ExtremeXOS", "Extreme Networks", None),
        m("telnet", r"ExtremeWare", "Extreme Networks", None),

        // Dell (extra)
        m("telnet", r"Dell", "Dell Networking", None),
        m("telnet", r"PowerConnect", "Dell PowerConnect", None),

        // HPE (extra)
        m("telnet", r"ProCurve", "HP ProCurve", None),
        m("telnet", r"HPE", "HPE", None),
        m("telnet", r"ArubaOS", "ArubaOS", None),

        // Juniper (extra)
        m("telnet", r"JUNOS", "Juniper Junos", None),

        // Telnet banners - generic
        m("telnet", r"User Access Verification", "Network Device", None),
        m("telnet", r"login:", "Network Device (telnet)", None),
        m("telnet", r"Username:", "Network Device (telnet)", None),

        // SNMP responses
        m("snmp", r"Linux", "Linux SNMP", None),
        m("snmp", r"Windows", "Windows SNMP", None),
        m("snmp", r"Cisco", "Cisco SNMP", None),
        m("snmp", r"Juniper", "Juniper SNMP", None),
        m("snmp", r"MikroTik", "MikroTik SNMP", None),
        m("snmp", r"Synology", "Synology SNMP", None),
    ]
}

/// Get additional monitoring/DevOps signatures
pub fn devops_signatures() -> Vec<MatchPattern> {
    vec![
        // Datadog Agent
        m("http", r"X-Datadog-.*:", "Datadog Agent", None),
        m("datadog", r"datadog-agent", "Datadog Agent", None),

        // New Relic (extra)
        m("http", r"X-NewRelic-.*:", "New Relic", None),
        m("http", r"newrelic", "New Relic", None),

        // AppDynamics
        m("http", r"X-AppDynamics-.*:", "AppDynamics", None),
        m("appdynamics", r"AppDynamics", "AppDynamics", None),

        // Dynatrace
        m("http", r"X-Dynatrace-.*:", "Dynatrace", None),
        m("dynatrace", r"Dynatrace", "Dynatrace", None),
        m("http", r"DTCookie:", "Dynatrace", None),

        // Elastic APM
        m("http", r"X-Cloud-Trace-Context:", "Elastic APM", None),

        // Sentry
        m("http", r"X-Sentry-.*:", "Sentry", None),
        m("sentry", r"Sentry", "Sentry", None),

        // Bamboo
        m("bamboo", r"Bamboo", "Atlassian Bamboo", None),
        m("http", r"bamboo", "Atlassian Bamboo", None),

        // CircleCI
        m("circleci", r"CircleCI", "CircleCI", None),
        m("http", r"circleci", "CircleCI", None),

        // Travis CI
        m("travisci", r"Travis CI", "Travis CI", None),
        m("http", r"travis-ci", "Travis CI", None),

        // TeamCity
        m("teamcity", r"TeamCity", "JetBrains TeamCity", None),
        m("http", r"TeamCity", "JetBrains TeamCity", None),
        m("http", r"X-TeamCity-.*:", "JetBrains TeamCity", None),

        // Drone CI
        m("drone", r"Drone", "Drone CI", None),
        m("http", r"X-Drone-.*:", "Drone CI", None),

        // Argo CD
        m("argocd", r"Argo CD", "Argo CD", None),
        m("http", r"X-Argocd-.*:", "Argo CD", None),

        // Flux
        m("flux", r"Flux", "Flux CD", None),

        // Podman
        m("podman", r"Podman", "Podman", None),
        m("http", r"X-Podman-.*:", "Podman", None),

        // containerd
        m("containerd", r"containerd", "containerd", None),
        m("http", r"Server: containerd", "containerd", None),

        // CRI-O
        m("crio", r"CRI-O", "CRI-O", None),

        // BuildKit
        m("buildkit", r"BuildKit", "BuildKit", None),

        // Terraform Cloud
        m("http", r"X-Terraform-.*:", "Terraform Cloud", None),

        // Vault (extra)
        m("http", r"X-Vault-.*:", "HashiCorp Vault", None),

        // Consul (extra)
        m("http", r"X-Consul-.*:", "HashiCorp Consul", None),

        // Nomad
        m("nomad", r"Nomad", "HashiCorp Nomad", None),
        m("http", r"X-Nomad-.*:", "HashiCorp Nomad", None),

        // Istio
        m("http", r"Server: istio-envoy", "Istio", None),
        m("http", r"x-envoy-decorator-operation:", "Istio", None),

        // Keycloak
        m("keycloak", r"Keycloak", "Keycloak", None),
        m("http", r"X-Keycloak-.*:", "Keycloak", None),

        // Argo Workflows
        m("http", r"X-Argo-.*:", "Argo Workflows", None),

        // Rancher
        m("rancher", r"Rancher", "Rancher", None),
        m("http", r"X-Rancher-.*:", "Rancher", None),

        // Portainer
        m("portainer", r"Portainer", "Portainer", None),
        m("http", r"X-Portainer-.*:", "Portainer", None),
    ]
}

/// Get additional IoT/embedded device signatures
pub fn iot_extended_signatures() -> Vec<MatchPattern> {
    vec![
        // Axis cameras
        m("http", r"Server: AXIS (\w+)", "Axis Camera", Some("$1")),
        m("http", r"Server: axis", "Axis Camera", None),
        m("http", r"Axis.*Network Camera", "Axis Camera", None),
        m("http", r"X-AXIS-.*:", "Axis Camera", None),

        // Hikvision (extra)
        m("http", r"Server: Hikvision", "Hikvision", None),
        m("http", r"Hikvision-Webs", "Hikvision", None),
        m("rtsp", r"Hikvision", "Hikvision", None),

        // Dahua (extra)
        m("http", r"Server: DNVRS-Webs", "Dahua", None),
        m("http", r"Dahua", "Dahua", None),
        m("rtsp", r"Dahua", "Dahua", None),

        // Amcrest
        m("http", r"Server: Amcrest", "Amcrest Camera", None),
        m("http", r"Amcrest", "Amcrest Camera", None),

        // Foscam
        m("http", r"FOSCAM", "Foscam Camera", None),
        m("http", r"Foscam", "Foscam Camera", None),

        // Reolink
        m("http", r"Reolink", "Reolink Camera", None),

        // Wyze
        m("http", r"WyzeCam", "Wyze Camera", None),

        // Ring
        m("http", r"Ring Doorbell", "Ring Doorbell", None),

        // MikroTik RouterOS (extra)
        m("http", r"RouterOS", "MikroTik RouterOS", None),
        m("mikrotik", r"MikroTik", "MikroTik RouterOS", None),

        // DD-WRT
        m("http", r"Server: httpd/.*DD-WRT", "DD-WRT", None),
        m("http", r"DD-WRT", "DD-WRT", None),
        m("http", r"X-Powered-By: DD-WRT", "DD-WRT", None),

        // OpenWrt
        m("http", r"Server: uhttpd/(\d+\.\d+\.\d+)", "OpenWrt uhttpd", Some("$1")),
        m("http", r"Server: uhttpd", "OpenWrt uhttpd", None),
        m("http", r"OpenWrt", "OpenWrt", None),

        // Tomato firmware
        m("http", r"Server: httpd/.*Tomato", "Tomato firmware", None),
        m("http", r"Tomato.*firmware", "Tomato firmware", None),

        // Asuswrt-Merlin
        m("http", r"Server: httpd/.*Merlin", "Asuswrt-Merlin", None),
        m("http", r"Asuswrt-Merlin", "Asuswrt-Merlin", None),

        // Ubiquiti UniFi
        m("http", r"Server: UniFi", "Ubiquiti UniFi", None),
        m("http", r"UniFi Controller", "Ubiquiti UniFi", None),
        m("unifi", r"UniFi", "Ubiquiti UniFi", None),

        // Siemens SIMATIC
        m("http", r"Server: SIMATIC", "Siemens SIMATIC", None),
        m("http", r"Siemens", "Siemens Device", None),
        m("siemens", r"SIMATIC", "Siemens SIMATIC", None),

        // Allen-Bradley / Rockwell
        m("http", r"Allen-Bradley", "Allen-Bradley", None),
        m("http", r"Rockwell", "Rockwell Automation", None),
        m("ethernetip", r"Rockwell", "Rockwell Automation", None),

        // Schneider Electric
        m("http", r"Schneider Electric", "Schneider Electric", None),
        m("http", r"Modicon", "Schneider Modicon", None),
        m("modbus", r"Schneider", "Schneider Modicon", None),

        // ABB
        m("http", r"ABB", "ABB Device", None),

        // Honeywell
        m("http", r"Honeywell", "Honeywell Device", None),

        // Bosch Security
        m("http", r"Bosch.*Security", "Bosch Security Camera", None),
        m("rtsp", r"Bosch", "Bosch Camera", None),

        // Sony IPELA
        m("http", r"Sony.*IPELA", "Sony IPELA Camera", None),
        m("rtsp", r"Sony", "Sony Camera", None),

        // Vivotek
        m("http", r"Vivotek", "Vivotek Camera", None),
        m("rtsp", r"Vivotek", "Vivotek Camera", None),

        // Uniview
        m("http", r"Uniview", "Uniview Camera", None),
    ]
}

/// Get additional game/media server signatures
pub fn game_media_signatures() -> Vec<MatchPattern> {
    vec![
        // Counter-Strike
        m("steam", r"Counter-Strike", "Counter-Strike Server", None),
        m("steam", r"cstrike", "Counter-Strike Server", None),
        m("steam", r"cs2", "Counter-Strike 2 Server", None),

        // Team Fortress 2
        m("steam", r"Team Fortress", "Team Fortress 2 Server", None),
        m("steam", r"tf2", "Team Fortress 2 Server", None),

        // ARK: Survival Evolved
        m("steam", r"ARK", "ARK Server", None),
        m("gamespy", r"ARK: Survival Evolved", "ARK Server", None),

        // Rust
        m("steam", r"Rust", "Rust Server", None),

        // Garry's Mod
        m("steam", r"Garry.s Mod", "Garry's Mod Server", None),
        m("steam", r"gmod", "Garry's Mod Server", None),

        // Valheim
        m("steam", r"Valheim", "Valheim Server", None),

        // Factorio
        m("factorio", r"Factorio", "Factorio Server", None),

        // 7 Days to Die
        m("steam", r"7 Days to Die", "7 Days to Die Server", None),

        // Terraria
        m("terraria", r"Terraria", "Terraria Server", None),

        // Unturned
        m("steam", r"Unturned", "Unturned Server", None),

        // FiveM (GTA V)
        m("fivem", r"FiveM", "FiveM Server", None),
        m("http", r"X-Cfx-.*:", "FiveM Server", None),

        // SA-MP (San Andreas Multiplayer)
        m("samp", r"SA-MP", "SA-MP Server", None),

        // DayZ
        m("steam", r"DayZ", "DayZ Server", None),

        // Conan Exiles
        m("steam", r"Conan Exiles", "Conan Exiles Server", None),

        // Plex Media Server
        m("http", r"Server: Plex Media Server", "Plex Media Server", None),
        m("http", r"X-Plex-.*:", "Plex Media Server", None),
        m("plex", r"Plex Media Server", "Plex Media Server", None),
        m("http", r"X-Plex-Protocol:", "Plex Media Server", None),

        // Jellyfin
        m("http", r"Server: Jellyfin", "Jellyfin", None),
        m("http", r"X-Emby-.*:", "Jellyfin", None),
        m("http", r"X-Jellyfin-.*:", "Jellyfin", None),
        m("jellyfin", r"Jellyfin", "Jellyfin", None),

        // Emby
        m("http", r"Server: Emby", "Emby", None),
        m("http", r"X-Emby-Server:", "Emby", None),
        m("emby", r"Emby", "Emby", None),

        // Subsonic
        m("http", r"Server: Subsonic", "Subsonic", None),
        m("http", r"X-Subsonic-.*:", "Subsonic", None),
        m("subsonic", r"Subsonic", "Subsonic", None),

        // Airsonic
        m("http", r"Server: Airsonic", "Airsonic", None),
        m("http", r"X-Airsonic-.*:", "Airsonic", None),

        // Navidrome
        m("http", r"Server: Navidrome", "Navidrome", None),
        m("http", r"X-Navidrome-.*:", "Navidrome", None),

        // Ampache
        m("http", r"X-Powered-By: Ampache", "Ampache", None),
        m("ampache", r"Ampache", "Ampache", None),

        // Icecast
        m("http", r"Server: Icecast (\d+\.\d+\.\d+)", "Icecast", Some("$1")),
        m("http", r"Server: Icecast", "Icecast", None),

        // Shoutcast
        m("http", r"Server: SHOUTcast", "SHOUTcast", None),
        m("http", r"Server: SHOUTcast (\d+\.\d+)", "SHOUTcast", Some("$1")),

        // Red5
        m("http", r"Server: Red5", "Red5", None),

        // Wowza
        m("http", r"Server: Wowza Streaming Engine", "Wowza Streaming", None),
        m("rtsp", r"Wowza", "Wowza Streaming", None),

        // Nginx-RTMP
        m("http", r"Server: nginx-rtmp", "nginx-rtmp", None),
    ]
}

/// Get additional web server and framework signatures
pub fn web_server_framework_signatures() -> Vec<MatchPattern> {
    vec![
        // Apache modules
        m("http", r"Server: Apache/(\d+\.\d+\.\d+).*mod_security", "Apache mod_security", Some("$1")),
        m("http", r"Server: Apache.*mod_security", "Apache mod_security", None),
        m("http", r"Server: Apache.*mod_jk", "Apache mod_jk", None),
        m("http", r"Server: Apache.*mod_python", "Apache mod_python", None),
        m("http", r"Server: Apache.*mod_perl", "Apache mod_perl", None),
        m("http", r"Server: Apache.*mod_wsgi", "Apache mod_wsgi", None),
        m("http", r"Server: Apache.*mod_ssl", "Apache mod_ssl", None),
        m("http", r"Server: Apache.*mod_fastcgi", "Apache mod_fastcgi", None),
        m("http", r"Server: Apache.*mod_fcgid", "Apache mod_fcgid", None),
        m("http", r"Server: Apache.*mod_dav", "Apache mod_dav", None),
        m("http", r"Server: Apache.*mod_proxy", "Apache mod_proxy", None),
        m("http", r"Server: Apache.*mod_pagespeed", "Apache mod_pagespeed", None),

        // Nginx modules
        m("http", r"Server: nginx.*njs", "nginx njs", None),
        m("http", r"Server: nginx.*mod_waf", "nginx mod_waf", None),
        m("http", r"Server: nginx.*VestaCP", "nginx (VestaCP)", None),
        m("http", r"Server: nginx.*Plesk", "nginx (Plesk)", None),
        m("http", r"Server: nginx.*cPanel", "nginx (cPanel)", None),
        m("http", r"Server: nginx.*BoringSSL", "nginx (BoringSSL)", None),
        m("http", r"Server: nginx.*quic", "nginx (QUIC)", None),

        // More IIS versions
        m("http", r"Server: Microsoft-IIS/10\.0", "Microsoft IIS 10.0", None),
        m("http", r"Server: Microsoft-IIS/8\.5", "Microsoft IIS 8.5", None),
        m("http", r"Server: Microsoft-IIS/8\.0", "Microsoft IIS 8.0", None),
        m("http", r"Server: Microsoft-IIS/7\.5", "Microsoft IIS 7.5", None),
        m("http", r"Server: Microsoft-IIS/7\.0", "Microsoft IIS 7.0", None),
        m("http", r"Server: Microsoft-IIS/6\.0", "Microsoft IIS 6.0", None),

        // Application servers
        m("http", r"Server: WildFly/(\d+)", "WildFly", Some("$1")),
        m("http", r"Server: GlassFish Server (\d+\.\d+)", "GlassFish", Some("$1")),
        m("http", r"Server: WebSphere Application Server", "IBM WebSphere", None),
        m("http", r"Server: IBM_HTTP_Server", "IBM HTTP Server", None),
        m("http", r"Server: Oracle-Application-Server", "Oracle App Server", None),
        m("http", r"Server: Oracle-HTTP-Server", "Oracle HTTP Server", None),
        m("http", r"Server: JBoss-EAP", "JBoss EAP", None),
        m("http", r"Server: JBoss-Web", "JBoss Web", None),
        m("http", r"Server: Apache Tomcat/(\d+)", "Apache Tomcat", Some("$1")),
        m("http", r"Server: Tomcat", "Apache Tomcat", None),

        // Python frameworks
        m("http", r"Server: Django/(\d+\.\d+)", "Django", Some("$1")),
        m("http", r"Server: Django", "Django", None),
        m("http", r"X-Powered-By: Django", "Django", None),
        m("http", r"Server: Flask/(\d+\.\d+)", "Flask", Some("$1")),
        m("http", r"Server: FastAPI", "FastAPI", None),
        m("http", r"X-Powered-By: FastAPI", "FastAPI", None),
        m("http", r"Server: uvicorn", "uvicorn", None),
        m("http", r"Server: Gunicorn/(\d+\.\d+\.\d+)", "Gunicorn", Some("$1")),
        m("http", r"Server: Waitress", "Waitress", None),
        m("http", r"Server: Daphne", "Daphne", None),

        // Node.js frameworks
        m("http", r"X-Powered-By: Express", "Express.js", None),
        m("http", r"X-Powered-By: Koa", "Koa", None),
        m("http", r"X-Powered-By: Hapi", "Hapi", None),
        m("http", r"X-Powered-By: NestJS", "NestJS", None),
        m("http", r"Server: Fastify/(\d+\.\d+)", "Fastify", Some("$1")),
        m("http", r"X-Powered-By: Fastify", "Fastify", None),
        m("http", r"X-Powered-By: Loopback", "LoopBack", None),
        m("http", r"X-Powered-By: Sails", "Sails.js", None),
        m("http", r"X-Powered-By: Adonis", "AdonisJS", None),
        m("http", r"X-Powered-By: Feathers", "FeathersJS", None),

        // Ruby frameworks
        m("http", r"Server: Puma (\d+\.\d+\.\d+)", "Puma", Some("$1")),
        m("http", r"Server: Puma", "Puma", None),
        m("http", r"Server: Thin (\d+\.\d+\.\d+)", "Thin", Some("$1")),
        m("http", r"Server: Unicorn (\d+\.\d+\.\d+)", "Unicorn", Some("$1")),
        m("http", r"Server: Passenger (\d+\.\d+\.\d+)", "Passenger", Some("$1")),
        m("http", r"X-Powered-By: Phusion Passenger", "Phusion Passenger", None),
        m("http", r"Server: Phusion Passenger", "Phusion Passenger", None),
        m("http", r"X-Powered-By: Rack", "Rack", None),
        m("http", r"X-Powered-By: Sinatra", "Sinatra", None),
        m("http", r"Server: Sinatra", "Sinatra", None),
        m("http", r"X-Powered-By: Grape", "Grape", None),

        // PHP frameworks
        m("http", r"X-Powered-By: Laravel", "Laravel", None),
        m("http", r"laravel_session", "Laravel", None),
        m("http", r"X-Powered-By: Symfony", "Symfony", None),
        m("http", r"X-Powered-By: CodeIgniter", "CodeIgniter", None),
        m("http", r"X-Powered-By: CakePHP", "CakePHP", None),
        m("http", r"X-Powered-By: Zend", "Zend Framework", None),
        m("http", r"X-Powered-By: Laminas", "Laminas", None),
        m("http", r"X-Powered-By: Yii", "Yii", None),
        m("http", r"X-Powered-By: Slim", "Slim Framework", None),
        m("http", r"X-Powered-By: Lumen", "Lumen", None),
        m("http", r"X-Powered-By: Drupal", "Drupal", None),
        m("http", r"X-Powered-By: WordPress", "WordPress", None),
        m("http", r"X-Powered-By: Magento", "Magento", None),

        // Go frameworks
        m("http", r"Server: Gin", "Gin", None),
        m("http", r"Server: Echo", "Echo", None),
        m("http", r"Server: Fiber", "Fiber", None),
        m("http", r"Server: Buffalo", "Buffalo", None),

        // Rust frameworks
        m("http", r"Server: Actix", "Actix Web", None),
        m("http", r"Server: Actix-Web", "Actix Web", None),
        m("http", r"Server: Rocket", "Rocket", None),
        m("http", r"Server: Axum", "Axum", None),
        m("http", r"Server: Warp", "Warp", None),

        // Java frameworks
        m("http", r"X-Powered-By: Spring", "Spring Framework", None),
        m("http", r"X-Powered-By: Spring Boot", "Spring Boot", None),
        m("http", r"X-Powered-By: Dropwizard", "Dropwizard", None),
        m("http", r"Server: Dropwizard", "Dropwizard", None),

        // .NET frameworks
        m("http", r"X-Powered-By: ASP\.NET Core", "ASP.NET Core", None),
        m("http", r"Server: Kestrel", "Kestrel", None),
        m("http", r"X-Powered-By: Nancy", "Nancy", None),
    ]
}

/// Get additional database signatures
pub fn database_more_signatures() -> Vec<MatchPattern> {
    vec![
        // MySQL variants
        m("mysql", r"(\d+\.\d+\.\d+)-MariaDB-.*Ubuntu", "MariaDB (Ubuntu)", Some("$1")),
        m("mysql", r"(\d+\.\d+\.\d+)-MariaDB-.*Debian", "MariaDB (Debian)", Some("$1")),
        m("mysql", r"(\d+\.\d+\.\d+)-MariaDB-.*CentOS", "MariaDB (CentOS)", Some("$1")),
        m("mysql", r"(\d+\.\d+\.\d+)-MariaDB", "MariaDB", Some("$1")),
        m("mysql", r"(\d+\.\d+\.\d+)-MySQL", "MySQL", Some("$1")),
        m("mysql", r"(\d+\.\d+\.\d+)-cll-lve", "MySQL (CloudLinux)", Some("$1")),
        m("mysql", r"Percona Server", "Percona Server", None),
        m("mysql", r"(\d+\.\d+\.\d+)-percona", "Percona Server", Some("$1")),
        m("mysql", r"Aurora", "Amazon Aurora", None),

        // PostgreSQL variants
        m("postgres", r"PostgreSQL (\d+\.\d+\.\d+)", "PostgreSQL", Some("$1")),
        m("postgres", r"PostgreSQL (\d+\.\d+)", "PostgreSQL", Some("$1")),
        m("postgres", r"EnterpriseDB", "EnterpriseDB", None),
        m("postgres", r"Citus", "Citus", None),
        m("postgres", r"Greenplum", "Greenplum", None),
        m("postgres", r"YugabyteDB", "YugabyteDB", None),

        // MongoDB versions
        m("mongodb", r"MongoDB (\d+\.\d+\.\d+)", "MongoDB", Some("$1")),
        m("mongodb", r"MongoDB (\d+\.\d+)", "MongoDB", Some("$1")),
        m("mongodb", r"mongod", "MongoDB", None),
        m("mongodb", r"mongos", "MongoDB Router", None),
        m("mongodb", r"MongoDB shell version", "MongoDB Shell", None),
        m("mongodb", r"Percona Server for MongoDB", "Percona MongoDB", None),

        // Redis versions
        m("redis", r"redis_version:(\d+\.\d+\.\d+)", "Redis", Some("$1")),
        m("redis", r"redis_version:(\d+\.\d+)", "Redis", Some("$1")),
        m("redis", r"Redis server v=(\d+\.\d+\.\d+)", "Redis", Some("$1")),
        m("redis", r"redis_version:(\d+\.\d+\.\d+).*valkey", "Valkey", Some("$1")),
        m("redis", r"KeyDB", "KeyDB", None),

        // Elasticsearch versions
        m("elasticsearch", r"elasticsearch/(\d+\.\d+\.\d+)", "Elasticsearch", Some("$1")),
        m("elasticsearch", r"elasticsearch/(\d+\.\d+)", "Elasticsearch", Some("$1")),
        m("elasticsearch", r"cluster_name.*elasticsearch", "Elasticsearch", None),
        m("elasticsearch", r"OpenSearch", "OpenSearch", None),
        m("elasticsearch", r"opensearch/(\d+\.\d+\.\d+)", "OpenSearch", Some("$1")),

        // Cassandra versions
        m("cassandra", r"Cassandra (\d+\.\d+\.\d+)", "Apache Cassandra", Some("$1")),
        m("cassandra", r"Cassandra (\d+\.\d+)", "Apache Cassandra", Some("$1")),
        m("cassandra", r"Scylla (\d+\.\d+\.\d+)", "ScyllaDB", Some("$1")),

        // CouchDB versions
        m("couchdb", r"CouchDB/(\d+\.\d+\.\d+)", "CouchDB", Some("$1")),
        m("couchdb", r"CouchDB/(\d+\.\d+)", "CouchDB", Some("$1")),
        m("couchdb", r"couchdb/(\d+\.\d+\.\d+)", "CouchDB", Some("$1")),
        m("couchdb", r"CouchDB", "CouchDB", None),
    ]
}

/// Get additional mail server signatures
pub fn mail_more_signatures() -> Vec<MatchPattern> {
    vec![
        // Exchange versions
        m("smtp", r"220.*Microsoft ESMTP MAIL Service.*Version: (\d+)", "Microsoft Exchange", Some("$1")),
        m("smtp", r"220.*Exchange Server (\d+)", "Microsoft Exchange", Some("$1")),
        m("imap", r"Microsoft Exchange IMAP4", "Microsoft Exchange IMAP", None),
        m("pop3", r"Microsoft Exchange POP3", "Microsoft Exchange POP3", None),
        m("imap", r"Exchange Server (\d+)", "Microsoft Exchange IMAP", Some("$1")),
        m("pop3", r"Exchange Server (\d+)", "Microsoft Exchange POP3", Some("$1")),

        // Postfix variants
        m("smtp", r"220.*Postfix \((\d+\.\d+\.\d+)\)", "Postfix", Some("$1")),
        m("smtp", r"220.*Postfix \((\d+\.\d+)\)", "Postfix", Some("$1")),
        m("smtp", r"220.*Postfix.*Ubuntu", "Postfix (Ubuntu)", None),
        m("smtp", r"220.*Postfix.*Debian", "Postfix (Debian)", None),
        m("smtp", r"220.*Postfix.*RHEL", "Postfix (RHEL)", None),
        m("smtp", r"220.*Postfix.*CentOS", "Postfix (CentOS)", None),
        m("smtp", r"220.*Postfix.*Amazon", "Postfix (Amazon Linux)", None),

        // Exim variants
        m("smtp", r"220.*Exim (\d+\.\d+\.\d+)", "Exim", Some("$1")),
        m("smtp", r"220.*Exim (\d+\.\d+)", "Exim", Some("$1")),
        m("smtp", r"220.*ESMTP Exim (\d+\.\d+)", "Exim", Some("$1")),
        m("smtp", r"220.*Exim.*Debian", "Exim (Debian)", None),
        m("smtp", r"220.*Exim.*cPanel", "Exim (cPanel)", None),
        m("smtp", r"220.*Exim.*WHM", "Exim (WHM/cPanel)", None),

        // Dovecot variants
        m("imap", r"Dovecot (\d+\.\d+\.\d+)", "Dovecot", Some("$1")),
        m("imap", r"Dovecot (\d+\.\d+)", "Dovecot", Some("$1")),
        m("imap", r"Dovecot \(Ubuntu\)", "Dovecot (Ubuntu)", None),
        m("imap", r"Dovecot \(Debian\)", "Dovecot (Debian)", None),
        m("pop3", r"Dovecot (\d+\.\d+\.\d+)", "Dovecot POP3", Some("$1")),
        m("pop3", r"Dovecot (\d+\.\d+)", "Dovecot POP3", Some("$1")),
        m("imap", r"Dovecot-ee", "Dovecot Enterprise", None),

        // Courier variants
        m("imap", r"Courier-IMAP (\d+\.\d+)", "Courier IMAP", Some("$1")),
        m("pop3", r"Courier Mail Server", "Courier POP3", None),

        // Cyrus variants
        m("imap", r"Cyrus IMAP (\d+\.\d+\.\d+)", "Cyrus IMAP", Some("$1")),
        m("imap", r"Cyrus IMAP (\d+\.\d+)", "Cyrus IMAP", Some("$1")),
        m("imap", r"Cyrus", "Cyrus IMAP", None),
        m("pop3", r"Cyrus POP3", "Cyrus POP3", None),

        // Zimbra
        m("smtp", r"220.*Zimbra (\d+)", "Zimbra", Some("$1")),
        m("imap", r"Zimbra", "Zimbra IMAP", None),
        m("pop3", r"Zimbra", "Zimbra POP3", None),
    ]
}

/// Get additional network equipment signatures
pub fn network_more_signatures() -> Vec<MatchPattern> {
    vec![
        // Cisco IOS versions
        m("telnet", r"Cisco IOS Software", "Cisco IOS", None),
        m("telnet", r"Cisco IOS XE", "Cisco IOS XE", None),
        m("telnet", r"Cisco NX-OS", "Cisco NX-OS", None),
        m("telnet", r"Cisco ASA", "Cisco ASA", None),
        m("telnet", r"Cisco Adaptive Security", "Cisco ASA", None),
        m("ssh", r"SSH-2.0-Cisco-.*NX-OS", "Cisco NX-OS", None),
        m("ssh", r"SSH-2.0-Cisco-.*ASA", "Cisco ASA", None),
        m("ssh", r"SSH-2.0-Cisco-.*IOS", "Cisco IOS", None),
        m("http", r"Server: cisco-IOS", "Cisco IOS HTTP", None),

        // Juniper Junos versions
        m("ssh", r"SSH-2.0-Junos", "Juniper Junos", None),
        m("ssh", r"SSH-2.0-JUNOS", "Juniper Junos", None),
        m("telnet", r"Juniper Networks.*Junos", "Juniper Junos", None),
        m("telnet", r"JUNOS (\d+\.\d+)", "Juniper Junos", Some("$1")),
        m("http", r"Server: Juniper", "Juniper", None),
        m("https", r"Juniper", "Juniper", None),

        // Fortinet FortiOS versions
        m("ssh", r"SSH-2.0-Fortinet", "Fortinet FortiOS", None),
        m("ssh", r"SSH-2.0-FortiOS", "Fortinet FortiOS", None),
        m("telnet", r"Fortinet", "Fortinet FortiOS", None),
        m("https", r"FortiGate", "Fortinet FortiGate", None),
        m("https", r"FortiOS", "Fortinet FortiOS", None),
        m("http", r"Server: Fortinet", "Fortinet", None),
        m("https", r"FORTINET", "Fortinet FortiOS", None),

        // Palo Alto PAN-OS versions
        m("ssh", r"SSH-2.0-Palo Alto", "Palo Alto PAN-OS", None),
        m("ssh", r"SSH-2.0-PAN-OS", "Palo Alto PAN-OS", None),
        m("https", r"Palo Alto Networks", "Palo Alto PAN-OS", None),
        m("http", r"Server: PanWeb Server", "Palo Alto PAN-OS", None),
        m("https", r"GlobalProtect Portal", "Palo Alto GlobalProtect", None),

        // Arista EOS versions
        m("ssh", r"SSH-2.0-Arista", "Arista EOS", None),
        m("telnet", r"Arista", "Arista EOS", None),

        // Dell Networking OS versions
        m("ssh", r"SSH-2.0-Dell", "Dell Networking OS", None),
        m("telnet", r"Dell Networking", "Dell Networking OS", None),
        m("telnet", r"Dell EMC", "Dell EMC Networking", None),
        m("telnet", r"OS10", "Dell EMC OS10", None),

        // HPE/Aruba versions
        m("ssh", r"SSH-2.0-HP", "HP ProCurve", None),
        m("ssh", r"SSH-2.0-HPE", "HPE", None),
        m("ssh", r"SSH-2.0-ArubaOS", "ArubaOS", None),
        m("telnet", r"ArubaOS", "ArubaOS", None),
        m("telnet", r"HP ProCurve", "HP ProCurve", None),

        // Huawei VRP versions
        m("ssh", r"SSH-2.0-SSH_.*VRP", "Huawei VRP", None),
        m("telnet", r"Huawei Versatile Routing Platform", "Huawei VRP", None),
        m("telnet", r"VRP.*Huawei", "Huawei VRP", None),

        // MikroTik RouterOS versions
        m("ssh", r"SSH-2.0-ROSSSH", "MikroTik RouterOS", None),
        m("telnet", r"MikroTik", "MikroTik RouterOS", None),
        m("http", r"RouterOS", "MikroTik RouterOS", None),
        m("http", r"MikroTik", "MikroTik RouterOS", None),
    ]
}

/// Get additional IoT device signatures
pub fn iot_more_signatures() -> Vec<MatchPattern> {
    vec![
        // Camera vendors
        m("http", r"Server: GeoHttpServer", "GeoVision Camera", None),
        m("http", r"Server: IQinVision", "IQeye Camera", None),
        m("http", r"Server: MOBOTIX", "MOBOTIX Camera", None),
        m("http", r"MOBOTIX", "MOBOTIX Camera", None),
        m("http", r"Server: Vivotek", "Vivotek Camera", None),
        m("http", r"Server: TRASSIR", "TRASSIR DVR", None),
        m("http", r"Server: Avigilon", "Avigilon Camera", None),
        m("http", r"Server: Arecont Vision", "Arecont Vision Camera", None),
        m("http", r"Server: FLIR", "FLIR Camera", None),
        m("http", r"FLIR Systems", "FLIR Camera", None),
        m("http", r"Server: Hanwha", "Hanwha Camera", None),
        m("http", r"Samsung.*Camera", "Samsung Camera", None),
        m("http", r"Server: Pelco", "Pelco Camera", None),
        m("http", r"Server: Panasonic", "Panasonic Camera", None),
        m("rtsp", r"GeoVision", "GeoVision Camera", None),
        m("rtsp", r"MOBOTIX", "MOBOTIX Camera", None),
        m("rtsp", r"FLIR", "FLIR Camera", None),
        m("rtsp", r"Hanwha", "Hanwha Camera", None),

        // Router vendors
        m("http", r"Server: httpd/.*ASUS", "ASUS Router", None),
        m("http", r"ASUS.*Router", "ASUS Router", None),
        m("http", r"Server: Netgear", "Netgear Router", None),
        m("http", r"NETGEAR.*Router", "Netgear Router", None),
        m("http", r"Server: TP-LINK", "TP-Link Router", None),
        m("http", r"TP-LINK.*Router", "TP-Link Router", None),
        m("http", r"Server: Linksys", "Linksys Router", None),
        m("http", r"Linksys.*Router", "Linksys Router", None),
        m("http", r"Server: D-Link", "D-Link Router", None),
        m("http", r"D-Link.*Router", "D-Link Router", None),
        m("http", r"Server: DrayTek", "DrayTek Router", None),
        m("http", r"DrayTek.*Vigor", "DrayTek Vigor", None),
        m("http", r"Server: Zyxel", "Zyxel Router", None),
        m("http", r"ZyXEL.*Router", "Zyxel Router", None),
        m("http", r"Server: Ruckus", "Ruckus", None),
        m("http", r"Ruckus Wireless", "Ruckus", None),

        // Embedded devices
        m("http", r"Server: GoAhead-Webs", "GoAhead Web Server", None),
        m("http", r"Server: mini_httpd", "mini_httpd", None),
        m("http", r"Server: thttpd", "thttpd", None),
        m("http", r"Server: Boa", "Boa HTTP Server", None),
        m("http", r"Server: Allegro", "Allegro RomPager", None),
        m("http", r"Server: RomPager", "Allegro RomPager", None),
        m("http", r"Server: Virata-EmWeb", "Virata-EmWeb", None),
        m("http", r"Server: Embedthis", "Embedthis HTTP", None),
        m("http", r"Server: lighttpd", "lighttpd", None),
        m("http", r"Server: BusyBox", "BusyBox httpd", None),
        m("http", r"Server: Mongoose", "Mongoose HTTP", None),
        m("http", r"Server: lwIP", "lwIP HTTP", None),
        m("http", r"Server: ZLIB", "ZLIB HTTP", None),

        // Smart home
        m("http", r"Philips Hue", "Philips Hue", None),
        m("http", r"Server: Hue", "Philips Hue", None),
        m("http", r"Sonos", "Sonos", None),
        m("http", r"Server: Sonos", "Sonos", None),
        m("http", r"Nest", "Google Nest", None),
        m("http", r"ecobee", "Ecobee", None),

        // Printers extra
        m("http", r"Server: HP HTTP", "HP Printer", None),
        m("http", r"HP Color LaserJet", "HP Color LaserJet", None),
        m("http", r"KONICA MINOLTA", "Konica Minolta Printer", None),
        m("http", r"SHARP MX", "Sharp MX Printer", None),
        m("http", r"OKI Data", "OKI Printer", None),
        m("http", r"Server: DELL", "Dell Printer", None),
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
    sigs.extend(http_frameworks_signatures());
    sigs.extend(cdn_signatures());
    sigs.extend(reverse_proxy_signatures());
    sigs.extend(api_gateway_signatures());
    sigs.extend(ssh_vendor_signatures());
    sigs.extend(ssh_os_signatures());
    sigs.extend(ftp_extended_signatures());
    sigs.extend(smtp_extended_signatures());
    sigs.extend(database_extended_signatures());
    sigs.extend(webapp_extended_signatures());
    sigs.extend(network_extended_signatures());
    sigs.extend(devops_signatures());
    sigs.extend(iot_extended_signatures());
    sigs.extend(game_media_signatures());
    sigs.extend(web_server_framework_signatures());
    sigs.extend(database_more_signatures());
    sigs.extend(mail_more_signatures());
    sigs.extend(network_more_signatures());
    sigs.extend(iot_more_signatures());
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
        assert!(sigs.len() >= 750, "Expected at least 750 total signatures, got {}", sigs.len());
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
