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

/// Get additional web framework signatures - Python, Node, Ruby, PHP, Java, Go, Rust
pub fn web_frameworks_extra_signatures() -> Vec<MatchPattern> {
    vec![
        // Django extra
        m("http", r"Server: Django/(\d+\.\d+\.\d+)", "Django", Some("$1")),
        m("http", r"X-Frame-Options: DENY.*django", "Django", None),
        m("http", r"Set-Cookie:.*csrftoken", "Django", None),
        m("http", r"Set-Cookie:.*sessionid", "Django", None),
        m("http", r"X-Content-Type-Options:.*Server:.*WSGIServer", "Django", None),

        // Flask extra
        m("http", r"Server: Werkzeug/(\d+\.\d+) Python/(\d+\.\d+)", "Flask", Some("$1")),
        m("http", r"X-Powered-By: Flask/(\d+\.\d+)", "Flask", Some("$1")),
        m("http", r"Set-Cookie:.*session=.*httponly.*Secure", "Flask", None),
        m("http", r"Server: CherryPy/(\d+\.\d+) Python/(\d+\.\d+)", "CherryPy", Some("$1")),

        // FastAPI extra
        m("http", r"Server: uvicorn/(\d+\.\d+) Python/(\d+\.\d+)", "FastAPI/uvicorn", Some("$1")),
        m("http", r"X-Process-Time:", "FastAPI", None),
        m("http", r"openapi.json", "FastAPI", None),
        m("http", r"docs", "FastAPI", None),

        // Tornado extra
        m("http", r"Server: TornadoServer/(\d+\.\d+\.\d+)", "Tornado", Some("$1")),
        m("http", r"X-Powered-By: Tornado", "Tornado", None),

        // Pyramid
        m("http", r"Server: Pyramid/(\d+\.\d+)", "Pyramid", Some("$1")),
        m("http", r"X-Powered-By: Pyramid", "Pyramid", None),
        m("http", r"Set-Cookie:.*pyramid_session", "Pyramid", None),

        // Zope extra
        m("http", r"Server: Zope/(\d+\.\d+)", "Zope", Some("$1")),
        m("http", r"X-Powered-By: Zope/(\d+\.\d+)", "Zope", Some("$1")),

        // web2py extra
        m("http", r"Set-Cookie:.*w2p_session", "web2py", None),

        // Dash (Plotly)
        m("http", r"X-Powered-By: Dash", "Plotly Dash", None),
        m("http", r"Server: Dash", "Plotly Dash", None),

        // Streamlit
        m("http", r"Server: Streamlit", "Streamlit", None),
        m("http", r"X-Powered-By: Streamlit", "Streamlit", None),

        // Gradio
        m("http", r"Server: Gradio", "Gradio", None),
        m("http", r"X-Powered-By: Gradio", "Gradio", None),

        // Express extra
        m("http", r"X-Powered-By: Express/(\d+\.\d+\.\d+)", "Express.js", Some("$1")),
        m("http", r"Set-Cookie:.*connect.sid", "Express.js", None),
        m("http", r"Server: Express/(\d+\.\d+)", "Express.js", Some("$1")),

        // Koa extra
        m("http", r"X-Powered-By: Koa/(\d+\.\d+)", "Koa", Some("$1")),
        m("http", r"Set-Cookie:.*koa:sess", "Koa", None),

        // Hapi extra
        m("http", r"Server: hapi/(\d+\.\d+)", "hapi", Some("$1")),
        m("http", r"X-Powered-By: hapi", "hapi", None),

        // NestJS extra
        m("http", r"X-Powered-By: NestJS/(\d+\.\d+)", "NestJS", Some("$1")),
        m("http", r"Server: NestJS", "NestJS", None),

        // Fastify extra
        m("http", r"Server: fastify/(\d+\.\d+)", "Fastify", Some("$1")),
        m("http", r"X-Powered-By: fastify", "Fastify", None),

        // Sails.js
        m("http", r"X-Powered-By: Sails.js", "Sails.js", None),
        m("http", r"Set-Cookie:.*sails.sid", "Sails.js", None),

        // AdonisJS
        m("http", r"X-Powered-By: AdonisJs", "AdonisJS", None),
        m("http", r"Set-Cookie:.*adonis-session", "AdonisJS", None),

        // FeathersJS
        m("http", r"X-Powered-By: FeathersJS", "FeathersJS", None),

        // LoopBack
        m("http", r"X-Powered-By: LoopBack", "LoopBack", None),

        // Restify
        m("http", r"Server: restify", "Restify", None),
        m("http", r"X-Powered-By: Restify", "Restify", None),

        // Meteor
        m("http", r"X-Powered-By: Meteor", "Meteor", None),
        m("http", r"Set-Cookie:.*meteor_login_token", "Meteor", None),

        // Strapi
        m("http", r"X-Powered-By: Strapi", "Strapi", None),
        m("http", r"Server: Strapi", "Strapi", None),

        // KeystoneJS
        m("http", r"X-Powered-By: KeystoneJS", "KeystoneJS", None),

        // Rails extra
        m("http", r"X-Powered-By: Ruby on Rails", "Ruby on Rails", None),
        m("http", r"Set-Cookie:.*_session_id", "Ruby on Rails", None),
        m("http", r"X-Runtime:", "Ruby on Rails", None),
        m("http", r"X-Request-Id:", "Ruby on Rails", None),
        m("http", r"Server: Puma/(\d+\.\d+\.\d+)", "Puma", Some("$1")),
        m("http", r"X-Powered-By: Rails", "Ruby on Rails", None),
        m("http", r"Set-Cookie:.*_rails_session", "Ruby on Rails", None),

        // Sinatra extra
        m("http", r"Server: Sinatra/(\d+\.\d+)", "Sinatra", Some("$1")),
        m("http", r"X-Powered-By: Sinatra/(\d+\.\d+)", "Sinatra", Some("$1")),

        // Puma extra
        m("http", r"Server: Puma (\d+\.\d+) .*Rails", "Puma (Rails)", Some("$1")),
        m("http", r"X-Powered-By: Puma", "Puma", None),

        // Unicorn extra
        m("http", r"Server: Unicorn/(\d+\.\d+)", "Unicorn", Some("$1")),
        m("http", r"X-Powered-By: Unicorn", "Unicorn", None),

        // Thin extra
        m("http", r"Server: thin/(\d+\.\d+)", "Thin", Some("$1")),
        m("http", r"X-Powered-By: Thin", "Thin", None),

        // Passenger extra
        m("http", r"Server: Phusion Passenger/(\d+\.\d+)", "Phusion Passenger", Some("$1")),
        m("http", r"X-Powered-By: Phusion Passenger/(\d+\.\d+)", "Phusion Passenger", Some("$1")),

        // Grape
        m("http", r"X-Powered-By: Grape/(\d+\.\d+)", "Grape", Some("$1")),

        // Hanami
        m("http", r"X-Powered-By: Hanami", "Hanami", None),
        m("http", r"Set-Cookie:.*hanami_session", "Hanami", None),

        // Camping
        m("http", r"X-Powered-By: Camping", "Camping", None),

        // Ramaze
        m("http", r"X-Powered-By: Ramaze", "Ramaze", None),

        // Laravel extra
        m("http", r"Set-Cookie:.*laravel_session", "Laravel", None),
        m("http", r"X-Powered-By: Laravel/(\d+\.\d+)", "Laravel", Some("$1")),
        m("http", r"Set-Cookie:.*XSRF-TOKEN", "Laravel", None),
        m("http", r"X-RateLimit-Limit:", "Laravel", None),

        // Symfony extra
        m("http", r"X-Powered-By: Symfony/(\d+\.\d+)", "Symfony", Some("$1")),
        m("http", r"Set-Cookie:.*PHPSESSID", "PHP", None),
        m("http", r"X-Debug-Token:", "Symfony", None),
        m("http", r"X-Symfony-Cache:", "Symfony", None),

        // CodeIgniter extra
        m("http", r"X-Powered-By: CodeIgniter/(\d+\.\d+)", "CodeIgniter", Some("$1")),
        m("http", r"Set-Cookie:.*ci_session", "CodeIgniter", None),

        // CakePHP extra
        m("http", r"X-Powered-By: CakePHP/(\d+\.\d+)", "CakePHP", Some("$1")),
        m("http", r"Set-Cookie:.*CAKEPHP", "CakePHP", None),

        // Zend/Laminas extra
        m("http", r"X-Powered-By: Zend Framework/(\d+\.\d+)", "Zend Framework", Some("$1")),
        m("http", r"X-Powered-By: Laminas/(\d+\.\d+)", "Laminas", Some("$1")),

        // Yii
        m("http", r"X-Powered-By: Yii/(\d+\.\d+)", "Yii", Some("$1")),
        m("http", r"Set-Cookie:.*YII_CSRF_TOKEN", "Yii", None),

        // Slim extra
        m("http", r"X-Powered-By: Slim/(\d+\.\d+)", "Slim Framework", Some("$1")),
        m("http", r"Server: Slim", "Slim Framework", None),

        // Lumen
        m("http", r"X-Powered-By: Lumen/(\d+\.\d+)", "Lumen", Some("$1")),

        // Phalcon
        m("http", r"X-Powered-By: Phalcon", "Phalcon", None),

        // FuelPHP
        m("http", r"X-Powered-By: FuelPHP", "FuelPHP", None),

        // Nette
        m("http", r"X-Powered-By: Nette Framework", "Nette Framework", None),
        m("http", r"Set-Cookie:.*nette-browser", "Nette Framework", None),

        // October CMS
        m("http", r"X-Powered-By: October CMS", "October CMS", None),

        // Craft CMS
        m("http", r"Set-Cookie:.*CraftSessionId", "Craft CMS", None),
        m("http", r"X-Powered-By: Craft CMS", "Craft CMS", None),

        // Gin extra
        m("http", r"Server: Gin/(\d+\.\d+)", "Gin", Some("$1")),
        m("http", r"X-Powered-By: Gin", "Gin", None),

        // Echo extra
        m("http", r"Server: Echo/(\d+\.\d+)", "Echo", Some("$1")),
        m("http", r"X-Powered-By: Echo", "Echo", None),

        // Fiber extra
        m("http", r"Server: Fiber/(\d+\.\d+)", "Fiber", Some("$1")),
        m("http", r"X-Powered-By: Fiber", "Fiber", None),

        // Chi
        m("http", r"Server: Chi", "Chi", None),
        m("http", r"X-Powered-By: Chi", "Chi", None),

        // Buffalo extra
        m("http", r"X-Powered-By: Buffalo", "Buffalo", None),

        // Beego
        m("http", r"Server: BeegoServer/(\d+\.\d+)", "Beego", Some("$1")),
        m("http", r"X-Powered-By: Beego", "Beego", None),

        // Iris
        m("http", r"Server: Iris", "Iris", None),
        m("http", r"X-Powered-By: Iris", "Iris", None),

        // Revel
        m("http", r"Server: Revel", "Revel", None),
        m("http", r"X-Powered-By: Revel", "Revel", None),

        // Martini
        m("http", r"Server: Martini", "Martini", None),

        // Gorilla
        m("http", r"X-Powered-By: Gorilla", "Gorilla", None),

        // Actix extra
        m("http", r"Server: actix-web/(\d+\.\d+)", "Actix Web", Some("$1")),
        m("http", r"Server: Actix", "Actix Web", None),
        m("http", r"X-Powered-By: Actix", "Actix Web", None),

        // Axum extra
        m("http", r"Server: axum/(\d+\.\d+)", "Axum", Some("$1")),
        m("http", r"X-Powered-By: Axum", "Axum", None),

        // Rocket extra
        m("http", r"Server: Rocket/(\d+\.\d+)", "Rocket", Some("$1")),
        m("http", r"X-Powered-By: Rocket", "Rocket", None),

        // Warp extra
        m("http", r"Server: warp/(\d+\.\d+)", "Warp", Some("$1")),
        m("http", r"X-Powered-By: Warp", "Warp", None),

        // Tide
        m("http", r"Server: Tide", "Tide", None),
        m("http", r"X-Powered-By: Tide", "Tide", None),

        // Hyper
        m("http", r"Server: hyper/(\d+\.\d+)", "hyper", Some("$1")),

        // Spring Boot extra
        m("http", r"X-Application-Context:.*Spring", "Spring Boot", None),
        m("http", r"Set-Cookie:.*JSESSIONID", "Java", None),
        m("http", r"Server: Apache-Coyote/(\d+\.\d+)", "Apache Tomcat", Some("$1")),
        m("http", r"X-Powered-By: Spring/(\d+\.\d+)", "Spring Framework", Some("$1")),
        m("http", r"X-Powered-By: Spring Boot/(\d+\.\d+)", "Spring Boot", Some("$1")),

        // Struts extra
        m("http", r"X-Powered-By: Struts/(\d+\.\d+)", "Apache Struts", Some("$1")),
        m("http", r"Server: Struts", "Apache Struts", None),

        // Play extra
        m("http", r"X-Powered-By: Play/(\d+\.\d+)", "Play Framework", Some("$1")),
        m("http", r"Set-Cookie:.*PLAY_SESSION", "Play Framework", None),
        m("http", r"Server: Play Framework/(\d+\.\d+)", "Play Framework", Some("$1")),

        // Vert.x extra
        m("http", r"Server: Vert\.x-Web/(\d+\.\d+)", "Vert.x-Web", Some("$1")),
        m("http", r"X-Powered-By: Vert\.x/(\d+\.\d+)", "Vert.x", Some("$1")),

        // Micronaut extra
        m("http", r"X-Micronaut-Request-Id:", "Micronaut", None),
        m("http", r"Server: Micronaut/(\d+\.\d+)", "Micronaut", Some("$1")),

        // Quarkus extra
        m("http", r"X-Powered-By: Quarkus/(\d+\.\d+)", "Quarkus", Some("$1")),
        m("http", r"Server: Quarkus/(\d+\.\d+)", "Quarkus", Some("$1")),

        // Dropwizard extra
        m("http", r"Server: Dropwizard/(\d+\.\d+)", "Dropwizard", Some("$1")),
        m("http", r"X-Powered-By: Dropwizard/(\d+\.\d+)", "Dropwizard", Some("$1")),

        // Grails extra
        m("http", r"X-Powered-By: Grails/(\d+\.\d+)", "Grails", Some("$1")),

        // Kestrel extra
        m("http", r"Server: Kestrel/(\d+\.\d+)", "Kestrel", Some("$1")),
        m("http", r"X-Powered-By: Kestrel", "Kestrel", None),

        // ASP.NET Core extra
        m("http", r"Server: Microsoft-IIS/(\d+\.\d+).*ASP\.NET", "ASP.NET Core", Some("$1")),
        m("http", r"X-Powered-By: ASP\.NET Core/(\d+\.\d+)", "ASP.NET Core", Some("$1")),

        // Nancy
        m("http", r"X-Powered-By: Nancy/(\d+\.\d+)", "Nancy", Some("$1")),
    ]
}

/// Get additional database signatures - more variants and versions
pub fn database_variants_signatures() -> Vec<MatchPattern> {
    vec![
        // Percona MySQL extra
        m("mysql", r"(\d+\.\d+\.\d+)-percona-sql", "Percona Server", Some("$1")),
        m("mysql", r"Percona Server.*(\d+\.\d+\.\d+)", "Percona Server", Some("$1")),
        m("mysql", r"Percona XtraDB Cluster", "Percona XtraDB Cluster", None),
        m("mysql", r"(\d+\.\d+\.\d+)-PXC", "Percona XtraDB Cluster", Some("$1")),

        // MariaDB extra
        m("mysql", r"(\d+\.\d+\.\d+)-MariaDB-.*log", "MariaDB", Some("$1")),
        m("mysql", r"MariaDB (\d+\.\d+\.\d+)", "MariaDB", Some("$1")),
        m("mysql", r"MariaDB Galera cluster", "MariaDB Galera", None),
        m("mysql", r"(\d+\.\d+\.\d+)-MariaDB-.*MariaDB Server", "MariaDB", Some("$1")),

        // Aurora extra
        m("mysql", r"Amazon Aurora MySQL", "Amazon Aurora MySQL", None),
        m("mysql", r"Aurora MySQL (\d+\.\d+)", "Amazon Aurora MySQL", Some("$1")),

        // MySQL HeatWave
        m("mysql", r"MySQL.*HeatWave", "MySQL HeatWave", None),

        // Citus extra
        m("postgres", r"citus/(\d+\.\d+)", "Citus", Some("$1")),
        m("postgres", r"PostgreSQL.*Citus", "Citus", None),

        // TimescaleDB extra
        m("postgres", r"timescaledb/(\d+\.\d+\.\d+)", "TimescaleDB", Some("$1")),
        m("postgres", r"PostgreSQL.*TimescaleDB", "TimescaleDB", None),

        // CockroachDB extra
        m("postgres", r"CockroachDB CCL v(\d+\.\d+)", "CockroachDB", Some("$1")),
        m("postgres", r"cockroachdb/(\d+\.\d+)", "CockroachDB", Some("$1")),

        // Greenplum extra
        m("postgres", r"Greenplum Database (\d+\.\d+)", "Greenplum", Some("$1")),
        m("postgres", r"Pivotal Greenplum", "Greenplum", None),

        // YugabyteDB extra
        m("postgres", r"YugabyteDB (\d+\.\d+)", "YugabyteDB", Some("$1")),
        m("cassandra", r"Yugabyte", "YugabyteDB", None),

        // EnterpriseDB extra
        m("postgres", r"EnterpriseDB (\d+\.\d+)", "EnterpriseDB", Some("$1")),
        m("postgres", r"Postgres Plus", "EnterpriseDB", None),

        // Aurora PostgreSQL
        m("postgres", r"Amazon Aurora PostgreSQL", "Amazon Aurora PostgreSQL", None),
        m("postgres", r"Aurora PostgreSQL (\d+\.\d+)", "Amazon Aurora PostgreSQL", Some("$1")),

        // MongoDB extra
        m("mongodb", r"MongoDB (\d+\.\d+\.\d+).*replica set", "MongoDB Replica Set", Some("$1")),
        m("mongodb", r"MongoDB (\d+\.\d+\.\d+).*sharded", "MongoDB Sharded", Some("$1")),
        m("mongodb", r"MongoDB Atlas", "MongoDB Atlas", None),
        m("mongodb", r"mongod.*(\d+\.\d+\.\d+)", "MongoDB", Some("$1")),
        m("mongodb", r"Percona Server for MongoDB (\d+\.\d+)", "Percona MongoDB", Some("$1")),

        // KeyDB extra
        m("redis", r"KeyDB v(\d+\.\d+\.\d+)", "KeyDB", Some("$1")),
        m("redis", r"keydb_version:(\d+\.\d+\.\d+)", "KeyDB", Some("$1")),

        // Dragonfly
        m("redis", r"dragonfly", "Dragonfly", None),
        m("redis", r"Dragonfly v(\d+\.\d+\.\d+)", "Dragonfly", Some("$1")),
        m("redis", r"dfly_version:(\d+\.\d+\.\d+)", "Dragonfly", Some("$1")),

        // Valkey extra
        m("redis", r"valkey_version:(\d+\.\d+\.\d+)", "Valkey", Some("$1")),
        m("redis", r"Valkey v(\d+\.\d+\.\d+)", "Valkey", Some("$1")),

        // Redis Sentinel
        m("redis", r"redis_sentinel", "Redis Sentinel", None),

        // Redis Cluster
        m("redis", r"redis_cluster", "Redis Cluster", None),

        // Elasticsearch extra
        m("elasticsearch", r"elasticsearch/(\d+\.\d+\.\d+).*cluster", "Elasticsearch", Some("$1")),
        m("elasticsearch", r"You Know, for Search", "Elasticsearch", None),
        m("elasticsearch", r"tagline.*elasticsearch", "Elasticsearch", None),
        m("http", r"X-elastic-product: Elasticsearch", "Elasticsearch", None),

        // OpenSearch extra
        m("elasticsearch", r"opensearch/(\d+\.\d+\.\d+)", "OpenSearch", Some("$1")),
        m("elasticsearch", r"OpenSearch (\d+\.\d+\.\d+)", "OpenSearch", Some("$1")),
        m("http", r"X-elastic-product: OpenSearch", "OpenSearch", None),

        // Cassandra extra
        m("cassandra", r"Apache Cassandra (\d+\.\d+\.\d+)", "Apache Cassandra", Some("$1")),
        m("cassandra", r"thrift/(\d+\.\d+\.\d+)", "Apache Cassandra", Some("$1")),
        m("cassandra", r"cql/(\d+\.\d+)", "Apache Cassandra", Some("$1")),
        m("cassandra", r"ScyllaDB (\d+\.\d+\.\d+)", "ScyllaDB", Some("$1")),
        m("cassandra", r"Scylla (\d+\.\d+)", "ScyllaDB", Some("$1")),

        // CouchDB extra
        m("couchdb", r"Apache CouchDB/(\d+\.\d+\.\d+)", "Apache CouchDB", Some("$1")),
        m("couchdb", r"Apache CouchDB (\d+\.\d+\.\d+)", "Apache CouchDB", Some("$1")),
        m("http", r"Server: CouchDB/(\d+\.\d+)", "CouchDB", Some("$1")),
        m("http", r"X-CouchDB", "CouchDB", None),

        // ClickHouse extra
        m("clickhouse", r"ClickHouse server version (\d+\.\d+\.\d+)", "ClickHouse", Some("$1")),
        m("http", r"X-ClickHouse-Format:", "ClickHouse", None),
        m("http", r"X-ClickHouse-Timezone:", "ClickHouse", None),

        // InfluxDB extra
        m("influxdb", r"InfluxDB (\d+\.\d+\.\d+)", "InfluxDB", Some("$1")),
        m("influxdb", r"InfluxDB OSS", "InfluxDB OSS", None),
        m("influxdb", r"InfluxDB Enterprise", "InfluxDB Enterprise", None),
        m("http", r"X-Influxdb-Build: OSS", "InfluxDB OSS", None),

        // Prometheus extra
        m("prometheus", r"Prometheus (\d+\.\d+\.\d+)", "Prometheus", Some("$1")),
        m("http", r"X-Prometheus", "Prometheus", None),

        // VictoriaMetrics
        m("http", r"X-VictoriaMetrics", "VictoriaMetrics", None),
        m("vmselect", r"VictoriaMetrics", "VictoriaMetrics", None),

        // Memcached extra
        m("memcached", r"memcached (\d+\.\d+\.\d+)", "Memcached", Some("$1")),
        m("memcached", r"Memcached (\d+\.\d+\.\d+)", "Memcached", Some("$1")),

        // Aerospike extra
        m("aerospike", r"Aerospike (\d+\.\d+\.\d+)", "Aerospike", Some("$1")),
        m("aerospike", r"ASDB (\d+\.\d+)", "Aerospike", Some("$1")),

        // Couchbase extra
        m("couchbase", r"Couchbase Server (\d+\.\d+)", "Couchbase", Some("$1")),
        m("http", r"X-Couchbase-.*:.*(\d+\.\d+)", "Couchbase", Some("$1")),

        // Neo4j extra
        m("neo4j", r"Neo4j/(\d+\.\d+\.\d+)", "Neo4j", Some("$1")),
        m("bolt", r"Neo4j/(\d+\.\d+)", "Neo4j", Some("$1")),
        m("http", r"X-Neo4j-Version:", "Neo4j", None),

        // ArangoDB extra
        m("arangodb", r"ArangoDB (\d+\.\d+\.\d+)", "ArangoDB", Some("$1")),
        m("http", r"X-ArangoDB-Version:", "ArangoDB", None),

        // RethinkDB extra
        m("rethinkdb", r"RethinkDB (\d+\.\d+\.\d+)", "RethinkDB", Some("$1")),

        // RavenDB extra
        m("ravendb", r"RavenDB/(\d+\.\d+)", "RavenDB", Some("$1")),
        m("http", r"RavenDB/(\d+\.\d+)", "RavenDB", Some("$1")),

        // OrientDB extra
        m("orientdb", r"OrientDB (\d+\.\d+\.\d+)", "OrientDB", Some("$1")),

        // Firebird extra
        m("firebird", r"Firebird/(\d+\.\d+\.\d+)", "Firebird", Some("$1")),
        m("firebird", r"Firebird SQL", "Firebird", None),

        // SQLite
        m("sqlite", r"SQLite (\d+\.\d+\.\d+)", "SQLite", Some("$1")),
        m("sqlite", r"SQLite3", "SQLite", None),

        // HBase
        m("hbase", r"Apache HBase", "Apache HBase", None),
        m("hbase", r"HBase (\d+\.\d+\.\d+)", "Apache HBase", Some("$1")),

        // Solr
        m("solr", r"Apache Solr", "Apache Solr", None),
        m("solr", r"Solr/(\d+\.\d+\.\d+)", "Apache Solr", Some("$1")),
        m("http", r"X-Solr", "Apache Solr", None),

        // Presto/Trino
        m("presto", r"Presto", "Presto", None),
        m("trino", r"Trino", "Trino", None),
        m("http", r"X-Presto", "Presto", None),
        m("http", r"X-Trino", "Trino", None),

        // DynamoDB
        m("dynamodb", r"DynamoDB", "Amazon DynamoDB", None),
        m("http", r"X-Amz-Target:.*DynamoDB", "Amazon DynamoDB", None),
    ]
}

/// Get additional network equipment signatures
pub fn network_equip_signatures() -> Vec<MatchPattern> {
    vec![
        // Cisco IOS versions extra
        m("telnet", r"Cisco IOS Software,.*Version (\d+\.\d+)", "Cisco IOS", Some("$1")),
        m("telnet", r"Cisco Internetwork Operating System Software", "Cisco IOS", None),
        m("ssh", r"SSH-2.0-Cisco-1\.25", "Cisco IOS SSH", None),
        m("http", r"cisco-IOS/(\d+\.\d+)", "Cisco IOS HTTP", Some("$1")),
        m("telnet", r"Cisco Catalyst", "Cisco Catalyst", None),
        m("telnet", r"Cisco Systems.*Switch", "Cisco Switch", None),
        m("telnet", r"Cisco.*Router", "Cisco Router", None),

        // Cisco Meraki extra
        m("http", r"Meraki Dashboard", "Cisco Meraki", None),
        m("http", r"Server: Meraki/(\d+)", "Cisco Meraki", Some("$1")),

        // Cisco WLC
        m("ssh", r"SSH-2.0-Cisco.*WLC", "Cisco WLC", None),
        m("http", r"Cisco Controller", "Cisco WLC", None),

        // Cisco ASA extra
        m("ssh", r"SSH-2.0-Cisco-.*Adaptive", "Cisco ASA", None),
        m("http", r"Cisco ASA", "Cisco ASA", None),
        m("telnet", r"Cisco Adaptive Security Appliance", "Cisco ASA", None),

        // Juniper Junos extra
        m("ssh", r"SSH-2.0-JUNOS (\d+\.\d+)", "Juniper Junos", Some("$1")),
        m("telnet", r"Juniper Networks.*JUNOS Software", "Juniper Junos", None),
        m("telnet", r"Juniper.*MX", "Juniper MX", None),
        m("telnet", r"Juniper.*SRX", "Juniper SRX", None),
        m("telnet", r"Juniper.*EX", "Juniper EX", None),
        m("telnet", r"Juniper.*QFX", "Juniper QFX", None),

        // Juniper Mist
        m("https", r"Mist Systems", "Juniper Mist", None),

        // Fortinet FortiOS extra
        m("ssh", r"SSH-2.0-FortiOS v(\d+\.\d+)", "Fortinet FortiOS", Some("$1")),
        m("https", r"FortiGate/(\d+\.\d+)", "Fortinet FortiGate", Some("$1")),
        m("http", r"Server: Fortinet/(\d+\.\d+)", "Fortinet", Some("$1")),
        m("https", r"FortiAnalyzer", "FortiAnalyzer", None),
        m("https", r"FortiManager", "FortiManager", None),
        m("https", r"FortiWeb", "FortiWeb", None),
        m("https", r"FortiMail", "FortiMail", None),
        m("https", r"FortiSwitch", "FortiSwitch", None),
        m("https", r"FortiAP", "FortiAP", None),

        // Palo Alto PAN-OS extra
        m("ssh", r"SSH-2.0-PAN-OS (\d+\.\d+)", "Palo Alto PAN-OS", Some("$1")),
        m("https", r"PAN-OS (\d+\.\d+)", "Palo Alto PAN-OS", Some("$1")),
        m("http", r"Server: PanWeb Server/", "Palo Alto PAN-OS", None),
        m("https", r"GlobalProtect", "Palo Alto GlobalProtect", None),
        m("https", r"Panorama", "Palo Alto Panorama", None),

        // Arista EOS extra
        m("ssh", r"SSH-2.0-Arista.*EOS v(\d+\.\d+)", "Arista EOS", Some("$1")),
        m("telnet", r"Arista Networks EOS", "Arista EOS", None),
        m("http", r"Arista EOS", "Arista EOS", None),

        // Dell Networking OS extra
        m("ssh", r"SSH-2.0-OpenSSH.*Dell EMC", "Dell EMC SSH", None),
        m("telnet", r"Dell Networking OS (\d+\.\d+)", "Dell Networking OS", Some("$1")),
        m("telnet", r"PowerConnect (\d+)", "Dell PowerConnect", Some("$1")),
        m("telnet", r"OS10 Enterprise", "Dell OS10", None),
        m("telnet", r"Dell Force10", "Dell Force10", None),

        // HPE ArubaOS extra
        m("ssh", r"SSH-2.0-ArubaOS (\d+\.\d+)", "ArubaOS", Some("$1")),
        m("telnet", r"ArubaOS (\d+\.\d+)", "ArubaOS", Some("$1")),
        m("ssh", r"SSH-2.0-HP ProCurve", "HP ProCurve", None),
        m("telnet", r"HP.*ProCurve Switch", "HP ProCurve", None),
        m("ssh", r"SSH-2.0-HPE OfficeConnect", "HPE OfficeConnect", None),
        m("telnet", r"HPE.*FlexNetwork", "HPE FlexNetwork", None),

        // Huawei VRP extra
        m("ssh", r"SSH-2.0-SSH_.*VRP (\d+\.\d+)", "Huawei VRP", Some("$1")),
        m("telnet", r"Huawei.*VRP.*Version (\d+\.\d+)", "Huawei VRP", Some("$1")),
        m("telnet", r"AR Series", "Huawei AR Router", None),
        m("telnet", r"S Series Switch", "Huawei S Series Switch", None),
        m("telnet", r"NE Series Router", "Huawei NE Router", None),
        m("http", r"Huawei.*Home Gateway", "Huawei Home Gateway", None),

        // MikroTik extra
        m("ssh", r"SSH-2.0-ROSSSH.*(\d+\.\d+)", "MikroTik RouterOS", Some("$1")),
        m("telnet", r"MikroTik.*RouterOS (\d+\.\d+)", "MikroTik RouterOS", Some("$1")),
        m("http", r"RouterOS (\d+\.\d+)", "MikroTik RouterOS", Some("$1")),
        m("http", r"MikroTik.*RouterOS", "MikroTik RouterOS", None),
        m("mikrotik", r"RouterOS", "MikroTik RouterOS", None),

        // Ubiquiti extra
        m("ssh", r"SSH-2.0-Ubiquiti Networks", "Ubiquiti SSH", None),
        m("ssh", r"SSH-2.0-EdgeMax", "Ubiquiti EdgeRouter SSH", None),
        m("http", r"UBNT.*airOS", "Ubiquiti airOS", None),
        m("http", r"airOS/(\d+\.\d+)", "Ubiquiti airOS", Some("$1")),
        m("http", r"UniFi Network", "Ubiquiti UniFi", None),
        m("http", r"EdgeRouter", "Ubiquiti EdgeRouter", None),
        m("http", r"EdgeSwitch", "Ubiquiti EdgeSwitch", None),

        // Check Point extra
        m("ssh", r"SSH-2.0-CP.*Gaia", "Check Point Gaia SSH", None),
        m("https", r"Check Point.*Gateway", "Check Point Gateway", None),
        m("http", r"Server: Check Point", "Check Point HTTP", None),
        m("https", r"Check Point Mobile Access", "Check Point VPN", None),

        // SonicWall extra
        m("ssh", r"SSH-2.0-SonicWall.*(\d+\.\d+)", "SonicWall", Some("$1")),
        m("http", r"Server: SonicWALL/(\d+)", "SonicWall", Some("$1")),
        m("https", r"SonicWall.*NSA", "SonicWall NSA", None),
        m("https", r"SonicWall.*TZ", "SonicWall TZ", None),

        // Barracuda extra
        m("ssh", r"SSH-2.0-Barracuda.*(\d+\.\d+)", "Barracuda", Some("$1")),
        m("http", r"Server: BarracudaHTTP/(\d+)", "Barracuda", Some("$1")),
        m("https", r"Barracuda.*Web Application Firewall", "Barracuda WAF", None),

        // Citrix NetScaler/ADC extra
        m("ssh", r"SSH-2.0-NS", "Citrix ADC SSH", None),
        m("http", r"Server: NetScaler/(\d+\.\d+)", "Citrix NetScaler", Some("$1")),
        m("http", r"ns_af=.*NSC_", "Citrix NetScaler", None),
        m("https", r"Citrix ADC", "Citrix ADC", None),

        // F5 BIG-IP extra
        m("ssh", r"SSH-2.0-OpenSSH.*f5.*BIG-IP", "F5 BIG-IP SSH", None),
        m("http", r"Server: BigIP/(\d+\.\d+)", "F5 BIG-IP", Some("$1")),
        m("http", r"BIGipServer.*!encoded", "F5 BIG-IP", None),
        m("http", r"X-Cnection: close", "F5 BIG-IP", None),
        m("https", r"F5 BIG-IP", "F5 BIG-IP", None),
        m("https", r"Big-IP", "F5 BIG-IP", None),

        // A10 Networks extra
        m("ssh", r"SSH-2.0-A10.*(\d+\.\d+)", "A10 Networks", Some("$1")),
        m("http", r"A10.*Thunder", "A10 Thunder", None),
        m("https", r"ACOS", "A10 ACOS", None),

        // Brocade extra
        m("ssh", r"SSH-2.0-Brocade.*(\d+\.\d+)", "Brocade", Some("$1")),
        m("telnet", r"Brocade.*FabricOS", "Brocade FabricOS", None),
        m("telnet", r"FabricOS.*v(\d+\.\d+)", "Brocade FabricOS", Some("$1")),

        // Extreme Networks extra
        m("ssh", r"SSH-2.0-ExtremeXOS.*(\d+\.\d+)", "Extreme Networks", Some("$1")),
        m("telnet", r"ExtremeXOS.*(\d+\.\d+)", "Extreme Networks", Some("$1")),
        m("telnet", r"Extreme.*SLX", "Extreme SLX", None),

        // Ruckus extra
        m("ssh", r"SSH-2.0-Ruckus.*(\d+\.\d+)", "Ruckus", Some("$1")),
        m("http", r"Ruckus Wireless", "Ruckus Wireless", None),
        m("http", r"Ruckus.*ZoneFlex", "Ruckus ZoneFlex", None),
        m("http", r"Ruckus.*Unleashed", "Ruckus Unleashed", None),

        // Zyxel extra
        m("ssh", r"SSH-2.0-Zyxel.*(\d+\.\d+)", "Zyxel", Some("$1")),
        m("telnet", r"ZyXEL.*(\d+\.\d+)", "Zyxel", Some("$1")),
        m("http", r"ZyXEL.*Router", "Zyxel Router", None),
        m("http", r"ZyWALL", "Zyxel ZyWALL", None),

        // DrayTek extra
        m("ssh", r"SSH-2.0-DrayTek.*(\d+\.\d+)", "DrayTek", Some("$1")),
        m("telnet", r"DrayTek.*Vigor (\d+)", "DrayTek Vigor", Some("$1")),
        m("http", r"DrayTek.*Vigor (\d+)", "DrayTek Vigor", Some("$1")),

        // TP-Link extra
        m("ssh", r"SSH-2.0-TP-LINK.*(\d+)", "TP-Link", Some("$1")),
        m("telnet", r"TP-LINK", "TP-Link", None),
        m("http", r"TP-LINK.*Router", "TP-Link Router", None),
        m("http", r"Server: TP-LINK", "TP-Link", None),

        // Netgear extra
        m("ssh", r"SSH-2.0-Netgear.*(\d+)", "Netgear", Some("$1")),
        m("http", r"NETGEAR.*(\w+)", "Netgear", None),
        m("http", r"Server: NETGEAR", "Netgear", None),

        // Linksys extra
        m("ssh", r"SSH-2.0-Linksys.*(\d+)", "Linksys", Some("$1")),
        m("http", r"Linksys.*Smart Wi-Fi", "Linksys Smart Wi-Fi", None),
        m("http", r"Server: Linksys", "Linksys", None),
    ]
}

/// Get additional IoT device signatures
pub fn iot_devices_signatures() -> Vec<MatchPattern> {
    vec![
        // Hikvision extra
        m("http", r"Hikvision.*DS-\w+", "Hikvision Camera", None),
        m("http", r"Server: App-webs/", "Hikvision", None),
        m("rtsp", r"Hikvision.*(\d+\.\d+)", "Hikvision", Some("$1")),
        m("http", r"Hikvision.*NVR", "Hikvision NVR", None),
        m("http", r"Hikvision.*DVR", "Hikvision DVR", None),

        // Dahua extra
        m("http", r"Dahua.*IPC", "Dahua IPC Camera", None),
        m("http", r"Dahua.*NVR", "Dahua NVR", None),
        m("http", r"Dahua.*DVR", "Dahua DVR", None),
        m("rtsp", r"Dahua.*(\d+\.\d+)", "Dahua", Some("$1")),
        m("http", r"Server: DNVRS-Webs/(\d+)", "Dahua", Some("$1")),

        // Axis extra
        m("http", r"AXIS.*P\d+", "Axis Camera", None),
        m("http", r"AXIS.*M\d+", "Axis Camera", None),
        m("http", r"AXIS.*Q\d+", "Axis Camera", None),
        m("http", r"Server: AXIS/(\d+\.\d+)", "Axis Camera", Some("$1")),
        m("rtsp", r"AXIS.*(\d+\.\d+)", "Axis Camera", Some("$1")),

        // Bosch extra
        m("http", r"Bosch.*DINION", "Bosch Dinion Camera", None),
        m("http", r"Bosch.*FLEXIDOME", "Bosch Flexidome Camera", None),
        m("http", r"Bosch.*MIC", "Bosch MIC Camera", None),
        m("rtsp", r"Bosch.*(\d+\.\d+)", "Bosch Camera", Some("$1")),

        // Hanwha/Samsung extra
        m("http", r"Hanwha.*WiseNet", "Hanwha WiseNet Camera", None),
        m("http", r"Samsung.*WiseNet", "Hanwha WiseNet Camera", None),
        m("http", r"Server: Hanwha/(\d+)", "Hanwha Camera", Some("$1")),

        // FLIR extra
        m("http", r"FLIR.*FC-\w+", "FLIR Camera", None),
        m("http", r"FLIR.*PTZ", "FLIR PTZ Camera", None),

        // Pelco extra
        m("http", r"Pelco.*Sarix", "Pelco Sarix Camera", None),
        m("http", r"Pelco.*Spectra", "Pelco Spectra Camera", None),

        // Panasonic extra
        m("http", r"Panasonic.*WV-\w+", "Panasonic Camera", None),
        m("rtsp", r"Panasonic", "Panasonic Camera", None),

        // Geovision extra
        m("http", r"GeoVision.*GV-\w+", "GeoVision Camera", None),
        m("http", r"Server: GeoHttpServer/(\d+)", "GeoVision", Some("$1")),

        // Sony extra
        m("http", r"Sony.*SNC-\w+", "Sony SNC Camera", None),
        m("http", r"Server: Sony Network Camera", "Sony Camera", None),

        // Mobotix extra
        m("http", r"MOBOTIX.*M\d+", "MOBOTIX Camera", None),
        m("http", r"Server: MOBOTIX/(\d+)", "MOBOTIX Camera", Some("$1")),

        // Vivotek extra
        m("http", r"Vivotek.*FD\d+", "Vivotek Camera", None),
        m("http", r"Vivotek.*MD\d+", "Vivotek Camera", None),
        m("http", r"Server: Vivotek/(\d+)", "Vivotek Camera", Some("$1")),

        // Uniview extra
        m("http", r"Uniview.*IPC", "Uniview IPC Camera", None),
        m("http", r"Uniview.*NVR", "Uniview NVR", None),

        // Amcrest extra
        m("http", r"Amcrest.*IP\d+", "Amcrest Camera", None),

        // Foscam extra
        m("http", r"FOSCAM.*FI\d+", "Foscam Camera", None),
        m("http", r"Foscam.*FI\d+", "Foscam Camera", None),

        // Reolink extra
        m("http", r"Reolink.*RLC-\w+", "Reolink Camera", None),
        m("http", r"Reolink.*(\d+MP)", "Reolink Camera", None),

        // Siemens SIMATIC extra
        m("http", r"SIMATIC.*S7-\d+", "Siemens SIMATIC S7", None),
        m("http", r"SIMATIC.*WinCC", "Siemens WinCC", None),
        m("http", r"SIMATIC HMI", "Siemens HMI", None),
        m("http", r"Siemens.*LOGO!", "Siemens LOGO!", None),
        m("http", r"Siemens.*Scalance", "Siemens Scalance", None),
        m("siemens", r"SIMATIC S7", "Siemens SIMATIC S7", None),
        m("siemens", r"SIMATIC WinCC", "Siemens WinCC", None),
        m("http", r"Server: Siemens", "Siemens Device", None),

        // Allen-Bradley / Rockwell extra
        m("http", r"Allen-Bradley.*MicroLogix", "Allen-Bradley MicroLogix", None),
        m("http", r"Allen-Bradley.*CompactLogix", "Allen-Bradley CompactLogix", None),
        m("http", r"Allen-Bradley.*ControlLogix", "Allen-Bradley ControlLogix", None),
        m("http", r"Rockwell.*CompactLogix", "Rockwell CompactLogix", None),
        m("http", r"Rockwell.*ControlLogix", "Rockwell ControlLogix", None),
        m("ethernetip", r"Rockwell Automation", "Rockwell Automation", None),

        // Schneider Electric extra
        m("http", r"Schneider.*Modicon M\d+", "Schneider Modicon M", None),
        m("http", r"Schneider.*Modicon TM\d+", "Schneider Modicon TM", None),
        m("http", r"Schneider.*PowerLogic", "Schneider PowerLogic", None),
        m("http", r"Schneider.*EcoStruxure", "Schneider EcoStruxure", None),
        m("modbus", r"Schneider Electric", "Schneider Electric", None),

        // ABB extra
        m("http", r"ABB.*AC500", "ABB AC500 PLC", None),
        m("http", r"ABB.*Drive", "ABB Drive", None),

        // Honeywell extra
        m("http", r"Honeywell.*HC\d+", "Honeywell Controller", None),
        m("http", r"Honeywell.*WEBs", "Honeywell WEBs", None),

        // Phoenix Contact
        m("http", r"Phoenix Contact", "Phoenix Contact Device", None),
        m("http", r"PCWORX", "Phoenix Contact PCWORX", None),
        m("http", r"Server: ILC", "Phoenix Contact ILC", None),

        // Beckhoff
        m("http", r"Beckhoff.*TwinCAT", "Beckhoff TwinCAT", None),
        m("http", r"Server: Beckhoff", "Beckhoff Device", None),

        // WAGO
        m("http", r"WAGO.*PFC\d+", "WAGO PFC Controller", None),
        m("http", r"Server: WAGO", "WAGO Device", None),

        // Omron
        m("http", r"Omron.*NJ\d+", "Omron NJ Controller", None),
        m("http", r"Omron.*NX\d+", "Omron NX Controller", None),
        m("http", r"Server: Omron", "Omron Device", None),

        // Emerson/GE
        m("http", r"Emerson.*PACSystems", "Emerson PACSystems", None),
        m("http", r"GE.*PACSystems", "GE PACSystems", None),

        // Yokogawa
        m("http", r"Yokogawa.*STARDOM", "Yokogawa STARDOM", None),
        m("http", r"Server: Yokogawa", "Yokogawa Device", None),

        // Mitsubishi
        m("http", r"Mitsubishi.*MELSEC", "Mitsubishi MELSEC", None),
        m("http", r"Server: Mitsubishi", "Mitsubishi Device", None),

        // Smart home extra
        m("http", r"Server: HomeAssistant", "Home Assistant", None),
        m("http", r"X-Home-Assistant", "Home Assistant", None),
        m("http", r"Home Assistant/(\d+\.\d+)", "Home Assistant", Some("$1")),
        m("http", r"OpenHAB/(\d+\.\d+)", "OpenHAB", Some("$1")),
        m("http", r"Server: openHAB", "OpenHAB", None),
        m("http", r"Domoticz", "Domoticz", None),
        m("http", r"Server: Domoticz", "Domoticz", None),

        // Router firmware extra
        m("http", r"Server: httpd/.*ASUS.*(\d+\.\d+)", "ASUS Router", Some("$1")),
        m("http", r"RT-\w+", "ASUS Router", None),
        m("http", r"ASUS.*RT-\w+", "ASUS Router", None),

        // DD-WRT extra
        m("http", r"DD-WRT v\d+", "DD-WRT", None),
        m("http", r"Server: httpd.*DD-WRT.*(\d+)", "DD-WRT", Some("$1")),

        // OpenWrt extra
        m("http", r"Server: uhttpd.*OpenWrt", "OpenWrt", None),
        m("http", r"OpenWrt.*(\d+\.\d+)", "OpenWrt", Some("$1")),

        // Tomato extra
        m("http", r"Tomato.*(\d+\.\d+)", "Tomato firmware", Some("$1")),
        m("http", r"Server: httpd.*Tomato.*(\d+)", "Tomato firmware", Some("$1")),

        // Ubiquiti UniFi extra
        m("http", r"UniFi.*AP", "Ubiquiti UniFi AP", None),
        m("http", r"UniFi.*Switch", "Ubiquiti UniFi Switch", None),
        m("http", r"UniFi.*Gateway", "Ubiquiti UniFi Gateway", None),
        m("unifi", r"UniFi Network", "Ubiquiti UniFi Network", None),

        // NVR/DVR extra
        m("http", r"Server: XMGOO", "XMGOO DVR", None),
        m("http", r"Server: JAWS", "JAWS Camera", None),
        m("http", r"Server: NetSurveillance", "NetSurveillance DVR", None),
        m("http", r"Server: Cross Web Server", "Cross Web DVR", None),

        // VoIP phones
        m("http", r"Polycom.*VVX", "Polycom VVX Phone", None),
        m("http", r"Polycom.*SoundStation", "Polycom Conference Phone", None),
        m("http", r"Yealink.*T\d+", "Yealink Phone", None),
        m("http", r"Yealink.*W\d+", "Yealink Phone", None),
        m("http", r"Cisco.*SPA\d+", "Cisco SPA Phone", None),
        m("http", r"Cisco.*IP Phone", "Cisco IP Phone", None),
        m("http", r"Grandstream.*GXP", "Grandstream Phone", None),
        m("http", r"Grandstream.*GXV", "Grandstream Video Phone", None),
        m("http", r"Snom.*\d+", "Snom Phone", None),
        m("http", r"Fanvil.*\d+", "Fanvil Phone", None),

        // NAS devices
        m("http", r"Synology.*DiskStation", "Synology DiskStation", None),
        m("http", r"Server: Synology", "Synology NAS", None),
        m("http", r"QNAP.*Turbo NAS", "QNAP Turbo NAS", None),
        m("http", r"Server: QNAP", "QNAP NAS", None),
        m("http", r"WD.*My Cloud", "WD My Cloud", None),
        m("http", r"ReadyNAS", "Netgear ReadyNAS", None),
        m("http", r"TerraMaster.*F\d+", "TerraMaster NAS", None),
        m("http", r"Asustor.*ADM", "Asustor NAS", None),

        // UPS devices
        m("http", r"APC.*UPS", "APC UPS", None),
        m("http", r"Server: APC", "APC Device", None),
        m("http", r"Eaton.*UPS", "Eaton UPS", None),
        m("http", r"CyberPower.*UPS", "CyberPower UPS", None),
        m("http", r"Server: CyberPower", "CyberPower Device", None),
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
    sigs.extend(web_frameworks_extra_signatures());
    sigs.extend(database_variants_signatures());
    sigs.extend(network_equip_signatures());
    sigs.extend(iot_devices_signatures());
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
        assert!(sigs.len() >= 1500, "Expected at least 1500 total signatures, got {}", sigs.len());
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
