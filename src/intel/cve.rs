use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// CVE vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    pub cve_id: String,
    pub description: String,
    pub severity: CveSeverity,
    pub cvss_score: f32,
    pub published_date: String,
    pub references: Vec<String>,
}

/// CVE severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CveSeverity {
    Critical,
    High,
    Medium,
    Low,
    None,
}

impl CveSeverity {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s >= 9.0 => CveSeverity::Critical,
            s if s >= 7.0 => CveSeverity::High,
            s if s >= 4.0 => CveSeverity::Medium,
            s if s >= 0.1 => CveSeverity::Low,
            _ => CveSeverity::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CveSeverity::Critical => "CRITICAL",
            CveSeverity::High => "HIGH",
            CveSeverity::Medium => "MEDIUM",
            CveSeverity::Low => "LOW",
            CveSeverity::None => "NONE",
        }
    }
}

/// CVE database for vulnerability lookups
pub struct CveDatabase {
    cache: HashMap<String, Vec<CveInfo>>,
    use_cache: bool,
}

impl CveDatabase {
    pub fn new(use_cache: bool) -> Self {
        Self {
            cache: HashMap::new(),
            use_cache,
        }
    }

    /// Lookup vulnerabilities for a specific service and version
    pub async fn lookup_vulnerabilities(
        &mut self,
        service: &str,
        version: &str,
    ) -> Result<Vec<CveInfo>> {
        let cache_key = format!("{}:{}", service, version);

        // Check cache first
        if self.use_cache {
            if let Some(cached) = self.cache.get(&cache_key) {
                return Ok(cached.clone());
            }
        }

        // In a real implementation, this would query NVD API or local database
        // For now, we'll use a simplified pattern matching system
        let vulnerabilities = self.search_known_vulnerabilities(service, version);

        // Cache the results
        if self.use_cache {
            self.cache.insert(cache_key, vulnerabilities.clone());
        }

        Ok(vulnerabilities)
    }

    /// Search known vulnerabilities using pattern matching
    /// In production, this would query the NVD API: https://nvd.nist.gov/developers/vulnerabilities
    fn search_known_vulnerabilities(&self, service: &str, version: &str) -> Vec<CveInfo> {
        let mut results = Vec::new();

        // Apache HTTP Server vulnerabilities
        if service.to_lowercase().contains("apache") {
            if let Some(ver) = self.parse_version(version) {
                if ver.major == 2 && ver.minor <= 4 && ver.patch < 50 {
                    results.push(CveInfo {
                        cve_id: "CVE-2021-44790".to_string(),
                        description: "Apache HTTP Server 2.4.x < 2.4.51 buffer overflow in mod_lua"
                            .to_string(),
                        severity: CveSeverity::Critical,
                        cvss_score: 9.8,
                        published_date: "2021-12-20".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-44790".to_string()
                        ],
                    });
                }
            }
        }

        // OpenSSH vulnerabilities
        if service.to_lowercase().contains("openssh") || service.to_lowercase().contains("ssh") {
            if let Some(ver) = self.parse_version(version) {
                if ver.major <= 8 && ver.minor < 8 {
                    results.push(CveInfo {
                        cve_id: "CVE-2021-41617".to_string(),
                        description: "OpenSSH < 8.8 privilege escalation via supplemental groups"
                            .to_string(),
                        severity: CveSeverity::High,
                        cvss_score: 7.0,
                        published_date: "2021-09-26".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-41617".to_string()
                        ],
                    });
                }
            }
        }

        // OpenSSL vulnerabilities
        if (service.to_lowercase().contains("openssl") || service.to_lowercase().contains("ssl"))
            && version.contains("1.1.1")
        {
            results.push(CveInfo {
                cve_id: "CVE-2022-0778".to_string(),
                description: "OpenSSL 1.1.1 infinite loop vulnerability (denial of service)"
                    .to_string(),
                severity: CveSeverity::High,
                cvss_score: 7.5,
                published_date: "2022-03-15".to_string(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-0778".to_string()],
            });
        }

        // MySQL vulnerabilities
        if service.to_lowercase().contains("mysql") {
            if let Some(ver) = self.parse_version(version) {
                if ver.major == 5 || (ver.major == 8 && ver.minor == 0 && ver.patch < 28) {
                    results.push(CveInfo {
                        cve_id: "CVE-2021-2471".to_string(),
                        description: "MySQL Server vulnerability in replication component"
                            .to_string(),
                        severity: CveSeverity::Medium,
                        cvss_score: 4.9,
                        published_date: "2021-10-20".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-2471".to_string()
                        ],
                    });
                }
            }
        }

        // PostgreSQL vulnerabilities
        if service.to_lowercase().contains("postgresql")
            || service.to_lowercase().contains("postgres")
        {
            if let Some(ver) = self.parse_version(version) {
                if ver.major <= 13 {
                    results.push(CveInfo {
                        cve_id: "CVE-2021-32027".to_string(),
                        description:
                            "PostgreSQL buffer overflow in array subscripting calculations"
                                .to_string(),
                        severity: CveSeverity::High,
                        cvss_score: 8.8,
                        published_date: "2021-05-14".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-32027".to_string()
                        ],
                    });
                }
            }
        }

        // nginx vulnerabilities
        if service.to_lowercase().contains("nginx") {
            if let Some(ver) = self.parse_version(version) {
                if ver.major == 1 && ver.minor <= 20 {
                    results.push(CveInfo {
                        cve_id: "CVE-2021-23017".to_string(),
                        description: "nginx resolver off-by-one buffer overflow".to_string(),
                        severity: CveSeverity::High,
                        cvss_score: 8.1,
                        published_date: "2021-05-25".to_string(),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-23017".to_string()
                        ],
                    });
                }
            }
        }

        // Log4j vulnerabilities (Log4Shell)
        if (service.to_lowercase().contains("log4j") || service.to_lowercase().contains("java"))
            && version.contains("2.")
        {
            let ver = self.parse_version(version);
            if let Some(v) = ver {
                if v.major == 2 && v.minor < 17 {
                    results.push(CveInfo {
                            cve_id: "CVE-2021-44228".to_string(),
                            description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP (Log4Shell)".to_string(),
                            severity: CveSeverity::Critical,
                            cvss_score: 10.0,
                            published_date: "2021-12-10".to_string(),
                            references: vec![
                                "https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string(),
                                "https://logging.apache.org/log4j/2.x/security.html".to_string(),
                            ],
                        });
                }
                if v.major == 2 && v.minor < 16 {
                    results.push(CveInfo {
                            cve_id: "CVE-2021-45046".to_string(),
                            description: "Apache Log4j2 DoS via crafted data in ThreadContext (incomplete fix for Log4Shell)".to_string(),
                            severity: CveSeverity::Critical,
                            cvss_score: 9.0,
                            published_date: "2021-12-14".to_string(),
                            references: vec![
                                "https://nvd.nist.gov/vuln/detail/CVE-2021-45046".to_string(),
                            ],
                        });
                }
            }
        }

        // Microsoft Exchange Server vulnerabilities (ProxyShell)
        if service.to_lowercase().contains("exchange") || service.to_lowercase().contains("smtp") {
            results.push(CveInfo {
                cve_id: "CVE-2021-34473".to_string(),
                description: "Microsoft Exchange Server Remote Code Execution (ProxyShell)"
                    .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2021-08-12".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-34473".to_string(),
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473"
                        .to_string(),
                ],
            });
            results.push(CveInfo {
                cve_id: "CVE-2021-34523".to_string(),
                description: "Microsoft Exchange Server Elevation of Privilege (ProxyShell)"
                    .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2021-08-12".to_string(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-34523".to_string()],
            });
        }

        // Windows Print Spooler (PrintNightmare)
        if service.to_lowercase().contains("print") || service.to_lowercase().contains("spooler") {
            results.push(CveInfo {
                cve_id: "CVE-2021-34527".to_string(),
                description: "Windows Print Spooler Remote Code Execution (PrintNightmare)"
                    .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 8.8,
                published_date: "2021-07-02".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-34527".to_string(),
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527"
                        .to_string(),
                ],
            });
        }

        // Active Directory (Zerologon)
        if service.to_lowercase().contains("netlogon") || service.to_lowercase().contains("domain")
        {
            results.push(CveInfo {
                cve_id: "CVE-2020-1472".to_string(),
                description: "Netlogon Elevation of Privilege Vulnerability (Zerologon)"
                    .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 10.0,
                published_date: "2020-08-17".to_string(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-1472".to_string()],
            });
        }

        // VMware vCenter (CVE-2021-21985)
        if service.to_lowercase().contains("vmware") || service.to_lowercase().contains("vcenter") {
            results.push(CveInfo {
                cve_id: "CVE-2021-21985".to_string(),
                description:
                    "VMware vCenter Server RCE via vSphere Client (Virtual SAN Health Check)"
                        .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2021-05-25".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-21985".to_string(),
                    "https://www.vmware.com/security/advisories/VMSA-2021-0010.html".to_string(),
                ],
            });
        }

        // Atlassian Confluence (CVE-2021-26084)
        if service.to_lowercase().contains("confluence") {
            results.push(CveInfo {
                cve_id: "CVE-2021-26084".to_string(),
                description: "Atlassian Confluence Server OGNL injection RCE".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2021-08-30".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-26084".to_string(),
                    "https://confluence.atlassian.com/doc/confluence-security-advisory-2021-08-25-1077906215.html".to_string(),
                ],
            });
        }

        // Spring Framework (Spring4Shell)
        if service.to_lowercase().contains("spring") || service.to_lowercase().contains("tomcat") {
            results.push(CveInfo {
                cve_id: "CVE-2022-22965".to_string(),
                description: "Spring Framework RCE via Data Binding on JDK 9+ (Spring4Shell)"
                    .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2022-04-01".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-22965".to_string(),
                    "https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement"
                        .to_string(),
                ],
            });
        }

        // Apache Struts2 (CVE-2021-31805)
        if service.to_lowercase().contains("struts") {
            results.push(CveInfo {
                cve_id: "CVE-2021-31805".to_string(),
                description: "Apache Struts2 forced OGNL evaluation when evaluated raw attribute"
                    .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2021-04-13".to_string(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-31805".to_string()],
            });
        }

        // GitLab RCE (CVE-2021-22205)
        if service.to_lowercase().contains("gitlab") {
            results.push(CveInfo {
                cve_id: "CVE-2021-22205".to_string(),
                description: "GitLab CE/EE unauthenticated RCE via ExifTool".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 10.0,
                published_date: "2021-04-01".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-22205".to_string(),
                    "https://about.gitlab.com/releases/2021/04/14/security-release-gitlab-13-10-3-released/".to_string(),
                ],
            });
        }

        // Fortinet FortiOS (CVE-2022-40684)
        if service.to_lowercase().contains("fortinet") || service.to_lowercase().contains("fortios")
        {
            results.push(CveInfo {
                cve_id: "CVE-2022-40684".to_string(),
                description: "Fortinet FortiOS & FortiProxy authentication bypass vulnerability"
                    .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.6,
                published_date: "2022-10-18".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-40684".to_string(),
                    "https://www.fortiguard.com/psirt/FG-IR-22-377".to_string(),
                ],
            });
        }

        // Citrix ADC/Gateway (CVE-2023-3519)
        if service.to_lowercase().contains("citrix") || service.to_lowercase().contains("netscaler")
        {
            results.push(CveInfo {
                cve_id: "CVE-2023-3519".to_string(),
                description: "Citrix ADC & Gateway unauthenticated remote code execution"
                    .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2023-07-18".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-3519".to_string(),
                    "https://support.citrix.com/article/CTX561482".to_string(),
                ],
            });
        }

        // MOVEit Transfer SQL Injection (CVE-2023-34362)
        if service.to_lowercase().contains("moveit") {
            results.push(CveInfo {
                cve_id: "CVE-2023-34362".to_string(),
                description: "Progress MOVEit Transfer SQL injection vulnerability".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2023-06-02".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-34362".to_string(),
                    "https://www.progress.com/moveit-transfer".to_string(),
                ],
            });
        }

        // Atlassian Jira (CVE-2022-0540)
        if service.to_lowercase().contains("jira") {
            results.push(CveInfo {
                cve_id: "CVE-2022-0540".to_string(),
                description: "Atlassian Jira Seraph authentication bypass".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.9,
                published_date: "2022-04-20".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-0540".to_string(),
                    "https://jira.atlassian.com/browse/JRASERVER-73465".to_string(),
                ],
            });
        }

        // Apache HTTP Server (CVE-2023-25690)
        if service.to_lowercase().contains("apache") && service.to_lowercase().contains("http") {
            results.push(CveInfo {
                cve_id: "CVE-2023-25690".to_string(),
                description: "Apache HTTP Server mod_proxy HTTP Response Splitting".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2023-03-07".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-25690".to_string(),
                    "https://httpd.apache.org/security/vulnerabilities_24.html".to_string(),
                ],
            });
        }

        // Cisco IOS XE (CVE-2023-20198)
        if service.to_lowercase().contains("cisco") || service.to_lowercase().contains("ios") {
            results.push(CveInfo {
                cve_id: "CVE-2023-20198".to_string(),
                description: "Cisco IOS XE Web UI Privilege Escalation Vulnerability".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 10.0,
                published_date: "2023-10-16".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-20198".to_string(),
                    "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z".to_string(),
                ],
            });
        }

        // Windows SMB MS08-067
        if service.to_lowercase().contains("smb") || service.to_lowercase().contains("microsoft-ds")
        {
            results.push(CveInfo {
                cve_id: "CVE-2008-4250".to_string(),
                description: "Microsoft Windows Server Service RPC Request Handling RCE (MS08-067)"
                    .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 10.0,
                published_date: "2008-10-23".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2008-4250".to_string(),
                    "https://technet.microsoft.com/en-us/library/security/ms08-067.aspx"
                        .to_string(),
                ],
            });
        }

        // Apache Struts2 (CVE-2017-5638)
        if service.to_lowercase().contains("struts") || service.to_lowercase().contains("tomcat") {
            results.push(CveInfo {
                cve_id: "CVE-2017-5638".to_string(),
                description: "Apache Struts2 Jakarta Multipart Parser RCE (Equifax breach)"
                    .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 10.0,
                published_date: "2017-03-06".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2017-5638".to_string(),
                    "https://struts.apache.org/docs/s2-045.html".to_string(),
                ],
            });
        }

        // OpenSSL Heartbleed (CVE-2014-0160)
        if service.to_lowercase().contains("ssl") || service.to_lowercase().contains("tls") {
            results.push(CveInfo {
                cve_id: "CVE-2014-0160".to_string(),
                description: "OpenSSL TLS Heartbeat Extension Information Disclosure (Heartbleed)"
                    .to_string(),
                severity: CveSeverity::High,
                cvss_score: 7.5,
                published_date: "2014-04-07".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2014-0160".to_string(),
                    "http://heartbleed.com/".to_string(),
                ],
            });
        }

        // SSLv3 POODLE (CVE-2014-3566)
        if service.to_lowercase().contains("ssl") || service.to_lowercase().contains("https") {
            results.push(CveInfo {
                cve_id: "CVE-2014-3566".to_string(),
                description: "SSL Protocol 3.0 Padding Oracle Attack (POODLE)".to_string(),
                severity: CveSeverity::Medium,
                cvss_score: 4.3,
                published_date: "2014-10-14".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2014-3566".to_string(),
                    "https://www.openssl.org/~bodo/ssl-poodle.pdf".to_string(),
                ],
            });
        }

        // Bash Shellshock (CVE-2014-6271)
        if service.to_lowercase().contains("cgi") || service.to_lowercase().contains("bash") {
            results.push(CveInfo {
                cve_id: "CVE-2014-6271".to_string(),
                description:
                    "GNU Bash Remote Code Execution via Environment Variables (Shellshock)"
                        .to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 10.0,
                published_date: "2014-09-24".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2014-6271".to_string(),
                    "http://seclists.org/oss-sec/2014/q3/650".to_string(),
                ],
            });
        }

        // vsFTPd Backdoor (CVE-2011-2523)
        if service.to_lowercase().contains("ftp") || service.to_lowercase().contains("vsftpd") {
            results.push(CveInfo {
                cve_id: "CVE-2011-2523".to_string(),
                description: "vsFTPd 2.3.4 Backdoor Command Execution".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 10.0,
                published_date: "2011-07-04".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2011-2523".to_string(),
                    "http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html".to_string(),
                ],
            });
        }

        // ProFTPD Backdoor (CVE-2010-4221)
        if service.to_lowercase().contains("ftp") || service.to_lowercase().contains("proftpd") {
            results.push(CveInfo {
                cve_id: "CVE-2010-4221".to_string(),
                description: "ProFTPD 1.3.3c Backdoor Remote Code Execution".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 10.0,
                published_date: "2010-12-06".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2010-4221".to_string(),
                    "http://www.securityfocus.com/bid/45150".to_string(),
                ],
            });
        }

        // Slowloris DoS (CVE-2007-6750)
        if service.to_lowercase().contains("http") || service.to_lowercase().contains("apache") {
            results.push(CveInfo {
                cve_id: "CVE-2007-6750".to_string(),
                description: "Apache HTTP Server Slowloris Denial of Service".to_string(),
                severity: CveSeverity::High,
                cvss_score: 7.8,
                published_date: "2009-09-28".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2007-6750".to_string(),
                    "https://web.archive.org/web/20150315054838/http://ha.ckers.org/slowloris/"
                        .to_string(),
                ],
            });
        }

        // Java RMI Remote Classloading (CVE-2017-3241)
        if service.to_lowercase().contains("rmi") || service.to_lowercase().contains("java") {
            results.push(CveInfo {
                cve_id: "CVE-2017-3241".to_string(),
                description: "Java RMI Remote Classloading Vulnerability".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.0,
                published_date: "2017-01-27".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2017-3241".to_string(),
                    "https://mogwailabs.de/blog/2019/03/attacking-rmi-based-jmx-services/"
                        .to_string(),
                ],
            });
        }

        // Drupal SQL Injection (CVE-2014-3704)
        if service.to_lowercase().contains("http") || service.to_lowercase().contains("drupal") {
            results.push(CveInfo {
                cve_id: "CVE-2014-3704".to_string(),
                description: "Drupal 7.x SQL Injection (Drupalgeddon)".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 7.5,
                published_date: "2014-10-15".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2014-3704".to_string(),
                    "https://www.drupal.org/SA-CORE-2014-005".to_string(),
                ],
            });
        }

        // Tomcat AJP File Read/Inclusion (Ghostcat)
        if service.to_lowercase().contains("tomcat") || service.to_lowercase().contains("ajp") {
            results.push(CveInfo {
                cve_id: "CVE-2020-1938".to_string(),
                description: "Apache Tomcat AJP File Read/Inclusion (Ghostcat)".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2020-02-24".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2020-1938".to_string(),
                    "https://www.chaitin.cn/en/ghostcat".to_string(),
                ],
            });
        }

        // Jenkins RCE
        if service.to_lowercase().contains("jenkins") {
            results.push(CveInfo {
                cve_id: "CVE-2024-23897".to_string(),
                description: "Jenkins CLI Arbitrary File Read Vulnerability".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2024-01-24".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2024-23897".to_string(),
                    "https://www.jenkins.io/security/advisory/2024-01-24/".to_string(),
                ],
            });
        }

        // Microsoft Exchange ProxyLogon
        if service.to_lowercase().contains("exchange") || service.to_lowercase().contains("outlook")
        {
            results.push(CveInfo {
                cve_id: "CVE-2021-26855".to_string(),
                description: "Microsoft Exchange Server SSRF (ProxyLogon)".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2021-03-02".to_string(),
                references: vec![
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-26855".to_string(),
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855"
                        .to_string(),
                ],
            });
        }

        // WordPress vulnerabilities
        if service.to_lowercase().contains("wordpress") || service.to_lowercase().contains("wp") {
            results.push(CveInfo {
                cve_id: "CVE-2024-27956".to_string(),
                description: "WordPress Backup Migration Plugin Unauthenticated RCE".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2024-03-01".to_string(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-27956".to_string()],
            });
        }

        // SolarWinds Orion
        if service.to_lowercase().contains("solarwinds") || service.to_lowercase().contains("orion")
        {
            results.push(CveInfo {
                cve_id: "CVE-2020-10148".to_string(),
                description: "SolarWinds Orion API Authentication Bypass".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2020-12-14".to_string(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-10148".to_string()],
            });
        }

        // Confluence RCE (2023)
        if service.to_lowercase().contains("confluence") {
            results.push(CveInfo {
                cve_id: "CVE-2023-22515".to_string(),
                description: "Atlassian Confluence Privilege Escalation".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 10.0,
                published_date: "2023-10-04".to_string(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-22515".to_string()],
            });
        }

        // Apache Struts (newer)
        if service.to_lowercase().contains("struts") {
            results.push(CveInfo {
                cve_id: "CVE-2023-50164".to_string(),
                description: "Apache Struts File Upload Path Traversal".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.8,
                published_date: "2023-12-07".to_string(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-50164".to_string()],
            });
        }

        // Ivanti Connect Secure
        if service.to_lowercase().contains("ivanti")
            || service.to_lowercase().contains("pulse secure")
        {
            results.push(CveInfo {
                cve_id: "CVE-2024-21887".to_string(),
                description: "Ivanti Connect Secure Command Injection".to_string(),
                severity: CveSeverity::Critical,
                cvss_score: 9.1,
                published_date: "2024-01-31".to_string(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-21887".to_string()],
            });
        }

        results
    }

    /// Parse version string into major.minor.patch
    fn parse_version(&self, version: &str) -> Option<Version> {
        let parts: Vec<&str> = version
            .trim()
            .split(|c: char| c == '.' || c == '-' || c.is_whitespace())
            .collect();

        if parts.is_empty() {
            return None;
        }

        let major = parts.first()?.parse().ok()?;
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

        Some(Version {
            major,
            minor,
            patch,
        })
    }

    /// Clear the cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let entries = self.cache.len();
        let total_vulns = self.cache.values().map(|v| v.len()).sum();
        (entries, total_vulns)
    }
}

#[derive(Debug)]
struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_apache_vulnerability_detection() {
        let mut db = CveDatabase::new(true);
        let vulns = db
            .lookup_vulnerabilities("Apache httpd", "2.4.49")
            .await
            .unwrap();
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.severity == CveSeverity::Critical));
    }

    #[tokio::test]
    async fn test_openssh_vulnerability_detection() {
        let mut db = CveDatabase::new(true);
        let vulns = db.lookup_vulnerabilities("OpenSSH", "8.0").await.unwrap();
        assert!(!vulns.is_empty());
        assert!(vulns.iter().any(|v| v.cve_id.contains("CVE")));
    }

    #[tokio::test]
    async fn test_version_parsing() {
        let db = CveDatabase::new(false);
        assert!(db.parse_version("2.4.49").is_some());
        assert!(db.parse_version("8.0p1").is_some());
        assert!(db.parse_version("1.1.1k").is_some());
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let mut db = CveDatabase::new(true);

        // First lookup
        let _ = db.lookup_vulnerabilities("Apache", "2.4.49").await.unwrap();
        let (entries, _) = db.cache_stats();
        assert_eq!(entries, 1);

        // Second lookup should use cache
        let _ = db.lookup_vulnerabilities("Apache", "2.4.49").await.unwrap();
        let (entries, _) = db.cache_stats();
        assert_eq!(entries, 1);

        // Clear cache
        db.clear_cache();
        let (entries, _) = db.cache_stats();
        assert_eq!(entries, 0);
    }

    #[test]
    fn test_severity_from_score() {
        assert_eq!(CveSeverity::from_score(9.5), CveSeverity::Critical);
        assert_eq!(CveSeverity::from_score(7.5), CveSeverity::High);
        assert_eq!(CveSeverity::from_score(5.0), CveSeverity::Medium);
        assert_eq!(CveSeverity::from_score(2.0), CveSeverity::Low);
        assert_eq!(CveSeverity::from_score(0.0), CveSeverity::None);
    }
}
