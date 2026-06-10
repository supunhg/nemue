use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default credential entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialEntry {
    /// Service or product name
    pub product: String,
    /// Username
    pub username: String,
    /// Password
    pub password: String,
    /// Additional notes
    pub notes: Option<String>,
}

/// Default credentials database
#[derive(Clone)]
pub struct DefaultCredentials {
    entries: HashMap<String, Vec<CredentialEntry>>,
}

impl DefaultCredentials {
    /// Create a new default credentials database
    pub fn new() -> Self {
        let mut db = Self {
            entries: HashMap::new(),
        };
        db.populate();
        db
    }

    /// Populate database with common default credentials
    fn populate(&mut self) {
        // Database Systems
        self.add_credentials(
            "mysql",
            vec![
                ("root", "", "Default MySQL installation"),
                ("root", "root", "Common default"),
                ("root", "password", "Weak default"),
                ("admin", "admin", "Administrative account"),
            ],
        );

        self.add_credentials(
            "postgresql",
            vec![
                ("postgres", "postgres", "Default PostgreSQL"),
                ("postgres", "password", "Common default"),
                ("admin", "admin", "Administrative account"),
            ],
        );

        self.add_credentials(
            "mongodb",
            vec![
                ("admin", "", "MongoDB no password"),
                ("admin", "admin", "Common default"),
                ("root", "root", "Administrative account"),
            ],
        );

        self.add_credentials("redis", vec![("", "", "Redis no authentication")]);

        self.add_credentials(
            "mssql",
            vec![
                ("sa", "", "SQL Server default"),
                ("sa", "password", "Common weak password"),
                ("sa", "Password1", "Common weak password"),
            ],
        );

        self.add_credentials(
            "oracle",
            vec![
                ("sys", "sys", "Oracle system account"),
                ("system", "manager", "Oracle system manager"),
                ("scott", "tiger", "Oracle demo account"),
            ],
        );

        // Web Servers & Application Servers
        self.add_credentials(
            "tomcat",
            vec![
                ("admin", "admin", "Tomcat manager"),
                ("tomcat", "tomcat", "Tomcat default"),
                ("admin", "password", "Common default"),
                ("admin", "", "No password"),
            ],
        );

        self.add_credentials("jboss", vec![("admin", "admin", "JBoss default")]);

        self.add_credentials(
            "weblogic",
            vec![
                ("system", "password", "WebLogic default"),
                ("weblogic", "weblogic", "WebLogic default"),
            ],
        );

        // Message Queues
        self.add_credentials(
            "rabbitmq",
            vec![
                ("guest", "guest", "RabbitMQ default"),
                ("admin", "admin", "Common default"),
            ],
        );

        self.add_credentials("activemq", vec![("admin", "admin", "ActiveMQ default")]);

        // Network Devices
        self.add_credentials(
            "cisco",
            vec![
                ("admin", "admin", "Cisco default"),
                ("cisco", "cisco", "Cisco default"),
                ("admin", "", "No password"),
            ],
        );

        self.add_credentials(
            "juniper",
            vec![
                ("netscreen", "netscreen", "Juniper default"),
                ("admin", "admin", "Juniper default"),
            ],
        );

        // SSH/Telnet
        self.add_credentials(
            "ssh",
            vec![
                ("root", "root", "Common default"),
                ("admin", "admin", "Administrative account"),
                ("user", "user", "User account"),
                ("test", "test", "Test account"),
            ],
        );

        self.add_credentials(
            "telnet",
            vec![
                ("admin", "admin", "Administrative account"),
                ("root", "root", "Root account"),
            ],
        );

        // FTP
        self.add_credentials(
            "ftp",
            vec![
                ("anonymous", "", "Anonymous FTP"),
                ("ftp", "ftp", "FTP default"),
                ("admin", "admin", "Administrative account"),
            ],
        );

        // Monitoring & Management
        self.add_credentials(
            "nagios",
            vec![
                ("nagiosadmin", "nagiosadmin", "Nagios default"),
                ("nagios", "nagios", "Nagios default"),
            ],
        );

        self.add_credentials(
            "zabbix",
            vec![
                ("Admin", "zabbix", "Zabbix default (case sensitive)"),
                ("admin", "admin", "Common default"),
            ],
        );

        self.add_credentials("grafana", vec![("admin", "admin", "Grafana default")]);

        self.add_credentials(
            "jenkins",
            vec![
                ("admin", "admin", "Jenkins default"),
                ("admin", "password", "Common default"),
            ],
        );

        // Containers & Orchestration
        self.add_credentials("docker", vec![("admin", "admin", "Docker registry")]);

        self.add_credentials("kubernetes", vec![("admin", "admin", "K8s dashboard")]);

        // VPN & Remote Access
        self.add_credentials("openvpn", vec![("admin", "admin", "OpenVPN default")]);

        self.add_credentials(
            "vpn",
            vec![
                ("admin", "admin", "Generic VPN"),
                ("vpn", "vpn", "VPN default"),
            ],
        );

        // IoT & Cameras
        self.add_credentials(
            "camera",
            vec![
                ("admin", "admin", "IP camera default"),
                ("admin", "12345", "Common IP camera"),
                ("admin", "", "No password"),
                ("root", "root", "Root account"),
            ],
        );

        self.add_credentials(
            "iot",
            vec![
                ("admin", "admin", "IoT device default"),
                ("root", "root", "Root account"),
            ],
        );

        // Web Applications
        self.add_credentials(
            "wordpress",
            vec![
                ("admin", "admin", "WordPress default"),
                ("admin", "password", "Common default"),
            ],
        );

        self.add_credentials("joomla", vec![("admin", "admin", "Joomla default")]);

        self.add_credentials("drupal", vec![("admin", "admin", "Drupal default")]);

        // ERP/CRM
        self.add_credentials(
            "sap",
            vec![
                ("SAP*", "06071992", "SAP default"),
                ("DDIC", "19920706", "SAP default"),
            ],
        );

        self.add_credentials("salesforce", vec![("admin", "admin", "Salesforce default")]);

        // Elasticsearch & Search
        self.add_credentials(
            "elasticsearch",
            vec![("elastic", "changeme", "Elasticsearch default")],
        );

        self.add_credentials("kibana", vec![("elastic", "changeme", "Kibana default")]);

        // Printers
        self.add_credentials(
            "printer",
            vec![
                ("admin", "admin", "Printer default"),
                ("admin", "password", "Common default"),
                ("admin", "", "No password"),
            ],
        );

        // IPMI/BMC
        self.add_credentials(
            "ipmi",
            vec![
                ("ADMIN", "ADMIN", "IPMI default"),
                ("admin", "admin", "Common default"),
            ],
        );

        // General/Other
        self.add_credentials(
            "default",
            vec![
                ("admin", "admin", "Generic default"),
                ("administrator", "administrator", "Generic default"),
                ("root", "toor", "Common reverse password"),
                ("admin", "password", "Very common"),
                ("admin", "12345", "Very weak"),
                ("user", "user", "User account"),
            ],
        );
    }

    /// Add credentials for a service
    fn add_credentials(&mut self, service: &str, creds: Vec<(&str, &str, &str)>) {
        let entries = creds
            .into_iter()
            .map(|(user, pass, notes)| CredentialEntry {
                product: service.to_string(),
                username: user.to_string(),
                password: pass.to_string(),
                notes: Some(notes.to_string()),
            })
            .collect();

        self.entries.insert(service.to_lowercase(), entries);
    }

    /// Get credentials for a service
    pub fn get_credentials(&self, service: &str) -> Option<&Vec<CredentialEntry>> {
        self.entries.get(&service.to_lowercase())
    }

    /// Get all credentials
    pub fn all_credentials(&self) -> Vec<&CredentialEntry> {
        self.entries.values().flat_map(|v| v.iter()).collect()
    }

    /// Get credential count
    pub fn count(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Get service count
    pub fn service_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for DefaultCredentials {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_credentials() {
        let db = DefaultCredentials::new();

        // Check database is populated
        assert!(
            db.count() > 50,
            "Should have 50+ credentials, got {}",
            db.count()
        );
        assert!(
            db.service_count() > 20,
            "Should have 20+ services, got {}",
            db.service_count()
        );
    }

    #[test]
    fn test_get_credentials() {
        let db = DefaultCredentials::new();

        // Test MySQL credentials
        let mysql_creds = db.get_credentials("mysql").unwrap();
        assert!(mysql_creds.len() >= 3);
        assert!(mysql_creds.iter().any(|c| c.username == "root"));

        // Test SSH credentials
        let ssh_creds = db.get_credentials("ssh").unwrap();
        assert!(ssh_creds.len() >= 3);

        // Test nonexistent service
        assert!(db.get_credentials("nonexistent").is_none());
    }

    #[test]
    fn test_case_insensitive() {
        let db = DefaultCredentials::new();

        assert!(db.get_credentials("MySQL").is_some());
        assert!(db.get_credentials("MYSQL").is_some());
        assert!(db.get_credentials("mysql").is_some());
    }
}
