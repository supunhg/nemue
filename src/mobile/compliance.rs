//! Mobile Compliance Scanning Module
//!
//! OWASP Mobile Top 10 compliance checks, mobile security best practices,
//! compliance reporting, and security recommendations.

use serde::{Deserialize, Serialize};

use crate::mobile::MobileSeverity;
use crate::mobile::android::AndroidResults;
use crate::mobile::ios::IosResults;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileBenchmarkType {
    OwaspMobileTop10,
    MobileBestPractices,
    AndroidSpecific,
    IosSpecific,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileComplianceConfig {
    pub benchmarks: Vec<MobileBenchmarkType>,
    pub include_info: bool,
    pub fail_threshold: MobileSeverity,
}

impl Default for MobileComplianceConfig {
    fn default() -> Self {
        Self {
            benchmarks: vec![MobileBenchmarkType::All],
            include_info: true,
            fail_threshold: MobileSeverity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileComplianceCheck {
    pub id: String,
    pub benchmark: MobileBenchmarkType,
    pub title: String,
    pub description: String,
    pub severity: MobileSeverity,
    pub result: MobileComplianceResult,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MobileComplianceResult {
    Pass,
    Fail,
    Warn,
    Info,
    NotApplicable,
}

impl MobileComplianceResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            MobileComplianceResult::Pass => "PASS",
            MobileComplianceResult::Fail => "FAIL",
            MobileComplianceResult::Warn => "WARN",
            MobileComplianceResult::Info => "INFO",
            MobileComplianceResult::NotApplicable => "N/A",
        }
    }
}

impl std::fmt::Display for MobileComplianceResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MobileComplianceReport {
    pub checks: Vec<MobileComplianceCheck>,
    pub total_checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub na: usize,
    pub compliance_score: f64,
}

pub struct MobileComplianceScanner {
    config: MobileComplianceConfig,
}

impl MobileComplianceScanner {
    pub fn new(config: MobileComplianceConfig) -> Self {
        Self { config }
    }

    pub fn with_default() -> Self {
        Self::new(MobileComplianceConfig::default())
    }

    pub fn scan_android(&self, android_results: &AndroidResults) -> MobileComplianceReport {
        let mut checks = Vec::new();

        checks.extend(self.owasp_mobile_checks());
        checks.extend(self.android_specific_checks(android_results));
        checks.extend(self.mobile_best_practices());

        self.build_report(checks)
    }

    pub fn scan_ios(&self, ios_results: &IosResults) -> MobileComplianceReport {
        let mut checks = Vec::new();

        checks.extend(self.owasp_mobile_checks());
        checks.extend(self.ios_specific_checks(ios_results));
        checks.extend(self.mobile_best_practices());

        self.build_report(checks)
    }

    fn build_report(&self, checks: Vec<MobileComplianceCheck>) -> MobileComplianceReport {
        let total_checks = checks.len();
        let passed = checks.iter().filter(|c| c.result == MobileComplianceResult::Pass).count();
        let failed = checks.iter().filter(|c| c.result == MobileComplianceResult::Fail).count();
        let warnings = checks.iter().filter(|c| c.result == MobileComplianceResult::Warn).count();
        let na = checks.iter().filter(|c| c.result == MobileComplianceResult::NotApplicable).count();

        let applicable = total_checks - na;
        let compliance_score = if applicable > 0 {
            (passed as f64 / applicable as f64) * 100.0
        } else {
            100.0
        };

        MobileComplianceReport {
            checks,
            total_checks,
            passed,
            failed,
            warnings,
            na,
            compliance_score,
        }
    }

    fn owasp_mobile_checks(&self) -> Vec<MobileComplianceCheck> {
        vec![
            MobileComplianceCheck {
                id: "M1".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "M1: Improper Platform Usage".to_string(),
                description: "Misuse of platform features or security controls.".to_string(),
                severity: MobileSeverity::High,
                result: MobileComplianceResult::Warn,
                evidence: "Manual review required for platform API usage.".to_string(),
                remediation: "Follow platform security best practices for API usage.".to_string(),
            },
            MobileComplianceCheck {
                id: "M2".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "M2: Insecure Data Storage".to_string(),
                description: "Sensitive data stored insecurely on the device.".to_string(),
                severity: MobileSeverity::High,
                result: MobileComplianceResult::Warn,
                evidence: "Requires application-level analysis.".to_string(),
                remediation: "Use platform keystore/keychain for sensitive data storage.".to_string(),
            },
            MobileComplianceCheck {
                id: "M3".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "M3: Insecure Communication".to_string(),
                description: "Data transmitted without proper encryption.".to_string(),
                severity: MobileSeverity::High,
                result: MobileComplianceResult::Warn,
                evidence: "Network traffic analysis required.".to_string(),
                remediation: "Use TLS 1.2+ for all network communications. Implement certificate pinning.".to_string(),
            },
            MobileComplianceCheck {
                id: "M4".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "M4: Insecure Authentication".to_string(),
                description: "Weak or improper authentication mechanisms.".to_string(),
                severity: MobileSeverity::High,
                result: MobileComplianceResult::Warn,
                evidence: "Application authentication analysis required.".to_string(),
                remediation: "Implement strong authentication with biometrics or MFA. Use secure session management.".to_string(),
            },
            MobileComplianceCheck {
                id: "M5".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "M5: Insufficient Cryptography".to_string(),
                description: "Weak or improper cryptographic implementations.".to_string(),
                severity: MobileSeverity::High,
                result: MobileComplianceResult::Warn,
                evidence: "Cryptographic implementation review required.".to_string(),
                remediation: "Use platform-provided cryptographic APIs. Avoid custom crypto implementations.".to_string(),
            },
            MobileComplianceCheck {
                id: "M6".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "M6: Insecure Authorization".to_string(),
                description: "Improper authorization checks allowing privilege escalation.".to_string(),
                severity: MobileSeverity::High,
                result: MobileComplianceResult::Warn,
                evidence: "Authorization logic review required.".to_string(),
                remediation: "Enforce authorization checks on the server side. Validate permissions for every request.".to_string(),
            },
            MobileComplianceCheck {
                id: "M7".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "M7: Client Code Quality".to_string(),
                description: "Code-level vulnerabilities in the mobile application.".to_string(),
                severity: MobileSeverity::Medium,
                result: MobileComplianceResult::Warn,
                evidence: "Static analysis required.".to_string(),
                remediation: "Follow secure coding practices. Use static analysis tools. Address all compiler warnings.".to_string(),
            },
            MobileComplianceCheck {
                id: "M8".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "M8: Code Tampering".to_string(),
                description: "Application binary can be modified or reverse-engineered.".to_string(),
                severity: MobileSeverity::Medium,
                result: MobileComplianceResult::Warn,
                evidence: "Binary protection analysis required.".to_string(),
                remediation: "Implement code obfuscation, integrity checks, and anti-tampering mechanisms.".to_string(),
            },
            MobileComplianceCheck {
                id: "M9".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "M9: Reverse Engineering".to_string(),
                description: "Application can be reverse-engineered to extract sensitive logic.".to_string(),
                severity: MobileSeverity::Medium,
                result: MobileComplianceResult::Warn,
                evidence: "Reverse engineering resistance analysis required.".to_string(),
                remediation: "Use code obfuscation tools. Minimize sensitive logic in client-side code.".to_string(),
            },
            MobileComplianceCheck {
                id: "M10".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "M10: Extraneous Functionality".to_string(),
                description: "Debug or test code left in production builds.".to_string(),
                severity: MobileSeverity::Medium,
                result: MobileComplianceResult::Warn,
                evidence: "Build configuration review required.".to_string(),
                remediation: "Remove all debug code, test endpoints, and backdoors from production builds.".to_string(),
            },
        ]
    }

    fn android_specific_checks(&self, results: &AndroidResults) -> Vec<MobileComplianceCheck> {
        let mut checks = Vec::new();

        let debuggable_apps = results.packages.iter().filter(|p| p.debuggable).count();
        checks.push(MobileComplianceCheck {
            id: "ANDROID-001".to_string(),
            benchmark: MobileBenchmarkType::AndroidSpecific,
            title: "No debuggable applications in production".to_string(),
            description: "Debuggable applications expose internal state and allow code injection.".to_string(),
            severity: MobileSeverity::High,
            result: if debuggable_apps == 0 { MobileComplianceResult::Pass } else { MobileComplianceResult::Fail },
            evidence: format!("{} debuggable applications found", debuggable_apps),
            remediation: "Set android:debuggable=false in all production application manifests.".to_string(),
        });

        let backup_apps = results.packages.iter().filter(|p| p.allow_backup && !p.is_system).count();
        checks.push(MobileComplianceCheck {
            id: "ANDROID-002".to_string(),
            benchmark: MobileBenchmarkType::AndroidSpecific,
            title: "Disable application backup for sensitive apps".to_string(),
            description: "Applications with allowBackup=true can have data extracted via adb.".to_string(),
            severity: MobileSeverity::Medium,
            result: if backup_apps == 0 { MobileComplianceResult::Pass } else { MobileComplianceResult::Fail },
            evidence: format!("{} non-system apps with backup enabled", backup_apps),
            remediation: "Set android:allowBackup=false for applications handling sensitive data.".to_string(),
        });

        let rooted = results.devices.iter().any(|d| d.is_rooted);
        checks.push(MobileComplianceCheck {
            id: "ANDROID-003".to_string(),
            benchmark: MobileBenchmarkType::AndroidSpecific,
            title: "Device integrity verification".to_string(),
            description: "Rooted devices bypass Android's security sandbox.".to_string(),
            severity: MobileSeverity::Critical,
            result: if rooted { MobileComplianceResult::Fail } else { MobileComplianceResult::Pass },
            evidence: if rooted { "Device is rooted".to_string() } else { "Device appears non-rooted".to_string() },
            remediation: "Use non-rooted devices. Implement root detection in sensitive applications.".to_string(),
        });

        let adb_tcp = results.services.iter().any(|s| s.port == 5555 && s.state == "open");
        checks.push(MobileComplianceCheck {
            id: "ANDROID-004".to_string(),
            benchmark: MobileBenchmarkType::AndroidSpecific,
            title: "Disable ADB over network".to_string(),
            description: "ADB over TCP allows remote debugging access to the device.".to_string(),
            severity: MobileSeverity::High,
            result: if adb_tcp { MobileComplianceResult::Fail } else { MobileComplianceResult::Pass },
            evidence: if adb_tcp { "ADB over TCP is enabled on port 5555".to_string() } else { "ADB over TCP is not detected".to_string() },
            remediation: "Disable ADB over TCP. Use USB debugging only when necessary.".to_string(),
        });

        checks
    }

    fn ios_specific_checks(&self, results: &IosResults) -> Vec<MobileComplianceCheck> {
        let mut checks = Vec::new();

        let passcode_set = results.devices.iter().all(|d| d.passcode_set);
        checks.push(MobileComplianceCheck {
            id: "IOS-001".to_string(),
            benchmark: MobileBenchmarkType::IosSpecific,
            title: "Device passcode enabled".to_string(),
            description: "Devices without passcodes allow unrestricted physical access.".to_string(),
            severity: MobileSeverity::Critical,
            result: if passcode_set { MobileComplianceResult::Pass } else { MobileComplianceResult::Fail },
            evidence: if passcode_set { "All devices have passcodes set".to_string() } else { "One or more devices without passcode".to_string() },
            remediation: "Enable passcode on all devices. Use alphanumeric passcodes for maximum security.".to_string(),
        });

        if let Some(ref config) = results.configuration {
            checks.push(MobileComplianceCheck {
                id: "IOS-002".to_string(),
                benchmark: MobileBenchmarkType::IosSpecific,
                title: "USB Restricted Mode enabled".to_string(),
                description: "USB Restricted Mode prevents unauthorized USB access when locked.".to_string(),
                severity: MobileSeverity::High,
                result: if config.usb_restricted_mode { MobileComplianceResult::Pass } else { MobileComplianceResult::Fail },
                evidence: format!("USB Restricted Mode: {}", if config.usb_restricted_mode { "enabled" } else { "disabled" }),
                remediation: "Enable USB Restricted Mode in Settings > Face ID & Passcode.".to_string(),
            });

            checks.push(MobileComplianceCheck {
                id: "IOS-003".to_string(),
                benchmark: MobileBenchmarkType::IosSpecific,
                title: "Find My enabled".to_string(),
                description: "Find My enables remote wipe and device location for lost devices.".to_string(),
                severity: MobileSeverity::Medium,
                result: if config.find_my_enabled { MobileComplianceResult::Pass } else { MobileComplianceResult::Fail },
                evidence: format!("Find My: {}", if config.find_my_enabled { "enabled" } else { "disabled" }),
                remediation: "Enable Find My in Settings > Apple ID > Find My.".to_string(),
            });

            checks.push(MobileComplianceCheck {
                id: "IOS-004".to_string(),
                benchmark: MobileBenchmarkType::IosSpecific,
                title: "Siri disabled on lock screen".to_string(),
                description: "Siri on lock screen can expose sensitive information.".to_string(),
                severity: MobileSeverity::Medium,
                result: if config.siri_on_lock_screen { MobileComplianceResult::Fail } else { MobileComplianceResult::Pass },
                evidence: format!("Siri on lock screen: {}", if config.siri_on_lock_screen { "enabled" } else { "disabled" }),
                remediation: "Disable Siri on lock screen in Settings > Face ID & Passcode.".to_string(),
            });
        }

        checks
    }

    fn mobile_best_practices(&self) -> Vec<MobileComplianceCheck> {
        vec![
            MobileComplianceCheck {
                id: "BP-001".to_string(),
                benchmark: MobileBenchmarkType::MobileBestPractices,
                title: "Regular OS updates".to_string(),
                description: "Outdated operating systems lack critical security patches.".to_string(),
                severity: MobileSeverity::High,
                result: MobileComplianceResult::Warn,
                evidence: "Verify devices are running recent OS versions.".to_string(),
                remediation: "Enable automatic updates. Update devices within 30 days of patch release.".to_string(),
            },
            MobileComplianceCheck {
                id: "BP-002".to_string(),
                benchmark: MobileBenchmarkType::MobileBestPractices,
                title: "App store only installations".to_string(),
                description: "Apps from unofficial sources may contain malware.".to_string(),
                severity: MobileSeverity::Medium,
                result: MobileComplianceResult::Warn,
                evidence: "Verify installation sources for all applications.".to_string(),
                remediation: "Install apps only from official app stores (Google Play, App Store).".to_string(),
            },
            MobileComplianceCheck {
                id: "BP-003".to_string(),
                benchmark: MobileBenchmarkType::MobileBestPractices,
                title: "Device encryption enabled".to_string(),
                description: "Unencrypted devices expose data if physically compromised.".to_string(),
                severity: MobileSeverity::High,
                result: MobileComplianceResult::Warn,
                evidence: "Verify device encryption status.".to_string(),
                remediation: "Enable full-disk encryption. iOS encrypts by default with passcode; Android requires enabling in settings.".to_string(),
            },
            MobileComplianceCheck {
                id: "BP-004".to_string(),
                benchmark: MobileBenchmarkType::MobileBestPractices,
                title: "Remote wipe capability".to_string(),
                description: "Remote wipe protects data on lost or stolen devices.".to_string(),
                severity: MobileSeverity::Medium,
                result: MobileComplianceResult::Warn,
                evidence: "Verify remote wipe is configured.".to_string(),
                remediation: "Enable Find My (iOS) or Find My Device (Android) for remote wipe capability.".to_string(),
            },
            MobileComplianceCheck {
                id: "BP-005".to_string(),
                benchmark: MobileBenchmarkType::MobileBestPractices,
                title: "VPN for enterprise access".to_string(),
                description: "Enterprise data should be accessed through encrypted VPN tunnels.".to_string(),
                severity: MobileSeverity::Medium,
                result: MobileComplianceResult::Warn,
                evidence: "Verify VPN configuration for enterprise access.".to_string(),
                remediation: "Configure and require VPN for accessing enterprise resources.".to_string(),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mobile::android::{AndroidResults, InstalledPackage, AdbDevice, AndroidService};

    #[test]
    fn test_compliance_config_default() {
        let config = MobileComplianceConfig::default();
        assert!(config.include_info);
        assert_eq!(config.fail_threshold, MobileSeverity::Medium);
    }

    #[test]
    fn test_compliance_scanner_creation() {
        let scanner = MobileComplianceScanner::with_default();
        assert!(scanner.config.include_info);
    }

    #[test]
    fn test_compliance_result_display() {
        assert_eq!(format!("{}", MobileComplianceResult::Pass), "PASS");
        assert_eq!(format!("{}", MobileComplianceResult::Fail), "FAIL");
        assert_eq!(format!("{}", MobileComplianceResult::Warn), "WARN");
        assert_eq!(format!("{}", MobileComplianceResult::NotApplicable), "N/A");
    }

    #[test]
    fn test_build_report_empty() {
        let scanner = MobileComplianceScanner::with_default();
        let report = scanner.build_report(Vec::new());
        assert_eq!(report.total_checks, 0);
        assert_eq!(report.compliance_score, 100.0);
    }

    #[test]
    fn test_build_report_with_checks() {
        let scanner = MobileComplianceScanner::with_default();
        let checks = vec![
            MobileComplianceCheck {
                id: "TEST-1".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "Test".to_string(),
                description: "Test".to_string(),
                severity: MobileSeverity::Medium,
                result: MobileComplianceResult::Pass,
                evidence: "Test".to_string(),
                remediation: "Test".to_string(),
            },
            MobileComplianceCheck {
                id: "TEST-2".to_string(),
                benchmark: MobileBenchmarkType::OwaspMobileTop10,
                title: "Test".to_string(),
                description: "Test".to_string(),
                severity: MobileSeverity::Medium,
                result: MobileComplianceResult::Fail,
                evidence: "Test".to_string(),
                remediation: "Test".to_string(),
            },
        ];
        let report = scanner.build_report(checks);
        assert_eq!(report.total_checks, 2);
        assert_eq!(report.passed, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.compliance_score, 50.0);
    }

    #[test]
    fn test_owasp_mobile_checks_count() {
        let scanner = MobileComplianceScanner::with_default();
        let checks = scanner.owasp_mobile_checks();
        assert_eq!(checks.len(), 10);
    }

    #[test]
    fn test_android_scan_debuggable_apps() {
        let scanner = MobileComplianceScanner::with_default();
        let mut android_results = AndroidResults::default();
        android_results.packages.push(InstalledPackage {
            name: "com.example.app".to_string(),
            debuggable: true,
            ..Default::default()
        });

        let report = scanner.scan_android(&android_results);
        assert!(report.checks.iter().any(|c| c.id == "ANDROID-001" && c.result == MobileComplianceResult::Fail));
    }

    #[test]
    fn test_android_scan_rooted_device() {
        let scanner = MobileComplianceScanner::with_default();
        let mut android_results = AndroidResults::default();
        android_results.devices.push(AdbDevice {
            serial: "test123".to_string(),
            is_rooted: true,
            ..Default::default()
        });

        let report = scanner.scan_android(&android_results);
        assert!(report.checks.iter().any(|c| c.id == "ANDROID-003" && c.result == MobileComplianceResult::Fail));
    }

    #[test]
    fn test_android_scan_adb_over_tcp() {
        let scanner = MobileComplianceScanner::with_default();
        let mut android_results = AndroidResults::default();
        android_results.services.push(AndroidService {
            name: "adb".to_string(),
            port: 5555,
            state: "open".to_string(),
            ..Default::default()
        });

        let report = scanner.scan_android(&android_results);
        assert!(report.checks.iter().any(|c| c.id == "ANDROID-004" && c.result == MobileComplianceResult::Fail));
    }

    #[test]
    fn test_android_scan_clean_device() {
        let scanner = MobileComplianceScanner::with_default();
        let android_results = AndroidResults::default();

        let report = scanner.scan_android(&android_results);
        assert!(report.checks.iter().any(|c| c.id == "ANDROID-001" && c.result == MobileComplianceResult::Pass));
        assert!(report.checks.iter().any(|c| c.id == "ANDROID-003" && c.result == MobileComplianceResult::Pass));
    }

    #[test]
    fn test_ios_scan_no_passcode() {
        let scanner = MobileComplianceScanner::with_default();
        let mut ios_results = IosResults::default();
        ios_results.devices.push(crate::mobile::ios::IosDevice {
            udid: "test123".to_string(),
            passcode_set: false,
            ..Default::default()
        });

        let report = scanner.scan_ios(&ios_results);
        assert!(report.checks.iter().any(|c| c.id == "IOS-001" && c.result == MobileComplianceResult::Fail));
    }

    #[test]
    fn test_mobile_best_practices_count() {
        let scanner = MobileComplianceScanner::with_default();
        let checks = scanner.mobile_best_practices();
        assert_eq!(checks.len(), 5);
    }
}
