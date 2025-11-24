// CLI Integration Tests
// Tests command-line interface functionality

use std::process::Command;
use std::fs;

fn get_binary_path() -> String {
    // Use debug binary for tests
    let mut path = std::env::current_dir().unwrap();
    path.push("target");
    path.push("debug");
    path.push("nemue");
    path.to_str().unwrap().to_string()
}

#[test]
fn test_cli_help() {
    let output = Command::new(get_binary_path())
        .arg("--help")
        .output()
        .expect("Failed to execute nemue");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("network scanner"));
}

#[test]
fn test_cli_version() {
    let output = Command::new(get_binary_path())
        .arg("--version")
        .output()
        .expect("Failed to execute nemue");

    assert!(output.status.success());
}

#[test]
fn test_scan_subcommand_help() {
    let output = Command::new(get_binary_path())
        .args(&["scan", "--help"])
        .output()
        .expect("Failed to execute nemue");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Target IP"));
    assert!(stdout.contains("Ports to scan"));
}

#[test]
fn test_invalid_target() {
    let output = Command::new(get_binary_path())
        .args(&["scan", "invalid.target"])
        .output()
        .expect("Failed to execute nemue");

    assert!(!output.status.success());
}

#[test]
fn test_localhost_scan_basic() {
    let output = Command::new(get_binary_path())
        .args(&["scan", "127.0.0.1", "-p", "1-10", "-q"])
        .output()
        .expect("Failed to execute nemue");

    // Should complete without error (may or may not find open ports)
    assert!(output.status.success());
}

#[test]
fn test_timing_template_flag() {
    let output = Command::new(get_binary_path())
        .args(&["scan", "127.0.0.1", "-p", "80", "-T", "3", "-q"])
        .output()
        .expect("Failed to execute nemue");

    assert!(output.status.success());
}

#[test]
fn test_invalid_timing_template() {
    let output = Command::new(get_binary_path())
        .args(&["scan", "127.0.0.1", "-p", "80", "-T", "6"])
        .output()
        .expect("Failed to execute nemue");

    assert!(!output.status.success());
}

#[test]
fn test_output_file_json() {
    let temp_file = "/tmp/nemue_test_output.json";
    
    let output = Command::new(get_binary_path())
        .args(&["scan", "127.0.0.1", "-p", "1-10", "-o", temp_file, "-q"])
        .output()
        .expect("Failed to execute nemue");

    assert!(output.status.success());
    assert!(std::path::Path::new(temp_file).exists());
    
    // Cleanup
    let _ = fs::remove_file(temp_file);
}

#[test]
fn test_script_updatedb_flag() {
    let output = Command::new(get_binary_path())
        .args(&["scan", "127.0.0.1", "--script-updatedb"])
        .output()
        .expect("Failed to execute nemue");

    // Should exit early after database update
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    // Either succeeds or fails with directory not found
    assert!(stdout.contains("script") || stderr.contains("directory"));
}

#[test]
fn test_script_help_nonexistent() {
    let output = Command::new(get_binary_path())
        .args(&["scan", "127.0.0.1", "--script-help", "nonexistent-script"])
        .output()
        .expect("Failed to execute nemue");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not found") || stderr.contains("Script"));
}

#[test]
fn test_fine_grained_timing_flags() {
    let output = Command::new(get_binary_path())
        .args(&[
            "scan", "127.0.0.1", "-p", "80",
            "--min-rtt-timeout", "100ms",
            "--max-rtt-timeout", "2s",
            "--max-rate", "1000",
            "-q"
        ])
        .output()
        .expect("Failed to execute nemue");

    assert!(output.status.success());
}

#[test]
fn test_port_exclusion() {
    let output = Command::new(get_binary_path())
        .args(&["scan", "127.0.0.1", "-p", "1-100", "-e", "22,80", "-q"])
        .output()
        .expect("Failed to execute nemue");

    assert!(output.status.success());
}

#[test]
fn test_common_ports_preset() {
    let output = Command::new(get_binary_path())
        .args(&["scan", "127.0.0.1", "-p", "common", "-q"])
        .output()
        .expect("Failed to execute nemue");

    assert!(output.status.success());
}

#[test]
fn test_top100_ports_preset() {
    let output = Command::new(get_binary_path())
        .args(&["scan", "127.0.0.1", "-p", "top100", "-q"])
        .output()
        .expect("Failed to execute nemue");

    assert!(output.status.success());
}

#[test]
fn test_verbose_flag() {
    let output = Command::new(get_binary_path())
        .args(&["scan", "127.0.0.1", "-p", "80", "-v"])
        .output()
        .expect("Failed to execute nemue");

    assert!(output.status.success());
}

#[test]
fn test_script_args_parsing() {
    let output = Command::new(get_binary_path())
        .args(&[
            "scan", "127.0.0.1", "-p", "80",
            "--script-args", "user=admin,pass=test",
            "-q"
        ])
        .output()
        .expect("Failed to execute nemue");

    // Should parse arguments successfully
    assert!(output.status.success());
}

#[test]
fn test_multiple_timing_overrides() {
    let output = Command::new(get_binary_path())
        .args(&[
            "scan", "127.0.0.1", "-p", "1-10",
            "-T", "4",
            "--max-rate", "5000",
            "--min-parallelism", "50",
            "--max-retries", "2",
            "-q"
        ])
        .output()
        .expect("Failed to execute nemue");

    assert!(output.status.success());
}
