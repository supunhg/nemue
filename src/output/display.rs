use colored::*;
use std::io::{self, Write};

use crate::scanner::{PortState, ScanResults};

pub struct DisplayFormatter {
    show_banner: bool,
    verbose: bool,
}

impl DisplayFormatter {
    pub fn new(show_banner: bool, verbose: bool) -> Self {
        Self {
            show_banner,
            verbose,
        }
    }

    pub fn print_banner(&self) {
        if !self.show_banner {
            return;
        }

        let banner = r#"
    _   __                          
   / | / /__  ____ ___  __  _____  
  /  |/ / _ \/ __ `__ \/ / / / _ \ 
 / /|  /  __/ / / / / / /_/ /  __/ 
/_/ |_/\___/_/ /_/ /_/\__,_/\___/  
                                    
        "#;

        println!("{}", banner.bright_cyan().bold());
        println!(
            "{}",
            "Nemue - High-Performance Network Scanner v0.1.0".bright_white()
        );
        println!("{}", "https://github.com/nemue-project/nemue".dimmed());
        println!();
    }

    pub fn print_scan_info(&self, target: &str, ports: &str, rate: u32) {
        println!(
            "{} Scan report for {}",
            "→".bright_green().bold(),
            target.bright_white().bold()
        );
        println!(
            "{} Ports: {} | Rate: {} pps",
            "•".bright_blue(),
            ports.bright_white(),
            rate.to_string().bright_white()
        );
        println!();
    }

    pub fn print_results(&self, results: &ScanResults) {
        let mut stdout = io::stdout();
        
        // Group results by target
        let mut targets: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
        for result in &results.results {
            targets
                .entry(result.target.to_string())
                .or_insert_with(Vec::new)
                .push(result);
        }

        for (target, target_results) in targets.iter() {
            println!(
                "{} Scan Results for {}",
                "┌─".bright_cyan().bold(),
                target.bright_white().bold()
            );
            println!("{}", "│".bright_cyan());

            // Count states
            let open_count = target_results
                .iter()
                .filter(|r| matches!(r.state, PortState::Open))
                .count();
            let closed_count = target_results
                .iter()
                .filter(|r| matches!(r.state, PortState::Closed))
                .count();
            let filtered_count = target_results
                .iter()
                .filter(|r| matches!(r.state, PortState::Filtered))
                .count();

            println!(
                "{} {} open | {} closed | {} filtered",
                "│".bright_cyan(),
                format!("{}", open_count).bright_green().bold(),
                format!("{}", closed_count).bright_red(),
                format!("{}", filtered_count).yellow()
            );
            println!("{}", "│".bright_cyan());

            // Print header
            println!(
                "{} {:<8} {:<10} {:<12} {:<20} {}",
                "│".bright_cyan(),
                "PORT".bright_white().bold(),
                "STATE".bright_white().bold(),
                "SERVICE".bright_white().bold(),
                "VERSION".bright_white().bold(),
                "PRODUCT".bright_white().bold()
            );
            println!(
                "{} {}",
                "│".bright_cyan(),
                "─".repeat(75).bright_black()
            );

            // Print each result
            for result in target_results {
                let port_str = format!("{}/{}", result.port, result.protocol);
                let state_str = match result.state {
                    PortState::Open => "open".bright_green().bold(),
                    PortState::Closed => "closed".bright_red(),
                    PortState::Filtered => "filtered".yellow(),
                    PortState::Unknown => "unknown".bright_black(),
                };

                let service = result.service.as_deref().unwrap_or("-");
                
                let (product, version) = if let Some(ref info) = result.service_info {
                    (
                        info.product.as_deref().unwrap_or("-"),
                        info.version.as_deref().unwrap_or("-"),
                    )
                } else {
                    ("-", "-")
                };

                println!(
                    "{} {:<8} {:<10} {:<12} {:<20} {}",
                    "│".bright_cyan(),
                    port_str.bright_white(),
                    state_str,
                    service.bright_blue(),
                    version,
                    product.dimmed()
                );

                // Show banner if verbose
                if self.verbose {
                    if let Some(ref info) = result.service_info {
                        if let Some(ref banner) = info.banner {
                            println!(
                                "{} {}  {}",
                                "│".bright_cyan(),
                                "  ".repeat(1),
                                format!("Banner: {}", banner).dimmed()
                            );
                        }
                    }
                }
            }

            println!("{}", "│".bright_cyan());
            
            // OS Detection results
            let target_os: Vec<_> = results
                .os_fingerprints
                .iter()
                .filter(|os| os.target.to_string() == *target)
                .collect();

            if !target_os.is_empty() {
                println!(
                    "{} {} OS Detection",
                    "│".bright_cyan(),
                    "🖥️".bright_yellow()
                );
                for os in target_os {
                    let confidence_color = if os.confidence >= 80 {
                        "bright green".to_string()
                    } else if os.confidence >= 60 {
                        "yellow".to_string()
                    } else {
                        "bright red".to_string()
                    };

                    println!(
                        "{} {}  {} ({}% confidence)",
                        "│".bright_cyan(),
                        "  ".repeat(1),
                        format!("{:?}", os.os_family).color(confidence_color),
                        os.confidence
                    );
                    
                    if self.verbose {
                        let ttl_str = os.ttl.map(|t| t.to_string()).unwrap_or_else(|| "?".to_string());
                        let win_str = os.window_size.map(|w| w.to_string()).unwrap_or_else(|| "?".to_string());
                        println!(
                            "{} {}  {}",
                            "│".bright_cyan(),
                            "  ".repeat(2),
                            format!("TTL: {} | Window: {}", ttl_str, win_str).dimmed()
                        );
                    }
                }
                println!("{}", "│".bright_cyan());
            }

            println!("{}", "└─".bright_cyan().bold());
            println!();
        }

        // Summary
        let elapsed = results
            .scan_end
            .signed_duration_since(results.scan_start)
            .num_milliseconds() as f64
            / 1000.0;

        println!(
            "{} Scan completed in {:.2}s",
            "✓".bright_green().bold(),
            elapsed
        );
        println!(
            "{} {} ports scanned across {} target(s)",
            "•".bright_blue(),
            results.port_count.to_string().bright_white(),
            results.target_count.to_string().bright_white()
        );
        
        let total_open = results
            .results
            .iter()
            .filter(|r| matches!(r.state, PortState::Open))
            .count();
        
        if total_open > 0 {
            println!(
                "{} {} open port(s) discovered",
                "•".bright_blue(),
                total_open.to_string().bright_green().bold()
            );
        }

        println!();
    }

    pub fn print_error(&self, error: &str) {
        eprintln!("{} {}", "✗".bright_red().bold(), error.bright_red());
    }

    pub fn print_warning(&self, warning: &str) {
        println!("{} {}", "⚠".yellow().bold(), warning.yellow());
    }

    pub fn print_progress(&self, message: &str) {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        write!(handle, "\r{} {}...", "⏳".bright_yellow(), message).ok();
        handle.flush().ok();
    }

    pub fn clear_progress(&self) {
        print!("\r{}\r", " ".repeat(80));
        io::stdout().flush().ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_formatter_creation() {
        let formatter = DisplayFormatter::new(true, false);
        assert!(formatter.show_banner);
        assert!(!formatter.verbose);
    }

    #[test]
    fn test_banner_display() {
        let formatter = DisplayFormatter::new(true, false);
        formatter.print_banner(); // Should not panic
    }

    #[test]
    fn test_no_banner() {
        let formatter = DisplayFormatter::new(false, false);
        formatter.print_banner(); // Should not print anything
    }
}
