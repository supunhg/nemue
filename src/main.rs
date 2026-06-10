#![allow(clippy::all)]

use anyhow::Result;
use clap::Parser;

use nemue::output::{DisplayFormatter, OutputFormat, ResultFormatter};
use nemue::scanner::ScanEngine;
use nemue::scanner::TimingTemplate;

/// Nemue - Advanced Security Testing Framework
#[derive(Parser, Debug)]
#[command(name = "nemue")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Scan target hosts and ports
    Scan {
        /// Target IP address or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24)
        target: String,

        /// Ports to scan (e.g., 80,443 or 1-1000, common, top100, top1000)
        #[arg(short, long, default_value = "1-1000")]
        ports: String,

        /// Exclude ports from scan (e.g., 80,443 or 1-100)
        #[arg(short = 'e', long)]
        exclude: Option<String>,

        /// Maximum packets per second (rate limiting)
        #[arg(short, long, default_value = "1000")]
        rate: u32,

        /// Timeout for each port in milliseconds
        #[arg(long, default_value = "3000")]
        timeout: u64,

        /// Scan type: syn (default), connect, udp
        #[arg(short = 's', long, default_value = "syn")]
        scan_type: String,

        /// Aggressive scan (enables service detection, OS detection, SYN scan, top1000 ports)
        #[arg(short = 'A', long)]
        aggressive: bool,

        /// Timing template: 0 (Paranoid), 1 (Sneaky), 2 (Polite), 3 (Normal), 4 (Aggressive), 5 (Insane)
        #[arg(short = 'T', long, value_parser = clap::value_parser!(u8).range(0..=5))]
        timing: Option<u8>,

        /// Minimum RTT timeout (e.g., "100ms", "1s")
        #[arg(long)]
        min_rtt_timeout: Option<String>,

        /// Maximum RTT timeout (e.g., "10s", "1m")
        #[arg(long)]
        max_rtt_timeout: Option<String>,

        /// Initial RTT timeout (e.g., "1s", "500ms")
        #[arg(long)]
        initial_rtt_timeout: Option<String>,

        /// Maximum number of port scan probe retransmissions
        #[arg(long)]
        max_retries: Option<String>,

        /// Give up on target after this long (e.g., "15m", "1h")
        #[arg(long)]
        host_timeout: Option<String>,

        /// Adjust delay between probes (e.g., "400ms", "5s")
        #[arg(long)]
        scan_delay: Option<String>,

        /// Maximum TCP scan delay between successive probes
        #[arg(long)]
        max_scan_delay: Option<String>,

        /// Minimum number of parallel operations
        #[arg(long)]
        min_parallelism: Option<String>,

        /// Maximum number of parallel port scan probes
        #[arg(long)]
        max_parallelism: Option<String>,

        /// Minimum number of hosts to scan in parallel
        #[arg(long)]
        min_hostgroup: Option<String>,

        /// Maximum number of hosts to scan in parallel
        #[arg(long)]
        max_hostgroup: Option<String>,

        /// Send packets no slower than NUM per second
        #[arg(long)]
        min_rate: Option<String>,

        /// Send packets no faster than NUM per second (overrides --rate)
        #[arg(long)]
        max_rate: Option<String>,

        /// Service/version detection
        #[arg(short = 'V', long)]
        version_detect: bool,

        /// Light version detection (fewer probes, faster)
        #[arg(long)]
        version_light: bool,

        /// All version detection probes (comprehensive, slower)
        #[arg(long)]
        version_all: bool,

        /// Version detection intensity (0-9, where 2=light, 7=default, 9=all)
        #[arg(long)]
        version_intensity: Option<u8>,

        /// OS detection
        #[arg(short = 'O', long)]
        os_detect: bool,

        /// Use raw sockets for stealth SYN scan (requires root)
        #[arg(long)]
        raw: bool,

        /// Idle scan using zombie host (format: -sI zombie[:port])
        #[arg(short = 'I', long)]
        idle_scan: Option<String>,

        /// FTP bounce scan using FTP server (format: -b ftp_server[:port])
        #[arg(short = 'b', long)]
        ftp_bounce: Option<String>,

        /// Resume a previous scan from checkpoint
        #[arg(long)]
        resume: Option<String>,

        /// Enable packet trace logging
        #[arg(long)]
        packet_trace: bool,

        /// Show reason for port state
        #[arg(long)]
        reason: bool,

        /// Scan top N most common ports (e.g., --top-ports 100)
        #[arg(long)]
        top_ports: Option<usize>,

        /// Hide filtered ports (shown by default like Nmap)
        #[arg(short = 'F', long)]
        hide_filtered: bool,

        /// Hide closed ports (shown by default)
        #[arg(short = 'c', long)]
        hide_closed: bool,

        /// Output file path
        #[arg(short, long)]
        output: Option<String>,

        /// Output format: json (default), xml
        #[arg(short = 'f', long, default_value = "json")]
        format: String,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Disable banner
        #[arg(short = 'q', long)]
        quiet: bool,

        /// Script arguments in key=value format (e.g., "user=admin,pass=test")
        #[arg(long)]
        script_args: Option<String>,

        /// File containing script arguments
        #[arg(long)]
        script_args_file: Option<String>,

        /// Enable script execution tracing/debugging
        #[arg(long)]
        script_trace: bool,

        /// Update script database
        #[arg(long)]
        script_updatedb: bool,

        /// Show help for a specific script
        #[arg(long)]
        script_help: Option<String>,
    },

    /// Web content discovery and fuzzing
    Fuzz {
        /// Target URL (e.g., https://example.com)
        url: String,

        /// Fuzzing mode: dir, file, ext, vhost, subdomain, s3, azure, gcp
        #[arg(short, long, default_value = "dir")]
        mode: String,

        /// Wordlist file path (or use built-in with --builtin)
        #[arg(short, long)]
        wordlist: Option<String>,

        /// Built-in wordlist: dirs1k, dirs10k, files, extensions, subdomains, params, wordpress, joomla, laravel, api
        #[arg(short, long)]
        builtin: Option<String>,

        /// Concurrent requests
        #[arg(short, long, default_value = "50")]
        concurrency: usize,

        /// Rate limit (requests per second)
        #[arg(short, long)]
        rate_limit: Option<u64>,

        /// Filter by status codes (comma-separated, e.g., 200,301,302)
        #[arg(short = 's', long)]
        status_codes: Option<String>,

        /// Exclude status codes (comma-separated)
        #[arg(long)]
        exclude_status: Option<String>,

        /// Minimum response size in bytes
        #[arg(long)]
        min_size: Option<usize>,

        /// Maximum response size in bytes
        #[arg(long)]
        max_size: Option<usize>,

        /// Enable recursive scanning
        #[arg(short = 'R', long)]
        recursive: bool,

        /// Maximum recursion depth
        #[arg(long, default_value = "3")]
        max_depth: usize,

        /// Extensions for extension fuzzing (comma-separated, e.g., php,asp,jsp)
        #[arg(short, long)]
        extensions: Option<String>,

        /// Custom User-Agent
        #[arg(short = 'U', long)]
        user_agent: Option<String>,

        /// Custom headers (format: "Name: Value")
        #[arg(short = 'H', long)]
        headers: Vec<String>,

        /// Follow redirects
        #[arg(long)]
        follow_redirects: bool,

        /// Maximum redirect hops
        #[arg(long, default_value = "10")]
        max_redirects: usize,

        /// Request timeout in milliseconds
        #[arg(long, default_value = "10000")]
        timeout: u64,

        /// Output format: text, json, csv, markdown, html
        #[arg(short, long, default_value = "text")]
        output_format: String,

        /// Output file path
        #[arg(short = 'O', long)]
        output: Option<String>,

        /// Enable wildcard detection
        #[arg(long, default_value = "true")]
        wildcard_detection: bool,

        /// Apply wordlist mutations (l33t, case, year, suffixes)
        #[arg(long)]
        mutate: bool,
    },

    /// Start MCP server for AI assistant integration (stdio transport)
    Mcp,

    /// Compare two scan results and show changes
    Diff {
        /// First scan result file (JSON)
        file_a: String,

        /// Second scan result file (JSON)
        file_b: String,

        /// Output format: text (default), json
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Show only new open ports
        #[arg(long)]
        new_only: bool,

        /// Show only closed ports
        #[arg(long)]
        closed_only: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            ports,
            exclude,
            rate,
            timeout,
            scan_type,
            aggressive,
            timing,
            min_rtt_timeout,
            max_rtt_timeout,
            initial_rtt_timeout,
            max_retries,
            host_timeout,
            scan_delay,
            max_scan_delay,
            min_parallelism,
            max_parallelism,
            min_hostgroup,
            max_hostgroup,
            min_rate,
            max_rate,
            version_detect,
            version_light,
            version_all,
            version_intensity,
            os_detect,
            raw,
            idle_scan,
            ftp_bounce: _,
            resume,
            packet_trace: _,
            reason,
            top_ports,
            hide_closed,
            hide_filtered,
            output,
            format,
            verbose,
            quiet,
            script_args,
            script_args_file,
            script_trace,
            script_updatedb,
            script_help,
        } => {
            // Handle --script-help (show help and exit)
            if let Some(ref script_name) = script_help {
                use nemue::script::ScriptHelp;

                // Try to find and display script help
                let script_dir = std::env::current_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("."))
                    .join("scripts");

                let script_path = script_dir.join(format!("{}.lua", script_name));

                if script_path.exists() {
                    match ScriptHelp::from_file(&script_path) {
                        Ok(help) => {
                            help.display();
                            return Ok(());
                        }
                        Err(e) => {
                            eprintln!("Error loading script help: {}", e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    eprintln!("Script not found: {}", script_name);
                    eprintln!("Looked in: {}", script_path.display());
                    std::process::exit(1);
                }
            }

            // Handle --script-updatedb (update database and exit)
            if script_updatedb {
                use nemue::script::ScriptDatabase;

                println!("Updating script database...");

                let script_dir = std::env::current_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("."))
                    .join("scripts");

                if !script_dir.exists() {
                    eprintln!("Script directory not found: {}", script_dir.display());
                    eprintln!("Please create a 'scripts' directory with .lua files");
                    std::process::exit(1);
                }

                let mut db = ScriptDatabase::new();
                match db.update(&script_dir) {
                    Ok(count) => {
                        println!("✓ Found {} script(s)", count);

                        let db_path = script_dir.join("scripts.db");
                        if let Err(e) = db.save(&db_path) {
                            eprintln!("Warning: Failed to save database: {}", e);
                        } else {
                            println!("✓ Database saved to: {}", db_path.display());
                        }

                        // Show summary
                        println!("\nCategories found:");
                        for category in db.categories() {
                            let scripts = db.by_category(&category);
                            println!(
                                "  {} ({} script{})",
                                category,
                                scripts.len(),
                                if scripts.len() == 1 { "" } else { "s" }
                            );
                        }

                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("Error updating database: {}", e);
                        std::process::exit(1);
                    }
                }
            }

            // Parse script arguments if provided
            let mut parsed_script_args = nemue::script::ScriptArgs::new();

            if let Some(ref args_str) = script_args {
                match nemue::script::ScriptArgs::parse(args_str) {
                    Ok(args) => parsed_script_args.merge(args),
                    Err(e) => {
                        eprintln!("Error parsing --script-args: {}", e);
                        std::process::exit(1);
                    }
                }
            }

            if let Some(ref args_file) = script_args_file {
                match nemue::script::ScriptArgs::from_file(args_file) {
                    Ok(args) => parsed_script_args.merge(args),
                    Err(e) => {
                        eprintln!("Error loading --script-args-file: {}", e);
                        std::process::exit(1);
                    }
                }
            }

            // Initialize script tracer if enabled
            let _tracer = nemue::script::ScriptTracer::new(script_trace);
            if script_trace && !quiet {
                println!("🔍 Script tracing enabled");
            }

            // Show script args if verbose and any were provided
            if verbose && !parsed_script_args.is_empty() {
                println!("📝 Script arguments ({}):", parsed_script_args.len());
                for (key, value) in parsed_script_args.as_map() {
                    println!("  {} = {}", key, value);
                }
            }

            // Apply aggressive mode defaults (like nmap -A)
            let (ports, version_detect, os_detect, raw, scan_type) = if aggressive {
                // Check if we're running as root/admin
                // On Unix, check if effective UID is 0
                let is_elevated = std::env::var("USER").map(|u| u == "root").unwrap_or(false)
                    || std::env::var("SUDO_USER").is_ok();

                let effective_scan_type = if is_elevated && scan_type == "syn" {
                    "syn".to_string()
                } else if !is_elevated && scan_type == "syn" {
                    // Fall back to connect scan if not root
                    eprintln!("⚠️  Warning: Aggressive mode requires root for SYN scan. Falling back to Connect scan.");
                    eprintln!("   Run with 'sudo' for full aggressive scan capabilities.");
                    "connect".to_string()
                } else {
                    scan_type
                };

                (
                    if ports == "1-1000" {
                        "top1000".to_string()
                    } else {
                        ports
                    },
                    true,        // enable version detection
                    true,        // enable OS detection
                    is_elevated, // only use raw sockets if we have root
                    effective_scan_type,
                )
            } else {
                (ports, version_detect, os_detect, raw, scan_type)
            };

            // Handle --top-ports N
            let ports = if let Some(top_n) = top_ports {
                format!("top{}", top_n)
            } else {
                ports
            };

            // Handle --version-light / --version-all / --version-intensity
            let version_detect =
                version_detect || version_light || version_all || version_intensity.is_some();

            // Apply timing template if specified
            let timing_template = timing
                .and_then(TimingTemplate::from_number)
                .unwrap_or_default();

            let mut timing_config = timing_template.to_config();

            // Apply individual timing overrides if specified
            if let Some(ref min_rtt) = min_rtt_timeout {
                match nemue::scanner::parse_duration(min_rtt) {
                    Ok(duration) => timing_config.min_rtt_timeout = duration,
                    Err(e) => eprintln!("Warning: Invalid --min-rtt-timeout: {}", e),
                }
            }

            if let Some(ref max_rtt) = max_rtt_timeout {
                match nemue::scanner::parse_duration(max_rtt) {
                    Ok(duration) => timing_config.max_rtt_timeout = duration,
                    Err(e) => eprintln!("Warning: Invalid --max-rtt-timeout: {}", e),
                }
            }

            if let Some(ref initial_rtt) = initial_rtt_timeout {
                match nemue::scanner::parse_duration(initial_rtt) {
                    Ok(duration) => timing_config.initial_rtt_timeout = duration,
                    Err(e) => eprintln!("Warning: Invalid --initial-rtt-timeout: {}", e),
                }
            }

            if let Some(ref retries) = max_retries {
                match nemue::scanner::parse_retries(retries) {
                    Ok(r) => timing_config.max_retries = r,
                    Err(e) => eprintln!("Warning: Invalid --max-retries: {}", e),
                }
            }

            if let Some(ref host_to) = host_timeout {
                match nemue::scanner::parse_duration(host_to) {
                    Ok(duration) => timing_config.host_timeout = duration,
                    Err(e) => eprintln!("Warning: Invalid --host-timeout: {}", e),
                }
            }

            if let Some(ref delay) = scan_delay {
                match nemue::scanner::parse_duration(delay) {
                    Ok(duration) => timing_config.scan_delay = duration,
                    Err(e) => eprintln!("Warning: Invalid --scan-delay: {}", e),
                }
            }

            if let Some(ref max_delay) = max_scan_delay {
                match nemue::scanner::parse_duration(max_delay) {
                    Ok(duration) => timing_config.max_scan_delay = duration,
                    Err(e) => eprintln!("Warning: Invalid --max-scan-delay: {}", e),
                }
            }

            if let Some(ref min_par) = min_parallelism {
                match nemue::scanner::parse_parallelism(min_par) {
                    Ok(p) => timing_config.min_parallelism = p,
                    Err(e) => eprintln!("Warning: Invalid --min-parallelism: {}", e),
                }
            }

            if let Some(ref max_par) = max_parallelism {
                match nemue::scanner::parse_parallelism(max_par) {
                    Ok(p) => timing_config.max_parallelism = p,
                    Err(e) => eprintln!("Warning: Invalid --max-parallelism: {}", e),
                }
            }

            if let Some(ref min_hg) = min_hostgroup {
                match nemue::scanner::parse_hostgroup(min_hg) {
                    Ok(h) => timing_config.min_hostgroup = h,
                    Err(e) => eprintln!("Warning: Invalid --min-hostgroup: {}", e),
                }
            }

            if let Some(ref max_hg) = max_hostgroup {
                match nemue::scanner::parse_hostgroup(max_hg) {
                    Ok(h) => timing_config.max_hostgroup = h,
                    Err(e) => eprintln!("Warning: Invalid --max-hostgroup: {}", e),
                }
            }

            if let Some(ref min_r) = min_rate {
                match nemue::scanner::parse_rate(min_r) {
                    Ok(r) => timing_config.min_rate = r,
                    Err(e) => eprintln!("Warning: Invalid --min-rate: {}", e),
                }
            }

            if let Some(ref max_r) = max_rate {
                match nemue::scanner::parse_rate(max_r) {
                    Ok(r) => timing_config.max_rate = r,
                    Err(e) => eprintln!("Warning: Invalid --max-rate: {}", e),
                }
            }

            // Validate timing configuration (ensures min <= max, etc.)
            timing_config.validate();

            // Use timing config to override rate if not explicitly set
            let effective_rate = if max_rate.is_some() || timing.is_some() {
                timing_config.get_max_rate()
            } else {
                rate
            };

            let display = DisplayFormatter::new(!quiet, verbose);

            display.print_banner();
            if !quiet && timing.is_some() {
                println!("⏱️  Timing template: {}", timing_template);
            }
            display.print_scan_info(&target, &ports, effective_rate);

            display.print_progress("Initializing scanner");
            let scan_engine = ScanEngine::with_all_options(
                effective_rate,
                timeout,
                version_detect,
                os_detect,
                raw,
            )?;

            display.clear_progress();
            display.print_progress("Scanning ports");

            // Handle resume if specified
            let results = if let Some(ref scan_id) = resume {
                use nemue::performance::ScanDatabase;

                let db = ScanDatabase::new(".nemue/scans");
                let checkpoint = db
                    .load_checkpoint(scan_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to load checkpoint: {}", e))?;

                println!("📂 Resuming scan {}", scan_id);
                println!(
                    "  Completed targets: {}",
                    checkpoint.completed_targets.len()
                );
                println!("  Pending targets: {}", checkpoint.pending_targets.len());

                // Scan only pending targets
                let pending_targets = checkpoint.pending_targets.join(",");
                if pending_targets.is_empty() {
                    println!("✅ All targets already completed!");
                    nemue::scanner::ScanResults {
                        scan_start: chrono::Utc::now(),
                        scan_end: chrono::Utc::now(),
                        target_count: 0,
                        port_count: 0,
                        results: Vec::new(),
                        os_fingerprints: Vec::new(),
                        script_results: Vec::new(),
                    }
                } else {
                    scan_engine
                        .scan(&pending_targets, &ports, &scan_type)
                        .await?
                }
            } else if let Some(ref zombie_spec) = idle_scan {
                use nemue::scanner::idle::{self, IdleScanConfig};

                // Parse zombie specification (format: zombie[:port])
                let parts: Vec<&str> = zombie_spec.split(':').collect();
                let zombie_ip: std::net::Ipv4Addr = parts[0]
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid zombie IP: {}", parts[0]))?;
                let zombie_port = if parts.len() > 1 {
                    parts[1]
                        .parse::<u16>()
                        .map_err(|_| anyhow::anyhow!("Invalid zombie port: {}", parts[1]))?
                } else {
                    80
                };

                let config = IdleScanConfig::new(zombie_ip)
                    .with_port(zombie_port)
                    .with_timeout(timeout);

                let target_ip: std::net::Ipv4Addr = match target.parse::<std::net::IpAddr>()? {
                    std::net::IpAddr::V4(ip) => ip,
                    _ => return Err(anyhow::anyhow!("Idle scan requires IPv4 target")),
                };

                let port_list = nemue::scanner::PortParser::parse(&ports)?;
                let port_numbers: Vec<u16> = port_list.iter().map(|p| p.value()).collect();

                display.print_progress(&format!(
                    "Idle scan via zombie {}:{}",
                    zombie_ip, zombie_port
                ));

                let idle_results = idle::idle_scan(&config, target_ip, &port_numbers).await?;
                let scan_results = idle::to_scan_results(idle_results, target_ip.into());

                nemue::scanner::ScanResults {
                    scan_start: chrono::Utc::now(),
                    scan_end: chrono::Utc::now(),
                    target_count: 1,
                    port_count: port_numbers.len(),
                    results: scan_results,
                    os_fingerprints: Vec::new(),
                    script_results: Vec::new(),
                }
            } else if let Some(ref exclude_ports) = exclude {
                scan_engine
                    .scan_with_exclusions(&target, &ports, exclude_ports, &scan_type)
                    .await?
            } else {
                scan_engine.scan(&target, &ports, &scan_type).await?
            };

            display.clear_progress();

            // If output file specified, save to file
            if let Some(output_path) = output {
                let formatter = ResultFormatter::new(OutputFormat::from_str(&format)?);
                let output_data = formatter.format(&results)?;
                std::fs::write(&output_path, &output_data)?;

                // Still show results on console
                display.print_results_filtered(&results, !hide_closed, !hide_filtered);

                println!("💾 Results saved to: {}", output_path);
            } else {
                // Just display to console
                display.print_results_filtered(&results, !hide_closed, !hide_filtered);
            }

            // Show reason codes if --reason flag is set
            if reason {
                println!("\nReason codes:");
                for r in &results.results {
                    let reason_str = r.reason.as_deref().unwrap_or(match r.state {
                        nemue::scanner::PortState::Open => "syn-ack",
                        nemue::scanner::PortState::Closed => "reset",
                        nemue::scanner::PortState::Filtered => "no-response",
                        nemue::scanner::PortState::Unfiltered => "reset",
                        nemue::scanner::PortState::OpenFiltered => "no-response",
                        nemue::scanner::PortState::Unknown => "unknown",
                    });
                    let state_str = match r.state {
                        nemue::scanner::PortState::Open => "open",
                        nemue::scanner::PortState::Closed => "closed",
                        nemue::scanner::PortState::Filtered => "filtered",
                        nemue::scanner::PortState::Unfiltered => "unfiltered",
                        nemue::scanner::PortState::OpenFiltered => "open|filtered",
                        nemue::scanner::PortState::Unknown => "unknown",
                    };
                    if !hide_closed || r.state == nemue::scanner::PortState::Open {
                        println!(
                            "  {}/{}: {} ({})",
                            r.port, r.protocol, state_str, reason_str
                        );
                    }
                }
            }
        }

        Commands::Fuzz {
            url,
            mode,
            wordlist,
            builtin,
            concurrency,
            rate_limit,
            status_codes,
            exclude_status,
            min_size,
            max_size,
            recursive,
            max_depth,
            extensions,
            user_agent,
            headers,
            follow_redirects,
            max_redirects,
            timeout,
            output_format,
            output,
            wildcard_detection,
            mutate,
        } => {
            use nemue::fuzzer::*;
            use std::collections::HashMap;

            // Print banner
            let display = DisplayFormatter::new(true, false);
            display.print_banner();

            println!("🔍 Web Content Discovery & Fuzzing");
            println!("Target: {}", url);
            println!("Mode: {}", mode);

            // Create wordlist manager
            let wordlist_mgr = WordlistManager::new();

            // Load wordlist
            let mut wordlist_data = if let Some(ref builtin_name) = builtin {
                println!("📚 Loading built-in wordlist: {}", builtin_name);

                let builtin_type = match builtin_name.as_str() {
                    "dirs1k" => BuiltinWordlist::CommonDirs1k,
                    "dirs10k" => BuiltinWordlist::CommonDirs10k,
                    "files" => BuiltinWordlist::CommonFiles,
                    "extensions" => BuiltinWordlist::CommonExtensions,
                    "subdomains" => BuiltinWordlist::CommonSubdomains,
                    "params" => BuiltinWordlist::CommonParameters,
                    "wordpress" => BuiltinWordlist::WordPress,
                    "joomla" => BuiltinWordlist::Joomla,
                    "laravel" => BuiltinWordlist::Laravel,
                    "api" => BuiltinWordlist::ApiEndpoints,
                    _ => {
                        eprintln!("❌ Unknown built-in wordlist: {}", builtin_name);
                        eprintln!("Available: dirs1k, dirs10k, files, extensions, subdomains, params, wordpress, joomla, laravel, api");
                        std::process::exit(1);
                    }
                };

                wordlist_mgr.load_builtin(builtin_type)
            } else if let Some(ref wordlist_path) = wordlist {
                println!("📚 Loading wordlist from: {}", wordlist_path);
                wordlist_mgr.load_from_file(wordlist_path).await?
            } else {
                eprintln!("❌ Either --wordlist or --builtin must be specified");
                std::process::exit(1);
            };

            // Apply mutations if requested
            if mutate {
                println!("🔄 Applying wordlist mutations...");
                let original_size = wordlist_data.len();
                wordlist_data = wordlist_mgr.mutate(wordlist_data);
                println!(
                    "📈 Wordlist expanded: {} → {} entries",
                    original_size,
                    wordlist_data.len()
                );
            }

            println!("📊 Wordlist size: {} entries", wordlist_data.len());

            // Parse fuzzing mode
            let fuzz_mode = match mode.as_str() {
                "dir" | "directory" => FuzzMode::Directory,
                "file" => FuzzMode::File,
                "ext" | "extension" => FuzzMode::Extension,
                "vhost" => FuzzMode::VirtualHost,
                "subdomain" | "dns" => FuzzMode::Subdomain,
                "s3" => FuzzMode::S3Bucket,
                "azure" => FuzzMode::AzureBlob,
                "gcp" => FuzzMode::GcpBucket,
                _ => {
                    eprintln!("❌ Invalid mode: {}", mode);
                    eprintln!("Available: dir, file, ext, vhost, subdomain, s3, azure, gcp");
                    std::process::exit(1);
                }
            };

            // Build response filter
            let mut filter = ResponseFilter {
                status_codes: Vec::new(),
                exclude_status_codes: Vec::new(),
                min_size,
                max_size,
                exclude_sizes: Vec::new(),
                include_regex: None,
                exclude_regex: None,
                min_time: None,
                max_time: None,
            };

            if let Some(codes) = status_codes {
                filter.status_codes = codes
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .collect();
            }

            if let Some(codes) = exclude_status {
                filter.exclude_status_codes = codes
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .collect();
            }

            // Parse custom headers
            let mut custom_headers = Vec::new();
            for header in headers {
                if let Some((key, value)) = header.split_once(':') {
                    custom_headers.push((key.trim().to_string(), value.trim().to_string()));
                }
            }

            // Add User-Agent if specified
            if let Some(ua) = user_agent {
                custom_headers.push(("User-Agent".to_string(), ua));
            }

            // Build fuzz config
            let config = FuzzConfig {
                base_url: url.clone(),
                mode: fuzz_mode,
                concurrency,
                rate_limit: rate_limit.unwrap_or(0) as u32,
                timeout: std::time::Duration::from_millis(timeout),
                follow_redirects: if follow_redirects {
                    Some(max_redirects as u8)
                } else {
                    None
                },
                user_agent: "Nemue/0.1.0".to_string(),
                headers: custom_headers,
                filter,
                recursive: false, // Handled separately
                max_depth,
                wordlist: String::new(), // Not used in this flow
                extensions: extensions
                    .map(|e| e.split(',').map(String::from).collect())
                    .unwrap_or_default(),
                detect_wildcards: wildcard_detection,
                auto_calibrate: true,
            };

            println!("⚙️  Concurrency: {}", concurrency);
            if let Some(rps) = rate_limit {
                println!("⏱️  Rate limit: {} req/s", rps);
            }
            println!("🚀 Starting fuzzing...\n");

            let start_time = std::time::Instant::now();
            let results = if recursive {
                println!("🔁 Recursive mode enabled (depth: {})", max_depth);

                let recursive_config = RecursiveConfig {
                    max_depth,
                    breadth_first: true,
                    min_status: 200,
                    max_status: 399,
                    extract_links: true,
                    follow_sitemaps: true,
                    extract_from_js: true,
                    generate_backups: true,
                };

                let scanner = RecursiveScanner::new(config, recursive_config);
                scanner.scan(wordlist_data).await?
            } else {
                let engine = FuzzEngine::new(config)?;
                engine.fuzz(wordlist_data).await?
            };

            let duration = start_time.elapsed();

            println!("\n✅ Fuzzing complete!");
            println!("⏱️  Duration: {:.2}s", duration.as_secs_f64());
            println!("📊 Results: {} findings", results.len());

            // Generate report
            use chrono::Utc;
            let report = FuzzReport {
                metadata: ScanMetadata {
                    scan_id: uuid::Uuid::new_v4().to_string(),
                    target: url.clone(),
                    mode: mode.clone(),
                    start_time: Utc::now()
                        - chrono::Duration::from_std(duration).unwrap_or_default(),
                    end_time: Some(Utc::now()),
                    wordlist_name: builtin
                        .clone()
                        .or(wordlist.clone())
                        .unwrap_or_else(|| "custom".to_string()),
                    wordlist_size: results.len(), // Use results length instead
                    config: HashMap::new(),
                },
                fuzz_results: results.clone(),
                subdomain_results: Vec::new(),
                cloud_results: Vec::new(),
                stats: ScanStats::from_results(&results, duration),
            };

            // Output results
            let output_data = match output_format.as_str() {
                "json" => FuzzOutput::format_json(&report)?,
                "csv" => FuzzOutput::format_csv(&results),
                "markdown" | "md" => FuzzOutput::format_markdown(&report),
                "html" => FuzzOutput::format_html(&report),
                _ => FuzzOutput::format_text(&report),
            };

            if let Some(output_path) = output {
                std::fs::write(&output_path, &output_data)?;
                println!("💾 Report saved to: {}", output_path);
            } else {
                println!("\n{}", output_data);
            }
        }

        Commands::Mcp => {
            use nemue::mcp::NemueMcpServer;
            use rmcp::ServiceExt;
            use tokio::io::{stdin, stdout};

            eprintln!("Nemue MCP Server v{}", env!("CARGO_PKG_VERSION"));
            eprintln!("Transport: stdio");
            eprintln!("Waiting for client connection...");

            let server = NemueMcpServer::new()?;
            let service = server.serve((stdin(), stdout())).await?;

            eprintln!("Client connected. Server running.");
            service.waiting().await?;
        }

        Commands::Diff {
            file_a,
            file_b,
            format,
            new_only,
            closed_only,
        } => {
            use nemue::scanner::diff;

            let scan_a = diff::load_scan(&file_a)?;
            let scan_b = diff::load_scan(&file_b)?;

            let mut diff_result = diff::compare_scans(&scan_a, &scan_b);

            // Apply filters
            if new_only {
                diff_result.closed_ports.clear();
                diff_result.changed_services.clear();
                diff_result.removed_hosts.clear();
            }
            if closed_only {
                diff_result.new_ports.clear();
                diff_result.changed_services.clear();
                diff_result.new_hosts.clear();
            }

            match format.as_str() {
                "json" => {
                    let json = serde_json::to_string_pretty(&diff_result)?;
                    println!("{}", json);
                }
                _ => {
                    println!("{}", diff::format_diff_text(&diff_result));
                }
            }
        }
    }

    Ok(())
}
