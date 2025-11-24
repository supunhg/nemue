use anyhow::Result;
use clap::Parser;

use nemue::scanner::ScanEngine;
use nemue::output::{OutputFormat, ResultFormatter, DisplayFormatter};

/// Nemue - A high-performance network scanner
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

        /// Ports to scan (e.g., 80,443 or 1-1000)
        #[arg(short, long, default_value = "1-1000")]
        ports: String,

        /// Maximum packets per second (rate limiting)
        #[arg(short, long, default_value = "1000")]
        rate: u32,

        /// Timeout for each port in milliseconds
        #[arg(short, long, default_value = "1000")]
        timeout: u64,

        /// Output file path
        #[arg(short, long)]
        output: Option<String>,

        /// Output format (json or xml)
        #[arg(short = 'f', long, default_value = "json")]
        format: String,

        /// Scan type (syn, connect, udp)
        #[arg(short = 't', long, default_value = "syn")]
        scan_type: String,

        /// Enable service/version detection
        #[arg(short = 'S', long, default_value = "true")]
        service_detection: bool,

        /// Enable OS detection
        #[arg(short = 'O', long, default_value = "true")]
        os_detection: bool,

        /// Disable banner
        #[arg(long)]
        no_banner: bool,

        /// Verbose output
        #[arg(short, long)]
        verbose: bool,

        /// Use raw sockets for SYN scan (requires root/admin privileges)
        #[arg(long)]
        raw: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            ports,
            rate,
            timeout,
            output,
            format,
            scan_type,
            service_detection,
            os_detection,
            no_banner,
            verbose,
            raw,
        } => {
            let display = DisplayFormatter::new(!no_banner, verbose);
            
            display.print_banner();
            display.print_scan_info(&target, &ports, rate);
            
            display.print_progress("Initializing scanner");
            let scan_engine = ScanEngine::with_all_options(
                rate, 
                timeout, 
                service_detection, 
                os_detection,
                raw
            )?;
            
            display.clear_progress();
            display.print_progress("Scanning ports");
            
            let results = scan_engine.scan(&target, &ports, &scan_type).await?;
            
            display.clear_progress();

            // If output file specified, save to file
            if let Some(output_path) = output {
                let formatter = ResultFormatter::new(OutputFormat::from_str(&format)?);
                let output_data = formatter.format(&results)?;
                std::fs::write(&output_path, &output_data)?;
                
                // Still show results on console
                display.print_results(&results);
                
                println!("💾 Results saved to: {}", output_path);
            } else {
                // Just display to console
                display.print_results(&results);
            }
        }
    }

    Ok(())
}
