// Packet trace module
// Provides detailed logging of all packets sent and received during scanning

use chrono::{DateTime, Utc};
use std::fmt;
use std::net::IpAddr;
use std::sync::Mutex;
use tracing::info;

/// Packet direction
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketDirection {
    Sent,
    Received,
}

impl fmt::Display for PacketDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketDirection::Sent => write!(f, "SENT"),
            PacketDirection::Received => write!(f, "RCVD"),
        }
    }
}

/// TCP flags representation
#[derive(Debug, Clone)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();
        if self.syn {
            flags.push("SYN");
        }
        if self.ack {
            flags.push("ACK");
        }
        if self.fin {
            flags.push("FIN");
        }
        if self.rst {
            flags.push("RST");
        }
        if self.psh {
            flags.push("PSH");
        }
        if self.urg {
            flags.push("URG");
        }
        if self.ece {
            flags.push("ECE");
        }
        if self.cwr {
            flags.push("CWR");
        }
        if flags.is_empty() {
            write!(f, "NONE")
        } else {
            write!(f, "{}", flags.join(","))
        }
    }
}

/// A traced packet event
#[derive(Debug, Clone)]
pub struct PacketEvent {
    pub timestamp: DateTime<Utc>,
    pub direction: PacketDirection,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub dest_ip: IpAddr,
    pub dest_port: u16,
    pub protocol: String,
    pub flags: Option<TcpFlags>,
    pub length: usize,
    pub ttl: Option<u8>,
    pub summary: String,
}

impl fmt::Display for PacketEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}:{} -> {}:{} {} len={}",
            self.timestamp.format("%H:%M:%S%.3f"),
            self.direction,
            self.protocol,
            self.source_ip,
            self.source_port,
            self.dest_ip,
            self.dest_port,
            self.flags
                .as_ref()
                .map(|f| f.to_string())
                .unwrap_or_default(),
            self.length,
        )
    }
}

/// Packet tracer for logging all packet events
pub struct PacketTracer {
    enabled: bool,
    events: Mutex<Vec<PacketEvent>>,
}

impl PacketTracer {
    /// Create a new packet tracer
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            events: Mutex::new(Vec::new()),
        }
    }

    /// Log a sent packet
    pub fn trace_sent(
        &self,
        source_ip: IpAddr,
        source_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
        protocol: &str,
        flags: Option<TcpFlags>,
        length: usize,
        ttl: Option<u8>,
    ) {
        if !self.enabled {
            return;
        }

        let event = PacketEvent {
            timestamp: Utc::now(),
            direction: PacketDirection::Sent,
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            protocol: protocol.to_string(),
            flags,
            length,
            ttl,
            summary: format!(
                "{}:{} -> {}:{} {}",
                source_ip, source_port, dest_ip, dest_port, protocol
            ),
        };

        info!("{}", event);
        self.events.lock().unwrap().push(event);
    }

    /// Log a received packet
    pub fn trace_received(
        &self,
        source_ip: IpAddr,
        source_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
        protocol: &str,
        flags: Option<TcpFlags>,
        length: usize,
        ttl: Option<u8>,
    ) {
        if !self.enabled {
            return;
        }

        let event = PacketEvent {
            timestamp: Utc::now(),
            direction: PacketDirection::Received,
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            protocol: protocol.to_string(),
            flags,
            length,
            ttl,
            summary: format!(
                "{}:{} <- {}:{} {}",
                dest_ip, dest_port, source_ip, source_port, protocol
            ),
        };

        info!("{}", event);
        self.events.lock().unwrap().push(event);
    }

    /// Get all recorded events
    pub fn events(&self) -> Vec<PacketEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Get event count
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    /// Clear all events
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }

    /// Format all events as a trace log
    pub fn format_trace(&self) -> String {
        let events = self.events.lock().unwrap();
        let mut output = String::new();
        output.push_str("=== Packet Trace ===\n\n");

        for event in events.iter() {
            output.push_str(&format!("{}\n", event));
        }

        output.push_str(&format!("\nTotal packets: {}\n", events.len()));
        output
    }
}

/// Parse TCP flags from a u8 bitmask
pub fn parse_tcp_flags(flags: u8) -> TcpFlags {
    TcpFlags {
        syn: flags & 0x02 != 0,
        ack: flags & 0x10 != 0,
        fin: flags & 0x01 != 0,
        rst: flags & 0x04 != 0,
        psh: flags & 0x08 != 0,
        urg: flags & 0x20 != 0,
        ece: flags & 0x40 != 0,
        cwr: flags & 0x80 != 0,
    }
}

/// Global packet tracer instance
use std::sync::OnceLock;

static GLOBAL_TRACER: OnceLock<PacketTracer> = OnceLock::new();

/// Get the global packet tracer
pub fn global_tracer() -> &'static PacketTracer {
    GLOBAL_TRACER.get_or_init(|| PacketTracer::new(false))
}

/// Enable/disable the global packet tracer
pub fn set_global_tracer_enabled(_enabled: bool) {
    // Note: This creates a new tracer, which is not ideal
    // In production, we'd use an AtomicBool for the enabled flag
    // For now, this is a placeholder
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_packet_tracer_disabled() {
        let tracer = PacketTracer::new(false);
        tracer.trace_sent(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            80,
            "TCP",
            Some(TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                psh: false,
                urg: false,
                ece: false,
                cwr: false,
            }),
            60,
            Some(64),
        );
        assert_eq!(tracer.event_count(), 0);
    }

    #[test]
    fn test_packet_tracer_enabled() {
        let tracer = PacketTracer::new(true);
        tracer.trace_sent(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            80,
            "TCP",
            Some(TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                psh: false,
                urg: false,
                ece: false,
                cwr: false,
            }),
            60,
            Some(64),
        );
        assert_eq!(tracer.event_count(), 1);
    }

    #[test]
    fn test_tcp_flags_display() {
        let flags = TcpFlags {
            syn: true,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
            ece: false,
            cwr: false,
        };
        assert_eq!(flags.to_string(), "SYN,ACK");
    }

    #[test]
    fn test_parse_tcp_flags() {
        let flags = parse_tcp_flags(0x12); // SYN + ACK
        assert!(flags.syn);
        assert!(flags.ack);
        assert!(!flags.fin);
        assert!(!flags.rst);
    }

    #[test]
    fn test_format_trace() {
        let tracer = PacketTracer::new(true);
        tracer.trace_sent(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            12345,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            80,
            "TCP",
            Some(TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                psh: false,
                urg: false,
                ece: false,
                cwr: false,
            }),
            60,
            Some(64),
        );

        let trace = tracer.format_trace();
        assert!(trace.contains("SENT"));
        assert!(trace.contains("SYN"));
        assert!(trace.contains("Total packets: 1"));
    }
}
