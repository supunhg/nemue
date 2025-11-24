// Script Execution Tracing and Debugging
// Implements --script-trace functionality

use chrono::Utc;
use std::sync::{Arc, Mutex};

/// Script execution event types
#[derive(Debug, Clone)]
pub enum TraceEvent {
    /// Script started execution
    ScriptStart {
        script_name: String,
        timestamp: chrono::DateTime<Utc>,
    },
    /// Script finished execution
    ScriptEnd {
        script_name: String,
        duration_ms: u64,
        timestamp: chrono::DateTime<Utc>,
    },
    /// Script function called
    FunctionCall {
        script_name: String,
        function: String,
        args: String,
        timestamp: chrono::DateTime<Utc>,
    },
    /// Script printed output
    Output {
        script_name: String,
        message: String,
        timestamp: chrono::DateTime<Utc>,
    },
    /// Script encountered error
    Error {
        script_name: String,
        error: String,
        timestamp: chrono::DateTime<Utc>,
    },
}

/// Script execution tracer
#[derive(Clone)]
pub struct ScriptTracer {
    enabled: bool,
    events: Arc<Mutex<Vec<TraceEvent>>>,
}

impl ScriptTracer {
    /// Create new tracer
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            events: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record trace event
    pub fn trace(&self, event: TraceEvent) {
        if !self.enabled {
            return;
        }

        // Print event immediately for real-time debugging
        self.print_event(&event);

        // Store event for later analysis
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }

    /// Print event to console
    fn print_event(&self, event: &TraceEvent) {
        match event {
            TraceEvent::ScriptStart { script_name, timestamp } => {
                eprintln!("[TRACE {}] Starting script: {}", 
                    timestamp.format("%H:%M:%S%.3f"), script_name);
            }
            TraceEvent::ScriptEnd { script_name, duration_ms, timestamp } => {
                eprintln!("[TRACE {}] Finished script: {} ({}ms)", 
                    timestamp.format("%H:%M:%S%.3f"), script_name, duration_ms);
            }
            TraceEvent::FunctionCall { script_name, function, args, timestamp } => {
                eprintln!("[TRACE {}] {}::{} called with: {}", 
                    timestamp.format("%H:%M:%S%.3f"), script_name, function, args);
            }
            TraceEvent::Output { script_name, message, timestamp } => {
                eprintln!("[TRACE {}] {} output: {}", 
                    timestamp.format("%H:%M:%S%.3f"), script_name, message);
            }
            TraceEvent::Error { script_name, error, timestamp } => {
                eprintln!("[TRACE {}] {} ERROR: {}", 
                    timestamp.format("%H:%M:%S%.3f"), script_name, error);
            }
        }
    }

    /// Get all recorded events
    pub fn get_events(&self) -> Vec<TraceEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Clear all recorded events
    pub fn clear(&self) {
        if let Ok(mut events) = self.events.lock() {
            events.clear();
        }
    }

    /// Get number of events
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    /// Check if tracing is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for ScriptTracer {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tracer_creation() {
        let tracer = ScriptTracer::new(true);
        assert!(tracer.is_enabled());
        assert_eq!(tracer.event_count(), 0);
    }

    #[test]
    fn test_tracer_disabled() {
        let tracer = ScriptTracer::new(false);
        assert!(!tracer.is_enabled());
    }

    #[test]
    fn test_trace_events() {
        let tracer = ScriptTracer::new(true);
        
        tracer.trace(TraceEvent::ScriptStart {
            script_name: "test-script".to_string(),
            timestamp: Utc::now(),
        });
        
        tracer.trace(TraceEvent::Output {
            script_name: "test-script".to_string(),
            message: "Hello World".to_string(),
            timestamp: Utc::now(),
        });
        
        tracer.trace(TraceEvent::ScriptEnd {
            script_name: "test-script".to_string(),
            duration_ms: 150,
            timestamp: Utc::now(),
        });
        
        assert_eq!(tracer.event_count(), 3);
        
        let events = tracer.get_events();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn test_trace_when_disabled() {
        let tracer = ScriptTracer::new(false);
        
        tracer.trace(TraceEvent::ScriptStart {
            script_name: "test".to_string(),
            timestamp: Utc::now(),
        });
        
        // When disabled, events are not stored (early return in trace method)
        assert_eq!(tracer.event_count(), 0);
    }

    #[test]
    fn test_clear_events() {
        let tracer = ScriptTracer::new(true);
        
        tracer.trace(TraceEvent::ScriptStart {
            script_name: "test".to_string(),
            timestamp: Utc::now(),
        });
        
        assert_eq!(tracer.event_count(), 1);
        
        tracer.clear();
        assert_eq!(tracer.event_count(), 0);
    }

    #[test]
    fn test_function_call_trace() {
        let tracer = ScriptTracer::new(true);
        
        tracer.trace(TraceEvent::FunctionCall {
            script_name: "http-check".to_string(),
            function: "http_get".to_string(),
            args: "url=\"http://example.com\"".to_string(),
            timestamp: Utc::now(),
        });
        
        let events = tracer.get_events();
        assert_eq!(events.len(), 1);
        
        if let TraceEvent::FunctionCall { function, .. } = &events[0] {
            assert_eq!(function, "http_get");
        } else {
            panic!("Expected FunctionCall event");
        }
    }

    #[test]
    fn test_error_trace() {
        let tracer = ScriptTracer::new(true);
        
        tracer.trace(TraceEvent::Error {
            script_name: "bad-script".to_string(),
            error: "Connection timeout".to_string(),
            timestamp: Utc::now(),
        });
        
        let events = tracer.get_events();
        if let TraceEvent::Error { error, .. } = &events[0] {
            assert_eq!(error, "Connection timeout");
        } else {
            panic!("Expected Error event");
        }
    }
}
