// MCP (Model Context Protocol) server integration for Nemue
// Exposes scanning capabilities as MCP tools for AI assistant integration

pub mod server;
pub mod tools;

pub use server::NemueMcpServer;
