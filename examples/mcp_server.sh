#!/bin/bash
# MCP server examples for Nemue
# These examples show how to use Nemue as an MCP tool server

set -e

echo "=== MCP Server Examples ==="
echo ""

# 1. Start MCP server (stdio mode for Claude Desktop)
echo "[1] Start MCP server (stdio mode):"
echo "    nemue mcp"
echo ""

# 2. MCP server configuration for Claude Desktop
echo "[2] Claude Desktop configuration (~/.claude/claude_desktop_config.json):"
cat << 'EOF'
{
  "mcpServers": {
    "nemue": {
      "command": "nemue",
      "args": ["mcp"]
    }
  }
}
EOF
echo ""

# 3. MCP server configuration for Cursor
echo "[3] Cursor configuration (.cursor/mcp.json):"
cat << 'EOF'
{
  "mcpServers": {
    "nemue": {
      "command": "nemue",
      "args": ["mcp"]
    }
  }
}
EOF
echo ""

# 4. MCP server configuration for VS Code
echo "[4] VS Code configuration (.vscode/mcp.json):"
cat << 'EOF'
{
  "servers": {
    "nemue": {
      "command": "nemue",
      "args": ["mcp"]
    }
  }
}
EOF
echo ""

# 5. Available MCP tools
echo "[5] Available MCP tools:"
echo "    - nemue_scan: Full port scan with service detection"
echo "    - nemue_quick_scan: Fast top-ports scan"
echo "    - nemue_service_detect: Service/version detection"
echo "    - nemue_os_detect: OS fingerprinting"
echo "    - nemue_ssl_check: SSL/TLS analysis"
echo "    - nemue_host_discovery: Ping sweep"
echo "    - nemue_traceroute: Network path discovery"
echo "    - nemue_fuzz: Web content fuzzing"
echo "    - nemue_vuln_scan: Vulnerability scanning"
echo ""

# 6. Example MCP tool calls (for testing)
echo "[6] Example MCP tool call JSON:"
cat << 'EOF'
{
  "tool": "nemue_scan",
  "arguments": {
    "target": "192.168.1.1",
    "ports": "22,80,443",
    "scan_type": "connect"
  }
}
EOF
echo ""

# 7. Docker MCP server
echo "[7] Docker MCP server:"
echo "    docker build -t nemue ."
echo "    docker run --rm -i nemue mcp"
echo ""

# 8. Test MCP server with stdio
echo "[8] Test MCP server (manual stdio):"
echo "    echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}' | nemue mcp"
echo ""

echo "=== MCP server examples complete ==="
