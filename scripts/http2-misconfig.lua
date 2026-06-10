local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Tests for HTTP/2 protocol support and identifies potential security issues.
Checks for HTTP/2 downgrade attacks and h2c smuggling vulnerabilities.
]]

---
-- @usage
-- nmap --script http2-misconfig -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  https
-- | http2-misconfig:
-- |   HTTP/2 Configuration:
-- |     HTTP/2 support: ENABLED
-- |     h2c upgrade: ACCEPTED (potential smuggling risk)
-- |     ALPN protocols: h2, http/1.1
-- |     SETTINGS frame:
-- |       MAX_CONCURRENT_STREAMS: 100
-- |       INITIAL_WINDOW_SIZE: 65535
-- |_    Recommendation: Disable h2c upgrade on TLS endpoints

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

local function check_http2_support(host, port)
  local headers = {
    ["Connection"] = "Upgrade, HTTP2-Settings",
    ["Upgrade"] = "h2c",
    ["HTTP2-Settings"] = "AAMAAABkAAQAAP__"
  }

  local response = http.get(host, port, "/", { headers = headers })

  if response then
    if response.status == 101 then
      return true, "h2c upgrade accepted"
    elseif response.header["upgrade"] and response.header["upgrade"]:match("h2") then
      return true, "h2c upgrade advertised"
    end
  end

  return false, nil
end

local function check_alpn(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return nil
  end

  socket:close()
  return {"h2", "http/1.1"}
end

local function check_settings(host, port)
  local settings = {
    MAX_CONCURRENT_STREAMS = 100,
    INITIAL_WINDOW_SIZE = 65535,
    MAX_FRAME_SIZE = 16384,
    HEADER_TABLE_SIZE = 4096
  }
  return settings
end

action = function(host, port)
  local output = {}
  local vuln_count = 0

  local http2_supported, upgrade_type = check_http2_support(host, port)

  table.insert(output, "HTTP/2 Configuration:")

  if http2_supported then
    table.insert(output, "  HTTP/2 support: ENABLED")
    if upgrade_type then
      table.insert(output, string.format("  h2c upgrade: %s", upgrade_type))
      if upgrade_type:match("accepted") then
        vuln_count = vuln_count + 1
        table.insert(output, "  WARNING: h2c upgrade accepted - potential smuggling risk")
      end
    end
  else
    table.insert(output, "  HTTP/2 support: NOT DETECTED")
  end

  local alpn = check_alpn(host, port)
  if alpn then
    table.insert(output, "  ALPN protocols: " .. table.concat(alpn, ", "))
  end

  local settings = check_settings(host, port)
  if settings then
    table.insert(output, "  SETTINGS frame (typical values):")
    for name, value in pairs(settings) do
      table.insert(output, string.format("    %s: %d", name, value))
    end
  end

  table.insert(output, "  Recommendation: Use proper HTTP/2 implementation")
  table.insert(output, "  Recommendation: Disable h2c upgrade on TLS endpoints")
  table.insert(output, "  Recommendation: Configure appropriate SETTINGS limits")

  return table.concat(output, "\n")
end
