local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects X-Debug and similar debug headers that may expose sensitive information.
Checks for debug mode indicators, trace headers, and development artifacts.
]]

---
-- @usage
-- nmap --script http-x-debug -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-x-debug:
-- |   Debug Header Analysis:
-- |     X-Debug-Token: abc123
-- |     X-Debug-Dump: /tmp/debug.log
-- |   [!] Debug headers exposed - potential information disclosure

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local debug_headers = {
  "x-debug",
  "x-debug-token",
  "x-debug-token-link",
  "x-debug-dump",
  "x-debug-info",
  "x-debug-mode",
  "x-debug-trace",
  "x-debug-log",
  "x-trace",
  "x-trace-id",
  "x-request-id",
  "x-correlation-id",
  "x-runtime",
  "x-rack-cache",
  "x-served-by",
  "x-cache",
  "x-cache-hits",
  "x-timer",
  "x-varnish",
  "x-akamai",
  "x-envoy",
  "x-kong",
  "x-request-start",
  "x-backend",
  "x-powered-by",
  "x-generator",
  "x-drupal-cache",
  "x-drupal-dynamic-cache",
  "x-varnish-cache",
  "x-page-speed",
  "x-mod-pagespeed"
}

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local response = http.get(host, port, path)

  if not response or not response.header then
    return "No response received"
  end

  local output = {}
  local issues = {}
  local found_headers = {}

  for _, header_name in ipairs(debug_headers) do
    local value = response.header[header_name]
    if value then
      table.insert(found_headers, { name = header_name, value = value })
    end
  end

  table.insert(output, "Debug Header Analysis:")
  table.insert(output, "")

  if #found_headers > 0 then
    for _, header in ipairs(found_headers) do
      table.insert(output, string.format("  %s: %s", header.name, header.value))
    end

    -- Specific analysis
    for _, header in ipairs(found_headers) do
      local name = header.name
      local value = header.value

      if name == "x-debug-token" then
        table.insert(issues, "Symfony debug token exposed")
      elseif name == "x-debug-token-link" then
        table.insert(issues, string.format("Debug profiler accessible: %s", value))
      elseif name == "x-debug-trace" then
        table.insert(issues, "Debug trace information exposed")
      elseif name == "x-runtime" then
        table.insert(issues, "Request processing time disclosed")
      elseif name == "x-request-id" or name == "x-correlation-id" then
        table.insert(issues, "Request tracing ID exposed")
      elseif string.find(name, "cache") then
        table.insert(issues, "Caching infrastructure details disclosed")
      elseif string.find(name, "x%-envoy") or string.find(name, "x%-kong") then
        table.insert(issues, "API gateway information disclosed")
      end
    end

    table.insert(issues, string.format("Found %d debug/informational headers", #found_headers))
  else
    table.insert(output, "[+] No debug headers detected")
  end

  -- Check response body for debug indicators
  local body = response.body
  if body then
    if string.find(body, "debug%s*=%s*true") or string.find(body, "DEBUG_MODE") then
      table.insert(issues, "Debug mode indicator found in response body")
    end
    if string.find(body, "stack.trace") or string.find(body, "Stack Trace") then
      table.insert(issues, "Stack trace found in response")
    end
    if string.find(body, "SQLSTATE") or string.find(body, "mysql_fetch") then
      table.insert(issues, "Database error details in response")
    end
  end

  if #issues > 0 then
    table.insert(output, "")
    table.insert(output, "Issues Found:")
    for _, issue in ipairs(issues) do
      table.insert(output, string.format("  [!] %s", issue))
    end
  end

  return table.concat(output, "\n")
end
