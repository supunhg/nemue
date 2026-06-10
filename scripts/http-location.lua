local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Analyzes Location headers for open redirect vulnerabilities and information disclosure.
Tests if the server redirects to user-supplied or external destinations.
]]

---
-- @usage
-- nmap --script http-location -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-location:
-- |   Location Header Analysis:
-- |     /redirect -> http://evil.com
-- |   [!] Possible open redirect vulnerability

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local test_paths = {
  "/redirect",
  "/login",
  "/logout",
  "/callback",
  "/oauth",
  "/sso",
  "/goto",
  "/url",
  "/link",
  "/out"
}

local function check_redirect(host, port, path)
  local response = http.get(host, port, path, { redirect = false })

  if response and response.header then
    local location = response.header["location"]
    if location then
      return response.status, location
    end
  end

  return nil, nil
end

action = function(host, port)
  local output = {}
  local issues = {}
  local redirects_found = false

  for _, path in ipairs(test_paths) do
    local status, location = check_redirect(host, port, path)

    if location then
      redirects_found = true
      table.insert(output, string.format("Path: %s", path))
      table.insert(output, string.format("  Status: %d", status))
      table.insert(output, string.format("  Location: %s", location))

      if string.match(location, "^https?://") then
        if not string.find(location, host.ip) and
           not string.find(location, "localhost") and
           not string.find(location, "127%.0%.0%.1") then
          local target_host = string.match(location, "^https?://([^/]+)")
          table.insert(issues, string.format("Possible open redirect: %s -> %s", path, target_host))
        end
      end

      if string.find(location, "://") and not string.find(location, "https://") then
        table.insert(issues, string.format("Redirect to HTTP (not HTTPS): %s", path))
      end

      table.insert(output, "")
    end
  end

  -- Check custom redirect parameter
  local custom_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")
  if custom_path then
    local status, location = check_redirect(host, port, custom_path)
    if location then
      redirects_found = true
      table.insert(output, string.format("Custom Path: %s", custom_path))
      table.insert(output, string.format("  Status: %d", status))
      table.insert(output, string.format("  Location: %s", location))
      table.insert(output, "")
    end
  end

  if redirects_found then
    local result = {}
    table.insert(result, "Location Header Analysis:")
    table.insert(result, "")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end

    if #issues > 0 then
      table.insert(result, "Issues Found:")
      for _, issue in ipairs(issues) do
        table.insert(result, string.format("  [!] %s", issue))
      end
    end

    return table.concat(result, "\n")
  end

  return "No Location headers detected on common paths"
end
