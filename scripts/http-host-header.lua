local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Tests for Host header injection vulnerabilities.
Checks if the application reflects or trusts arbitrary Host headers.
]]

---
-- @usage
-- nmap --script http-host-header -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-host-header:
-- |   Host Header Injection:
-- |     Type: Password reset poisoning
-- |     Injected host: evil.com
-- |     Response contains evil.com in links
-- |_  Use --script-args http-host-header.url=<url> to test specific endpoint

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local malicious_hosts = {
  "evil.com",
  "attacker.com",
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "internal-server",
  "admin.internal"
}

local function test_host_header(host, port, path, malicious_host)
  local headers = {
    ["Host"] = malicious_host
  }

  local response = http.get(host, port, path, { headers = headers })

  if response and response.body then
    if response.body:match(malicious_host) then
      return true, "Host reflected in response"
    end

    if response.body:match("href=[\"']https?://" .. malicious_host) or
       response.body:match("action=[\"']https?://" .. malicious_host) then
      return true, "Host used in links/forms"
    end
  end

  return false, nil
end

local function test_x_forwarded_host(host, port, path, malicious_host)
  local headers = {
    ["X-Forwarded-Host"] = malicious_host
  }

  local response = http.get(host, port, path, { headers = headers })

  if response and response.body then
    if response.body:match(malicious_host) then
      return true, "X-Forwarded-Host reflected"
    end
  end

  return false, nil
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output = {}
  local vuln_count = 0

  for _, malicious_host in ipairs(malicious_hosts) do
    local vulnerable, detail = test_host_header(host, port, path, malicious_host)

    if vulnerable then
      vuln_count = vuln_count + 1
      table.insert(output, string.format("Injected host: %s", malicious_host))
      table.insert(output, string.format("Type: Host header injection"))
      table.insert(output, string.format("Detail: %s", detail))
      table.insert(output, "")
      break
    end
  end

  for _, malicious_host in ipairs(malicious_hosts) do
    local vulnerable, detail = test_x_forwarded_host(host, port, path, malicious_host)

    if vulnerable then
      vuln_count = vuln_count + 1
      table.insert(output, string.format("Injected X-Forwarded-Host: %s", malicious_host))
      table.insert(output, string.format("Type: X-Forwarded-Host injection"))
      table.insert(output, string.format("Detail: %s", detail))
      table.insert(output, "")
      break
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "Host Header Injection Vulnerabilities Found:")
    table.insert(result, "")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end
    return table.concat(result, "\n")
  end

  return "No host header injection vulnerabilities detected"
end
