local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Tests for Web Cache Poisoning vulnerabilities.
Checks if unkeyed headers can be used to poison cached responses.
]]

---
-- @usage
-- nmap --script http-cache-poisoning -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-cache-poisoning:
-- |   Potential Cache Poisoning:
-- |     Header: X-Forwarded-Host
-- |     Cache key does not include header
-- |     Response reflected injected content
-- |_  Test with unique value to verify caching behavior

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local unkeyed_headers = {
  "X-Forwarded-Host",
  "X-Forwarded-For",
  "X-Forwarded-Proto",
  "X-Original-URL",
  "X-Rewrite-URL",
  "X-Host",
  "X-Real-IP",
  "True-Client-IP",
  "X-Custom-IP-Authorization",
  "X-Originating-IP",
  "CF-Connecting-IP",
  "Fastly-Client-IP"
}

local function generate_unique_string()
  return "nmap" .. tostring(os.time()) .. tostring(math.random(10000, 99999))
end

local function test_cache_poisoning(host, port, path, header_name)
  local unique_value = generate_unique_string()
  local headers = {}
  headers[header_name] = unique_value

  local response1 = http.get(host, port, path, { headers = headers })

  if response1 and response1.body and response1.body:match(unique_value) then
    local response2 = http.get(host, port, path)

    if response2 and response2.body and response2.body:match(unique_value) then
      return true, "Cached response contains injected content"
    end

    return true, "Content reflected (caching behavior uncertain)"
  end

  return false, nil
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output = {}
  local vuln_count = 0

  for _, header_name in ipairs(unkeyed_headers) do
    local vulnerable, detail = test_cache_poisoning(host, port, path, header_name)

    if vulnerable then
      vuln_count = vuln_count + 1
      table.insert(output, string.format("Header: %s", header_name))
      table.insert(output, string.format("Detail: %s", detail))
      table.insert(output, "")
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "Potential Cache Poisoning Vulnerabilities:")
    table.insert(result, "")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end
    return table.concat(result, "\n")
  end

  return "No cache poisoning vulnerabilities detected"
end
