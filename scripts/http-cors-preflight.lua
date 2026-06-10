local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Tests CORS preflight (OPTIONS) request handling.
Checks if the server properly validates Origin, Method, and Headers in preflight requests.
]]

---
-- @usage
-- nmap --script http-cors-preflight -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-cors-preflight:
-- |   Preflight Response:
-- |     Access-Control-Allow-Origin: *
-- |     Access-Control-Allow-Methods: GET, POST, PUT, DELETE
-- |     Access-Control-Allow-Headers: *
-- |_    Issue: Overly permissive preflight policy

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local test_origins = {
  "http://evil.com",
  "https://attacker.com",
  "null"
}

local test_methods = {
  "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
}

local test_headers = {
  "Authorization",
  "Content-Type",
  "X-Custom-Header",
  "X-Requested-With"
}

local function send_preflight(host, port, path, origin, method, headers)
  local req_headers = {
    ["Origin"] = origin,
    ["Access-Control-Request-Method"] = method,
    ["Access-Control-Request-Headers"] = headers
  }

  local response = http.generic_request(host, port, "OPTIONS", path, { headers = req_headers })

  if response and response.header then
    return {
      allow_origin = response.header["access-control-allow-origin"],
      allow_methods = response.header["access-control-allow-methods"],
      allow_headers = response.header["access-control-allow-headers"],
      max_age = response.header["access-control-max-age"],
      status = response.status
    }
  end

  return nil
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output = {}
  local issues = {}

  for _, origin in ipairs(test_origins) do
    local result = send_preflight(host, port, path, origin, "DELETE", "Authorization,Content-Type")

    if result then
      if result.allow_origin then
        table.insert(output, string.format("Origin: %s", origin))
        table.insert(output, string.format("  Access-Control-Allow-Origin: %s", result.allow_origin))
        table.insert(output, string.format("  Access-Control-Allow-Methods: %s", result.allow_methods or "N/A"))
        table.insert(output, string.format("  Access-Control-Allow-Headers: %s", result.allow_headers or "N/A"))
        table.insert(output, string.format("  Access-Control-Max-Age: %s", result.max_age or "N/A"))
        table.insert(output, "")

        if result.allow_origin == "*" then
          table.insert(issues, "Wildcard origin in preflight response")
        elseif result.allow_origin == origin then
          table.insert(issues, string.format("Origin reflected: %s", origin))
        end

        if result.allow_methods and string.find(result.allow_methods, "DELETE") then
          table.insert(issues, "DELETE method allowed in preflight")
        end

        if result.allow_headers == "*" then
          table.insert(issues, "All headers allowed in preflight")
        end
      end
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "CORS Preflight Analysis:")
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

  return "No CORS preflight headers detected"
end
