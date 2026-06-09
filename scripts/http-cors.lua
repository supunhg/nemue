local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks for CORS (Cross-Origin Resource Sharing) misconfigurations.
Tests if the server allows arbitrary origins or reflects origin in Access-Control-Allow-Origin.
]]

---
-- @usage
-- nmap --script http-cors -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-cors:
-- |   CORS Misconfiguration:
-- |     Origin: evil.com
-- |     Access-Control-Allow-Origin: evil.com
-- |     Access-Control-Allow-Credentials: true
-- |_  Vulnerable to cross-origin attacks

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local test_origins = {
  "http://evil.com",
  "https://evil.com",
  "null",
  "http://attacker.com",
  "http://subdomain.evil.com",
  "http://evil.com%00.target.com",
  "http://evil.com.target.com"
}

local function test_cors(host, port, path, origin)
  local headers = {
    ["Origin"] = origin
  }

  local response = http.get(host, port, path, { headers = headers })

  if response and response.header then
    local acao = response.header["access-control-allow-origin"]
    local acac = response.header["access-control-allow-credentials"]

    if acao then
      if acao == "*" then
        return true, "Wildcard origin", acac
      elseif acao == origin then
        return true, "Origin reflected", acac
      elseif acao == "null" and origin == "null" then
        return true, "Null origin allowed", acac
      end
    end
  end

  return false, nil, nil
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output = {}
  local vuln_count = 0

  for _, origin in ipairs(test_origins) do
    local vulnerable, detail, credentials = test_cors(host, port, path, origin)

    if vulnerable then
      vuln_count = vuln_count + 1
      table.insert(output, string.format("Origin: %s", origin))
      table.insert(output, string.format("Access-Control-Allow-Origin: %s", origin))
      if credentials then
        table.insert(output, string.format("Access-Control-Allow-Credentials: %s", credentials))
      end
      table.insert(output, string.format("Issue: %s", detail))
      table.insert(output, "")
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "CORS Misconfigurations Found:")
    table.insert(result, "")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end
    return table.concat(result, "\n")
  end

  return "No CORS misconfigurations detected"
end
