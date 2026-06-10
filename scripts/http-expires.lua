local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Analyzes HTTP cache expiration headers (Expires, Cache-Control).
Detects missing cache controls, overly permissive caching, and stale content risks.
]]

---
-- @usage
-- nmap --script http-expires -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-expires:
-- |   Cache Expiration Analysis:
-- |     Expires: Thu, 01 Jan 2025 00:00:00 GMT
-- |     Cache-Control: public, max-age=31536000
-- |     Pragma: not set
-- |   [!] Public caching allowed on sensitive resource

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local response = http.get(host, port, path)

  if not response or not response.header then
    return "No response received"
  end

  local output = {}
  local issues = {}

  local expires = response.header["expires"]
  local cache_control = response.header["cache-control"]
  local pragma = response.header["pragma"]
  local vary = response.header["vary"]

  table.insert(output, "Cache Expiration Analysis:")
  table.insert(output, string.format("  Expires: %s", expires or "not set"))
  table.insert(output, string.format("  Cache-Control: %s", cache_control or "not set"))
  table.insert(output, string.format("  Pragma: %s", pragma or "not set"))
  table.insert(output, string.format("  Vary: %s", vary or "not set"))
  table.insert(output, "")

  if expires and expires == "-1" then
    table.insert(issues, "Expires set to -1 (invalid)")
  end

  if not cache_control then
    table.insert(issues, "No Cache-Control header - caching behavior undefined")
  else
    if string.find(cache_control, "public") then
      table.insert(issues, "Public caching allowed - ensure no sensitive data")
    end

    if string.find(cache_control, "no%-store") == nil and
       string.find(cache_control, "no%-cache") == nil and
       string.find(cache_control, "private") == nil then
      if string.find(cache_control, "max%-age") then
        local max_age = string.match(cache_control, "max%-age=(%d+)")
        if max_age and tonumber(max_age) > 86400 then
          table.insert(issues, string.format("Long max-age (%s seconds) - content may become stale", max_age))
        end
      end
    end

    if string.find(cache_control, "no%-transform") == nil then
      table.insert(issues, "No-transform not set - proxies may modify content")
    end
  end

  if not expires and not cache_control then
    table.insert(issues, "No caching headers at all - full caching risk")
  end

  if #issues > 0 then
    table.insert(output, "Issues Found:")
    for _, issue in ipairs(issues) do
      table.insert(output, string.format("  [!] %s", issue))
    end
  else
    table.insert(output, "[+] Cache headers properly configured")
  end

  return table.concat(output, "\n")
end
