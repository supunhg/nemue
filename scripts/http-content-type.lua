local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Analyzes Content-Type headers for security issues.
Detects missing Content-Type, MIME sniffing risks, and charset issues.
]]

---
-- @usage
-- nmap --script http-content-type -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-content-type:
-- |   Content-Type Analysis:
-- |     Content-Type: text/html; charset=UTF-8
-- |     X-Content-Type-Options: missing
-- |   [!] X-Content-Type-Options header not set (MIME sniffing risk)

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

  local content_type = response.header["content-type"]
  local xcto = response.header["x-content-type-options"]
  local content_disposition = response.header["content-disposition"]

  table.insert(output, "Content-Type Analysis:")
  table.insert(output, string.format("  Content-Type: %s", content_type or "missing"))
  table.insert(output, string.format("  X-Content-Type-Options: %s", xcto or "missing"))
  table.insert(output, string.format("  Content-Disposition: %s", content_disposition or "not set"))
  table.insert(output, "")

  if not content_type then
    table.insert(issues, "Content-Type header is missing")
  else
    if not string.find(content_type, "charset") then
      table.insert(issues, "No charset specified in Content-Type")
    end

    if string.find(content_type, "text/html") and not string.find(content_type, "charset") then
      table.insert(issues, "HTML response without charset may allow XSS via encoding attacks")
    end

    if string.find(content_type, "application/octet-stream") then
      table.insert(issues, "Generic binary Content-Type may trigger MIME sniffing")
    end
  end

  if not xcto then
    table.insert(issues, "X-Content-Type-Options not set - browsers may sniff MIME type")
  elseif xcto ~= "nosniff" then
    table.insert(issues, string.format("X-Content-Type-Options set to '%s' instead of 'nosniff'", xcto))
  end

  if #issues > 0 then
    table.insert(output, "Issues Found:")
    for _, issue in ipairs(issues) do
      table.insert(output, string.format("  [!] %s", issue))
    end
  else
    table.insert(output, "[+] Content-Type headers properly configured")
  end

  return table.concat(output, "\n")
end
