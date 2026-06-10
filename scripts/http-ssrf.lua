local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for Server-Side Request Forgery (SSRF) indicators.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local result = {}

  table.insert(result, "SSRF Indicator Check:")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local response = http.get(host, port, "/")
  if response and response.body then
    local body = response.body:lower()
    if body:match("url") or body:match("fetch") or body:match("proxy") then
      table.insert(result, "URL/fetch parameters detected in page")
      table.insert(result, "SSRF may be possible with URL parameters")
    end
  end

  table.insert(result, "Note: Active SSRF testing requires URL input parameters")
  table.insert(result, "Common targets: cloud metadata (169.254.169.254)")

  return stdnse.format_output(true, result)
end
