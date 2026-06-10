local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for XML External Entity (XXE) injection indicators.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local result = {}

  table.insert(result, "XXE Injection Check:")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local response = http.get(host, port, "/")
  if response and response.body then
    local body = response.body:lower()
    if body:match("xml") or body:match("soap") or body:match("xhtml") then
      table.insert(result, "XML-related content detected")
      table.insert(result, "XXE may be possible if XML parsing is enabled")
    end
  end

  table.insert(result, "Note: Active XXE testing requires POST endpoint with XML")
  table.insert(result, "Remediation: Disable external entity processing in XML parsers")

  return stdnse.format_output(true, result)
end
