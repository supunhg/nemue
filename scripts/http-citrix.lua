local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for Citrix Bleed (CVE-2023-4966) vulnerability indicators.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local result = {}

  table.insert(result, "Citrix Bleed (CVE-2023-4966) Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Vulnerability: Citrix NetScaler ADC/Gateway info leak")
  table.insert(result, "Affected: NetScaler ADC/Gateway 13.1, 14.1")
  table.insert(result, "Note: Can leak session tokens allowing session hijacking")
  table.insert(result, "Remediation: Apply Citrix security updates")

  local response = http.get(host, port, "/")
  if response and response.body then
    if response.body:match("Citrix") or response.body:match("NetScaler") then
      table.insert(result, "Citrix indicators detected in response")
    end
  end

  return stdnse.format_output(true, result)
end
