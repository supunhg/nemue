local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for ProxyLogon (CVE-2021-26855) vulnerability indicators.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local result = {}

  table.insert(result, "ProxyLogon (CVE-2021-26855) Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Vulnerability: Microsoft Exchange Server SSRF RCE")
  table.insert(result, "Affected: Exchange Server 2013, 2016, 2019")
  table.insert(result, "Note: Requires Exchange OWA/EWS endpoint")
  table.insert(result, "Remediation: Apply latest Exchange CU and security updates")

  return stdnse.format_output(true, result)
end
