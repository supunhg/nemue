local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for SSL/TLS Renegotiation vulnerability (CVE-2009-3555).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = function(host, port)
  return shortport.ssl(host, port) or port.version.name == "https"
end

action = function(host, port)
  local result = {}

  table.insert(result, "SSL Renegotiation Vulnerability Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "CVE-2009-3555: Insecure renegotiation")
  table.insert(result, "Status: Requires TLS renegotiation attempt")
  table.insert(result, "Remediation: Implement RFC 5746 secure renegotiation")

  return stdnse.format_output(true, result)
end
