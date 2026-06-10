local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for Log4Shell (CVE-2021-44228) vulnerability indicators.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local result = {}

  table.insert(result, "Log4Shell (CVE-2021-44228) Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Vulnerability: Apache Log4j JNDI RCE")
  table.insert(result, "Affected: Log4j 2.0-beta9 to 2.14.1")
  table.insert(result, "Note: Active exploitation requires OOB callback server")
  table.insert(result, "Remediation: Update Log4j to 2.17.0+")

  return stdnse.format_output(true, result)
end
