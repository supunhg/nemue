local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for Spring4Shell (CVE-2022-22965) vulnerability indicators.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local result = {}

  table.insert(result, "Spring4Shell (CVE-2022-22965) Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Vulnerability: Spring Framework RCE via data binding")
  table.insert(result, "Affected: Spring Framework 5.3.0 to 5.3.17")
  table.insert(result, "Requirements: JDK 9+, WAR deployment, Spring MVC")
  table.insert(result, "Remediation: Update Spring Framework to 5.3.18+")

  return stdnse.format_output(true, result)
end
