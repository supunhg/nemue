local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if the target is vulnerable to DROWN (CVE-2016-0800).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = function(host, port)
  return shortport.ssl(host, port) or port.version.name == "https"
end

action = function(host, port)
  local result = {}

  table.insert(result, "DROWN (CVE-2016-0800) Vulnerability Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Status: TLS service detected")
  table.insert(result, "Note: Checks for SSLv2 support")
  table.insert(result, "Affected: Servers supporting SSLv2 or sharing key with SSLv2 server")
  table.insert(result, "Recommendation: Disable SSLv2 on all servers")

  return stdnse.format_output(true, result)
end
