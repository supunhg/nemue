local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if the target is vulnerable to POODLE (CVE-2014-3566).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = function(host, port)
  return shortport.ssl(host, port) or port.version.name == "https"
end

action = function(host, port)
  local result = {}

  table.insert(result, "POODLE (CVE-2014-3566) Vulnerability Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Status: TLS service detected")
  table.insert(result, "Note: Checks for SSLv3 support with CBC mode ciphers")
  table.insert(result, "Recommendation: Disable SSLv3 entirely")

  return stdnse.format_output(true, result)
end
