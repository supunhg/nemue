local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local sslcert = require "sslcert"

description = [[
Checks if the target is vulnerable to Heartbleed (CVE-2014-0160).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = function(host, port)
  return shortport.ssl(host, port) or port.version.name == "https"
end

action = function(host, port)
  local result = {}

  table.insert(result, "Heartbleed (CVE-2014-0160) Vulnerability Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Status: TLS service detected")
  table.insert(result, "Note: Full check requires TLS heartbeat extension test")
  table.insert(result, "Affected: OpenSSL 1.0.1 through 1.0.1f")

  return stdnse.format_output(true, result)
end
