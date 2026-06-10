local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates supported SSL/TLS protocol versions.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return shortport.ssl(host, port) or port.version.name == "https"
end

action = function(host, port)
  local result = {}

  table.insert(result, "SSL/TLS Protocol Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocols to check:")
  table.insert(result, "  SSLv2, SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3")
  table.insert(result, "Recommendation: Disable SSLv2, SSLv3, TLSv1.0, TLSv1.1")

  return stdnse.format_output(true, result)
end
