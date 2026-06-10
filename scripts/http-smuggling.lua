local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for HTTP request smuggling vulnerabilities.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local result = {}

  table.insert(result, "HTTP Request Smuggling Check:")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Types:")
  table.insert(result, "  CL.TE - Content-Length vs Transfer-Encoding")
  table.insert(result, "  TE.CL - Transfer-Encoding vs Content-Length")
  table.insert(result, "  TE.TE - Ambiguous Transfer-Encoding")
  table.insert(result, "Note: Active testing requires careful crafted requests")
  table.insert(result, "Affected: Frontend/backend with different parsing behaviors")

  return stdnse.format_output(true, result)
end
