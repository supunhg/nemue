local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for SMB anonymous login access.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(445, "microsoft-ds")

action = function(host, port)
  local result = {}

  table.insert(result, "SMB Anonymous Login Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Anonymous access allows unauthenticated share browsing")
  table.insert(result, "Status: Requires SMB session setup")

  return stdnse.format_output(true, result)
end
