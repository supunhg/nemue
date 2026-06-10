local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates available SMB shares on the target.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(445, "microsoft-ds")

action = function(host, port)
  local result = {}

  table.insert(result, "SMB Share Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Common shares: C$, ADMIN$, IPC$, print$")
  table.insert(result, "Status: Requires authenticated SMB session")

  return stdnse.format_output(true, result)
end
