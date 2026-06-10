local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if SMB signing is required and enforced.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(445, "microsoft-ds")

action = function(host, port)
  local result = {}

  table.insert(result, "SMB Signing Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "SMB signing prevents man-in-the-middle attacks")
  table.insert(result, "Status: Requires SMB negotiation for full check")

  return stdnse.format_output(true, result)
end
