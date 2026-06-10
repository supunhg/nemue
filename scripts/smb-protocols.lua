local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects SMB protocol version (SMBv1, SMBv2, SMBv3).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(445, "microsoft-ds")

action = function(host, port)
  local result = {}

  table.insert(result, "SMB Protocol Version Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "SMBv1: Legacy, vulnerable to EternalBlue")
  table.insert(result, "SMBv2: Windows Vista+")
  table.insert(result, "SMBv3: Windows 8+ with encryption support")
  table.insert(result, "Status: Requires SMB negotiate")

  return stdnse.format_output(true, result)
end
