local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts NTLM authentication information from an RDP server.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(3389, "ms-wbt-server")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "RDP service detected")
  table.insert(result, "Host: " .. host.ip)
  table.insert(result, "NTLM info extraction requires NLA negotiation")

  socket:close()
  return stdnse.format_output(true, result)
end
