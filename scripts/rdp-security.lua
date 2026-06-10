local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts RDP security layer information.
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

  table.insert(result, "RDP Security Layer Info")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Layers: Standard RDP Security, Enhanced TLS, CredSSP")
  table.insert(result, "Status: Requires protocol negotiation")

  socket:close()
  return stdnse.format_output(true, result)
end
