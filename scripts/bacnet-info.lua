local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts BACnet building automation protocol information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(47808, "bacnet")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "BACnet Service Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: BACnet (Building Automation)")
  table.insert(result, "Default port: 47808/UDP")
  table.insert(result, "Security: Often lacks authentication")
  port.version.name = "bacnet"
  port.version.product = "BACnet"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
