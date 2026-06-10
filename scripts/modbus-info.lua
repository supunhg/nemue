local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts Modbus industrial protocol information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(502, "modbus")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "Modbus Service Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: Modbus TCP (Industrial)")
  table.insert(result, "Default port: 502")
  table.insert(result, "Security: Often lacks authentication")
  port.version.name = "modbus"
  port.version.product = "Modbus"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
