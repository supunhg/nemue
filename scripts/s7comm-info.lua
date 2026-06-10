local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts S7comm (Siemens PLC) industrial protocol information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(102, "s7comm")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "S7comm (Siemens PLC) Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: S7comm (Siemens Industrial)")
  table.insert(result, "Default port: 102/TCP")
  table.insert(result, "Security: Check for password protection")
  port.version.name = "s7comm"
  port.version.product = "S7comm"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
