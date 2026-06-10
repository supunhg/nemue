local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts information from an SNMP server using common community strings.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(161, "snmp")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "SNMP service detected")
  table.insert(result, "Host: " .. host.ip)
  table.insert(result, "Port: " .. port.number)
  table.insert(result, "Protocol: SNMP")
  port.version.name = "snmp"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
