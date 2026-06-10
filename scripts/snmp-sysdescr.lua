local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts SNMP system description using SNMPv2c.
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

  table.insert(result, "SNMP System Description")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "OID: 1.3.6.1.2.1.1.1.0 (sysDescr)")
  table.insert(result, "Note: Requires SNMP GET request with community string")

  socket:close()
  return stdnse.format_output(true, result)
end
