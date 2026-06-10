local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts LDAP server naming contexts and base DNs.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(389, "ldap")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "LDAP Root DSE Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Note: Root DSE reveals naming contexts and capabilities")
  table.insert(result, "OID: 1.3.6.1.4.1.1466.20037 (startTLS)")

  socket:close()
  return stdnse.format_output(true, result)
end
