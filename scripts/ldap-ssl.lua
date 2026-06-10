local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects LDAP SSL/TLS (LDAPS) support.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(636, "ldap")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "LDAPS (LDAP over SSL) Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Port: 636 (LDAPS)")
  port.version.name = "ldap"
  port.version.product = "LDAP over SSL"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
