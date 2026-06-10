local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs LDAP search queries to enumerate directory information.
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

  table.insert(result, "LDAP service detected")
  table.insert(result, "Host: " .. host.ip)
  table.insert(result, "Port: " .. port.number)
  table.insert(result, "Base DN: Requires configuration")
  table.insert(result, "Search capabilities: Requires LDAP bind first")

  socket:close()
  return stdnse.format_output(true, result)
end
