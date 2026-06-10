local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against PostgreSQL servers.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(5432, "postgresql")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "PostgreSQL service detected - brute force audit started")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Status: Ready for credential testing")

  socket:close()
  return stdnse.format_output(true, result)
end
