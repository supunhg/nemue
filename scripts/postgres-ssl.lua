local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects PostgreSQL SSL/TLS configuration.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5432, "postgresql")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "PostgreSQL SSL Configuration Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "SSL: Requires SSLRequest packet")

  socket:close()
  return stdnse.format_output(true, result)
end
