local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Connects to PostgreSQL and extracts detailed server information.
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

  table.insert(result, "PostgreSQL Information:")
  table.insert(result, "Host: " .. host.ip)
  table.insert(result, "Port: " .. port.number)
  port.version.name = "postgresql"
  port.version.product = "PostgreSQL"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
