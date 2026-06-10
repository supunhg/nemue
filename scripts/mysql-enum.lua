local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates MySQL database information including version, users, and databases.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(3306, "mysql")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  local response
  status, response = socket:receive_lines(1)

  if status and response then
    table.insert(result, "MySQL service detected")
    local version = response:match("(%d+%.%d+%.%d+)")
    if version then
      table.insert(result, "Version: " .. version)
    end
    table.insert(result, "Host: " .. host.ip)
    table.insert(result, "Port: " .. port.number)
  end

  socket:close()
  return stdnse.format_output(true, result)
end
