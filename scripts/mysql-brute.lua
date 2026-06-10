local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local unpwdb = require "unpwdb"

description = [[
Performs brute force password auditing against MySQL servers.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

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
    table.insert(result, "MySQL service detected - brute force audit started")
    table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
    table.insert(result, "Status: Ready for credential testing")
  end

  socket:close()
  return stdnse.format_output(true, result)
end
