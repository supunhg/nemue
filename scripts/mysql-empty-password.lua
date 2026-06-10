local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for MySQL accounts with empty passwords.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

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
    table.insert(result, "Checking for empty password accounts...")
    table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  end

  socket:close()
  return stdnse.format_output(true, result)
end
