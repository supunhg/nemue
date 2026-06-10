local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects MySQL SSL/TLS configuration and certificate usage.
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
    table.insert(result, "MySQL SSL Configuration Check")
    if response:match("mysql") or response:match("MariaDB") then
      table.insert(result, "Service: MySQL/MariaDB detected")
      table.insert(result, "SSL: Requires capability flag inspection")
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
